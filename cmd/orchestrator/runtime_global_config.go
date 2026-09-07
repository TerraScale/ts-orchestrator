package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sync"

	"terrascale.tech/orchestrator/src/orchestrator/authorityjournal"
	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	"terrascale.tech/orchestrator/src/orchestrator/estate"
	"terrascale.tech/orchestrator/src/orchestrator/ocireconcile"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
	"terrascale.tech/orchestrator/src/orchestrator/reaper"
	"terrascale.tech/orchestrator/src/orchestrator/restoredrill"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

// ErrProductionGlobalDependency identifies a provider which has not yet been
// handed off to the composition root. It is deliberately distinct from static
// deployment admission: a valid deployment can be admitted while its live
// worker graph remains fail-closed until every provider is concrete.
var ErrProductionGlobalDependency = errors.New("production global dependency is unavailable")

type productionGlobalBuildInput struct {
	Global          *productionGlobalFile
	Auth            productionAuthBootstrapConfig
	Spec            estate.Spec
	Mirror          *delivery.ArtifactMirror
	Shared          provider.DeliveryRegionStoreConfig
	Ownership       *provider.DurableOwnershipJournal
	Close           func() error
	Transition      productionPlacementTransitionConfig
	RestoreBackup   restoredrill.BackupPort
	RestoreBranches restoredrill.BranchPort
	HostRemoval     func(context.Context, globalWorkerSession, *databaseadmission.NATSJournal, hostRemovalTransitionPorts) (ocireconcile.MemberRemovalOwner, error)
}

// buildProductionGlobalConfig is the lease-owned composition stage. All
// provider clients created here use the supplied session and are released in
// reverse construction order when a later dependency is absent.
func buildProductionGlobalConfig(ctx context.Context, session globalWorkerSession, input productionGlobalBuildInput) (productionGlobalWorkerConfig, error) {
	var config productionGlobalWorkerConfig
	if input.Global == nil || input.Mirror == nil || input.Ownership == nil || input.Shared.Journal == nil {
		return config, fmt.Errorf("%w: admitted delivery ownership and artifact mirror", ErrProductionGlobalDependency)
	}
	if input.Global.Compute.BootstrapSignerFile == "" || len(input.Global.Compute.BootstrapSignerPublicKeyPin) != 64 {
		return config, fmt.Errorf("%w: explicit delegated bootstrap signer and public pin", ErrProductionGlobalDependency)
	}
	if _, err := hex.DecodeString(input.Global.Compute.BootstrapSignerPublicKeyPin); err != nil {
		return config, fmt.Errorf("%w: delegated bootstrap signer pin is invalid", ErrProductionGlobalDependency)
	}
	signer, err := security.LoadCommandSignatureSignerPEM(input.Global.Compute.BootstrapSignerFile)
	if err != nil || signer.PublicKeyID() != input.Global.Compute.BootstrapSignerPublicKeyPin {
		if signer != nil {
			_ = signer.Close()
		}
		return config, fmt.Errorf("%w: delegated bootstrap signer does not match public pin", ErrProductionGlobalDependency)
	}
	config.BootstrapSigner = signer
	if err := session.CheckEffectAuthority(ctx); err != nil {
		_ = signer.Close()
		return config, err
	}

	cleanup := make([]func() error, 0, 4)
	cleanup = append(cleanup, signer.Close)
	closeAll := sync.OnceValue(func() error {
		var result error
		for i := len(cleanup) - 1; i >= 0; i-- {
			result = errors.Join(result, cleanup[i]())
		}
		if input.Close != nil {
			result = errors.Join(result, input.Close())
		}
		return result
	})
	fail := func(err error) (productionGlobalWorkerConfig, error) {
		config.Close = closeAll
		return config, err
	}

	estateClient, closeEstate, err := constructProductionEstateClient(input.Global.Estate)
	if err != nil {
		return fail(fmt.Errorf("global estate client: %w", err))
	}
	cleanup = append(cleanup, closeEstate)

	recovery, err := input.Global.Recovery.Construct(ctx, session, input.Shared, input.Ownership)
	if err != nil {
		return fail(fmt.Errorf("global recovery providers: %w", err))
	}
	config.LifecyclePolicy = recovery.Policy
	if config.LifecyclePolicy == nil {
		return fail(fmt.Errorf("%w: recovery lifecycle policy", ErrProductionGlobalDependency))
	}
	config.Reaper.Store = &recovery.ReaperState
	config.Reaper.Mail = recovery.Mail
	audit, err := reaper.NewNATSAuditSink(recovery.ReaperState)
	if err != nil {
		return fail(fmt.Errorf("global recovery audit: %w", err))
	}
	config.Reaper.Audit = audit
	config.Restore.Journal = recovery.Journal
	config.Restore.Pager = recovery.Pager
	config.Restore.Snapshotter = recovery.Snapshotter
	config.Restore.SnapshotMirror = recovery.SnapshotMirror
	config.Restore.Drill = recovery.Drill
	config.Restore.SnapshotRegions = recovery.SnapshotRegions
	config.Restore.Backup = input.RestoreBackup
	config.Restore.Branches = input.RestoreBranches
	config.HostRemoval = input.HostRemoval

	rotation, capabilityStore, closeRotation, err := input.Global.Rotation.Construct(ctx, session, productionDeliveryMirrorSource{mirror: input.Mirror, region: input.Global.Recovery.SourceRegion})
	if err != nil {
		return fail(fmt.Errorf("global rotation providers: %w", err))
	}
	cleanup = append(cleanup, closeRotation)
	config.Rotation = rotation
	config.MembershipRevocations, err = input.Global.MembershipRevocations.Construct(capabilityStore, session.CheckEffectAuthority)
	if err != nil {
		return fail(fmt.Errorf("global membership revocations: %w", err))
	}

	kv, closeKV, err := constructProductionKVWriter(input.Global.KV, input.Spec, input.Global.HealthFile, session)
	if err != nil {
		return fail(fmt.Errorf("global Cloudflare KV: %w", err))
	}
	cleanup = append(cleanup, closeKV)
	config.KV = kv

	database, err := resolveProductionDatabase(input.Global.Database, productionPlacementConfig{Targets: input.Auth.Targets}, input.Auth)
	if err != nil {
		return fail(fmt.Errorf("global database configuration: %w", err))
	}
	config.Database = database
	// The child branch is admitted through the same durable provisioning
	// pipeline as ordinary databases; it never mints a local identity.
	var databaseRef *productionDatabase
	config.BranchDatabaseRef = &databaseRef
	config.Restore.Branches = productionDatabaseBranchPort{database: &databaseRef, config: config.Database}
	var backupDatabaseRef *productionDatabase
	config.BackupDatabaseRef = &backupDatabaseRef
	config.Restore.Backup = productionDatabaseBackupPort{database: &backupDatabaseRef, config: config.Database, refresh: session.guard.RefreshAuthority, check: session.CheckEffectAuthority, keyID: input.Transition.Issuer.ProofKeyID, key: slices.Clone(input.Transition.Issuer.ProofKey), grantJournal: func(op string) (*authorityjournal.Journal[lifecycleGrantRecord], error) {
		h := sha256.Sum256([]byte(op))
		return authorityjournal.New(authorityjournal.Config{Connection: session.Connection, CandidateID: session.Lease.CandidateId, AuthorityEpoch: uint64(session.Lease.Epoch), LeaseID: session.Lease.LeaseId, StateKey: "restore-grant-" + hex.EncodeToString(h[:])}, func() lifecycleGrantRecord { return lifecycleGrantRecord{} }, func(lifecycleGrantRecord) error { return nil })
	}}
	branchPort := config.Restore.Branches.(productionDatabaseBranchPort)
	branchPort.grantJournal = config.Restore.Backup.(productionDatabaseBackupPort).grantJournal
	branchPort.renewStatsGrant = config.Restore.Backup.(productionDatabaseBackupPort).renewRestoreStatsGrant
	config.Restore.Branches = branchPort
	config.AuthBootstrap = input.Auth
	config.PlacementTransition = input.Transition
	config.EstateClient = estateClient
	config.Close = closeAll
	cloudInitByArch := make(map[string]string, 2)
	for arch := range input.Global.Compute.Artifacts {
		value, err := input.Global.Compute.cloudInitFor(arch)
		if err != nil {
			return fail(fmt.Errorf("global compute %s cloud-init: %w", arch, err))
		}
		cloudInitByArch[arch] = value
	}
	config.ComputeMutationJournalBucket = input.Global.Compute.MutationJournalKV
	config.Ownership = input.Ownership
	config.ComputeGateways = make(map[string]ocireconcile.ComputeGateway, len(input.Spec.Regions))
	computeAdapters := make(map[string]*provider.OCIComputeAdapter, len(input.Spec.Regions))
	for _, region := range input.Spec.Regions {
		estateSpec, err := provider.LoadOCIEstateSpec(input.Global.Compute.EstateFiles[region.Code])
		if err != nil {
			return fail(fmt.Errorf("compute estate %s: %w", region.Code, err))
		}
		reader, err := provider.NewOCIEstateHTTPReader(estateSpec, input.Global.Compute.KeyID, input.Global.Compute.PrivateKeyFile)
		if err != nil {
			return fail(fmt.Errorf("compute OCI reader %s: %w", region.Code, err))
		}
		adapter, err := provider.NewOCIComputeAdapter(reader.Transports[provider.OCIServiceCore], input.Shared.Journal)
		if err != nil {
			return fail(fmt.Errorf("compute OCI adapter %s: %w", region.Code, err))
		}
		adapter.Ownership = input.Ownership
		computeAdapters[region.Code] = adapter
		gateway, err := ocireconcile.NewDurableOCIMemberGateway(reader.Transports[provider.OCIServiceCore], adapter, estateSpec.WorkloadCompartmentID, input.Global.Compute.ImageID, provider.ProviderEpoch{Value: uint64(session.Lease.Epoch)})
		if err != nil {
			return fail(fmt.Errorf("compute gateway %s: %w", region.Code, err))
		}
		config.ComputeGateways[region.Code] = gateway
	}
	config.ComputeApply = func(applyCtx context.Context, journal provider.ProviderMutationJournal) error {
		if err := session.CheckEffectAuthority(applyCtx); err != nil {
			return err
		}
		for _, region := range input.Spec.Regions {
			if adapter := computeAdapters[region.Code]; adapter != nil {
				adapter.Journal = journal
			}
			estateFile := input.Global.Compute.EstateFiles[region.Code]
			estateSpec, err := provider.LoadOCIEstateSpec(estateFile)
			if err != nil {
				return fmt.Errorf("compute estate %s: %w", region.Code, err)
			}
			reader, err := provider.NewOCIEstateHTTPReader(estateSpec, input.Global.Compute.KeyID, input.Global.Compute.PrivateKeyFile)
			if err != nil {
				return fmt.Errorf("compute OCI reader %s: %w", region.Code, err)
			}
			core := reader.Transports[provider.OCIServiceCore]
			gateway := config.ComputeGateways[region.Code]
			if gateway == nil {
				return fmt.Errorf("compute gateway %s: unavailable", region.Code)
			}
			network, err := ocireconcile.NewOCINetworkGateway(core, estateSpec.NetworkCompartmentID)
			if err != nil {
				return fmt.Errorf("compute network %s: %w", region.Code, err)
			}
			candidates := make([]ocireconcile.MemberLaunchCandidate, 0, len(region.Members.Candidates))
			for _, candidate := range region.Members.Candidates {
				image := input.Global.Compute.ImageID
				if candidate.Architecture == ocireconcile.MemberArchAMD64 {
					image = input.Global.Compute.FallbackImageID
				}
				candidates = append(candidates, ocireconcile.MemberLaunchCandidate{Shape: candidate.Shape, ImageID: image, Architecture: candidate.Architecture, QualificationRef: candidate.QualificationRef, CostRef: candidate.CostRef, CloudInitBase64: cloudInitByArch[candidate.Architecture]})
			}
			cloudInitByMember := make(map[int]string, int(region.Members.Count))
			for index := 1; index <= int(region.Members.Count); index++ {
				cloudInitByMember[index] = cloudInitByArch[ocireconcile.MemberArchArm64]
			}
			bindings := make(map[int]ocireconcile.MemberBinding, int(region.Members.Count))
			for _, databaseRegion := range config.Database.Regions {
				if databaseRegion.Region != region.Code {
					continue
				}
				for index := 1; index <= int(region.Members.Count); index++ {
					var host productionDatabaseHost
					if index == 1 {
						host = databaseRegion.Writer
					} else if index == 2 {
						host = databaseRegion.Follower
					} else {
						continue
					}
					bindings[index] = ocireconcile.MemberBinding{ServerIdentity: host.ServerIdentity, Environment: config.Database.Environment, Cluster: config.Database.Cluster, MemberID: host.MemberID, CellID: region.Code, Generation: uint64(session.Lease.Epoch)}
				}
				break
			}
			declared := ocireconcile.ComputeDeclared{Region: region, ImageID: input.Global.Compute.ImageID, FallbackImageID: input.Global.Compute.FallbackImageID, Candidates: candidates, CloudInitByMember: cloudInitByMember, MemberBindings: bindings}
			reconciler := &ocireconcile.ComputeReconciler{Compute: gateway, Network: network, RemovalOwner: config.ComputeRemovalOwner}
			observed, err := reconciler.Observe(applyCtx, declared)
			if err != nil {
				return fmt.Errorf("compute observe %s: %w", region.Code, err)
			}
			plan, err := reconciler.Reconcile(applyCtx, declared, observed)
			if err != nil {
				return fmt.Errorf("compute reconcile %s: %w", region.Code, err)
			}
			if err := reconciler.Apply(applyCtx, declared, observed, plan); err != nil {
				return fmt.Errorf("compute apply %s: %w", region.Code, err)
			}
		}
		return nil
	}

	if input.RestoreBackup != nil {
		config.Restore.Backup = input.RestoreBackup
	}
	if input.RestoreBranches != nil {
		config.Restore.Branches = input.RestoreBranches
	}
	// Reaper database/key and estate snapshot are installed after the database,
	// placement transition, and accepted lease-bound lifecycle client exist.
	// Keep this stage fail closed while preserving the already opened clients.
	return config, fmt.Errorf("%w: lifecycle reaper database/key and estate snapshot adapters", ErrProductionGlobalDependency)
}
