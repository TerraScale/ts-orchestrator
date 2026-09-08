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
	"terrascale.tech/orchestrator/src/orchestrator/cloudflare"
	"terrascale.tech/orchestrator/src/orchestrator/control"
	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	"terrascale.tech/orchestrator/src/orchestrator/estate"
	"terrascale.tech/orchestrator/src/orchestrator/hostremoval"
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
	BindProjection       func(computeProjection)
	BindTargetProjection func(computeTargetProjection)
	Global               *productionGlobalFile
	Auth                 productionAuthBootstrapConfig
	Spec                 estate.Spec
	Mirror               *delivery.ArtifactMirror
	Shared               provider.DeliveryRegionStoreConfig
	Ownership            *provider.DurableOwnershipJournal
	Close                func() error
	Transition           productionPlacementTransitionConfig
	RestoreBackup        restoredrill.BackupPort
	RestoreBranches      restoredrill.BranchPort
	HostRemoval          func(context.Context, globalWorkerSession, *databaseadmission.NATSJournal, hostRemovalTransitionPorts) (ocireconcile.MemberRemovalOwner, error)
	GlobalEdge           func(*delivery.ArtifactMirror, *cloudflare.SnippetCapabilityStore, func(context.Context) error) (control.GlobalEdgeDelivery, error)
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
	if input.GlobalEdge == nil {
		return fail(fmt.Errorf("%w: global edge provider", ErrProductionGlobalDependency))
	}
	config.Edge, err = input.GlobalEdge(input.Mirror, capabilityStore, session.CheckEffectAuthority)
	if err != nil {
		return fail(fmt.Errorf("global edge provider: %w", err))
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
	config.Placement.Targets = slices.Clone(input.Auth.Targets)
	// The child branch is admitted through the same durable provisioning
	// pipeline as ordinary databases; it never mints a local identity.
	var databaseRef *productionDatabase
	config.BranchDatabaseRef = &databaseRef
	var backupDatabaseRef *productionDatabase
	config.BackupDatabaseRef = &backupDatabaseRef
	config.EstateSnapshot = deferredProductionEstateSnapshot(input.Spec, input.Global.HealthFile, &databaseRef)
	config.Restore.Backup = productionDatabaseBackupPort{database: &backupDatabaseRef, config: config.Database, refresh: session.guard.RefreshAuthority, check: session.CheckEffectAuthority, keyID: input.Transition.Issuer.ProofKeyID, key: slices.Clone(input.Transition.Issuer.ProofKey), grantJournal: func(op string) (*authorityjournal.Journal[lifecycleGrantRecord], error) {
		h := sha256.Sum256([]byte(op))
		return authorityjournal.New(authorityjournal.Config{Connection: session.Connection, CandidateID: session.Lease.CandidateId, AuthorityEpoch: uint64(session.Lease.Epoch), LeaseID: session.Lease.LeaseId, StateKey: "restore-grant-" + hex.EncodeToString(h[:])}, func() lifecycleGrantRecord { return lifecycleGrantRecord{} }, func(lifecycleGrantRecord) error { return nil })
	}}
	config.Restore.Branches = newProductionDatabaseBranchPort(&databaseRef, config.Database, config.Restore.Backup.(productionDatabaseBackupPort))
	config.AuthBootstrap = input.Auth
	config.PlacementTransition = input.Transition
	config.EstateClient = estateClient
	config.ServiceIdentity, err = input.Global.ServiceIdentity.Construct(ctx, session.Connection, session.Lease.CandidateId, uint64(session.Lease.Epoch), session.Lease.LeaseId, session.CheckEffectAuthority)
	if err != nil {
		return fail(fmt.Errorf("global service identity rotation: %w", err))
	}
	config.Close = closeAll
	projection, closeEnrollment, err := newProductionEnrollmentProjection(ctx, session, input.Global, config.Database.Environment, config.Database.Cluster)
	if err != nil {
		return fail(err)
	}
	cleanup = append(cleanup, closeEnrollment)
	if input.BindProjection != nil {
		input.BindProjection(projection.Declared)
		cleanup = append(cleanup, func() error { input.BindProjection(nil); return nil })
	}
	if input.BindTargetProjection != nil {
		input.BindTargetProjection(projection.TargetCount)
		cleanup = append(cleanup, func() error { input.BindTargetProjection(nil); return nil })
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
	projection.gateways = config.ComputeGateways
	config.ComputeRemovalOwner = &computeRemovalOwnerBinding{}
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
			declared, err := projection.Declared(applyCtx, region)
			if err != nil {
				if errors.Is(err, errBrokerGrantsPending) {
					return nil
				}
				return err
			}

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
				if errors.Is(err, errBrokerGrantsPending) {
					return nil
				}
				return fmt.Errorf("compute apply %s: %w", region.Code, err)
			}
		}
		return nil
	}
	config.HostRemoval = func(removeCtx context.Context, removeSession globalWorkerSession, admission *databaseadmission.NATSJournal, ports hostRemovalTransitionPorts) (ocireconcile.MemberRemovalOwner, error) {
		removalJournal, err := hostremoval.New(authorityjournal.Config{
			Connection: removeSession.Connection, CandidateID: removeSession.Lease.CandidateId,
			AuthorityEpoch: uint64(removeSession.Lease.Epoch), LeaseID: removeSession.Lease.LeaseId,
			StateKey: "host-removal",
		})
		if err != nil {
			return nil, err
		}
		owner, err := newProductionHostRemovalFromPorts(ports, removalJournal)
		if err != nil {
			return nil, err
		}
		production := owner.(*productionHostRemoval)
		completed := production.completed
		production.completed = func(ctx context.Context, operation string) error {
			if err := completed(ctx, operation); err != nil {
				return err
			}
			return projection.retireCompleted(ctx, operation)
		}
		return production, nil
	}

	if input.RestoreBackup != nil {
		config.Restore.Backup = input.RestoreBackup
	}
	if input.RestoreBranches != nil {
		config.Restore.Branches = input.RestoreBranches
	}
	// The native lifecycle database adapter is created by the composition root
	// after the retained production database exists. EstateSnapshot is deferred
	// through databaseRef for the same reason; both are concrete lease-bound
	// seams, so returning here permits the root to finish composition.
	return config, nil
}
