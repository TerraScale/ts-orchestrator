package main

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	"terrascale.tech/orchestrator/src/orchestrator/estate"
	"terrascale.tech/orchestrator/src/orchestrator/ocireconcile"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
	"terrascale.tech/orchestrator/src/orchestrator/reaper"
)

// ErrProductionGlobalDependency identifies a provider which has not yet been
// handed off to the composition root. It is deliberately distinct from static
// deployment admission: a valid deployment can be admitted while its live
// worker graph remains fail-closed until every provider is concrete.
var ErrProductionGlobalDependency = errors.New("production global dependency is unavailable")

type productionGlobalBuildInput struct {
	Global     *productionGlobalFile
	Auth       productionAuthBootstrapConfig
	Spec       estate.Spec
	Mirror     *delivery.ArtifactMirror
	Shared     provider.DeliveryRegionStoreConfig
	Ownership  *provider.DurableOwnershipJournal
	Close      func() error
	Transition productionPlacementTransitionConfig
}

// buildProductionGlobalConfig is the lease-owned composition stage. All
// provider clients created here use the supplied session and are released in
// reverse construction order when a later dependency is absent.
func buildProductionGlobalConfig(ctx context.Context, session globalWorkerSession, input productionGlobalBuildInput) (productionGlobalWorkerConfig, error) {
	var config productionGlobalWorkerConfig
	if input.Global == nil || input.Mirror == nil || input.Ownership == nil || input.Shared.Journal == nil {
		return config, fmt.Errorf("%w: admitted delivery ownership and artifact mirror", ErrProductionGlobalDependency)
	}
	if err := session.CheckEffectAuthority(ctx); err != nil {
		return config, err
	}

	cleanup := make([]func() error, 0, 4)
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

	rotation, _, closeRotation, err := input.Global.Rotation.Construct(ctx, session, productionDeliveryMirrorSource{mirror: input.Mirror, region: input.Global.Recovery.SourceRegion})
	if err != nil {
		return fail(fmt.Errorf("global rotation providers: %w", err))
	}
	cleanup = append(cleanup, closeRotation)
	config.Rotation = rotation

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
	config.AuthBootstrap = input.Auth
	config.PlacementTransition = input.Transition
	config.EstateClient = estateClient
	config.Close = closeAll
	cloudInit, err := input.Global.Compute.cloudInit()
	if err != nil {
		return fail(fmt.Errorf("global compute cloud-init: %w", err))
	}
	config.ComputeMutationJournalBucket = input.Global.Compute.MutationJournalKV
	config.ComputeApply = func(applyCtx context.Context, journal provider.ProviderMutationJournal) error {
		if err := session.CheckEffectAuthority(applyCtx); err != nil {
			return err
		}
		for _, region := range input.Spec.Regions {
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
			adapter, err := provider.NewOCIComputeAdapter(core, journal)
			if err != nil {
				return fmt.Errorf("compute OCI adapter %s: %w", region.Code, err)
			}
			epoch := provider.ProviderEpoch{Value: uint64(session.Lease.Epoch)}
			gateway, err := ocireconcile.NewDurableOCIMemberGateway(core, adapter, estateSpec.WorkloadCompartmentID, input.Global.Compute.ImageID, epoch)
			if err != nil {
				return fmt.Errorf("compute gateway %s: %w", region.Code, err)
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
				candidates = append(candidates, ocireconcile.MemberLaunchCandidate{Shape: candidate.Shape, ImageID: image, Architecture: candidate.Architecture, QualificationRef: candidate.QualificationRef, CostRef: candidate.CostRef})
			}
			cloudInitByMember := make(map[int]string, int(region.Members.Count))
			for index := 1; index <= int(region.Members.Count); index++ {
				cloudInitByMember[index] = cloudInit
			}
			declared := ocireconcile.ComputeDeclared{Region: region, ImageID: input.Global.Compute.ImageID, FallbackImageID: input.Global.Compute.FallbackImageID, Candidates: candidates, CloudInitByMember: cloudInitByMember}
			reconciler := &ocireconcile.ComputeReconciler{Compute: gateway, Network: network, RemovalOwner: nil}
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

	// The remaining ports are intentionally reported by name until their
	// assigned owners hand off concrete production adapters. Returning this
	// staged bundle lets callers retain and close all providers already opened.
	return config, fmt.Errorf("%w: restore backup and branch lifecycle adapters", ErrProductionGlobalDependency)
}
