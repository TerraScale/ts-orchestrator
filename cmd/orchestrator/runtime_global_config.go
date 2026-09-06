package main

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	"terrascale.tech/orchestrator/src/orchestrator/estate"
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

	// The remaining ports are intentionally reported by name until their
	// assigned owners hand off concrete production adapters. Returning this
	// staged bundle lets callers retain and close all providers already opened.
	return config, fmt.Errorf("%w: restore backup and branch lifecycle adapters", ErrProductionGlobalDependency)
}
