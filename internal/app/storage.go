package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/storage"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/storage/backup"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/storage/capacity"
)

// startControllerStorageCapacity measures this controller's boot root and
// JetStream StoreDir and publishes them to the regional TTL'd usage bucket.
// It runs on every controller; each node measures itself.
//
// The returned stop cancels the collector and waits for it, so the controller
// joins it on every return path before closing the NATS runtime it uses.
func startControllerStorageCapacity(ctx context.Context, cfg Config, runtime *natscell.Runtime, fullClusterReady func() bool) (func(), error) {
	if cfg.NATS.Embedded == nil || runtime == nil {
		return nil, errors.New("storage capacity requires the embedded regional NATS server")
	}
	store, _, err := retryControllerOpen(ctx, "open storage usage bucket", fullClusterReady, false,
		func(attempt context.Context) (*capacity.UsageStore, error) {
			return capacity.OpenUsageStore(attempt, runtime.JetStream(), cfg.NATS.Replicas, storage.DefaultUsageTTL, capacity.DefaultPolicy())
		}, nil)
	if err != nil {
		return nil, err
	}
	collector := capacity.Collector{
		Cell: cfg.NATS.Cell, Node: cfg.NATS.Instance,
		Targets: capacity.ControllerTargets(cfg.NATS.Embedded.StoreDir, runtime.LocalStoreUsedBytes, cfg.NATS.Embedded.StoreLimitBytes()),
	}
	return ownedLoop(ctx, "controller storage capacity collector", func(ctx context.Context) error {
		return capacity.Run(ctx, collector, store, capacity.DefaultPolicy(), storage.DefaultCollectInterval, capacity.LogSignal)
	}), nil
}

// ownedLoop runs a background service under a context the caller owns. The
// returned stop cancels it and waits until it has returned, so no loop
// outlives the dependencies the caller closes afterwards.
func ownedLoop(parent context.Context, name string, run func(context.Context) error) func() {
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := run(ctx); err != nil && ctx.Err() == nil {
			slog.ErrorContext(ctx, name+" stopped", "error", err)
		}
	}()
	return func() {
		cancel()
		<-done
	}
}

// startVolumeBackups runs the OCI volume backup policy on the authority
// leader. Followers evaluate nothing; every OCI effect is epoch-guarded.
// The returned stop cancels the runner and waits for it.
func startVolumeBackups(ctx context.Context, managed *managedControllerConfig,
	fencer authority.Fencer, store placement.Store, journal *oci.KVJournal,
) (func(), error) {
	if managed == nil || store == nil || fencer == nil {
		return nil, errors.New("volume backups require a managed OCI controller")
	}
	provider, err := oci.NewInstancePrincipalVolumeBackupProvider(managed.region, managed.intent, journal)
	if err != nil {
		return nil, fmt.Errorf("start OCI volume backup client: %w", err)
	}
	runner := backup.Runner{
		Provider: provider, Fencer: fencer,
		Scope:   backup.Scope{Owner: managed.region.Owner, Region: managed.region.Region},
		Volumes: func(ctx context.Context) ([]string, error) { return placementVolumeIDs(ctx, store) },
	}
	return ownedLoop(ctx, "volume backup runner", runner.Run), nil
}

// placementVolumeIDs lists the retained volumes of every placed member. An
// unreadable partition is skipped so it cannot block backups of every other
// volume; the listing then reports backup.ErrPartialVolumes, which keeps the
// runner from treating the skipped partition's volumes as orphaned.
func placementVolumeIDs(ctx context.Context, store placement.Store) ([]string, error) {
	members, skipped, err := placedVolumeMembers(ctx, store, true)
	if err != nil {
		return nil, err
	}
	volumes := make([]string, 0, len(members))
	for _, member := range members {
		volumes = append(volumes, member.VolumeID)
	}
	if len(skipped) > 0 {
		slog.WarnContext(ctx, "volume backup listing skipped unreadable partitions", "error", errors.Join(skipped...))
		return volumes, fmt.Errorf("%w: %w", backup.ErrPartialVolumes, errors.Join(skipped...))
	}
	return volumes, nil
}
