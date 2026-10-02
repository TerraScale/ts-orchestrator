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
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/storage/backup"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/storage/capacity"
)

// startControllerStorageCapacity measures this controller's boot root and
// JetStream StoreDir and publishes them to the regional TTL'd usage bucket.
// It runs on every controller (each node measures itself) and only when
// controller.storage_capacity.enabled is set.
func startControllerStorageCapacity(ctx context.Context, cfg Config, runtime *natscell.Runtime) error {
	settings := cfg.Controller.StorageCapacity
	if !settings.Enabled {
		return nil
	}
	if err := settings.Validate(); err != nil {
		return err
	}
	if cfg.NATS.Embedded == nil || runtime == nil {
		return errors.New("storage capacity requires the embedded regional NATS server")
	}
	store, err := capacity.OpenUsageStore(ctx, runtime.JetStream(), cfg.NATS.Replicas, settings.TTL(), settings.Policy)
	if err != nil {
		return fmt.Errorf("open storage usage bucket: %w", err)
	}
	collector := capacity.Collector{
		Cell: cfg.NATS.Cell, Node: cfg.NATS.Instance,
		Targets: capacity.ControllerTargets(cfg.NATS.Embedded.StoreDir, runtime.JetStream(), cfg.NATS.Embedded.StoreLimitBytes()),
	}
	go func() {
		if err := capacity.Run(ctx, collector, store, settings.Policy, settings.Interval(), capacity.LogSignal); err != nil && ctx.Err() == nil {
			slog.Error("controller storage capacity collector stopped", "error", err)
		}
	}()
	return nil
}

// startVolumeBackups runs the OCI volume backup policy on the authority
// leader when controller.volume_backup.enabled is set. Followers evaluate
// nothing; every OCI effect is epoch-guarded inside the runner.
func startVolumeBackups(ctx context.Context, cfg Config, managed *managedControllerConfig,
	fencer authority.Fencer, store placement.Store,
) error {
	policy := cfg.Controller.VolumeBackup
	if !policy.Enabled {
		return nil
	}
	if err := policy.Validate(); err != nil {
		return err
	}
	if managed == nil || store == nil {
		return errors.New("volume backups require a managed OCI controller")
	}
	provider, err := oci.NewInstancePrincipalVolumeBackupProvider(managed.region, managed.intent)
	if err != nil {
		return fmt.Errorf("start OCI volume backup client: %w", err)
	}
	runner := backup.Runner{
		Policy: policy, Provider: provider, Fencer: fencer,
		Scope:   backup.Scope{Owner: managed.region.Owner, Region: managed.region.Region},
		Volumes: func(ctx context.Context) ([]string, error) { return placementVolumeIDs(ctx, store) },
	}
	go func() {
		if err := runner.Run(ctx); err != nil && ctx.Err() == nil {
			slog.Error("volume backup runner stopped", "error", err)
		}
	}()
	return nil
}

// placementVolumeIDs lists the retained volumes of every placed member.
func placementVolumeIDs(ctx context.Context, store placement.Store) ([]string, error) {
	intents, err := store.ListIntents(ctx)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	var volumes []string
	for _, intent := range intents {
		members, err := store.ListMembers(ctx, intent.DatabaseID, intent.PartitionID)
		if err != nil {
			return nil, err
		}
		for _, member := range members {
			if id := member.State.VolumeID; id != "" && member.State.Stage != placement.StageRemoved && !seen[id] {
				seen[id] = true
				volumes = append(volumes, id)
			}
		}
	}
	return volumes, nil
}
