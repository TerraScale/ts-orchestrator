package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
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
