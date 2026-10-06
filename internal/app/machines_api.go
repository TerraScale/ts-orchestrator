package app

import (
	"context"
	"fmt"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/machines"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/machinesapi"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/tenant"
)

// startMachinesAPI serves the Machines REST API on every controller whose
// config enables it. Reads come from the replicated app and tenant buckets,
// so any controller answers them.
func startMachinesAPI(ctx context.Context, cfg Config, runtime *natscell.Runtime, control authority.Fencer,
	fullClusterReady func() bool,
) (<-chan error, error) {
	settings := cfg.Controller.MachinesAPI
	if settings == nil {
		return nil, nil
	}
	type stores struct {
		apps    *machines.Store
		tenants *tenant.Store
	}
	opened, _, err := retryControllerOpen(ctx, "open the machines API stores", fullClusterReady, false,
		func(attempt context.Context) (stores, error) {
			apps, err := machines.OpenStore(attempt, runtime.JetStream(), cfg.NATS.Cell, cfg.NATS.Replicas, control)
			if err != nil {
				return stores{}, err
			}
			tenants, err := tenant.OpenStore(attempt, runtime.JetStream(), cfg.NATS.Replicas)
			return stores{apps: apps, tenants: tenants}, err
		}, nil)
	if err != nil {
		return nil, err
	}
	server, err := machinesapi.NewServer(*settings, opened.apps, opened.tenants)
	if err != nil {
		return nil, err
	}
	errs, err := server.Start(ctx)
	if err != nil {
		return nil, fmt.Errorf("start machines API: %w", err)
	}
	return errs, nil
}
