package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/machinesapi"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/tenant"
)

// startMachinesAPI serves the Machines REST API on every controller whose
// signed configuration carries it. Apps come from the current manager;
// tenant organization membership comes from the replicated tenant bucket.
func startMachinesAPI(ctx context.Context, cfg Config, runtime *natscell.Runtime, control authority.Fencer,
	fullClusterReady func() bool, apps machinesapi.AppSource,
	links observability.ClusterSource,
) (<-chan error, error) {
	settings := cfg.Controller.MachinesAPI
	if settings == nil {
		return nil, nil
	}
	tenants, _, err := retryControllerOpen(ctx, "open the machines API tenant store", fullClusterReady, false,
		func(attempt context.Context) (*tenant.Store, error) {
			return tenant.OpenStore(attempt, runtime.JetStream(), cfg.NATS.Replicas)
		}, nil)
	if err != nil {
		return nil, err
	}
	server, err := machinesapi.NewServer(*settings, apps, tenants, links)
	if err != nil {
		return nil, err
	}
	errs, err := server.Start(ctx)
	if err != nil {
		return nil, fmt.Errorf("start machines API: %w", err)
	}
	return errs, nil
}

// machinesAPICheck is how often a controller reads the spec's machines_api.
var machinesAPICheck = 5 * time.Second

// machinesAPILoop serves the Machines REST API while the adopted cell spec
// carries machines_api (docs/machines-api.md): on the broker address at
// cellspec.MachinesAPIPort, with the controller's signed TLS certificate,
// which the regional load balancer verifies against the cell CA. A changed
// section restarts the listener and a removed one stops it, without a
// controller restart. A listener that fails to start or stops is retried at
// the next check; the API never stops the controller.
func machinesAPILoop(ctx context.Context, cfg Config, runtime *natscell.Runtime, control authority.Fencer,
	fullClusterReady func() bool, current func() *cellspec.MachinesAPI, apps machinesapi.AppSource,
	links observability.ClusterSource,
) error {
	var tenants *tenant.Store
	var running *cellspec.MachinesAPI
	var serving <-chan error
	stop, failure := context.CancelFunc(func() {}), ""
	defer func() { stop() }()
	ticker := time.NewTicker(machinesAPICheck)
	defer ticker.Stop()
	for {
		ctx := observability.StartTrace(ctx)
		if want := current(); !reflect.DeepEqual(want, running) {
			stop()
			running, serving = nil, nil
			err := error(nil)
			if want != nil && tenants == nil {
				tenants, err = tenant.OpenStore(ctx, runtime.JetStream(), cfg.NATS.Replicas)
			}
			if want != nil && err == nil && fullClusterReady() {
				var server *machinesapi.Server
				embedded := cfg.NATS.Embedded
				server, err = machinesapi.NewServer(want.Config(embedded.Host, embedded.TLS.CertFile, embedded.TLS.KeyFile), apps, tenants, links)
				serveCtx, cancel := context.WithCancel(ctx)
				if err == nil {
					serving, err = server.Start(serveCtx)
				}
				if err != nil {
					cancel()
				} else {
					stop, running = cancel, want
					slog.InfoContext(serveCtx, "Machines API serving", "address", want.Config(embedded.Host, "", "").ListenAddress)
				}
			}
			if err != nil && err.Error() != failure {
				slog.WarnContext(ctx, "Machines API is not serving; retrying", "error", err)
			}
			failure = ""
			if err != nil {
				failure = err.Error()
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case err := <-serving:
			slog.WarnContext(ctx, "Machines API stopped; restarting", "error", err)
			stop()
			running, serving = nil, nil
		case <-ticker.C:
		}
	}
}

// Cluster serves only the authenticated local scatter-gather; HTTP never
// triggers a cross-region probe or a control-plane action.
func (runtime *runtimeObservability) Cluster(ctx context.Context, metrics bool) (observability.ClusterSnapshot, error) {
	runtime.boardsMu.Lock()
	source := runtime.cluster
	runtime.boardsMu.Unlock()
	if source == nil {
		return observability.ClusterSnapshot{}, errors.New("controller snapshot source is unavailable")
	}
	return source.Cluster(ctx, metrics)
}
