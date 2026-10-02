package app

import (
	"context"
	"log/slog"
	"os"
	"sync/atomic"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
)

// runtimeObservability is one runtime role's metrics, health, event bus and
// private listener. It is started before the regional broker so liveness is
// observable while the cell forms, and the role attaches its providers once
// they exist. Observability never gates or drives a control-plane effect.
type runtimeObservability struct {
	config   observability.Config
	cell     string
	member   string
	role     string
	registry *observability.Registry
	health   *observability.Health
	events   *observability.EventBus
	server   *observability.Server
	started  atomic.Bool
}

// startRuntimeObservability installs the structured default logger and
// starts the private listener. A listener that cannot bind is logged and
// skipped: telemetry must not stop a controller from serving its region.
func startRuntimeObservability(ctx context.Context, cfg Config, role, member string) (*runtimeObservability, error) {
	settings := cfg.Observability
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	runtime := &runtimeObservability{config: settings, cell: cfg.NATS.Cell, member: member, role: role,
		registry: observability.NewRegistry(true), health: new(observability.Health),
		events: observability.NewEventBus(observability.DefaultEventCapacity)}
	logger, err := observability.NewLogger(os.Stderr,
		observability.LogConfig{Format: settings.LogFormat, Level: settings.LogLevel}, runtime.events,
		slog.String("cell", cfg.NATS.Cell), slog.String("member", member), slog.String("role", role))
	if err != nil {
		return nil, err
	}
	observability.ConfigureDefault(logger)
	runtime.registry.Register(observability.LogMetrics)
	runtime.health.Add(observability.Check{Name: "startup", Run: func(context.Context) (bool, string) {
		if runtime.started.Load() {
			return true, ""
		}
		return false, "runtime is still starting"
	}})
	if !settings.Enabled() {
		return runtime, nil
	}
	server, err := observability.NewServer(settings, observability.ServerDeps{Registry: runtime.registry,
		Health: runtime.health, Events: runtime.events})
	if err != nil {
		return nil, err
	}
	if _, err := server.Start(ctx, settings); err != nil {
		slog.Warn("observability listener unavailable; continuing without it",
			observability.ComponentKey, "observability", "address", settings.Address(), "error", err)
		return runtime, nil
	}
	runtime.server = server
	slog.Info("observability listener ready", observability.ComponentKey, "observability",
		"address", server.Addr().String())
	return runtime, nil
}

// controllerObservation is what a controller exposes once its regional
// broker, authority and placement state are open. Nil fields are omitted.
type controllerObservation struct {
	nats       *natscell.Runtime
	replicas   int
	brokerIDs  []string
	authority  authority.Fencer
	placements placement.Store
	managed    bool
}

// attachController registers controller metrics, readiness checks and the
// snapshot provider, and answers cell-wide snapshot requests when enabled.
func (runtime *runtimeObservability) attachController(ctx context.Context, observed controllerObservation,
	filesystems []observability.FilesystemRole,
) error {
	runtime.registry.Register(delivery.Metrics)
	if observed.managed {
		runtime.registry.Register(oci.Metrics)
		runtime.registry.Register(placement.Metrics)
	}
	runtime.health.Add(observability.Check{Name: "nats", Run: func(context.Context) (bool, string) {
		if observed.nats.Ready() {
			return true, ""
		}
		return false, "regional broker is not connected"
	}})
	runtime.health.Add(observability.Check{Name: "cluster", Run: func(context.Context) (bool, string) {
		if observed.nats.FullClusterReady(observed.replicas) {
			return true, ""
		}
		return false, "regional cluster is below its full replica count"
	}})
	runtime.health.Add(observability.Check{Name: "authority", Run: func(context.Context) (bool, string) {
		if observed.authority.Current().Ready {
			return true, ""
		}
		return false, "authority lease is not observed"
	}})
	config := observability.CollectorConfig{Cell: runtime.cell, Member: runtime.member, Role: runtime.role,
		Registry: runtime.registry, Health: runtime.health, Filesystems: filesystems,
		Authority: func() observability.AuthorityView { return authorityView(observed.authority.Current()) },
		NATS:      observed.nats.Observe,
		Delivery:  delivery.View,
	}
	if observed.managed {
		config.OCI = oci.APIView
	}
	if observed.placements != nil {
		store := observed.placements
		config.Placement = func(ctx context.Context) (observability.PlacementView, error) {
			return placement.Summarize(ctx, store)
		}
	}
	collector, err := observability.NewCollector(config)
	if err != nil {
		return err
	}
	if runtime.server != nil {
		runtime.server.HandleSnapshots(collector)
	}
	if !runtime.config.ClusterAggregation {
		return nil
	}
	if _, err := observability.ServeSnapshots(ctx, observed.nats.Conn(), runtime.cell, collector); err != nil {
		return err
	}
	aggregator, err := observability.NewAggregator(observed.nats.Conn(), runtime.cell, observed.brokerIDs,
		observability.DefaultAggregationTimeout)
	if err != nil {
		return err
	}
	if runtime.server != nil {
		runtime.server.HandleCluster(aggregator)
	}
	return nil
}

// attachHost registers host readiness and the snapshot provider. Hosts do
// not answer cell-wide requests: their NATS credentials only publish their
// own observation subjects.
func (runtime *runtimeObservability) attachHost(nats *natscell.Runtime, filesystems []observability.FilesystemRole) error {
	runtime.health.Add(observability.Check{Name: "nats", Run: func(context.Context) (bool, string) {
		if nats.Ready() {
			return true, ""
		}
		return false, "regional broker is not connected"
	}})
	collector, err := observability.NewCollector(observability.CollectorConfig{Cell: runtime.cell,
		Member: runtime.member, Role: runtime.role, Registry: runtime.registry, Health: runtime.health,
		Filesystems: filesystems})
	if err != nil {
		return err
	}
	if runtime.server != nil {
		runtime.server.HandleSnapshots(collector)
	}
	return nil
}

// close stops the private listener when the role returns, so a runtime that
// fails after startup (or an in-process test member) does not keep the port
// bound until its parent context ends.
func (runtime *runtimeObservability) close() {
	if runtime != nil && runtime.server != nil {
		_ = runtime.server.Close()
	}
}

// markStarted flips the startup readiness check once the role is serving.
func (runtime *runtimeObservability) markStarted() {
	if runtime != nil {
		runtime.started.Store(true)
	}
}

func authorityView(snapshot authority.Snapshot) observability.AuthorityView {
	return observability.AuthorityView{Leader: snapshot.Leader, Ready: snapshot.Ready,
		CanMutate: snapshot.CanMutate(), OwnerID: snapshot.OwnerID, Epoch: snapshot.Epoch,
		Revision: snapshot.Revision, ExpiresAt: snapshot.ExpiresAt, ObservedAt: snapshot.ObservedAt,
		Reason: snapshot.Reason}
}
