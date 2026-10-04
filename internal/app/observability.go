package app

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync/atomic"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/dashboard"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/insights"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionview"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/workload"
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
	// dashboard is set when the listener serves the operator dashboard; the
	// role attaches its snapshot providers once they exist.
	dashboard *dashboard.Dashboard
	started   atomic.Bool
	// journal is the controller's decision journal; providers holds the
	// journal-derived dashboard providers once the controller attaches them.
	journal   *decisionlog.Journal
	providers atomic.Pointer[journalProviders]
	// journalCtx scopes the journal and everything feeding it to this
	// runtime: close ends it on every return path of the role, so a failed
	// controller's journal stops and is no longer the process recorder.
	journalCtx  context.Context
	stopJournal context.CancelFunc
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
			return true, "runtime started"
		}
		return false, "runtime is still starting"
	}})
	if role == "controller" {
		runtime.startDecisionJournal(ctx)
	}
	if !settings.Enabled() {
		return runtime, nil
	}
	server, err := observability.NewServer(settings, observability.ServerDeps{Registry: runtime.registry,
		Health: runtime.health, Events: runtime.events})
	if err != nil {
		// An unusable bearer token file (missing, shared or malformed) fails
		// closed for the listener only: nothing is served, and the role
		// keeps running exactly as when the port cannot be bound.
		slog.Warn("observability listener unusable; continuing without it",
			observability.ComponentKey, "observability", "error", err)
		return runtime, nil
	}
	var board *dashboard.Dashboard
	if settings.Dashboard {
		// A token-protected listener issues browser sessions; a tokenless
		// one is loopback only and refuses DNS names against rebinding.
		board = dashboard.New(dashboard.Options{Health: runtime.health, Events: runtime.events,
			SignOut: settings.BearerTokenFile != "", RequireLiteralHost: settings.BearerTokenFile == ""})
		board.Mount(server)
	}
	serveErrors, err := server.Start(ctx, settings)
	if err != nil {
		slog.Warn("observability listener unavailable; continuing without it",
			observability.ComponentKey, "observability", "address", settings.Address(), "error", err)
		return runtime, nil
	}
	go watchObservabilityListener(serveErrors)
	runtime.server, runtime.dashboard = server, board
	slog.Info("observability listener ready", observability.ComponentKey, "observability",
		"address", server.Addr().String(), "dashboard", board != nil)
	return runtime, nil
}

// watchObservabilityListener logs a listener that stops serving after it
// bound, so an operator can tell a dead scrape target from a dead member.
// The channel yields one terminal result; a clean shutdown yields nil.
func watchObservabilityListener(serveErrors <-chan error) {
	if serveErrors == nil {
		return
	}
	if err, ok := <-serveErrors; ok && err != nil {
		slog.Warn("observability listener stopped serving",
			observability.ComponentKey, "observability", "error", err)
	}
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
	// holds is the placement reconciler's hold log, read by the insights.
	holds *placementHoldLog
	// autoscalers is the workload reconciler, when autoscaling is enabled.
	autoscalers *workload.Reconciler
	// linkedPeers are the interregion peers whose observability services
	// the cell account imports, so the local connection reaches them.
	linkedPeers []string
	// rollouts and budgets are the rollout store and the region planner's
	// budgets, when their feature flags enable them.
	rollouts insights.RolloutProvider
	budgets  insights.BudgetProvider
	// ociResources is the OCI reconcile's last observations, when enabled.
	ociResources insights.OCIResourceProvider
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
			return true, "regional broker connected"
		}
		return false, "regional broker is not connected"
	}})
	runtime.health.Add(observability.Check{Name: "cluster", Run: func(context.Context) (bool, string) {
		if observed.nats.FullClusterReady(observed.replicas) {
			return true, fmt.Sprintf("%d of %d replicas routed", observed.replicas, observed.replicas)
		}
		return false, "regional cluster is below its full replica count"
	}})
	runtime.health.Add(observability.Check{Name: "authority", Run: func(context.Context) (bool, string) {
		if lease := observed.authority.Current(); lease.Ready {
			if lease.Leader {
				return true, fmt.Sprintf("this controller holds the lease, epoch %d", lease.Epoch)
			}
			return true, fmt.Sprintf("lease observed, epoch %d", lease.Epoch)
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
	runtime.attachSnapshots(collector)
	if !runtime.config.ClusterAggregation {
		runtime.attachJournal(ctx, observed, collector, nil)
		return nil
	}
	// Cell-wide aggregation is telemetry too: a subscription the broker
	// refuses (for example credentials without the obs grant) leaves this
	// member's own view in place instead of stopping the controller.
	if _, err := observability.ServeSnapshots(ctx, observed.nats.Conn(), runtime.cell, collector); err != nil {
		slog.Warn("cell-wide observability unavailable; serving the local view only",
			observability.ComponentKey, "observability", "error", err)
		runtime.attachJournal(ctx, observed, collector, nil)
		return nil
	}
	aggregator, err := observability.NewAggregator(observed.nats.Conn(), runtime.cell, observed.brokerIDs,
		observability.DefaultAggregationTimeout)
	if err != nil {
		slog.Warn("cell-wide observability unavailable; serving the local view only",
			observability.ComponentKey, "observability", "error", err)
		runtime.attachJournal(ctx, observed, collector, nil)
		return nil
	}
	if runtime.server != nil {
		runtime.server.HandleCluster(aggregator)
	}
	if runtime.dashboard != nil {
		runtime.dashboard.SetCluster(aggregator)
	}
	runtime.attachJournal(ctx, observed, collector, aggregator)
	return nil
}

// mountJournalAPI serves the journal, history, insights, summary and region
// providers as JSON on the authenticated private listener.
func mountJournalAPI(server *observability.Server, providers journalProviders) {
	decisions := decisionlog.Handler(providers.Decisions)
	server.Handle("GET /v1/decisions", decisions)
	server.Handle("GET /v1/decisions/{id}", decisions)
	history := observability.HistoryHandler(providers.History)
	server.Handle("GET /v1/history", history)
	server.Handle("GET /v1/history/metrics", history)
	insightAPI := insights.Handler(providers.Insights, providers.Summarizer)
	server.Handle("GET /v1/insights", insightAPI)
	server.Handle("GET /v1/summary", insightAPI)
	regions := regionview.Handler(providers.Regions)
	server.Handle("GET /v1/regions", regions)
	server.Handle("GET /v1/regions/{region}", regions)
}

// attachHost registers host readiness and the snapshot provider. Hosts do
// not answer cell-wide requests: their NATS credentials only publish their
// own observation subjects.
func (runtime *runtimeObservability) attachHost(nats *natscell.Runtime, filesystems []observability.FilesystemRole) error {
	runtime.health.Add(observability.Check{Name: "nats", Run: func(context.Context) (bool, string) {
		if nats.Ready() {
			return true, "regional broker connected"
		}
		return false, "regional broker is not connected"
	}})
	collector, err := observability.NewCollector(observability.CollectorConfig{Cell: runtime.cell,
		Member: runtime.member, Role: runtime.role, Registry: runtime.registry, Health: runtime.health,
		Filesystems: filesystems})
	if err != nil {
		return err
	}
	runtime.attachSnapshots(collector)
	return nil
}

// attachSnapshots serves this member's snapshot as JSON and to the dashboard.
func (runtime *runtimeObservability) attachSnapshots(collector *observability.Collector) {
	if runtime.server != nil {
		runtime.server.HandleSnapshots(collector)
	}
	if runtime.dashboard != nil {
		runtime.dashboard.SetSnapshots(collector)
	}
}

// close stops the private listener when the role returns, so a runtime that
// fails after startup (or an in-process test member) does not keep the port
// bound until its parent context ends.
func (runtime *runtimeObservability) close() {
	if runtime == nil {
		return
	}
	if runtime.stopJournal != nil {
		runtime.stopJournal()
	}
	if runtime.server != nil {
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
