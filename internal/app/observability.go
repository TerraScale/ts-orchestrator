package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/budget"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/capacity"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/dashboard"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/globalview"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostload"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/insights"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/logs"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/maintenance"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/nodescale"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ocicost"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionview"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/rollout"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/workload"
)

// runtimeObservability is one runtime role's metrics, health, event bus and
// private listener. It is started before the regional broker so liveness is
// observable while the cell forms, and the role attaches its providers once
// they exist. Observability never gates or drives a control-plane effect.
type runtimeObservability struct {
	usage           *capacity.Store
	config          observability.Config
	cell            string
	member          string
	role            string
	registry        *observability.Registry
	health          *observability.Health
	events          *observability.EventBus
	server          *observability.Server
	sessionJS       jetstream.JetStream
	sessionReplicas int
	// boards are the dashboards this runtime serves: the listener's, and the
	// NetBird listener's while the cell spec enables it. The role attaches
	// its providers once they exist; they are kept, so a dashboard added
	// later gets them too.
	boardsMu     sync.Mutex
	boards       []*dashboard.Dashboard
	snapshots    observability.SnapshotSource
	cluster      observability.ClusterSource
	boardJournal *dashboard.Journal
	started      atomic.Bool
	// journal is the controller's decision journal; providers holds the
	// journal-derived dashboard providers once the controller attaches them.
	journal   *decisionlog.Journal
	providers atomic.Pointer[journalProviders]
	// journalCtx scopes the journal and everything feeding it to this
	// runtime: close ends it on every return path of the role, so a failed
	// controller's journal stops and is no longer the process recorder.
	journalCtx  context.Context
	stopJournal context.CancelFunc
	// logView is the controller's log summary; the rollup's errors come from it.
	logView *logs.View
}

func (r *runtimeObservability) recordHostLoad(load host.LoadSink, origin hostload.Origin, report hostload.Report, requests map[string]hostload.Request) error {
	var loadErr error
	if load != nil {
		loadErr = load(origin, report)
		if errors.Is(loadErr, authority.ErrFenced) {
			return loadErr
		}
	}
	usageErr := r.usage.Record(origin, report, requests)
	if load == nil {
		return usageErr
	}
	// Optional capacity history must not back off accepted autoscaler telemetry.
	if usageErr != nil {
		slog.Debug("capacity history discarded a host report", observability.ComponentKey, "capacity", "node", origin.Node, "error", usageErr)
	}
	return loadErr
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
		observability.Identity(role, cfg.NATS.Cell)...)
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
		runtime.usage = capacity.NewStore(cfg.NATS.Cell)
		runtime.startDecisionJournal(ctx)
	}
	server, err := observability.NewServer(settings, observability.ServerDeps{Registry: runtime.registry,
		Health: runtime.health, Events: runtime.events, LocalSessions: role == "host"})
	if err != nil {
		// An unusable bearer token file (missing, shared or malformed) fails
		// closed for the listener only: nothing is served, and the role
		// keeps running exactly as when the port cannot be bound.
		slog.WarnContext(ctx, "observability listener unusable; continuing without it",
			observability.ComponentKey, "observability", "error", err)
		return runtime, nil
	}
	runtime.mountUsage(server)
	// A token-protected listener issues browser sessions; a tokenless
	// one is loopback only and refuses DNS names against rebinding.
	board := dashboard.New(dashboard.Options{Health: runtime.health, Events: runtime.events,
		SignOut: settings.BearerTokenFile != "", RequireLiteralHost: settings.BearerTokenFile == ""})
	board.Mount(server)
	serveErrors, err := server.Start(ctx, settings)
	if err != nil {
		slog.WarnContext(ctx, "observability listener unavailable; continuing without it",
			observability.ComponentKey, "observability", "address", settings.Address(), "error", err)
		return runtime, nil
	}
	go watchObservabilityListener(serveErrors)
	runtime.server = server
	runtime.addBoard(board)
	slog.InfoContext(ctx, "observability listener ready", observability.ComponentKey, "observability",
		"address", server.Addr().String())
	return runtime, nil
}

func (runtime *runtimeObservability) mountUsage(server *observability.Server) {
	if runtime.usage != nil {
		server.HandleAuthenticated("GET /v1/usage", runtime.usage.Handler(runtime.usage.Expected))
	}
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
	// holds is the placement reconciler's hold log, read by the insights.
	holds *placementHoldLog
	// autoscalers is the workload reconciler of the cell spec.
	autoscalers *workload.Reconciler
	// hostLoad collects resource metrics independently of autoscale policies.
	hostLoad *hostTelemetry
	// hosts checks which NKey a node's log windows must come from.
	hosts *host.Controller
	// peers are the other regions of the roster, followed by this region.
	peers                 *rosterPeers
	linkProbes            func() []regionview.LinkProbe
	nativeTerraBaseRegion func() string
	// cost is the region's OCI cost view for its summary.
	cost func(context.Context) *ocicost.View
	// costRollup is the region's cost for the dashboard rollup, cached.
	costRollup func() *globalview.Cost
	// capacity reads TS-804's global capacity document from the mirror.
	capacity func(context.Context) (budget.Capacity, bool, error)
	// rollouts is the rollout store, when the controller runs one. budgets is
	// the monthly budget insight's source.
	rollouts *rollout.Store
	budgets  insights.BudgetProvider
	// ociResources is the OCI reconcile's last observations, when enabled.
	ociResources insights.OCIResourceProvider
	// credentials are the controller's expiring credential files.
	credentials []maintenance.CredentialFile
	kvSnapshots func() observability.KVSnapshotView
	// nodes lists the cell's granted nodes for the topology view.
	nodes func(context.Context) []regionview.Node
	// scale is the region's node scaling status, nil when the region runs no scaler.
	scale func() *nodescale.Status
}

// attachController registers controller metrics, readiness checks and the
// snapshot provider, and answers cell-wide snapshot requests.
func (runtime *runtimeObservability) attachController(ctx context.Context, observed controllerObservation,
	filesystems []observability.FilesystemRole,
) error {
	runtime.sessionJS, runtime.sessionReplicas = observed.nats.JetStream(), observed.replicas
	runtime.attachLogs(ctx, observed)
	if runtime.server != nil && runtime.config.BearerTokenFile != "" {
		go retryAttachment(ctx, "dashboard", "dashboard session storage", func(attempt context.Context) error {
			store, err := observability.OpenSessionStore(attempt, runtime.sessionJS, runtime.sessionReplicas, "local."+runtime.member)
			if err != nil {
				return err
			}
			return runtime.server.SetSessionStore(attempt, store)
		})
	}
	runtime.registry.Register(delivery.Metrics)
	runtime.registry.Register(oci.Metrics)
	runtime.registry.Register(placement.Metrics)
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
		Authority:   func() observability.AuthorityView { return authorityView(observed.authority.Current()) },
		NATS:        observed.nats.Observe,
		Delivery:    delivery.View,
		KVSnapshots: observed.kvSnapshots,
		OCI:         oci.APIView,
	}
	config.Links = func() []observability.RegionLinkProbe {
		if observed.linkProbes == nil {
			return nil
		}
		probes := observed.linkProbes()
		links := make([]observability.RegionLinkProbe, len(probes))
		for index, probe := range probes {
			links[index] = observability.RegionLinkProbe{Region: probe.Region, ObservedAt: probe.ObservedAt,
				Reach: probe.Reach, WAN: probe.WAN, LagGroups: probe.Lag, RTTMillis: probe.RoundTripMS}
		}
		return links
	}
	if observed.placements != nil {
		store := observed.placements
		config.Placement = func(ctx context.Context) (observability.PlacementView, error) {
			return placement.Summarize(ctx, store)
		}
	}
	if files := observed.credentials; len(files) > 0 {
		var mu sync.Mutex
		var last string
		config.Credentials = func() ([]observability.CredentialView, error) {
			credentials, err := maintenance.Scan(files)
			// The snapshot carries only an error class; log which file
			// failed, once per change. Roles and paths are not secret.
			text := ""
			if err != nil {
				text = err.Error()
			}
			mu.Lock()
			if text != "" && text != last {
				slog.WarnContext(ctx, "credential expiry scan incomplete", observability.ComponentKey, "maintenance", "error", err)
			}
			last = text
			mu.Unlock()
			return credentials, err
		}
	}
	collector, err := observability.NewCollector(config)
	if err != nil {
		return err
	}
	runtime.attachSnapshots(collector)
	// Cell-wide aggregation is telemetry too: a subscription the broker
	// refuses (for example credentials without the obs grant) leaves this
	// member's own view in place instead of stopping the controller.
	if _, err := observability.ServeSnapshots(ctx, observed.nats.Conn(), runtime.cell, collector); err != nil {
		slog.WarnContext(ctx, "cell-wide observability unavailable; serving the local view only",
			observability.ComponentKey, "observability", "error", err)
		runtime.attachJournal(ctx, observed, collector, nil)
		return nil
	}
	aggregator, err := observability.NewAggregator(observed.nats.Conn(), runtime.cell, observed.brokerIDs,
		observability.DefaultAggregationTimeout)
	if err != nil {
		slog.WarnContext(ctx, "cell-wide observability unavailable; serving the local view only",
			observability.ComponentKey, "observability", "error", err)
		runtime.attachJournal(ctx, observed, collector, nil)
		return nil
	}
	if runtime.server != nil {
		runtime.server.HandleCluster(aggregator)
	}
	runtime.attachBoards(func() { runtime.cluster = aggregator })
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
	regions := globalview.Handler(providers.Global)
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
	runtime.attachBoards(func() { runtime.snapshots = collector })
}

// attachBoards records a provider and gives every dashboard the providers.
func (runtime *runtimeObservability) attachBoards(record func()) {
	runtime.boardsMu.Lock()
	defer runtime.boardsMu.Unlock()
	record()
	for _, board := range runtime.boards {
		runtime.provide(board)
	}
}

// addBoard serves the attached providers on another dashboard.
func (runtime *runtimeObservability) addBoard(board *dashboard.Dashboard) {
	runtime.attachBoards(func() { runtime.boards = append(runtime.boards, board) })
}

// removeBoard stops feeding a dashboard whose listener closed.
func (runtime *runtimeObservability) removeBoard(board *dashboard.Dashboard) {
	runtime.boardsMu.Lock()
	defer runtime.boardsMu.Unlock()
	runtime.boards = slices.DeleteFunc(runtime.boards, func(candidate *dashboard.Dashboard) bool { return candidate == board })
}

func (runtime *runtimeObservability) provide(board *dashboard.Dashboard) {
	if runtime.snapshots != nil {
		board.SetSnapshots(runtime.snapshots)
	}
	if runtime.cluster != nil {
		board.SetCluster(runtime.cluster)
	}
	if runtime.boardJournal != nil {
		board.SetJournal(*runtime.boardJournal)
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

// Retry without blocking controller startup; each attempt and the backoff are
// bounded and stop with the runtime, including during a JetStream outage.
func retryAttachment(ctx context.Context, component, what string, attach func(context.Context) error) {
	delay := 100 * time.Millisecond
	var lastError string
	var nextWarning time.Time
	for ctx.Err() == nil {
		attempt, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := attach(attempt)
		cancel()
		if err == nil {
			return
		}
		if err.Error() != lastError || time.Now().After(nextWarning) {
			slog.Warn(what+" unavailable; retrying", observability.ComponentKey, component, "error", err)
			lastError, nextWarning = err.Error(), time.Now().Add(time.Minute)
		}
		timer := time.NewTimer(delay + time.Duration(rand.Int64N(int64(delay)/5+1)))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		delay = min(2*delay, 5*time.Second)
	}
}
