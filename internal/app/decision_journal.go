package app

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/insights"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionlink"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionview"
)

const (
	// journalOpenRetry is how often a controller retries opening the
	// decision stream and history bucket while JetStream forms.
	journalOpenRetry = 5 * time.Second
	// holdRepeat is how long one placement hold reason stays journaled
	// before it is recorded again.
	holdRepeat = 15 * time.Minute
	// regionRequestTimeout bounds one cross-region dashboard request.
	regionRequestTimeout = 1500 * time.Millisecond
)

// controlPlaneWatchInterval polls the authority lease, and
// clusterHealthInterval the cluster's full readiness. Tests shorten them.
var (
	controlPlaneWatchInterval = time.Second
	clusterHealthInterval     = 5 * time.Second
)

// journalProviders are the read-only providers the dashboard renders the
// decision journal, history charts, insights, summaries and the global
// region view from. Fields are nil until the controller attaches them.
type journalProviders struct {
	Decisions  decisionlog.Source
	Live       decisionlog.LiveSource
	History    observability.HistorySource
	Insights   insights.Source
	Summarizer insights.Summarizer
	Regions    regionview.Source
}

// startDecisionJournal installs the in-memory journal as the process-wide
// recorder as soon as a controller starts, so decisions taken while the
// cell forms are kept and published once the stream opens.
func (runtime *runtimeObservability) startDecisionJournal(ctx context.Context) {
	journal := decisionlog.NewJournal(decisionlog.JournalConfig{Region: runtime.cell, Member: runtime.member,
		Log: true})
	restore := decisionlog.SetDefault(journal)
	context.AfterFunc(ctx, restore)
	runtime.registry.Register(decisionlog.Metrics)
	runtime.journal = journal
	go func() { _ = journal.Run(ctx) }()
}

// attachJournal opens the replicated stream, serves cross-region queries,
// and, when the private listener runs, starts the history sampler, the
// insight engine and the region provider. Nothing here can fail the
// controller: every step that cannot start is logged and skipped.
func (runtime *runtimeObservability) attachJournal(ctx context.Context, observed controllerObservation,
	collector *observability.Collector, cluster observability.ClusterSource,
) {
	journal := runtime.journal
	if journal == nil {
		return
	}
	conn := observed.nats.Conn()
	go openDecisionStream(ctx, observed.nats.JetStream(), runtime.cell, observed.replicas, journal)
	if runtime.config.ClusterAggregation {
		if _, err := decisionlog.ServeQueries(ctx, conn, runtime.cell, journal); err != nil {
			slog.Warn("decision query responder unavailable", observability.ComponentKey, "decision", "error", err)
		}
	}
	if observed.nats != nil {
		go watchControlPlane(ctx, runtime.cell, runtime.member, observed.authority, observed.nats, observed.replicas)
	}
	if runtime.server == nil {
		return
	}
	links, err := regionlink.New(runtime.cell, conn, configuredRegions(runtime.cell), regionRequestTimeout)
	if err != nil {
		slog.Warn("region links unavailable", observability.ComponentKey, "regionview", "error", err)
		return
	}
	if cluster != nil {
		// The sampler, the insight engine and the region view share one
		// scatter-gather per few seconds instead of one each.
		cluster = &sharedCluster{source: cluster, cache: observability.Cache[observability.ClusterSnapshot]{TTL: 3 * time.Second}}
	}
	history := observability.NewHistory(observability.HistoryConfig{})
	runtime.registry.Register(observability.HistoryMetrics)
	go runHistorySampler(ctx, observed, runtime.member, history, observability.ClusterCollect(cluster, collector))
	regions := &regionview.Provider{Cell: runtime.cell, Cluster: cluster, Snapshot: collector, History: history,
		Decisions: journal, Links: links}
	engine := insights.NewEngine(insights.Config{Region: runtime.cell, Cluster: cluster, Local: collector,
		History: history, Decisions: journal, Reachability: regions, Holds: observed.holds})
	regions.Insights = engine
	go func() { _ = engine.Run(ctx) }()
	if runtime.config.ClusterAggregation {
		if _, err := regionview.Serve(ctx, conn, runtime.cell, regions); err != nil {
			slog.Warn("region summary responder unavailable", observability.ComponentKey, "regionview", "error", err)
		}
	}
	federation := decisionlog.Federation{Local: journal, Links: links}
	providers := journalProviders{Decisions: federation, Live: journal, History: history, Insights: engine,
		Summarizer: insights.Summarizer{Decisions: federation, Insights: engine, Scope: "all regions"},
		Regions:    regions}
	runtime.providers.Store(&providers)
	mountJournalAPI(runtime.server, providers)
}

// configuredRegions lists the product regions a product cell can link to.
// A lab or test cell sees only itself.
func configuredRegions(cell string) []string {
	all := []string{string(oci.RegionGRU), string(oci.RegionSFO), string(oci.RegionFRA)}
	if !slices.ContainsFunc(all, func(region string) bool { return strings.EqualFold(region, cell) }) {
		return nil
	}
	return all
}

func openDecisionStream(ctx context.Context, js jetstream.JetStream, cell string, replicas int,
	journal *decisionlog.Journal,
) {
	for attempt := 1; ; attempt++ {
		openCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		stream, err := decisionlog.OpenStream(openCtx, js, decisionlog.StreamConfig{Cell: cell, Replicas: replicas})
		cancel()
		if err == nil {
			journal.Attach(stream, stream)
			_ = stream.Tail(ctx, journal, 0)
			return
		}
		if ctx.Err() != nil {
			return
		}
		if attempt == 1 || attempt%12 == 0 {
			slog.Warn("decision stream not open yet; decisions stay in memory", observability.ComponentKey,
				"decision", "attempt", attempt, "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(journalOpenRetry):
		}
	}
}

func runHistorySampler(ctx context.Context, observed controllerObservation, member string,
	history *observability.History, collect func(context.Context) []observability.Sample,
) {
	sampler := observability.HistorySampler{Store: history, Collect: collect, Member: member}
	if conn := observed.nats.Conn(); conn != nil {
		limit := int32(min(conn.MaxPayload()-8<<10, 1<<20))
		openCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		snapshots, err := observability.OpenHistorySnapshots(openCtx, observed.nats.JetStream(), observed.replicas, limit)
		cancel()
		if err == nil {
			sampler.Snapshots, sampler.SnapshotLimit = snapshots, int(limit)
		} else {
			slog.Info("metric history snapshots unavailable; history restarts empty", observability.ComponentKey,
				"observability", "error", err)
		}
	}
	_ = sampler.Run(ctx)
}

// clusterHealth is the part of the regional broker the watcher reads.
// *natscell.Runtime implements it.
type clusterHealth interface {
	FullClusterReady(replicas int) bool
	Observe(ctx context.Context) (observability.NATSView, error)
}

var _ clusterHealth = (*natscell.Runtime)(nil)

// watchControlPlane journals authority leadership acquisitions (recorded by
// the new leader, so each change is recorded once) and regional cluster
// health transitions (recorded by the leader, or by any member while no
// leader exists).
func watchControlPlane(ctx context.Context, cell, member string, fencer authority.Fencer, nats clusterHealth,
	replicas int,
) {
	if fencer == nil || nats == nil {
		return
	}
	healthEvery := clusterHealthInterval
	ticker := time.NewTicker(controlPlaneWatchInterval)
	defer ticker.Stop()
	var observedEpoch uint64
	wasLeader := false
	healthy, everHealthy := false, false
	var lastHealthCheck time.Time
	for {
		snapshot := fencer.Current()
		leading := snapshot.Leader && snapshot.Ready
		if leading && (!wasLeader || snapshot.Epoch != observedEpoch) {
			recordLeadership(ctx, cell, member, snapshot, observedEpoch)
		}
		wasLeader = leading
		if snapshot.Epoch > 0 {
			observedEpoch = snapshot.Epoch
		}
		if time.Since(lastHealthCheck) >= healthEvery {
			lastHealthCheck = time.Now()
			ready := nats.FullClusterReady(replicas)
			// The first full formation at startup is not a recovery.
			if ready != healthy && everHealthy && (leading || snapshot.OwnerID == "") {
				recordClusterHealth(ctx, cell, member, nats, replicas, ready, snapshot.Epoch)
			}
			healthy = ready
			everHealthy = everHealthy || ready
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func recordLeadership(ctx context.Context, cell, member string, snapshot authority.Snapshot, previousEpoch uint64) {
	reason := "This controller acquired the regional authority lease."
	if previousEpoch > 0 && previousEpoch != snapshot.Epoch {
		reason = fmt.Sprintf("This controller acquired the regional authority lease, ending epoch %d.", previousEpoch)
	}
	decisionlog.Record(ctx, decisionlog.Decision{
		Region:  cell,
		Actor:   decisionlog.Actor{Slice: "authority"},
		Kind:    decisionlog.KindLeaderChanged,
		Subject: decisionlog.Subject{Kind: "member", ID: member},
		Summary: fmt.Sprintf("%s became the regional authority leader (epoch %d)", member, snapshot.Epoch),
		Reason:  reason,
		Rule:    "fenced JetStream authority lease",
		Status:  decisionlog.StatusSucceeded,
		Epoch:   snapshot.Epoch,
		Signals: []decisionlog.Signal{{Name: "epoch", Value: float64(snapshot.Epoch)},
			{Name: "lease_expires_at", Text: snapshot.ExpiresAt.UTC().Format(time.RFC3339)}},
	})
}

func recordClusterHealth(ctx context.Context, cell, member string, nats clusterHealth, replicas int,
	healthy bool, epoch uint64,
) {
	signals := []decisionlog.Signal{{Name: "required_replicas", Value: float64(replicas)}}
	viewCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	if view, err := nats.Observe(viewCtx); err == nil {
		offline := 0
		for _, peer := range view.MetaPeers {
			if peer.Offline {
				offline++
			}
		}
		signals = append(signals,
			decisionlog.Signal{Name: "cluster_peers", Value: float64(view.ClusterPeers), Comparison: ">=",
				Threshold: decisionlog.Threshold(float64(replicas - 1)), Passed: decisionlog.Passed(healthy)},
			decisionlog.Signal{Name: "meta_offline_peers", Value: float64(offline)},
			decisionlog.Signal{Name: "meta_leader", Text: view.MetaLeader})
	}
	cancel()
	decision := decisionlog.Decision{Region: cell, Actor: decisionlog.Actor{Slice: "cluster"},
		Subject: decisionlog.Subject{Kind: "cluster", ID: cell}, Rule: "full regional cluster readiness",
		Epoch: epoch, Signals: signals}
	if healthy {
		decision.Kind, decision.Status = decisionlog.KindQuorumRestored, decisionlog.StatusSucceeded
		decision.Summary = "Regional cluster is back at full strength"
		decision.Reason = fmt.Sprintf("All %d replicas route and the JetStream metadata quorum is current.", replicas)
	} else {
		decision.Kind, decision.Status = decisionlog.KindQuorumDegraded, decisionlog.StatusFailed
		decision.Summary = "Regional cluster dropped below full strength"
		decision.Reason = fmt.Sprintf("%s observed fewer than %d routed replicas or a lagging JetStream metadata quorum.",
			member, replicas)
	}
	decisionlog.Record(ctx, decision)
}

// holdJournal records placement holds, at most once per reason within
// holdRepeat, so a hold re-asserted every tick is one decision.
type holdJournal struct {
	mu   sync.Mutex
	cell string
	last map[string]time.Time
}

func newHoldJournal(cell string) *holdJournal {
	return &holdJournal{cell: cell, last: map[string]time.Time{}}
}

func (journal *holdJournal) record(ctx context.Context, reason string, now time.Time) {
	journal.mu.Lock()
	if at, seen := journal.last[reason]; seen && now.Sub(at) < holdRepeat {
		journal.mu.Unlock()
		return
	}
	journal.last[reason] = now
	if len(journal.last) > 256 {
		for key, at := range journal.last {
			if now.Sub(at) >= holdRepeat {
				delete(journal.last, key)
			}
		}
	}
	journal.mu.Unlock()
	subject := holdSubject(reason)
	decisionlog.Record(ctx, decisionlog.Decision{
		Region:  journal.cell,
		Actor:   decisionlog.Actor{Slice: "placement"},
		Kind:    decisionlog.KindHeld,
		Subject: subject,
		Summary: "Placement held " + subject.String(),
		Reason:  reason,
		Rule:    "placement reconciliation safety gate",
		Status:  decisionlog.StatusPending,
	})
}

// holdSubject names what a placement hold reason is about.
func holdSubject(reason string) decisionlog.Subject {
	fields := strings.Fields(reason)
	for index := 0; index+1 < len(fields); index++ {
		switch fields[index] {
		case "member":
			return decisionlog.Subject{Kind: "seat", ID: fields[index+1]}
		case "database":
			return decisionlog.Subject{Kind: "database", ID: fields[index+1]}
		case "update":
			return decisionlog.Subject{Kind: "operation", ID: fields[index+1]}
		}
	}
	return decisionlog.Subject{Kind: "placement", ID: "reconciler"}
}

// Holds adapts the placement hold log to the insight engine.
func (log *placementHoldLog) Holds(now time.Time) []insights.Hold {
	var holds []insights.Hold
	seen := map[string]bool{}
	for _, record := range log.recent(now) {
		if seen[record.Reason] {
			continue
		}
		seen[record.Reason] = true
		holds = append(holds, insights.Hold{Reason: record.Reason, LastSeen: record.At})
	}
	return holds
}

var _ insights.HoldProvider = (*placementHoldLog)(nil)

// sharedCluster memoizes a cell-wide snapshot without metrics for a few
// seconds. Requests for metrics bypass it.
type sharedCluster struct {
	source observability.ClusterSource
	cache  observability.Cache[observability.ClusterSnapshot]
}

func (shared *sharedCluster) Cluster(ctx context.Context, includeMetrics bool) (observability.ClusterSnapshot, error) {
	if includeMetrics {
		return shared.source.Cluster(ctx, true)
	}
	return shared.cache.Get(ctx, func(ctx context.Context) (observability.ClusterSnapshot, error) {
		return shared.source.Cluster(ctx, false)
	})
}
