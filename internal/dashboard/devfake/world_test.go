package devfake

import (
	"context"
	"fmt"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/dashboard"
	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/globalview"
	"github.com/TerraScale/ts-orchestrator/internal/insights"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/regionview"
)

var regionNames = []string{"gru", "sjc", "fra"}

// sampleEvery is the live history sampling interval.
const sampleEvery = 10 * time.Second

// World is the fake three-region world. GRU is "this" region: the dashboard
// renders its live snapshot, history and insight engine; SJC and FRA answer
// summaries as if over the region links.
type World struct {
	start   time.Time
	regions []*region
	store   *store
	events  *observability.EventBus
	health  *observability.Health
	local   *regionState
	others  []*regionState
	mu      sync.Mutex
	// stuck is when the demo volume started attaching; zero when attached.
	stuck time.Time
}

// regionState is one region's read side.
type regionState struct {
	region   *region
	history  *observability.History
	sampler  *observability.SnapshotSampler
	engine   *insights.Engine
	provider *regionview.Provider
	world    *World
}

// New builds the world and backfills a day of history and two days of
// decisions ending now.
func New() *World {
	now := time.Now().UTC()
	world := &World{start: now, store: &store{}, events: observability.NewEventBus(512), health: new(observability.Health)}
	world.regions = []*region{
		{name: "gru", controllers: []string{"gru-ctl-1", "gru-ctl-2", "gru-ctl-3"},
			hosts:    []string{"gru-host-a", "gru-host-b", "gru-host-c", "gru-host-d", "gru-host-e"},
			versions: map[string]string{"gru-ctl-1": "v0.43.0", "gru-ctl-2": "v0.43.0", "gru-ctl-3": "v0.43.0"},
			leader:   "gru-ctl-1", epoch: 41, fullDisk: "gru-ctl-2",
			databases: []database{{id: entityid.Derive("preview-database", "orders"), name: "orders", seats: 3}, {id: entityid.Derive("preview-database", "billing"), name: "billing", seats: 3}, {id: entityid.Derive("preview-database", "catalog"), name: "catalog", seats: 3},
				{id: entityid.Derive("preview-database", "sessions"), name: "sessions", seats: 3, stages: []string{"serving", "serving", "awaiting-attach"}},
				{id: entityid.Derive("preview-database", "ledger"), name: "ledger", seats: 3, rollout: &observability.RolloutView{OperationID: entityid.Derive("preview-rollout", "terrabase-3.8.2", "gru"),
					ArtifactDigest: "sha256:3b81c9e2d0f4", Seats: 3, Completed: 1, Phases: map[string]int{"done": 1, "pending": 2}}},
				{id: entityid.Derive("preview-database", "search"), name: "search", seats: 3}}},
		{name: "sjc", controllers: []string{"sjc-ctl-1", "sjc-ctl-2", "sjc-ctl-3"},
			hosts:    []string{"sjc-host-a", "sjc-host-b", "sjc-host-c", "sjc-host-d"},
			versions: map[string]string{"sjc-ctl-1": "v0.43.0", "sjc-ctl-2": "v0.42.1", "sjc-ctl-3": "v0.42.1"},
			leader:   "sjc-ctl-2", epoch: 17, throttled: true,
			databases: []database{{id: entityid.Derive("preview-database", "orders"), name: "orders", seats: 3}, {id: entityid.Derive("preview-database", "analytics"), name: "analytics", seats: 3,
				stages: []string{"serving", "draining", "awaiting-healthy"}}, {id: entityid.Derive("preview-database", "catalog"), name: "catalog", seats: 3}, {id: entityid.Derive("preview-database", "media"), name: "media", seats: 3}}},
		{name: "fra", controllers: []string{"fra-ctl-1", "fra-ctl-2"}, missing: []string{"fra-ctl-3"},
			hosts:    []string{"fra-host-a", "fra-host-b", "fra-host-c"},
			versions: map[string]string{"fra-ctl-1": "v0.42.1", "fra-ctl-2": "v0.42.1"},
			leader:   "fra-ctl-1", epoch: 9, backlog: true,
			databases: []database{{id: entityid.Derive("preview-database", "orders"), name: "orders", seats: 3}, {id: entityid.Derive("preview-database", "gdpr-vault"), name: "gdpr-vault", seats: 3}, {id: entityid.Derive("preview-database", "catalog"), name: "catalog", seats: 3,
				stages: []string{"serving", "serving", "cordoned"}}}},
	}
	world.stuck = now.Add(-22 * time.Minute)
	// This member's own checks: the same results its snapshot reports.
	for _, check := range world.regions[0].checks(world.regions[0].leader) {
		world.health.Add(observability.Check{Name: check.Name, Run: func(context.Context) (bool, string) {
			return check.OK, check.Detail
		}})
	}
	world.seedDecisions(now)
	for index, region := range world.regions {
		state := &regionState{region: region, world: world,
			history: observability.NewHistory(observability.HistoryConfig{Interval: sampleEvery}),
			sampler: &observability.SnapshotSampler{}}
		state.backfill(now)
		state.provider = &regionview.Provider{Cell: region.name, Cluster: state, History: state.history, Nodes: region.nodes,
			Decisions: regional{store: world.store, region: region.name}}
		config := insights.Config{Region: region.name, Cluster: state, History: state.history,
			Decisions: regional{store: world.store, region: region.name}, Interval: 5 * time.Second,
			Rollouts: rollouts{region: region.name}, Holds: holds{region: region.name}}
		if index == 0 {
			config.Volumes = world
			config.Certificates = certificates{}
			config.NetBird = peers{}
			config.Autoscalers = autoscalers{}
			config.Budgets = budgets{}
			config.Reachability = world
			world.local = state
		} else {
			world.others = append(world.others, state)
		}
		state.engine = insights.NewEngine(config)
		state.engine.Evaluate(context.Background())
		state.provider.Insights = state.engine
	}
	world.seedEvents(now)
	return world
}

// Cluster serves the region's live snapshot.
func (state *regionState) Cluster(_ context.Context, _ bool) (observability.ClusterSnapshot, error) {
	return state.region.cluster(time.Now().UTC(), state.world.start), nil
}

// Snapshot serves this member's own snapshot (the GRU leader's).
func (state *regionState) Snapshot(ctx context.Context, _ bool) (observability.MemberSnapshot, error) {
	cluster, _ := state.Cluster(ctx, false)
	return cluster.Members[0], nil
}

func (state *regionState) backfill(now time.Time) {
	start := now.Add(-24 * time.Hour)
	for at := start; at.Before(now); {
		cluster := state.region.cluster(at, state.world.start)
		state.history.Append(at, state.sampler.Samples(cluster))
		if now.Sub(at) > time.Hour {
			at = at.Add(time.Minute)
		} else {
			at = at.Add(sampleEvery)
		}
	}
}

// Run samples history, evaluates insights, records new decisions, flips the
// demo volume and publishes events until ctx ends.
func (world *World) Run(ctx context.Context) {
	for _, state := range append([]*regionState{world.local}, world.others...) {
		go func() { _ = state.engine.Run(ctx) }()
	}
	sample := time.NewTicker(sampleEvery)
	defer sample.Stop()
	activity := time.NewTicker(7 * time.Second)
	defer activity.Stop()
	random := rand.New(rand.NewPCG(uint64(world.start.UnixNano()), 7))
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-sample.C:
			for _, state := range append([]*regionState{world.local}, world.others...) {
				state.history.Append(now.UTC(), state.sampler.Samples(state.region.cluster(now.UTC(), world.start)))
			}
		case now := <-activity.C:
			world.tick(now.UTC(), random)
		}
	}
}

func (world *World) tick(now time.Time, random *rand.Rand) {
	// The demo volume attaches and gets stuck again every three minutes,
	// so the insight engine opens and resolves an insight (and the page
	// raises a toast) while someone watches.
	world.mu.Lock()
	cycle := now.Sub(world.start) % (3 * time.Minute)
	if cycle < 90*time.Second && world.stuck.IsZero() {
		world.stuck = now.Add(-16 * time.Minute)
	} else if cycle >= 90*time.Second {
		world.stuck = time.Time{}
	}
	world.mu.Unlock()
	region := world.regions[random.IntN(len(world.regions))]
	db := region.databases[random.IntN(len(region.databases))]
	seat := entityid.Derive("preview-seat", region.name, db.id, fmt.Sprint(random.IntN(db.seats)+1))
	switch random.IntN(4) {
	case 0:
		world.store.record(decisionlog.Decision{Time: now, Region: region.name,
			Actor: decisionlog.Actor{Slice: "placement", Member: region.leader}, Kind: decisionlog.KindStageChanged,
			Subject: decisionlog.Subject{Kind: "seat", ID: seat}, Summary: "Seat " + seat + " moved to serving",
			Reason: "The seat passed three consecutive health checks.", Rule: "seat readiness gate",
			Signals: []decisionlog.Signal{gate("health_checks_passed", 3, "", ">=", 3)}, Status: decisionlog.StatusSucceeded})
	case 1:
		world.store.record(decisionlog.Decision{Time: now, Region: region.name,
			Actor: decisionlog.Actor{Slice: "delivery", Member: region.leader}, Kind: decisionlog.KindDeliveryApplied,
			Subject: decisionlog.Subject{Kind: "intent", ID: entityid.New()},
			Summary: "Applied a desired-state intent for " + db.name, Reason: "The intent's generation is newer than the applied one.",
			Rule: "apply newer generations in order", Status: decisionlog.StatusSucceeded})
	}
	levels := []string{"INFO", "INFO", "INFO", "WARN", "ERROR"}
	components := []string{"placement", "delivery", "oci", "authority", "natscell", "insights"}
	component := components[random.IntN(len(components))]
	level := levels[random.IntN(len(levels))]
	world.events.Publish(observability.Event{Time: now, Level: level, Component: component,
		Message: eventMessage(component, level, seat), Attrs: map[string]string{"region": region.name, "seat": seat}})
}

func eventMessage(component, level, seat string) string {
	switch {
	case component == "oci" && level != "INFO":
		return "OCI request throttled (429); backing off 2.4s"
	case component == "placement" && level == "ERROR":
		return "volume attachment for " + seat + " did not complete within 10m"
	case component == "placement":
		return "reconciled seat " + seat
	case component == "delivery" && level != "INFO":
		return "delivery intent deferred: newer generation pending"
	case component == "delivery":
		return "applied delivery intent"
	case component == "authority":
		return "authority lease renewed"
	case component == "natscell" && level != "INFO":
		return "JetStream peer fra-ctl-3 is offline"
	case component == "insights":
		return "insight evaluation complete"
	default:
		return "route RTT within bounds"
	}
}

func (world *World) seedEvents(now time.Time) {
	random := rand.New(rand.NewPCG(1, 2))
	for at := now.Add(-50 * time.Minute); at.Before(now); at = at.Add(20 * time.Second) {
		world.tickEvent(at, random)
	}
}

func (world *World) tickEvent(at time.Time, random *rand.Rand) {
	levels := []string{"INFO", "INFO", "INFO", "INFO", "WARN", "ERROR"}
	components := []string{"placement", "delivery", "oci", "authority", "natscell"}
	component := components[random.IntN(len(components))]
	level := levels[random.IntN(len(levels))]
	world.events.Publish(observability.Event{Time: at, Level: level, Component: component,
		Message: eventMessage(component, level, "orders-2"), Attrs: map[string]string{"region": "gru"}})
}

// Reachability reports SJC and FRA as linked and answering.
func (world *World) Reachability(context.Context) []insights.RegionReach {
	now := time.Now()
	return []insights.RegionReach{{Region: "sjc", State: decisionlog.RegionOK, LastSeen: now},
		{Region: "fra", State: decisionlog.RegionOK, LastSeen: now}}
}

// Options returns dashboard options wired to the whole fake world.
func (world *World) Options() dashboard.Options {
	journal := dashboard.Journal{Decisions: world.store, Live: world.store, History: world.local.history,
		Insights: world.local.engine,
		Summaries: insights.Summarizer{Decisions: world.store, Insights: world.local.engine, Scope: "all regions",
			AttentionScope: "GRU"},
		Local: world.local.provider.Local, Versions: world, Rollouts: rollouts{region: "gru"}, Volumes: world,
		Qualification: qualifications{}, Inventory: inventory{}}
	global := globalview.NewView("gru", func() []string { return regionNames }, time.Now)
	for _, region := range world.regions {
		now := time.Now().UTC()
		global.Accept(globalview.Build(globalview.Inputs{Cell: region.name, Now: now, Cluster: region.cluster(now, world.start), ClusterOK: true}))
	}
	journal.Global = global
	return dashboard.Options{Health: world.health, Events: world.events, Snapshots: world.local,
		Cluster: world.local, Journal: &journal}
}

var (
	_ decisionlog.Source     = (*store)(nil)
	_ decisionlog.LiveSource = (*store)(nil)
)
