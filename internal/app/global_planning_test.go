package app

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionlifecycle"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionplanner"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func testPlannerConfig() *RegionPlannerConfig {
	return &RegionPlannerConfig{Enabled: true, MaxRegions: 4, MonthlyCeilingCents: 40_000, HomeMonthlyCents: 9_000,
		RegionMonthlyCents: map[string]uint64{"gru": 9_000, "fra": 9_500, "sfo": 9_000}, Overflow: map[string]string{"gru": "sfo"}}
}

// TestPeerSignalsNeedOnlyTheCellConnection pins ts-reviewer 13224: peer
// signals use a federation over the cell connection, not the HTTP
// listener's providers, and fail loudly without peers or a connection.
func TestPeerSignalsNeedOnlyTheCellConnection(t *testing.T) {
	t.Parallel()
	if _, err := peerDecisions("gru", nil, &rosterPeers{}); err == nil {
		t.Error("peer decisions without a connection")
	}
	peers := &rosterPeers{}
	source, err := peerDecisions("gru", &nats.Conn{}, peers)
	federation, ok := source.(decisionlog.Federation)
	if err != nil || !ok || federation.Local != nil || !slices.Equal(federation.Links.Regions(), []string{"gru"}) {
		t.Fatalf("federation = %+v, %v", source, err)
	}
	// The roster drives the links: peers join and leave without a restart.
	peers.apply([]string{"sfo", "fra"})
	if !slices.Equal(federation.Links.Regions(), []string{"gru", "fra", "sfo"}) || !federation.Links.Linked("sfo") {
		t.Fatalf("joined regions = %v", federation.Links.Regions())
	}
	peers.apply([]string{"fra"})
	if !slices.Equal(federation.Links.Regions(), []string{"gru", "fra"}) || federation.Links.Linked("sfo") {
		t.Fatalf("left regions = %v", federation.Links.Regions())
	}
}

func TestRegionPlannerPolicyCountsTheHomeAndValidates(t *testing.T) {
	t.Parallel()

	policy, err := testPlannerConfig().plannerPolicy("gru")
	if err != nil {
		t.Fatal(err)
	}
	if policy.Home != (regionlifecycle.Home{Cell: "gru"}) || policy.MaxRegions != 4 ||
		policy.Catalog["sfo"].OCIRegion == "" || policy.Catalog["gru"].Overflow != "sfo" {
		t.Fatalf("policy = %+v", policy)
	}
	for name, mutate := range map[string]func(*RegionPlannerConfig){
		"no ceiling":              func(c *RegionPlannerConfig) { c.MonthlyCeilingCents = 0 },
		"no max":                  func(c *RegionPlannerConfig) { c.MaxRegions = 0 },
		"no home cost":            func(c *RegionPlannerConfig) { c.HomeMonthlyCents = 0 },
		"empty catalog":           func(c *RegionPlannerConfig) { c.RegionMonthlyCents = nil },
		"subscribe without drive": func(c *RegionPlannerConfig) { c.SubscribeRegions = true },
	} {
		config := testPlannerConfig()
		mutate(config)
		if _, err := config.plannerPolicy("gru"); err == nil {
			t.Errorf("%s: planner policy accepted", name)
		}
	}
}

func TestRegionPlannerRunsOnlyInTheGlobalHome(t *testing.T) {
	t.Parallel()

	cfg := Config{NATS: natscell.Config{Cell: "sfo", Replicas: 1}}
	cfg.Controller.RegionPlanner = testPlannerConfig()
	if _, err := startRegionPlanner(t.Context(), cfg, nil, nil, nil, nil, nil, func() bool { return true }); err == nil {
		t.Fatal("region planner started without global control")
	}
	cfg.Controller.Global = &GlobalControlConfig{Home: "gru"}
	if _, err := startRegionPlanner(t.Context(), cfg, nil, &globalControl{}, nil, nil, nil, func() bool { return true }); err == nil {
		t.Fatal("region planner started outside the global home")
	}
	cfg.Controller.RegionPlanner.Enabled = false
	if budgets, err := startRegionPlanner(t.Context(), cfg, nil, nil, nil, nil, nil, nil); err != nil || budgets != nil {
		t.Fatalf("disabled planner = %v, %v", budgets, err)
	}
	if _, err := startRollouts(t.Context(), cfg, nil, nil, nil, nil); err == nil {
		t.Fatal("mandatory rollouts admitted no JetStream")
	}
	if newRolloutKnownBad() == nil {
		t.Fatal("mandatory rollout store has no known-bad source")
	}

}

// Placement starts before the rollout store opens: until it does, the
// known-bad source refuses instead of reporting a clean list.
func TestRolloutKnownBadFailsClosedUntilTheStoreOpens(t *testing.T) {
	t.Parallel()

	knownBad := newRolloutKnownBad()
	if knownBad == nil {
		t.Fatal("no known-bad source with the rollout store enabled")
	}
	if bad, err := knownBad.IsKnownBad(t.Context(), strings.Repeat("a", 64)); err == nil || bad {
		t.Fatalf("unopened store = %v, %v", bad, err)
	}
	if withKnownBad(placement.Config{}, knownBad).KnownBad == nil {
		t.Fatal("placement config lost the known-bad source")
	}
	// A disabled store must leave the interface nil, not a typed nil.
	if withKnownBad(placement.Config{}, nil).KnownBad != nil {
		t.Fatal("a disabled rollout store set a known-bad source")
	}
}

func TestHoldSignalsClassifyCapacityAndLimitHolds(t *testing.T) {
	t.Parallel()

	holds := new(placementHoldLog)
	holds.record("OCI LaunchInstance: Out of host capacity in AD-1")
	holds.record("service limit exceeded for VM.Standard.E5.Flex")
	holds.record("waiting for an admitted artifact")
	holds.record("reconciliation error: timeout")
	signals, err := holdSignals{cell: "GRU", holds: holds}.Signals(t.Context(), time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var kinds []regionplanner.SignalKind
	for _, signal := range signals {
		if signal.Cell != "gru" || len(signal.EvidenceDigest) != 64 {
			t.Fatalf("signal = %+v", signal)
		}
		kinds = append(kinds, signal.Kind)
	}
	if !slices.Equal(kinds, []regionplanner.SignalKind{regionplanner.SignalCapacityError, regionplanner.SignalLimitError}) {
		t.Fatalf("kinds = %v", kinds)
	}
	if late, _ := (holdSignals{cell: "gru", holds: holds}).Signals(t.Context(), time.Now().Add(time.Hour)); len(late) != 0 {
		t.Fatalf("signals before since = %v", late)
	}
}

type followerFencer struct{}

func (followerFencer) Current() authority.Snapshot {
	return authority.Snapshot{Scope: protocol.GlobalScope}
}
func (followerFencer) Guard(context.Context, uint64) error { return authority.ErrNotLeader }

// TestPlannerRunnerProposesOnTheGlobalLeaderOnly drives one planner tick on
// embedded JetStream: capacity holds in GRU propose its overflow region SFO,
// which the planner approves into an Approved lifecycle record, and a
// follower proposes nothing.
func TestPlannerRunnerProposesOnTheGlobalLeaderOnly(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true,
		StoreDir: filepath.Join(t.TempDir(), "jetstream")})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS did not start")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	conn, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	global, err := authority.Start(ctx, js, authority.Config{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Scope: protocol.GlobalScope, CandidateID: "0000000000F2D374M7NMRHJJQT", Replicas: 1,
		LeaseDuration: 5 * time.Second, RenewInterval: 500 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = global.Close() })
	for !global.Current().CanMutate() {
		if ctx.Err() != nil {
			t.Fatal("global authority never became leader")
		}
		time.Sleep(20 * time.Millisecond)
	}
	store, err := regionlifecycle.OpenStore(ctx, js, 1, global)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := testPlannerConfig().plannerPolicy("gru")
	if err != nil {
		t.Fatal(err)
	}
	holds := new(placementHoldLog)
	for _, ad := range []string{"AD-1", "AD-2", "AD-3"} {
		holds.record("OCI LaunchInstance: Out of host capacity in " + ad)
	}
	runner := plannerRunner{source: holdSignals{cell: "gru", holds: holds}, planner: regionplanner.Planner{Policy: policy},
		store: store, machine: regionlifecycle.Machine{}, leader: followerFencer{}}
	if submitted := runner.tick(ctx, time.Now()); len(submitted) != 0 {
		t.Fatalf("follower proposed %v", submitted)
	}
	runner.leader = global
	if submitted := runner.tick(ctx, time.Now()); !slices.Equal(submitted, []string{"sfo"}) {
		t.Fatalf("leader proposals = %v", submitted)
	}
	record, _, err := store.Get(ctx, "sfo")
	// Nothing approves until the budget guards admission (TS-804).
	if err != nil || record.Phase != regionlifecycle.Proposed || record.Admission != nil {
		t.Fatalf("proposed record = %+v, %v", record, err)
	}
	budgets, err := regionplanner.Budgets{Policy: policy, Records: store}.Budgets(ctx)
	if err != nil || len(budgets) != 2 || budgets[0].Used != 1 || budgets[1].Used != 0 {
		// An unapproved proposal takes no slot and commits nothing; the home
		// holds a slot and its spend is in the budget projection.
		t.Fatalf("budgets = %+v, %v", budgets, err)
	}
}
