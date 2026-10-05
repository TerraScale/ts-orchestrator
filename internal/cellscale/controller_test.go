package cellscale

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
)

// observeState reads a fake cell the way the controller does.
func observeState(t *testing.T, policy Policy, cell *fakeCell) State {
	t.Helper()
	// Model an already-running observer; startup freshness has its own tests.
	controller, err := New(Config{Cell: cell.cell, Policy: policy, Cloud: cell, Members: cell, Source: cell,
		Now: func() time.Time { return cell.now().Add(-MaxPressureClockSkew - time.Second) }})
	if err != nil {
		t.Fatal(err)
	}
	controller.config.Now = cell.now
	controller.config.Members = liveReplicaInventory{cell, controller}
	state, err := controller.observe(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return state
}

// act decides twice, the second time past the sustain window, the way a
// steady load reaches the rails.
func act(policy Policy, state State, history History) Action {
	_, history = Decide(policy, state, history)
	history.WantSince = history.WantSince.Add(-7 * 24 * time.Hour)
	action, _ := Decide(policy, state, history)
	return action
}

func TestRailsRefuseQuorumLoss(t *testing.T) {
	policy := testPolicy()
	state := observeState(t, policy, newFakeCell(3, small, 4, 50))
	if action, _ := rails(policy, state, History{}, Action{Kind: KindScaleIn, Node: "gru-1-db-3"}, 0); action.Reason != ReasonQuorum {
		t.Fatalf("scale in to 2 of replication factor 3 = %+v", action)
	}
	single := testPolicy()
	single.Nodes.Min, single.Nodes.Max, single.ReplicationFactor = 1, 1, 1
	one := observeState(t, single, newFakeCell(1, small, 4, 250))
	if action, _ := rails(single, one, History{}, Action{Kind: KindResize, From: small, To: Shape{OCPUs: 4, MemoryGB: 24}}, 0); action.Reason != ReasonQuorum {
		t.Fatalf("rolling restart of a single node cell = %+v", action)
	}
	// A CPU-bound single node cell can neither restart nor grow: it holds.
	cell := newFakeCell(1, small, 4, 250)
	cell.coresPerRequest = 1.0 / 400
	if action := act(single, observeState(t, single, cell), History{}); action.Kind != KindHold || action.Reason != ReasonAtCapacity {
		t.Fatalf("single node under CPU pressure = %+v", action)
	}
	// An idle cell at its floor never shrinks.
	if action := act(policy, state, History{}); action.Kind != KindHold || action.Reason != ReasonWithinBand {
		t.Fatalf("idle cell at min = %+v", action)
	}
}

func TestRailsBudgetCapsScaleUp(t *testing.T) {
	journal := captureJournal(t)
	policy := testPolicy()
	policy.MonthlyBudget = policy.MonthlyCost(3, small) + 1
	cell := newFakeCell(3, small, 4, 250)
	acted := newSim(t, policy, cell, time.Minute).run(60, func(time.Duration) float64 { return 2.6 })
	if len(acted) != 0 || len(cell.callLog()) != 0 {
		t.Fatalf("over-budget cell acted: %v, calls %v", kinds(acted), cell.callLog())
	}
	if !slices.ContainsFunc(journal.decisions, func(d decisionlog.Decision) bool {
		return d.Reason == ReasonBudget && len(d.Alternatives) == 1 && strings.Contains(d.Alternatives[0].Option, "add node gru-1-db-4")
	}) {
		t.Fatal("the budget hold was not journaled with the refused scale out")
	}
	// Scaling down is always within budget.
	policy.MonthlyBudget = policy.MonthlyCost(3, small)
	four := observeState(t, policy, newFakeCell(4, small, 1, 50))
	if action := act(policy, four, History{}); action.Kind != KindScaleIn {
		t.Fatalf("over-budget idle cell = %+v", action)
	}
}

func TestRailsCooldownAndHourlyLimit(t *testing.T) {
	policy := testPolicy()
	state := observeState(t, policy, func() *fakeCell { c := newFakeCell(3, small, 4, 250); c.scale = 2.6; return c }())
	action, history := Decide(policy, state, History{})
	if action.Reason != ReasonSustaining {
		t.Fatalf("first want = %+v", action)
	}
	history.WantSince = state.Now.Add(-time.Hour)
	history.LastAction = state.Now.Add(-5 * time.Minute)
	if action, _ := Decide(policy, state, history); action.Reason != ReasonCooldown {
		t.Fatalf("inside the 10 minute cooldown = %+v", action)
	}
	history.LastAction = state.Now.Add(-11 * time.Minute)
	history.Actions = []time.Time{state.Now.Add(-50 * time.Minute), state.Now.Add(-40 * time.Minute),
		state.Now.Add(-30 * time.Minute), state.Now.Add(-11 * time.Minute)}
	if action, _ := Decide(policy, state, history); action.Reason != ReasonRateLimit {
		t.Fatalf("fifth action inside an hour = %+v", action)
	}
	history.Actions = history.Actions[1:]
	if action, _ := Decide(policy, state, history); action.Kind != KindScaleOut {
		t.Fatalf("fourth action inside an hour = %+v", action)
	}
}

func TestDryRunJournalsWithoutEffects(t *testing.T) {
	journal := captureJournal(t)
	policy := testPolicy()
	policy.DryRun = true
	cell := newFakeCell(3, small, 4, 250)
	acted := newSim(t, policy, cell, time.Minute).run(60, func(time.Duration) float64 { return 2.6 })
	if len(acted) < 2 || acted[0].action.Kind != KindScaleOut {
		t.Fatalf("dry run recommendations = %v", kinds(acted))
	}
	if calls := cell.callLog(); len(calls) != 0 {
		t.Fatalf("dry run touched the cell: %v", calls)
	}
	recommended := slices.IndexFunc(journal.decisions, func(d decisionlog.Decision) bool { return d.Kind == decisionlog.KindScaleUp })
	if recommended < 0 {
		t.Fatal("dry run journaled no recommendation")
	}
	d := journal.decisions[recommended]
	if d.Status != decisionlog.StatusPending || d.Attrs["dry_run"] != "true" || !strings.HasPrefix(d.Summary, "Dry run: would add node gru-1-db-4") ||
		d.Attrs["undo"] == "" {
		t.Fatalf("dry run decision = %+v", d)
	}
}

func TestHoldsDuringRolloutAndUnsettledCell(t *testing.T) {
	policy := testPolicy()
	for name, setup := range map[string]func(*fakeCell){
		ReasonRollout:    func(c *fakeCell) { c.release["gru-1-db-2"] = "r2" },
		ReasonNotSettled: func(c *fakeCell) { c.state["gru-1-db-2"], c.state["gru-1-db-3"] = StateJoining, StateJoining },
		"unreadable":     func(c *fakeCell) { c.unread["gru-1-db-1"] = true },
		"terminating":    func(c *fakeCell) { c.instances[2].State = "TERMINATING" },
		ReasonLag:        func(c *fakeCell) { c.lag = map[string]uint64{"gru-1-db-3": 5000} },
	} {
		cell := newFakeCell(3, small, 4, 250)
		cell.scale = 2.6
		setup(cell)
		want := name
		if name == "unreadable" || name == "terminating" {
			want = ReasonNotSettled
		}
		if action := act(policy, observeState(t, policy, cell), History{}); action.Kind != KindHold || action.Reason != want {
			t.Fatalf("%s: %+v", name, action)
		}
	}
	captureJournal(t)
	cell := newFakeCell(3, small, 4, 250)
	controller, err := New(Config{Cell: "gru-1", Policy: policy, Cloud: cell, Members: cell, Source: cell,
		Rollouts: func(context.Context) (bool, error) { return true, nil }})
	if err != nil {
		t.Fatal(err)
	}
	if action, err := controller.Tick(t.Context()); err != nil || action.Reason != ReasonRollout {
		t.Fatalf("rollout store in flight: %+v, %v", action, err)
	}
	controller.config.Rollouts = func(context.Context) (bool, error) { return false, errors.New("store down") }
	if _, err := controller.Tick(t.Context()); err == nil {
		t.Fatal("an unknown rollout state must not act")
	}
}

func TestObservationGapRestartsSustain(t *testing.T) {
	captureJournal(t)
	cell := newFakeCell(3, small, 4, 250)
	s := newSim(t, testPolicy(), cell, 3*time.Minute)
	if acted := s.run(1, func(time.Duration) float64 { return 2.6 }); len(acted) != 0 {
		t.Fatalf("first tick acted: %v", kinds(acted))
	}
	cell.failList = errors.New("OCI unavailable")
	if _, err := s.controller.Tick(t.Context()); err == nil {
		t.Fatal("a failed listing must fail the tick")
	}
	cell.failList = nil
	s.now = s.now.Add(3 * time.Minute)
	// Six minutes after the first want, but the gap restarted the window.
	if acted := s.run(1, func(time.Duration) float64 { return 2.6 }); len(acted) != 0 {
		t.Fatalf("acted across an observation gap: %v", kinds(acted))
	}
	if acted := s.run(2, func(time.Duration) float64 { return 2.6 }); len(acted) != 1 {
		t.Fatalf("sustained load after the gap = %v", kinds(acted))
	}
}

func TestLastingObservationOutageAlertsOnce(t *testing.T) {
	journal := captureJournal(t)
	cell := newFakeCell(3, small, 4, 250)
	cell.failList = errors.New("OCI unavailable")
	s := newSim(t, testPolicy(), cell, time.Minute)
	for range 5 {
		if _, err := s.controller.Tick(t.Context()); err == nil {
			t.Fatal("a failed listing must fail the tick")
		}
	}
	alerts := 0
	for _, d := range journal.decisions {
		if d.Outcome == "observation-failing" && d.Status == decisionlog.StatusFailed {
			alerts++
		}
	}
	if alerts != 1 || s.controller.History().Paused {
		t.Fatalf("%d alerts, paused %v", alerts, s.controller.History().Paused)
	}
}

func TestRepeatedFailuresPauseAndAlert(t *testing.T) {
	journal := captureJournal(t)
	policy := testPolicy()
	cell := newFakeCell(3, small, 4, 250)
	cell.failLaunch = errors.New("out of host capacity")
	s := newSim(t, policy, cell, time.Minute)
	cell.setScale(2.6)
	failures := 0
	for range 60 {
		if _, err := s.controller.Tick(t.Context()); err != nil {
			failures++
		}
		s.now = s.now.Add(time.Minute)
	}
	if failures != policy.MaxFailures || !s.controller.History().Paused {
		t.Fatalf("failures %d, history %+v", failures, s.controller.History())
	}
	alert := slices.IndexFunc(journal.decisions, func(d decisionlog.Decision) bool {
		return d.Outcome == "paused" && d.Status == decisionlog.StatusFailed
	})
	if alert < 0 {
		t.Fatal("the pause raised no alert")
	}
	if action, _ := s.controller.Tick(t.Context()); action.Reason != ReasonPaused {
		t.Fatalf("paused controller = %+v", action)
	}
	cell.failLaunch = nil
	s.controller.Resume()
	acted := s.run(30, func(time.Duration) float64 { return 2.6 })
	if len(acted) == 0 || acted[0].action.Kind != KindScaleOut || cell.nodes() != 4 {
		t.Fatalf("resumed controller = %v", kinds(acted))
	}
}

func TestScaleInDrainsBeforeTerminate(t *testing.T) {
	captureJournal(t)
	cell := newFakeCell(4, small, 2, 150)
	acted := newSim(t, testPolicy(), cell, time.Minute).run(60, func(time.Duration) float64 { return 1 })
	if len(acted) != 1 || acted[0].action.Kind != KindScaleIn || acted[0].action.Node != "gru-1-db-4" || acted[0].at != 30*time.Minute+MaxPressureClockSkew+time.Second {
		t.Fatalf("idle 4 node cell actions = %v", kinds(acted))
	}
	if got, want := cell.callLog(), []string{"drain gru-1-db-4", "terminate gru-1-db-4"}; !slices.Equal(got, want) {
		t.Fatalf("scale in calls = %v, want %v", got, want)
	}
	if rate := cell.baseRate("gru-1-db-1") + cell.baseRate("gru-1-db-2") + cell.baseRate("gru-1-db-3"); rate != 4*2*150 {
		t.Fatalf("drained tenants were lost: %v requests/s remain", rate)
	}
}

// runUntilError ticks a minute apart until a tick fails.
func runUntilError(t *testing.T, s *sim, ticks int) error {
	t.Helper()
	for range ticks {
		if _, err := s.controller.Tick(t.Context()); err != nil {
			return err
		}
		s.now = s.now.Add(time.Minute)
	}
	return nil
}

func TestScaleInStopsWhenAPeerFailsDuringDrain(t *testing.T) {
	captureJournal(t)
	cell := newFakeCell(4, small, 2, 150)
	cell.after = map[string]func(string){"drain": func(string) { cell.unread["gru-1-db-2"] = true }}
	err := runUntilError(t, newSim(t, testPolicy(), cell, time.Minute), 60)
	if err == nil || !strings.Contains(err.Error(), "gru-1-db-2 is not ready") {
		t.Fatalf("scale in with a failed peer: %v", err)
	}
	if got := cell.callLog(); !slices.Equal(got, []string{"drain gru-1-db-4"}) {
		t.Fatalf("terminated with a failed peer: %v", got)
	}
}

func TestScaleOutStopsWhenARolloutStartsBeforeJoin(t *testing.T) {
	captureJournal(t)
	cell := newFakeCell(3, small, 4, 250)
	cell.after = map[string]func(string){"launch": func(string) { cell.release["gru-1-db-1"] = "r2" }}
	s := newSim(t, testPolicy(), cell, time.Minute)
	cell.setScale(2.6)
	err := runUntilError(t, s, 30)
	if err == nil || !strings.Contains(err.Error(), "rollout is in flight") {
		t.Fatalf("scale out into a rollout: %v", err)
	}
	if got := cell.callLog(); !slices.Equal(got, []string{"launch gru-1-db-4 2 OCPU/12 GB"}) {
		t.Fatalf("joined during a rollout: %v", got)
	}
}

func TestRollingResizeStopsWhenAnotherNodeFails(t *testing.T) {
	captureJournal(t)
	cell := newFakeCell(3, small, 4, 250)
	cell.coresPerRequest = 1.0 / 500
	cell.onResize = func(node string) {
		if node == "gru-1-db-1" {
			cell.unread["gru-1-db-3"] = true
		}
	}
	s := newSim(t, testPolicy(), cell, time.Minute)
	var err error
	for range 10 {
		if _, err = s.controller.Tick(t.Context()); err != nil {
			break
		}
		s.now = s.now.Add(time.Minute)
	}
	if err == nil || !strings.Contains(err.Error(), "gru-1-db-3 is not ready") {
		t.Fatalf("resize with a failed peer: %v", err)
	}
	if got := cell.callLog(); !slices.Equal(got, []string{"resize gru-1-db-1 4 OCPU/24 GB"}) {
		t.Fatalf("resize continued past a failed peer: %v", got)
	}

	// A peer that disappears between two restarts stops the resize.
	cell = newFakeCell(3, small, 4, 250)
	cell.coresPerRequest = 1.0 / 500
	cell.onResize = func(node string) {
		if node == "gru-1-db-1" {
			cell.instances = cell.instances[:2]
		}
	}
	s = newSim(t, testPolicy(), cell, time.Minute)
	for range 10 {
		if _, err = s.controller.Tick(t.Context()); err != nil {
			break
		}
		s.now = s.now.Add(time.Minute)
	}
	if err == nil || !strings.Contains(err.Error(), "membership changed") || len(cell.callLog()) != 1 {
		t.Fatalf("resize after a peer vanished: %v, calls %v", err, cell.callLog())
	}

	// A rollout that starts between two restarts stops the resize too.
	cell = newFakeCell(3, small, 4, 250)
	cell.coresPerRequest = 1.0 / 500
	cell.onResize = func(string) { cell.release["gru-1-db-3"] = "r2" }
	s = newSim(t, testPolicy(), cell, time.Minute)
	for range 10 {
		if _, err = s.controller.Tick(t.Context()); err != nil {
			break
		}
		s.now = s.now.Add(time.Minute)
	}
	if err == nil || !strings.Contains(err.Error(), "rollout is in flight") || len(cell.callLog()) != 1 {
		t.Fatalf("resize during a rollout: %v, calls %v", err, cell.callLog())
	}
}

func TestLowerTiersMoveFirst(t *testing.T) {
	policy := testPolicy()
	cell := newFakeCell(3, small, 2, 200)
	// Both tenants of the hot db-2 would fit on db-1; the hobby one moves.
	cell.tenants["gru-1-db-2"] = []TenantLoad{{Org: "bigcorp", Plan: PlanEnterprise, RequestRate: 1400},
		{Org: "tiny", Plan: PlanHobby, RequestRate: 700}}
	action := act(policy, observeState(t, policy, cell), History{})
	if action.Kind != KindRebalance || action.Tenant != "tiny" || action.Node != "gru-1-db-2" {
		t.Fatalf("hot node with an enterprise and a hobby tenant = %+v", action)
	}
	// Enterprise tenants have no limits, but they still move when nothing else can.
	cell.tenants["gru-1-db-2"][1].Plan = PlanEnterprise
	action = act(policy, observeState(t, policy, cell), History{})
	if action.Kind != KindRebalance || action.Tenant != "bigcorp" {
		t.Fatalf("enterprise-only hot node = %+v", action)
	}
	// A tenant too big for any node, new or existing, grows the shape.
	cell.tenants["gru-1-db-2"] = []TenantLoad{{Org: "bigcorp", Plan: PlanEnterprise, RequestRate: 2100}}
	action = act(policy, observeState(t, policy, cell), History{})
	if action.Kind != KindResize || action.Reason != ReasonHotspot || action.To.OCPUs != 4 {
		t.Fatalf("oversized tenant = %+v", action)
	}
}

func TestRebalanceSearchesEligibleDestinations(t *testing.T) {
	for _, test := range []struct {
		name   string
		kind   Kind
		target string
	}{
		{"CPU headroom", KindRebalance, "gru-1-db-3"},
		{"request headroom", KindRebalance, "gru-1-db-3"},
		{"coolest eligible", KindRebalance, "gru-1-db-2"},
		{"lower tier first", KindRebalance, "gru-1-db-3"},
		{"none fit", KindResize, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			policy := testPolicy()
			policy.Nodes.Max = 3 // A feasible move must work even at the node cap.
			state := observeState(t, policy, newFakeCell(3, small, 2, 100))
			hot, cool, peer := state.Nodes[0].Pressure, state.Nodes[1].Pressure, state.Nodes[2].Pressure
			hot.CPUUtil = 1.1 * policy.Targets.CPUUtil
			hot.TopTenants = []TenantLoad{{Org: "noisy", Plan: PlanHobby, RequestRate: 100, CPUShare: 0.3 / 1.1}}
			cool.CPUUtil, peer.CPUUtil = 0.8*policy.Targets.CPUUtil, 0.2*policy.Targets.CPUUtil
			peer.DiskTotalBytes, peer.DiskUsedBytes = 1000, 675 // 0.9 disk pressure; CPU/request load still fits.
			switch test.name {
			case "request headroom":
				hot.CPUUtil, cool.CPUUtil = peer.CPUUtil, peer.CPUUtil
				hot.RequestRate, cool.RequestRate, peer.RequestRate = 2200, 1600, 400
				hot.TopTenants[0].RequestRate = 600 // Adds 0.3 request pressure.
			case "coolest eligible":
				cool.CPUUtil = peer.CPUUtil
				cool.DiskTotalBytes, cool.DiskUsedBytes = 1000, 600 // 0.8 peak; both peers now fit.
			case "lower tier first":
				hot.TopTenants = append(hot.TopTenants, TenantLoad{Org: "bigcorp", Plan: PlanEnterprise, RequestRate: 100, CPUShare: 0.01})
			case "none fit":
				peer.CPUUtil = cool.CPUUtil
			}
			action := act(policy, state, History{})
			if action.Kind != test.kind || action.Target != test.target || action.Reason != ReasonHotspot ||
				action.Kind == KindRebalance && (action.Node != "gru-1-db-1" || action.Tenant != "noisy" || action.Plan != PlanHobby) {
				t.Fatalf("feasible destination search = %+v", action)
			}
			if !slices.Equal(names(state.Nodes), []string{"gru-1-db-1", "gru-1-db-2", "gru-1-db-3"}) {
				t.Fatal("destination ranking mutated the observed membership order")
			}
		})
	}
}

func TestStoragePressureNeverResizes(t *testing.T) {
	policy := testPolicy()
	policy.Nodes.Max = 3
	state := observeState(t, policy, newFakeCell(3, small, 4, 100))
	for _, node := range state.Nodes {
		node.Pressure.DiskUsedBytes = node.Pressure.DiskTotalBytes * 8 / 10 // 1.07 disk pressure
	}
	if action := act(policy, state, History{}); action.Kind != KindHold || action.Reason != ReasonAtCapacity {
		t.Fatalf("full disks at max nodes = %+v", action)
	}
	policy.Nodes.Max = 4
	if action := act(policy, state, History{}); action.Kind != KindScaleOut {
		t.Fatalf("full disks below max nodes = %+v", action)
	}
}

func TestBoundsAndShapeCorrectWithoutSustain(t *testing.T) {
	policy := testPolicy()
	cell := newFakeCell(3, small, 4, 250)
	cell.instances = slices.Delete(cell.instances, 1, 2) // db-2 is gone
	state := observeState(t, policy, cell)
	state.Now = time.Now()
	if action, _ := Decide(policy, state, History{}); action.Kind != KindScaleOut || action.Node != "gru-1-db-2" ||
		action.Reason != ReasonBelowMin {
		t.Fatalf("below min = %+v", action)
	}
	// A placement seat holds db-2 without the autoscaler's tags: the cell
	// counts two nodes and skips the seat's name.
	cell = newFakeCell(3, small, 4, 250)
	cell.instances[1].Foreign = true
	state = observeState(t, policy, cell)
	if action, _ := Decide(policy, state, History{}); action.Kind != KindScaleOut || action.Node != "gru-1-db-4" ||
		len(state.Nodes) != 2 {
		t.Fatalf("cell beside a foreign seat = %+v, nodes %d", action, len(state.Nodes))
	}
	cell = newFakeCell(3, small, 4, 250)
	cell.instances[2].Shape = Shape{OCPUs: 4, MemoryGB: 24} // an interrupted resize
	state = observeState(t, policy, cell)
	if action, _ := Decide(policy, state, History{}); action.Kind != KindResize || action.To.OCPUs != 4 ||
		action.Reason != ReasonConvergeShape {
		t.Fatalf("mixed shapes = %+v", action)
	}
}

func TestUndo(t *testing.T) {
	big := Shape{OCPUs: 4, MemoryGB: 24}
	for _, test := range []struct {
		action Action
		want   Action
		ok     bool
	}{
		{Action{Kind: KindScaleOut, Node: "gru-1-db-4"}, Action{Kind: KindScaleIn, Node: "gru-1-db-4", Reason: "undo"}, true},
		{Action{Kind: KindResize, From: small, To: big}, Action{Kind: KindResize, From: big, To: small, Reason: "undo"}, true},
		{Action{Kind: KindRebalance, Node: "a", Target: "b", Tenant: "t", Plan: PlanPro},
			Action{Kind: KindRebalance, Node: "b", Target: "a", Tenant: "t", Plan: PlanPro, Reason: "undo"}, true},
		{Action{Kind: KindScaleIn, Node: "gru-1-db-4"}, Action{}, false},
	} {
		got, ok := test.action.Undo()
		if ok != test.ok || got.Kind != test.want.Kind || got.Node != test.want.Node || got.Target != test.want.Target ||
			got.From != test.want.From || got.To != test.want.To {
			t.Fatalf("Undo(%+v) = %+v, %v", test.action, got, ok)
		}
	}
}

func TestPolicyValidate(t *testing.T) {
	if err := testPolicy().Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Policy){
		"min below replication": func(p *Policy) { p.Nodes.Min = 2 },
		"max below min":         func(p *Policy) { p.Nodes.Max = 2 },
		"floor over budget":     func(p *Policy) { p.MonthlyBudget = 50 },
		"no hysteresis band":    func(p *Policy) { p.ScaleDownBelow = 1 },
		"zero target":           func(p *Policy) { p.Targets.P95LatencyMS = 0 },
		"unbounded actions":     func(p *Policy) { p.MaxActionsPerHour = 0 },
		"no failure limit":      func(p *Policy) { p.MaxFailures = 0 },
		"inverted shape":        func(p *Policy) { p.Shape.MaxOCPUs = 1 },
	} {
		policy := testPolicy()
		mutate(&policy)
		if err := policy.Validate(); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}
