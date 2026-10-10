package regionplanner

import (
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/nodescale"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionlifecycle"
)

var testNow = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

const (
	// testPrice is three nodes at BRL 90.00 each.
	testPrice    = 27_000
	testHeadroom = 40_000
)

// testBudget decides under a BRL budget with the given headroom and region price.
func testBudget(headroom, price uint64) Budget {
	return Budget{HeadroomCents: headroom, RegionMonthlyCents: price, Currency: "BRL"}
}

func statusSaturated() *nodescale.Status {
	return &nodescale.Status{Nodes: 12, Saturated: true, NodeMonthlyCents: 9_000,
		Signals: map[nodescale.Signal]float64{nodescale.SignalCPU: 0.9}}
}

func statusBusy() *nodescale.Status {
	return &nodescale.Status{Nodes: 5, Signals: map[nodescale.Signal]float64{nodescale.SignalCPU: 0.6}}
}

func statusIdle() *nodescale.Status {
	return &nodescale.Status{Nodes: 3, Signals: map[nodescale.Signal]float64{nodescale.SignalCPU: 0.05,
		nodescale.SignalMemory: 0.1}}
}

func activeRecord(cell, ociRegion string) *regionlifecycle.Record {
	return &regionlifecycle.Record{Cell: cell, Phase: regionlifecycle.Active,
		Proposal: regionlifecycle.Proposal{Cell: cell, OCIRegion: ociRegion}}
}

// testRegions is a home at gru that measures two candidate OCI regions, and
// two serving regions, fra and sfo, with Active records.
func testRegions(gru, fra, sfo *nodescale.Status) []Region {
	return []Region{
		{Cell: "fra", OCIRegion: "eu-frankfurt-1", Status: fra, Record: activeRecord("fra", "eu-frankfurt-1")},
		{Cell: "gru", OCIRegion: "sa-saopaulo-1", Home: true, Status: gru, RTT: map[string]time.Duration{
			"uk-london-1": 150 * time.Millisecond, "eu-amsterdam-1": 120 * time.Millisecond}},
		{Cell: "sfo", OCIRegion: "us-sanjose-1", Status: sfo, Record: activeRecord("sfo", "us-sanjose-1")},
	}
}

var (
	lhrOnly    = []Candidate{{Cell: "lhr", OCIRegion: "uk-london-1"}}
	lhrAndAms  = []Candidate{{Cell: "lhr", OCIRegion: "uk-london-1"}, {Cell: "ams", OCIRegion: "eu-amsterdam-1"}}
	unmeasured = []Candidate{{Cell: "tyo", OCIRegion: "ap-tokyo-1"}}
)

func TestDecideRules(t *testing.T) {
	t.Parallel()

	saturatedLongEnough := Memory{SaturatedSince: map[string]time.Time{"gru": testNow.Add(-2 * time.Hour)}}
	idleLongEnough := Memory{IdleSince: map[string]time.Time{"sfo": testNow.Add(-regionlifecycle.MinIdle - time.Hour)}}
	noMeasurement := testRegions(statusSaturated(), statusBusy(), statusBusy())
	noMeasurement[1].RTT = nil
	cases := []struct {
		name       string
		regions    []Region
		candidates []Candidate
		records    []regionlifecycle.Record
		memory     Memory
		headroom   uint64
		price      uint64
		action     string
		cell       string // the decided cell
		reason     string // a substring of the written reason
	}{
		{name: "saturated region adds the nearest candidate", regions: testRegions(statusSaturated(), statusBusy(), statusBusy()),
			candidates: lhrAndAms, memory: saturatedLongEnough, headroom: testHeadroom, price: testPrice,
			action: ActionAdd, cell: "ams", reason: "gru has wanted more nodes for 2h0m0s; ams is 120ms away"},
		{name: "saturation needs an hour", regions: testRegions(statusSaturated(), statusBusy(), statusBusy()),
			candidates: lhrOnly, memory: Memory{SaturatedSince: map[string]time.Time{"gru": testNow.Add(-30 * time.Minute)}},
			headroom: testHeadroom, price: testPrice, action: ActionHold, reason: "wanted more nodes since"},
		{name: "a region at its ceiling is needed to add", regions: testRegions(statusBusy(), statusBusy(), statusBusy()),
			candidates: lhrOnly, memory: saturatedLongEnough, headroom: testHeadroom, price: testPrice,
			action: ActionHold, reason: "every region is within its load band"},
		{name: "unmeasured candidates hold", regions: noMeasurement, candidates: lhrOnly, memory: saturatedLongEnough,
			headroom: testHeadroom, price: testPrice, action: ActionHold,
			reason: "no candidate region has a measured round trip from gru"},
		{name: "a candidate nobody measured is ignored", regions: testRegions(statusSaturated(), statusBusy(), statusBusy()),
			candidates: unmeasured, memory: saturatedLongEnough, headroom: testHeadroom, price: testPrice,
			action: ActionHold, reason: "no candidate region has a measured round trip from gru"},
		{name: "unknown node price holds", regions: testRegions(statusSaturated(), statusBusy(), statusBusy()),
			candidates: lhrOnly, memory: saturatedLongEnough, headroom: testHeadroom, price: 0,
			action: ActionHold, reason: "the node price is unknown"},
		{name: "budget without headroom holds", regions: testRegions(statusSaturated(), statusBusy(), statusBusy()),
			candidates: lhrOnly, memory: saturatedLongEnough, headroom: 10_000, price: testPrice,
			action: ActionHold, reason: "the budget leaves BRL 100.00 with BRL 0.00 in flight; a new region costs BRL 270.00"},
		{name: "recent action holds", regions: testRegions(statusSaturated(), statusBusy(), statusBusy()),
			candidates: lhrOnly, headroom: testHeadroom, price: testPrice,
			memory: Memory{SaturatedSince: saturatedLongEnough.SaturatedSince, LastAction: testNow.Add(-time.Hour)},
			action: ActionHold, reason: "the last region action was at"},
		{name: "open record holds", regions: testRegions(statusSaturated(), statusBusy(), statusBusy()),
			candidates: lhrOnly, memory: saturatedLongEnough, headroom: testHeadroom, price: testPrice,
			records: []regionlifecycle.Record{{Cell: "lhr", Phase: regionlifecycle.Approved}},
			action:  ActionHold, reason: "region lhr is still approved: one region action at a time"},
		{name: "re-add cooldown keeps a removed region out", regions: testRegions(statusSaturated(), statusBusy(), statusBusy()),
			candidates: lhrOnly, headroom: testHeadroom, price: testPrice,
			memory: Memory{SaturatedSince: saturatedLongEnough.SaturatedSince,
				Removed: map[string]time.Time{"lhr": testNow.Add(-10 * 24 * time.Hour)}},
			action: ActionHold, reason: "no candidate region has a measured round trip from gru"},
		{name: "re-add cooldown passes", regions: testRegions(statusSaturated(), statusBusy(), statusBusy()),
			candidates: lhrOnly, headroom: testHeadroom, price: testPrice,
			memory: Memory{SaturatedSince: saturatedLongEnough.SaturatedSince,
				Removed: map[string]time.Time{"lhr": testNow.Add(-31 * 24 * time.Hour)}},
			action: ActionAdd, cell: "lhr"},
		{name: "idle region is removed", regions: testRegions(statusBusy(), statusBusy(), statusIdle()),
			memory: idleLongEnough, action: ActionRemove, cell: "sfo", reason: "sfo has been idle at 3 nodes"},
		{name: "never removes below two serving regions", regions: testRegions(statusBusy(), nil, statusIdle())[1:],
			memory: idleLongEnough, action: ActionHold, reason: "only 2 regions serve and never fewer than 2"},
		{name: "idle needs MinIdle", regions: testRegions(statusBusy(), statusBusy(), statusIdle()),
			memory: Memory{IdleSince: map[string]time.Time{"sfo": testNow.Add(-regionlifecycle.MinIdle + time.Hour)}},
			action: ActionHold, reason: "every region is within its load band"},
		{name: "never removes the home", regions: testRegions(statusIdle(), statusBusy(), statusBusy()),
			memory: Memory{IdleSince: map[string]time.Time{"gru": testNow.Add(-regionlifecycle.MinIdle - time.Hour)}},
			action: ActionHold, reason: "every region is within its load band"},
		{name: "a region founded by hand is never removed", regions: func() []Region {
			regions := testRegions(statusBusy(), statusBusy(), statusIdle())
			regions[2].Record = nil
			return regions
		}(), memory: idleLongEnough, action: ActionHold, reason: "sfo was founded by hand and has no lifecycle record"},
		{name: "a region homing a partition is never removed", regions: func() []Region {
			regions := testRegions(statusBusy(), statusBusy(), statusIdle())
			regions[2].HomesPartitions = true
			return regions
		}(), memory: idleLongEnough, action: ActionHold, reason: "every region is within its load band"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			decision, memory := Decide(tt.regions, tt.candidates, tt.records, tt.memory, testBudget(tt.headroom, tt.price), testNow)
			if decision.Action != tt.action || decision.Cell != tt.cell && tt.cell != "" {
				t.Fatalf("decision = %+v, want action %s for %q", decision, tt.action, tt.cell)
			}
			if !strings.Contains(decision.Reason, tt.reason) {
				t.Fatalf("reason = %q, want it to contain %q", decision.Reason, tt.reason)
			}
			if decision.Reason == "" || !decision.At.Equal(testNow) {
				t.Fatalf("decision %+v has no reason or time", decision)
			}
			if decision.Action == ActionAdd && (decision.OCIRegion == "" || memory.LastAction != testNow) {
				t.Fatalf("add %+v did not start the action clock: %+v", decision, memory)
			}
		})
	}
}

func TestAddIsRefusedByTheBudgetAndTheRegionMaximum(t *testing.T) {
	t.Parallel()

	saturatedLongEnough := Memory{SaturatedSince: map[string]time.Time{"gru": testNow.Add(-SaturatedFor - time.Hour)}}
	regions := testRegions(statusSaturated(), statusBusy(), statusBusy())
	cases := []struct {
		name   string
		budget Budget
		reason string
	}{
		{name: "in-flight spend counts against the headroom",
			budget: Budget{Fleet: regionlifecycle.Fleet{Regions: 3, CommittedMonthlyCents: 15_000},
				HeadroomCents: testHeadroom, RegionMonthlyCents: testPrice, Currency: "BRL"},
			reason: "the budget leaves BRL 400.00 with BRL 150.00 in flight"},
		{name: "the region maximum refuses the add",
			budget: Budget{Fleet: regionlifecycle.Fleet{Regions: regionlifecycle.MaxRegions},
				HeadroomCents: testHeadroom, RegionMonthlyCents: testPrice, Currency: "BRL"},
			reason: "the region maximum is 32"},
	}
	for _, tt := range cases {
		decision, _ := Decide(regions, lhrOnly, nil, saturatedLongEnough, tt.budget, testNow)
		if decision.Action != ActionHold || !strings.Contains(decision.Reason, tt.reason) {
			t.Fatalf("%s: decision = %+v, want a hold that says %q", tt.name, decision, tt.reason)
		}
	}
}

func TestSaturationNeedsAnHourAndForgetsWhenItEnds(t *testing.T) {
	t.Parallel()

	saturated := testRegions(statusSaturated(), statusBusy(), statusBusy())
	decision, memory := Decide(saturated, lhrOnly, nil, Memory{}, testBudget(testHeadroom, testPrice), testNow)
	if decision.Action != ActionHold || !memory.SaturatedSince["gru"].Equal(testNow) {
		t.Fatalf("first saturated round = %+v, %+v", decision, memory)
	}
	decision, memory = Decide(saturated, lhrOnly, nil, memory, testBudget(testHeadroom, testPrice), testNow.Add(SaturatedFor))
	if decision.Action != ActionAdd || decision.Cell != "lhr" {
		t.Fatalf("saturated for an hour = %+v", decision)
	}
	calm := testRegions(statusBusy(), statusBusy(), statusBusy())
	_, memory = Decide(calm, lhrOnly, nil, memory, testBudget(testHeadroom, testPrice), testNow.Add(SaturatedFor+ActionCooldown))
	if _, ok := memory.SaturatedSince["gru"]; ok {
		t.Fatalf("a region that stopped wanting nodes kept its clock: %+v", memory)
	}
}

func TestIdleNeedsMinIdleThenRemovesTheRegion(t *testing.T) {
	t.Parallel()

	regions := testRegions(statusBusy(), statusBusy(), statusIdle())
	decision, memory := Decide(regions, nil, nil, Memory{}, testBudget(0, 0), testNow)
	if decision.Action != ActionHold {
		t.Fatalf("first idle round = %+v", decision)
	}
	decision, memory = Decide(regions, nil, nil, memory, testBudget(0, 0), testNow.Add(regionlifecycle.MinIdle-time.Minute))
	if decision.Action != ActionHold {
		t.Fatalf("idle one minute short of MinIdle = %+v", decision)
	}
	later := testNow.Add(regionlifecycle.MinIdle)
	decision, memory = Decide(regions, nil, nil, memory, testBudget(0, 0), later)
	if decision.Action != ActionRemove || decision.Cell != "sfo" || decision.OCIRegion != "us-sanjose-1" {
		t.Fatalf("idle for MinIdle = %+v", decision)
	}
	if !memory.LastAction.Equal(later) || !memory.Removed["sfo"].Equal(later) {
		t.Fatalf("removal did not set its clocks: %+v", memory)
	}
}

func TestUnknownStatusForgetsTheIdleClock(t *testing.T) {
	t.Parallel()

	regions := testRegions(statusBusy(), statusBusy(), nil)
	_, memory := Decide(regions, nil, nil, Memory{IdleSince: map[string]time.Time{"sfo": testNow.Add(-time.Hour)}},
		testBudget(0, 0), testNow)
	if _, ok := memory.IdleSince["sfo"]; ok {
		t.Fatalf("an unknown status kept the idle clock: %+v", memory)
	}
}

func TestNearestPicksTheLowestRoundTrip(t *testing.T) {
	t.Parallel()

	from := Region{RTT: map[string]time.Duration{"uk-london-1": 150 * time.Millisecond, "eu-amsterdam-1": 120 * time.Millisecond}}
	candidate, rtt, ok := nearest(from, lhrAndAms, nil, testNow)
	if !ok || candidate.Cell != "ams" || rtt != 120*time.Millisecond {
		t.Fatalf("nearest = %+v %v %v", candidate, rtt, ok)
	}
	if _, _, ok := nearest(Region{}, lhrAndAms, nil, testNow); ok {
		t.Fatal("a region with no measurements picked a candidate")
	}
}
