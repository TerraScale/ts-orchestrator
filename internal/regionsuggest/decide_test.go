package regionsuggest

import (
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/nodescale"
)

var testNow = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

const (
	// testPrice is three nodes at BRL 90.00 each.
	testPrice    = 27_000
	testHeadroom = 40_000
)

// testBudget suggests under a BRL budget with the given headroom and region price.
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

// testRegions is a home at gru that measures two candidate OCI regions, and
// two serving regions, fra and sfo.
func testRegions(gru, fra, sfo *nodescale.Status) []Region {
	return []Region{
		{Cell: "fra", OCIRegion: "eu-frankfurt-1", Status: fra},
		{Cell: "gru", OCIRegion: "sa-saopaulo-1", Home: true, Status: gru, RTT: map[string]time.Duration{
			"uk-london-1": 150 * time.Millisecond, "eu-amsterdam-1": 120 * time.Millisecond}},
		{Cell: "sfo", OCIRegion: "us-sanjose-1", Status: sfo},
	}
}

var (
	lhrOnly    = []Candidate{{Cell: "lhr", OCIRegion: "uk-london-1"}}
	lhrAndAms  = []Candidate{{Cell: "lhr", OCIRegion: "uk-london-1"}, {Cell: "ams", OCIRegion: "eu-amsterdam-1"}}
	unmeasured = []Candidate{{Cell: "tyo", OCIRegion: "ap-tokyo-1"}}
)

func TestSuggestRules(t *testing.T) {
	t.Parallel()

	saturatedLongEnough := Memory{SaturatedSince: map[string]time.Time{"gru": testNow.Add(-2 * time.Hour)}}
	idleLongEnough := Memory{IdleSince: map[string]time.Time{"sfo": testNow.Add(-IdleFor - time.Hour)}}
	noMeasurement := testRegions(statusSaturated(), statusBusy(), statusBusy())
	noMeasurement[1].RTT = nil
	cases := []struct {
		name       string
		regions    []Region
		candidates []Candidate
		memory     Memory
		headroom   uint64
		price      uint64
		action     string
		cell       string // the suggested cell
		reason     string // a substring of the written reason
	}{
		{name: "saturated region suggests the nearest candidate", regions: testRegions(statusSaturated(), statusBusy(), statusBusy()),
			candidates: lhrAndAms, memory: saturatedLongEnough, headroom: testHeadroom, price: testPrice,
			action: ActionAdd, cell: "ams", reason: "gru has wanted more nodes for 2h0m0s; ams is 120ms away, and 3 nodes cost BRL 270.00 a month; the budget has BRL 400.00 headroom"},
		{name: "saturation needs an hour", regions: testRegions(statusSaturated(), statusBusy(), statusBusy()),
			candidates: lhrOnly, memory: Memory{SaturatedSince: map[string]time.Time{"gru": testNow.Add(-30 * time.Minute)}},
			headroom: testHeadroom, price: testPrice, action: ActionNone, reason: "wanted more nodes since"},
		{name: "a region at its ceiling is needed to add", regions: testRegions(statusBusy(), statusBusy(), statusBusy()),
			candidates: lhrOnly, memory: saturatedLongEnough, headroom: testHeadroom, price: testPrice,
			action: ActionNone, reason: "every region is within its load band"},
		{name: "unmeasured candidates fall back to distance", regions: noMeasurement, candidates: lhrOnly,
			memory: saturatedLongEnough, headroom: testHeadroom, price: testPrice, action: ActionAdd, cell: "lhr",
			reason: "km away (no round trip measured)"},
		{name: "a candidate neither measured nor located holds", regions: testRegions(statusSaturated(), statusBusy(), statusBusy()),
			candidates: unmeasured, memory: saturatedLongEnough, headroom: testHeadroom, price: testPrice,
			action: ActionNone, reason: "no candidate region has a measured round trip or a location near gru"},
		{name: "unknown node price gives none", regions: testRegions(statusSaturated(), statusBusy(), statusBusy()),
			candidates: lhrOnly, memory: saturatedLongEnough, headroom: testHeadroom, price: 0,
			action: ActionNone, reason: "the node price is unknown"},
		{name: "idle region is suggested for removal", regions: testRegions(statusBusy(), statusBusy(), statusIdle()),
			memory: idleLongEnough, action: ActionRemove, cell: "sfo", reason: "sfo has been idle at 3 nodes"},
		{name: "never suggests removing below two serving regions", regions: testRegions(statusBusy(), nil, statusIdle())[1:],
			memory: idleLongEnough, action: ActionNone, reason: "only 2 regions serve and never fewer than 2"},
		{name: "idle needs IdleFor", regions: testRegions(statusBusy(), statusBusy(), statusIdle()),
			memory: Memory{IdleSince: map[string]time.Time{"sfo": testNow.Add(-IdleFor + time.Hour)}},
			action: ActionNone, reason: "every region is within its load band"},
		{name: "never suggests removing the home", regions: testRegions(statusIdle(), statusBusy(), statusBusy()),
			memory: Memory{IdleSince: map[string]time.Time{"gru": testNow.Add(-IdleFor - time.Hour)}},
			action: ActionNone, reason: "every region is within its load band"},
		{name: "a region homing a partition is never suggested for removal", regions: func() []Region {
			regions := testRegions(statusBusy(), statusBusy(), statusIdle())
			regions[2].HomesPartitions = true
			return regions
		}(), memory: idleLongEnough, action: ActionNone, reason: "every region is within its load band"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			suggestion, _ := Suggest(tt.regions, tt.candidates, tt.memory, testBudget(tt.headroom, tt.price), testNow)
			if suggestion.Action != tt.action || suggestion.Cell != tt.cell && tt.cell != "" {
				t.Fatalf("suggestion = %+v, want action %s for %q", suggestion, tt.action, tt.cell)
			}
			if !strings.Contains(suggestion.Reason, tt.reason) {
				t.Fatalf("reason = %q, want it to contain %q", suggestion.Reason, tt.reason)
			}
			if suggestion.Reason == "" || !suggestion.At.Equal(testNow) {
				t.Fatalf("suggestion %+v has no reason or time", suggestion)
			}
			if suggestion.Action == ActionAdd && suggestion.OCIRegion == "" {
				t.Fatalf("add %+v names no OCI region", suggestion)
			}
		})
	}
}

func TestAddOverBudgetStillSuggestsAdd(t *testing.T) {
	t.Parallel()

	saturatedLongEnough := Memory{SaturatedSince: map[string]time.Time{"gru": testNow.Add(-SaturatedFor - time.Hour)}}
	regions := testRegions(statusSaturated(), statusBusy(), statusBusy())
	suggestion, _ := Suggest(regions, lhrOnly, saturatedLongEnough, testBudget(10_000, testPrice), testNow)
	if suggestion.Action != ActionAdd || suggestion.Cell != "lhr" || suggestion.MonthlyCents != testPrice ||
		!strings.Contains(suggestion.Reason, "that exceeds the budget's headroom of BRL 100.00") {
		t.Fatalf("over-budget suggestion = %+v", suggestion)
	}
}




func TestNearestPicksTheLowestRoundTrip(t *testing.T) {
	t.Parallel()

	from := Region{RTT: map[string]time.Duration{"uk-london-1": 150 * time.Millisecond, "eu-amsterdam-1": 120 * time.Millisecond}}
	candidate, rtt, ok := nearest(from, lhrAndAms)
	if !ok || candidate.Cell != "ams" || rtt != 120*time.Millisecond {
		t.Fatalf("nearest = %+v %v %v", candidate, rtt, ok)
	}
	if _, _, ok := nearest(Region{}, lhrAndAms); ok {
		t.Fatal("a region with no measurements picked a candidate")
	}
}

func TestGreatCircleDistance(t *testing.T) {
	// São Paulo to London is about 9,480 km.
	if km := greatCircleKM(-23.43, -46.47, 51.51, -0.13); km < 9300 || km > 9700 {
		t.Fatalf("GRU to LHR = %.0f km", km)
	}
	if km := greatCircleKM(1, 2, 1, 2); km != 0 {
		t.Fatalf("a point to itself = %.0f km", km)
	}
}
