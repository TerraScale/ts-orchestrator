package regionsuggest

import (
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
// two serving regions, fra and sjc.
func testRegions(gru, fra, sjc *nodescale.Status) []Region {
	return []Region{
		{Cell: "fra", OCIRegion: "eu-frankfurt-1", Status: fra},
		{Cell: "gru", OCIRegion: "sa-saopaulo-1", Home: true, Status: gru, RTT: map[string]time.Duration{
			"uk-london-1": 150 * time.Millisecond, "eu-amsterdam-1": 120 * time.Millisecond}},
		{Cell: "sjc", OCIRegion: "us-sanjose-1", Status: sjc},
	}
}

var (
	lhrOnly    = []Candidate{{Cell: "lhr", OCIRegion: "uk-london-1"}}
	lhrAndAms  = []Candidate{{Cell: "lhr", OCIRegion: "uk-london-1"}, {Cell: "ams", OCIRegion: "eu-amsterdam-1"}}
	unmeasured = []Candidate{{Cell: "tyo", OCIRegion: "ap-tokyo-1"}}
)
