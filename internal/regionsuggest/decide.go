// Package regionsuggest suggests when the home region should add or remove a
// region. The global leader computes a suggestion every Interval from the load
// each region reports and the monthly budget. Nothing acts on it and nothing
// journals it: regions change only when the user runs ts-orch region create or
// remove. The latest suggestion is saved for the capacity page.
package regionsuggest

import (
	"fmt"
	"maps"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/nodescale"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

const (
	// Interval is how often the suggester runs.
	Interval = 10 * time.Minute
	// SaturatedFor is how long a region at its node ceiling must keep wanting
	// more before the suggester suggests a new region.
	SaturatedFor = time.Hour
	// IdleSignal is the load below which every signal marks a region idle.
	IdleSignal = 0.15
	// IdleFor is how long a region must stay idle before a removal is suggested.
	IdleFor = 14 * 24 * time.Hour
	// MinRegions is the fewest serving regions the suggester leaves.
	MinRegions = 2
	// NodesPerNewRegion is the quorum a new region starts with. A region
	// idles at that size.
	NodesPerNewRegion = 3
)

// Suggestion actions.
const (
	ActionNone   = "none"
	ActionAdd    = "add"
	ActionRemove = "remove"
)

const idleNodes = NodesPerNewRegion

// Region is one serving region as the suggester sees it.
type Region struct {
	Cell      string
	OCIRegion string
	Home      bool
	// Status is nil when the region's status is unknown.
	Status *nodescale.Status
	// RTT is the measured round trip to OCI regions, by OCI region name.
	RTT map[string]time.Duration
	// HomesPartitions reports that the TerraBase directory homes a partition here.
	HomesPartitions bool
}

// Candidate is an OCI region that does not serve yet.
type Candidate struct{ Cell, OCIRegion string }

// Memory is what the suggester keeps between rounds: how long each region has
// been saturated or idle.
type Memory struct {
	SaturatedSince map[string]time.Time `json:"saturated_since,omitempty"`
	IdleSince      map[string]time.Time `json:"idle_since,omitempty"`
}

// Suggestion is the suggester's latest suggestion. Reason is always set.
type Suggestion struct {
	Action    string    `json:"action"` // "none", "add" or "remove"
	Cell      string    `json:"cell,omitempty"`
	OCIRegion string    `json:"oci_region,omitempty"`
	Reason    string    `json:"reason"`
	At        time.Time `json:"at"`
	// MonthlyCents and Currency price an add: NodesPerNewRegion nodes a month.
	MonthlyCents uint64 `json:"monthly_cents,omitempty"`
	Currency     string `json:"currency,omitempty"`
}

// Budget is what an add is priced against: the headroom the capacity document
// leaves and what one new region costs in the budget's currency. The budget
// informs the reason; it never turns an add into none.
type Budget struct {
	HeadroomCents      uint64
	RegionMonthlyCents uint64
	Currency           string
}

// Suggest applies the rules in order and returns the suggestion with the memory
// to keep.
func Suggest(regions []Region, candidates []Candidate, memory Memory, budget Budget, now time.Time,
) (Suggestion, Memory) {
	memory = memory.observe(regions, now)
	none := func(reason string) (Suggestion, Memory) {
		return Suggestion{Action: ActionNone, Reason: reason, At: now}, memory
	}

	reason := "every region is within its load band"
	if cells := oldest(memory.SaturatedSince); len(cells) > 0 {
		cell, saturated := cells[0], memory.SaturatedSince[cells[0]]
		if now.Sub(saturated) < SaturatedFor {
			reason = fmt.Sprintf("%s has wanted more nodes since %s; it asks for a region after %v",
				cell, saturated.UTC().Format(time.RFC3339), SaturatedFor)
		} else {
			origin := regionNamed(regions, cell)
			candidate, rtt, ok := nearest(origin, candidates)
			away := fmt.Sprintf("%v away", rtt.Round(time.Millisecond))
			if !ok {
				// No round trip measured (egress may block the probe): the closest by distance.
				var km float64
				if candidate, km, ok = closest(origin, candidates); ok {
					away = fmt.Sprintf("about %.0f km away (no round trip measured)", km)
				}
			}
			switch {
			case !ok:
				return none(fmt.Sprintf("no candidate region has a measured round trip or a location near %s", cell))
			case budget.RegionMonthlyCents == 0:
				return none("the node price is unknown")
			}
			return Suggestion{Action: ActionAdd, Cell: candidate.Cell, OCIRegion: candidate.OCIRegion, At: now,
				MonthlyCents: budget.RegionMonthlyCents, Currency: budget.Currency,
				Reason: fmt.Sprintf("%s has wanted more nodes for %v; %s is %s, and %d nodes cost %s a month; %s",
					cell, now.Sub(saturated).Round(time.Minute), candidate.Cell, away,
					NodesPerNewRegion, money(budget.RegionMonthlyCents, budget.Currency), headroom(budget))}, memory
		}
	}

	for _, cell := range oldest(memory.IdleSince) {
		if now.Sub(memory.IdleSince[cell]) < IdleFor {
			break
		}
		region := regionNamed(regions, cell)
		if region.Home || region.HomesPartitions {
			continue
		}
		if len(regions) <= MinRegions {
			return none(fmt.Sprintf("%s is idle, but only %d regions serve and never fewer than %d",
				cell, len(regions), MinRegions))
		}
		return Suggestion{Action: ActionRemove, Cell: cell, OCIRegion: region.OCIRegion, At: now,
			Reason: fmt.Sprintf("%s has been idle at %d nodes since %s, every signal below %.2f, and it homes no partition",
				cell, idleNodes, memory.IdleSince[cell].UTC().Format(time.RFC3339), IdleSignal)}, memory
	}
	return none(reason)
}

// observe restarts the saturation and idle clocks from this round's statuses.
// A region whose status is unknown, or no longer matches, loses its clocks.
func (memory Memory) observe(regions []Region, now time.Time) Memory {
	saturated := map[string]time.Time{}
	idle := map[string]time.Time{}
	for _, region := range regions {
		if region.Status == nil {
			continue
		}
		if region.Status.Saturated {
			saturated[region.Cell] = since(memory.SaturatedSince, region.Cell, now)
		}
		if idleStatus(*region.Status) {
			idle[region.Cell] = since(memory.IdleSince, region.Cell, now)
		}
	}
	memory.SaturatedSince, memory.IdleSince = saturated, idle
	return memory
}

// since keeps a running clock and starts a new one at now.
func since(clocks map[string]time.Time, cell string, now time.Time) time.Time {
	if at, ok := clocks[cell]; ok {
		return at
	}
	return now
}

// idleStatus reports a region at its starting size whose every signal is below IdleSignal.
func idleStatus(status nodescale.Status) bool {
	if status.Nodes != idleNodes || len(status.Signals) == 0 {
		return false
	}
	for _, value := range status.Signals {
		if value >= IdleSignal {
			return false
		}
	}
	return true
}

// nearest is the candidate with the lowest measured round trip from the
// region. Ties go to the lower cell.
func nearest(from Region, candidates []Candidate) (Candidate, time.Duration, bool) {
	var best Candidate
	var bestRTT time.Duration
	found := false
	for _, candidate := range candidates {
		rtt, ok := from.RTT[candidate.OCIRegion]
		if !ok {
			continue
		}
		if !found || rtt < bestRTT || rtt == bestRTT && candidate.Cell < best.Cell {
			best, bestRTT, found = candidate, rtt, true
		}
	}
	return best, bestRTT, found
}

// closest is the candidate nearest to from by great-circle distance between
// the catalog's region coordinates, in km.
func closest(from Region, candidates []Candidate) (Candidate, float64, bool) {
	origin, ok := catalog.Lookup(strings.ToUpper(from.Cell))
	if !ok {
		return Candidate{}, 0, false
	}
	var best Candidate
	var bestKM float64
	found := false
	for _, candidate := range candidates {
		entry, ok := catalog.Lookup(strings.ToUpper(candidate.Cell))
		if !ok {
			continue
		}
		km := greatCircleKM(origin.Latitude, origin.Longitude, entry.Latitude, entry.Longitude)
		if !found || km < bestKM || km == bestKM && candidate.Cell < best.Cell {
			best, bestKM, found = candidate, km, true
		}
	}
	return best, bestKM, found
}

// greatCircleKM is the haversine distance between two points on Earth.
func greatCircleKM(lat1, lon1, lat2, lon2 float64) float64 {
	const earthKM = 6371
	rad := math.Pi / 180
	dLat, dLon := (lat2-lat1)*rad, (lon2-lon1)*rad
	h := math.Sin(dLat/2)*math.Sin(dLat/2) + math.Cos(lat1*rad)*math.Cos(lat2*rad)*math.Sin(dLon/2)*math.Sin(dLon/2)
	return 2 * earthKM * math.Asin(math.Sqrt(h))
}

// oldest returns the cells whose clocks started first, ties by cell.
func oldest(clocks map[string]time.Time) []string {
	cells := slices.Collect(maps.Keys(clocks))
	slices.SortFunc(cells, func(a, b string) int {
		if order := clocks[a].Compare(clocks[b]); order != 0 {
			return order
		}
		return strings.Compare(a, b)
	})
	return cells
}

func regionNamed(regions []Region, cell string) Region {
	index := slices.IndexFunc(regions, func(region Region) bool { return region.Cell == cell })
	if index < 0 {
		return Region{}
	}
	return regions[index]
}

// headroom says whether one new region fits the budget's headroom.
func headroom(budget Budget) string {
	if budget.RegionMonthlyCents <= budget.HeadroomCents {
		return fmt.Sprintf("the budget has %s headroom", money(budget.HeadroomCents, budget.Currency))
	}
	return fmt.Sprintf("that exceeds the budget's headroom of %s", money(budget.HeadroomCents, budget.Currency))
}

// money formats cents in the budget's currency, for example BRL 123.45.
func money(cents uint64, currency string) string {
	return strings.TrimSpace(fmt.Sprintf("%s %d.%02d", currency, cents/100, cents%100))
}
