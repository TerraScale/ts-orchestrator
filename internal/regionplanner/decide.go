// Package regionplanner decides when the home region adds or removes a region.
// The global leader runs it every Interval from the load each region reports
// and the monthly budget. It approves its own proposals inside the guards
// below: one region action at a time, cooldowns, the budget and the region
// count. Its latest decision, holds included, is saved for the capacity page,
// and every change is journaled.
package regionplanner

import (
	"errors"
	"fmt"
	"maps"
	"math"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/nodescale"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionlifecycle"
)

const (
	// Interval is how often the planner decides.
	Interval = 10 * time.Minute
	// SaturatedFor is how long a region at its node ceiling must keep wanting
	// more before the planner asks for a new region.
	SaturatedFor = time.Hour
	// IdleSignal is the load below which every signal marks a region idle.
	IdleSignal = 0.15
	// ActionCooldown separates any two region actions.
	ActionCooldown = 24 * time.Hour
	// ReaddCooldown keeps a removed region out until it has been gone this long.
	ReaddCooldown = 30 * 24 * time.Hour
	// MinRegions is the fewest serving regions the planner leaves.
	MinRegions = 2
	// NodesPerNewRegion is the quorum a new region starts with. A region
	// idles at that size.
	NodesPerNewRegion = 3
)

// Decision actions.
const (
	ActionHold   = "hold"
	ActionAdd    = "add"
	ActionRemove = "remove"
)

const idleNodes = NodesPerNewRegion

// Region is one serving region as the planner sees it.
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
	// Record is nil for a region founded by hand.
	Record *regionlifecycle.Record
}

// Candidate is an OCI region that does not serve yet.
type Candidate struct{ Cell, OCIRegion string }

// Memory is what the planner keeps between decisions: how long each region
// has been saturated or idle, when it last acted and which regions it removed.
type Memory struct {
	SaturatedSince map[string]time.Time `json:"saturated_since,omitempty"`
	IdleSince      map[string]time.Time `json:"idle_since,omitempty"`
	LastAction     time.Time            `json:"last_action,omitzero"`
	Removed        map[string]time.Time `json:"removed,omitempty"`
}

// Decision is the planner's latest decision. Reason is always set.
type Decision struct {
	Action    string    `json:"action"` // "hold", "add" or "remove"
	Cell      string    `json:"cell,omitempty"`
	OCIRegion string    `json:"oci_region,omitempty"`
	Reason    string    `json:"reason"`
	At        time.Time `json:"at"`
}

// Budget is what an add is checked against: the headroom the capacity document
// leaves, the in-flight spend the admission also counts, and what one new
// region costs in the budget's currency.
type Budget struct {
	Fleet              regionlifecycle.Fleet
	HeadroomCents      uint64
	RegionMonthlyCents uint64
	Currency           string
}

// Decide applies the rules in order and returns the decision with the memory
// to keep.
func Decide(regions []Region, candidates []Candidate, records []regionlifecycle.Record, memory Memory,
	budget Budget, now time.Time,
) (Decision, Memory) {
	memory = memory.observe(regions, now)
	hold := func(reason string) (Decision, Memory) {
		return Decision{Action: ActionHold, Reason: reason, At: now}, memory
	}
	if open, ok := openRecord(records); ok {
		return hold(fmt.Sprintf("region %s is still %s: one region action at a time", open.Cell, open.Phase))
	}
	if !memory.LastAction.IsZero() && now.Sub(memory.LastAction) < ActionCooldown {
		return hold(fmt.Sprintf("the last region action was at %s: %v between region actions",
			memory.LastAction.UTC().Format(time.RFC3339), ActionCooldown))
	}

	reason := "every region is within its load band"
	if cells := oldest(memory.SaturatedSince); len(cells) > 0 {
		cell, saturated := cells[0], memory.SaturatedSince[cells[0]]
		if now.Sub(saturated) < SaturatedFor {
			reason = fmt.Sprintf("%s has wanted more nodes since %s; it asks for a region after %v",
				cell, saturated.UTC().Format(time.RFC3339), SaturatedFor)
		} else {
			origin := regionNamed(regions, cell)
			candidate, rtt, ok := nearest(origin, candidates, memory.Removed, now)
			away := fmt.Sprintf("%v away", rtt.Round(time.Millisecond))
			if !ok {
				// No round trip measured (egress may block the probe): the closest by distance.
				var km float64
				if candidate, km, ok = closest(origin, candidates, memory.Removed, now); ok {
					away = fmt.Sprintf("about %.0f km away (no round trip measured)", km)
				}
			}
			switch {
			case !ok:
				return hold(fmt.Sprintf("no candidate region has a measured round trip or a location near %s", cell))
			case budget.RegionMonthlyCents == 0:
				return hold("the node price is unknown")
			}
			if err := budget.Fleet.Admit(budget.HeadroomCents, budget.RegionMonthlyCents); err != nil {
				return hold(refusal(err, budget))
			}
			memory.LastAction = now
			return Decision{Action: ActionAdd, Cell: candidate.Cell, OCIRegion: candidate.OCIRegion, At: now,
				Reason: fmt.Sprintf("%s has wanted more nodes for %v; %s is %s, and %d nodes cost %s a month",
					cell, now.Sub(saturated).Round(time.Minute), candidate.Cell, away,
					NodesPerNewRegion, money(budget.RegionMonthlyCents, budget.Currency))}, memory
		}
	}

	for _, cell := range oldest(memory.IdleSince) {
		if now.Sub(memory.IdleSince[cell]) < regionlifecycle.MinIdle {
			break
		}
		region := regionNamed(regions, cell)
		if region.Home || region.HomesPartitions {
			continue
		}
		if len(regions) <= MinRegions {
			return hold(fmt.Sprintf("%s is idle, but only %d regions serve and never fewer than %d",
				cell, len(regions), MinRegions))
		}
		if region.Record == nil {
			return hold(fmt.Sprintf("%s was founded by hand and has no lifecycle record", cell))
		}
		if region.Record.Phase != regionlifecycle.Active {
			continue
		}
		memory.LastAction = now
		memory.Removed = withTime(memory.Removed, cell, now)
		return Decision{Action: ActionRemove, Cell: cell, OCIRegion: region.OCIRegion, At: now,
			Reason: fmt.Sprintf("%s has been idle at %d nodes since %s, every signal below %.2f, and it homes no partition",
				cell, idleNodes, memory.IdleSince[cell].UTC().Format(time.RFC3339), IdleSignal)}, memory
	}
	return hold(reason)
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

// openRecord returns the first region (by cell) with a lifecycle action in
// flight. An Active region is open but not in flight.
func openRecord(records []regionlifecycle.Record) (regionlifecycle.Record, bool) {
	var found regionlifecycle.Record
	ok := false
	for _, record := range records {
		if !record.Phase.Open() || record.Phase == regionlifecycle.Active {
			continue
		}
		if !ok || record.Cell < found.Cell {
			found, ok = record, true
		}
	}
	return found, ok
}

// nearest is the candidate with the lowest measured round trip from the
// region, skipping regions removed within ReaddCooldown. Ties go to the lower cell.
func nearest(from Region, candidates []Candidate, removed map[string]time.Time, now time.Time,
) (Candidate, time.Duration, bool) {
	var best Candidate
	var bestRTT time.Duration
	found := false
	for _, candidate := range candidates {
		if at, ok := removed[candidate.Cell]; ok && now.Sub(at) < ReaddCooldown {
			continue
		}
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
func closest(from Region, candidates []Candidate, removed map[string]time.Time, now time.Time,
) (Candidate, float64, bool) {
	origin, ok := catalog.Lookup(strings.ToUpper(from.Cell))
	if !ok {
		return Candidate{}, 0, false
	}
	var best Candidate
	var bestKM float64
	found := false
	for _, candidate := range candidates {
		if at, ok := removed[candidate.Cell]; ok && now.Sub(at) < ReaddCooldown {
			continue
		}
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

func withTime(clocks map[string]time.Time, cell string, now time.Time) map[string]time.Time {
	out := maps.Clone(clocks)
	if out == nil {
		out = map[string]time.Time{}
	}
	out[cell] = now
	return out
}

// refusal says why the region maximum or the budget refuses one more region.
func refusal(err error, budget Budget) string {
	if errors.Is(err, regionlifecycle.ErrRegionLimit) {
		return fmt.Sprintf("%d regions hold a slot, and the region maximum is %d",
			budget.Fleet.Regions, regionlifecycle.MaxRegions)
	}
	return fmt.Sprintf("the budget leaves %s with %s in flight; a new region costs %s",
		money(budget.HeadroomCents, budget.Currency), money(budget.Fleet.CommittedMonthlyCents, budget.Currency),
		money(budget.RegionMonthlyCents, budget.Currency))
}

// money formats cents in the budget's currency, for example BRL 123.45.
func money(cents uint64, currency string) string {
	return strings.TrimSpace(fmt.Sprintf("%s %d.%02d", currency, cents/100, cents%100))
}
