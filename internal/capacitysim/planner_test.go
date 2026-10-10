package capacitysim

import (
	"maps"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/nodescale"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionlifecycle"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionplanner"
)

const (
	plannerDays    = 40
	candidateCount = 10
	idleFrom       = 15 // cells idleFrom to idleFrom+idleCount-1 sit at the starting size for the whole run
	idleCount      = 4
	landingDelay   = 2 * time.Hour // how long an add or a remove takes to land in the lifecycle
	planHeadroom   = 100 * 3 * nodeMonthlyCents
)

// TestRegionPlannerGuardrailsOverTwentyDays steps the region planner alone for 40 simulated days over 20 serving
// regions and 10 candidates, with the lifecycle in memory, and asserts its guardrails at every decision.
func TestRegionPlannerGuardrailsOverTwentyDays(t *testing.T) {
	entries := catalog.Entries()
	used := regionCount + candidateCount
	if len(entries) < used || entries[0].Name() != homeCell {
		t.Fatalf("catalog has %d regions, first %q: need %d regions with %s first", len(entries), entries[0].Name(),
			used, homeCell)
	}
	home := regionlifecycle.Home{Cell: homeCell}
	end := simStart.Add(plannerDays * 24 * time.Hour)
	cells := make(map[string]*planCell, used)
	for index, entry := range entries[:used] {
		rng := rand.New(rand.NewPCG(seed, uint64(index)+1))
		c := &planCell{cell: entry.Name(), rng: rng, rtt: map[string]time.Duration{},
			idle: index >= idleFrom && index < idleFrom+idleCount}
		if !c.idle {
			c.bursts = burstsFor(rng, simStart, end)
		}
		for _, other := range entries[:used] {
			c.rtt[other.OCIRegion] = time.Duration(20+rng.IntN(280)) * time.Millisecond
		}
		cells[c.cell] = c
	}

	records := map[string]regionlifecycle.Record{}
	for _, entry := range entries[1:regionCount] {
		records[entry.Name()] = activeRecord(entry)
	}
	pending := map[string]transition{}
	removedAt := map[string]time.Time{}
	var memory regionplanner.Memory
	var lastAction time.Time
	var adds, removes int
	minServing, peakServing := regionCount+1, 0

	for now := simStart; now.Before(end); now = now.Add(regionplanner.Interval) {
		for cell, tr := range pending {
			if !now.Before(tr.due) {
				rec := records[cell]
				rec.Phase = tr.to
				records[cell] = rec
				delete(pending, cell)
			}
		}
		list := ledgerOf(records)
		regions := []regionplanner.Region{regionFor(cells[homeCell], entries[0].OCIRegion, now, nil, true)}
		for _, rec := range list {
			if rec.Phase == regionlifecycle.Active || rec.Phase == regionlifecycle.RetireApproved {
				regions = append(regions, regionFor(cells[rec.Cell], rec.Proposal.OCIRegion, now, &rec, false))
			}
		}
		var candidates []regionplanner.Candidate
		for _, entry := range entries[regionCount:used] {
			if rec, ok := records[entry.Name()]; ok && rec.Phase.Open() {
				continue
			}
			candidates = append(candidates, regionplanner.Candidate{Cell: entry.Name(), OCIRegion: entry.OCIRegion})
		}
		guard := regionplanner.Budget{Fleet: regionlifecycle.FleetOf(list, "", home), HeadroomCents: planHeadroom,
			RegionMonthlyCents: 3 * nodeMonthlyCents, Currency: "BRL"}
		decision, next := regionplanner.Decide(regions, candidates, list, memory, guard, now)
		memory = next

		if decision.Action != regionplanner.ActionHold {
			if !lastAction.IsZero() && now.Sub(lastAction) < regionplanner.ActionCooldown {
				t.Fatalf("%s %s at %s, %s after the last region action, inside the %s cooldown", decision.Action,
					decision.Cell, now.Format(time.RFC3339), now.Sub(lastAction), regionplanner.ActionCooldown)
			}
			lastAction = now
		}
		switch decision.Action {
		case regionplanner.ActionAdd:
			if at, ok := removedAt[decision.Cell]; ok && now.Sub(at) < regionplanner.ReaddCooldown {
				t.Fatalf("re-added %s at %s, %s after its removal, inside the %s re-add cooldown", decision.Cell,
					now.Format(time.RFC3339), now.Sub(at), regionplanner.ReaddCooldown)
			}
			prior := records[decision.Cell]
			records[decision.Cell] = regionlifecycle.Record{Cell: decision.Cell, Generation: prior.Generation + 1,
				Phase: regionlifecycle.Admitted, Proposal: regionlifecycle.Proposal{Cell: decision.Cell,
					OCIRegion: decision.OCIRegion, EstimatedMonthlyCents: 3 * nodeMonthlyCents}}
			pending[decision.Cell] = transition{due: now.Add(landingDelay), to: regionlifecycle.Active}
			adds++
		case regionplanner.ActionRemove:
			if decision.Cell == homeCell {
				t.Fatalf("planner removed the home %s at %s", homeCell, now.Format(time.RFC3339))
			}
			rec := records[decision.Cell]
			rec.Phase = regionlifecycle.RetireApproved
			records[decision.Cell] = rec
			pending[decision.Cell] = transition{due: now.Add(landingDelay), to: regionlifecycle.Retired}
			removedAt[decision.Cell] = now
			removes++
		}

		serving, open := 1, 0 // the home always serves
		for _, rec := range records {
			if rec.Phase == regionlifecycle.Active || rec.Phase == regionlifecycle.RetireApproved {
				serving++
			}
			if rec.Phase.Open() && rec.Phase != regionlifecycle.Active {
				open++
			}
		}
		if open > 1 {
			t.Fatalf("%d region actions open at %s, want at most one", open, now.Format(time.RFC3339))
		}
		if serving < regionplanner.MinRegions {
			t.Fatalf("%d regions serve at %s, want at least %d", serving, now.Format(time.RFC3339), regionplanner.MinRegions)
		}
		minServing, peakServing = min(minServing, serving), max(peakServing, serving)
	}
	if adds == 0 || removes == 0 {
		t.Fatalf("run missed a case: %d adds, %d removes over %d days", adds, removes, plannerDays)
	}
	t.Logf("%d days of %s decisions: %d adds, %d removes, serving between %d and %d regions",
		plannerDays, regionplanner.Interval, adds, removes, minServing, peakServing)
}

// planCell is one catalog cell's synthetic status: idle at the starting size, or busy with saturated bursts.
type planCell struct {
	cell   string
	idle   bool
	bursts []window
	rtt    map[string]time.Duration // round trip from this cell to each OCI region
	rng    *rand.Rand
}

// window is the span [from, until).
type window struct{ from, until time.Time }

// transition is a lifecycle phase change that lands at due.
type transition struct {
	due time.Time
	to  regionlifecycle.Phase
}

// status is the cell's synthetic scaling status at now.
func (c *planCell) status(now time.Time) nodescale.Status {
	st := nodescale.Status{Schema: nodescale.StatusSchema, Cell: c.cell, At: now, Nodes: 5, Currency: "BRL",
		NodeMonthlyCents: nodeMonthlyCents, Reason: "synthetic status"}
	level := 0.5
	switch {
	case c.idle:
		st.Nodes, level = 3, 0.04
	case c.saturated(now):
		st.Nodes, st.Saturated, level = 12, true, 0.9
	}
	st.Signals = map[nodescale.Signal]float64{}
	for _, sig := range nodescale.Signals {
		st.Signals[sig] = level + 0.05*c.rng.Float64()
	}
	return st
}

func (c *planCell) saturated(now time.Time) bool {
	return slices.ContainsFunc(c.bursts, func(w window) bool { return !now.Before(w.from) && now.Before(w.until) })
}

// burstsFor draws a busy cell's saturated spans from start to end. Each lasts 2 to 6 hours, and they recur a day
// or more apart.
func burstsFor(rng *rand.Rand, start, end time.Time) []window {
	var bursts []window
	for at := start.Add(time.Duration(rng.Int64N(int64(48 * time.Hour)))); at.Before(end); {
		length := 2*time.Hour + time.Duration(rng.Int64N(int64(4*time.Hour)))
		bursts = append(bursts, window{from: at, until: at.Add(length)})
		at = at.Add(length + 24*time.Hour + time.Duration(rng.Int64N(int64(72*time.Hour))))
	}
	return bursts
}

// regionFor is the planner's view of one serving cell at now.
func regionFor(c *planCell, ociRegion string, now time.Time, rec *regionlifecycle.Record, home bool) regionplanner.Region {
	st := c.status(now)
	return regionplanner.Region{Cell: c.cell, OCIRegion: ociRegion, Home: home, Status: &st, RTT: c.rtt, Record: rec}
}

// activeRecord is the lifecycle record of a region founded at the start.
func activeRecord(entry catalog.Entry) regionlifecycle.Record {
	return regionlifecycle.Record{Cell: entry.Name(), Generation: 1, Phase: regionlifecycle.Active,
		Proposal: regionlifecycle.Proposal{Cell: entry.Name(), OCIRegion: entry.OCIRegion,
			EstimatedMonthlyCents: 3 * nodeMonthlyCents}}
}

// ledgerOf returns the records sorted by cell, so the planner sees the same order on every run.
func ledgerOf(records map[string]regionlifecycle.Record) []regionlifecycle.Record {
	list := slices.Collect(maps.Values(records))
	slices.SortFunc(list, func(a, b regionlifecycle.Record) int { return strings.Compare(a.Cell, b.Cell) })
	return list
}
