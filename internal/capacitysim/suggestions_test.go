package capacitysim

import (
	"math/rand/v2"
	"slices"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/nodescale"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/regionsuggest"
)

const (
	suggestDays     = 40
	candidateCount  = 10
	idleFrom        = 15 // cells idleFrom to idleFrom+idleCount-1 sit at the starting size for the whole run
	idleCount       = 4
	suggestHeadroom = 100 * 3 * nodeMonthlyCents
)

// TestRegionSuggestionsOverFortyDays runs the suggester alone for 40 simulated days over 20 serving regions and 10
// candidates. Nothing acts on a suggestion, so the regions stay as they are, and the run asserts the rules at every round.
func TestRegionSuggestionsOverFortyDays(t *testing.T) {
	entries := catalog.Entries()
	used := regionCount + candidateCount
	if len(entries) < used || entries[0].Name() != homeCell {
		t.Fatalf("catalog has %d regions, first %q: need %d regions with %s first", len(entries), entries[0].Name(),
			used, homeCell)
	}
	end := simStart.Add(suggestDays * 24 * time.Hour)
	cells := make(map[string]*simCell, used)
	for index, entry := range entries[:used] {
		rng := rand.New(rand.NewPCG(seed, uint64(index)+1))
		c := &simCell{cell: entry.Name(), rng: rng,
			idle: index >= idleFrom && index < idleFrom+idleCount}
		if !c.idle {
			c.bursts = burstsFor(rng, simStart, end)
		}
		cells[c.cell] = c
	}

	var candidates []regionsuggest.Candidate
	for _, entry := range entries[regionCount:used] {
		candidates = append(candidates, regionsuggest.Candidate{Cell: entry.Name(), OCIRegion: entry.OCIRegion})
	}
	guard := regionsuggest.Budget{HeadroomCents: suggestHeadroom, RegionMonthlyCents: 3 * nodeMonthlyCents, Currency: "BRL"}
	var memory regionsuggest.Memory
	var adds, removes int
	for now := simStart; now.Before(end); now = now.Add(regionsuggest.Interval) {
		regions := []regionsuggest.Region{regionFor(cells[homeCell], entries[0].OCIRegion, now, true)}
		for _, entry := range entries[1:regionCount] {
			regions = append(regions, regionFor(cells[entry.Name()], entry.OCIRegion, now, false))
		}
		var suggestion regionsuggest.Suggestion
		suggestion, memory = regionsuggest.Suggest(regions, candidates, memory, guard, now)
		switch suggestion.Action {
		case regionsuggest.ActionAdd:
			if suggestion.OCIRegion == "" || suggestion.MonthlyCents != 3*nodeMonthlyCents {
				t.Fatalf("add %+v at %s names no region or misprices it", suggestion, now.Format(time.RFC3339))
			}
			adds++
		case regionsuggest.ActionRemove:
			if suggestion.Cell == homeCell {
				t.Fatalf("suggested removing the home %s at %s", homeCell, now.Format(time.RFC3339))
			}
			if len(regions) <= regionsuggest.MinRegions {
				t.Fatalf("suggested removing %s with %d regions; MinRegions is %d", suggestion.Cell, len(regions),
					regionsuggest.MinRegions)
			}
			if !cells[suggestion.Cell].idle || now.Sub(memory.IdleSince[suggestion.Cell]) < regionsuggest.IdleFor {
				t.Fatalf("suggested removing %s at %s, which has not been idle for %v", suggestion.Cell,
					now.Format(time.RFC3339), regionsuggest.IdleFor)
			}
			removes++
		}
	}
	if adds == 0 || removes == 0 {
		t.Fatalf("run missed a case: %d add rounds, %d remove rounds over %d days", adds, removes, suggestDays)
	}
	t.Logf("%d days of %s suggestions: %d add rounds, %d remove rounds", suggestDays, regionsuggest.Interval, adds, removes)
}

// simCell is one catalog cell's synthetic status: idle at the starting size, or busy with saturated bursts.
type simCell struct {
	cell   string
	idle   bool
	bursts []window
	rng    *rand.Rand
}

// window is the span [from, until).
type window struct{ from, until time.Time }

// status is the cell's synthetic scaling status at now.
func (c *simCell) status(now time.Time) nodescale.Status {
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

func (c *simCell) saturated(now time.Time) bool {
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

// regionFor is the suggester's view of one serving cell at now.
func regionFor(c *simCell, ociRegion string, now time.Time, home bool) regionsuggest.Region {
	st := c.status(now)
	return regionsuggest.Region{Cell: c.cell, OCIRegion: ociRegion, Home: home, Status: &st}
}
