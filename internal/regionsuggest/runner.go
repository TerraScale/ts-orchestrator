package regionsuggest

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/budget"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/globalcontrol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/globalview"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/nodescale"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

// Runner suggests on the global home's leader. Each round it reads the regions,
// suggests and saves the suggestion.
type Runner struct {
	// Home is the home region's cell.
	Home string
	// Rollups returns every region's latest rollup as this controller follows
	// it. A region without a rollup, or without a scaling status, is unknown.
	Rollups func() []globalview.Region
	// Roster returns the global roster. A roster that was never written leaves
	// only the summaries.
	Roster func(ctx context.Context) (globalcontrol.Roster, error)
	// Capacity returns the global capacity document, and false when none was written.
	Capacity func(ctx context.Context) (budget.Capacity, bool, error)
	State    *Store
}

// Suggest runs one round under the global epoch and saves the suggestion.
func (runner *Runner) Suggest(ctx context.Context, epoch uint64, now time.Time) (Suggestion, error) {
	state, revision, err := runner.State.Load(ctx)
	if err != nil {
		return Suggestion{}, err
	}
	regions, err := runner.regions(ctx)
	if err != nil {
		return Suggestion{}, err
	}
	capacity, found, err := runner.Capacity(ctx)
	if err != nil {
		return Suggestion{}, fmt.Errorf("read capacity: %w", err)
	}
	guard := Budget{RegionMonthlyCents: regionMonthlyCents(regions)}
	if found {
		guard.HeadroomCents, guard.Currency = capacity.Headroom(), capacity.Currency
	}
	suggestion, memory := Suggest(regions, candidates(regions), state.Memory, guard, now)
	if _, err := runner.State.Save(ctx, epoch, State{Memory: memory, Suggestion: suggestion}, revision); err != nil {
		return Suggestion{}, err
	}
	return suggestion, nil
}

// regions joins the roster and the region summaries. Every region is a cell;
// the home is always one.
func (runner *Runner) regions(ctx context.Context) ([]Region, error) {
	roster, err := runner.Roster(ctx)
	if err != nil && !errors.Is(err, globalcontrol.ErrNotFound) {
		return nil, fmt.Errorf("read region roster: %w", err)
	}
	byCell := map[string]Region{}
	for _, entry := range roster.Regions {
		if entry.State == globalcontrol.RegionActive {
			byCell[entry.Cell] = Region{Cell: entry.Cell, OCIRegion: entry.OCIRegion}
		}
	}
	for _, rollup := range runner.Rollups() {
		region := byCell[rollup.Cell]
		region.Cell = rollup.Cell
		if rollup.Rollup != nil {
			region.Status = rollup.Rollup.Scale
			region.RTT = roundTrips(rollup.Rollup.Scale)
		}
		byCell[rollup.Cell] = region
	}
	home := byCell[runner.Home]
	home.Cell = runner.Home
	byCell[home.Cell] = home
	regions := make([]Region, 0, len(byCell))
	// shortcut: globalcontrol lists no database directory, so a removal can be suggested for a region that homes a partition; upgrade when the directory can be listed.
	for cell, region := range byCell {
		region.Home = cell == runner.Home
		if region.OCIRegion == "" {
			region.OCIRegion = catalog.OCIRegion(strings.ToUpper(cell))
		}
		regions = append(regions, region)
	}
	slices.SortFunc(regions, func(a, b Region) int { return strings.Compare(a.Cell, b.Cell) })
	return regions, nil
}

// candidates are the catalog's regions that serve nothing. The bootstrap cell
// founds the deployment, so it is never a candidate.
func candidates(regions []Region) []Candidate {
	serving := map[string]bool{}
	for _, region := range regions {
		serving[region.Cell] = true
	}
	var out []Candidate
	for _, entry := range catalog.Entries() {
		if entry.Cell == catalog.Bootstrap || serving[entry.Name()] {
			continue
		}
		out = append(out, Candidate{Cell: entry.Name(), OCIRegion: entry.OCIRegion})
	}
	return out
}

// regionMonthlyCents prices a new region: NodesPerNewRegion nodes at the
// highest known node price. Zero when no region reports a price.
func regionMonthlyCents(regions []Region) uint64 {
	var perNode uint64
	for _, region := range regions {
		if region.Status != nil {
			perNode = max(perNode, region.Status.NodeMonthlyCents)
		}
	}
	return perNode * NodesPerNewRegion
}

// roundTrips is a region's measured round trips to OCI regions, from its status, in durations.
func roundTrips(status *nodescale.Status) map[string]time.Duration {
	if status == nil {
		return nil
	}
	rtt := make(map[string]time.Duration, len(status.RTTMillis))
	for region, millis := range status.RTTMillis {
		rtt[region] = time.Duration(millis) * time.Millisecond
	}
	return rtt
}
