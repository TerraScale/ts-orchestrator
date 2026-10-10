package regionplanner

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/oracle/oci-go-sdk/v65/identity"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/budget"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/globalcontrol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/globalview"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/nodescale"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionlifecycle"
)

// RegionLister lists every OCI region. The identity client implements it.
type RegionLister interface {
	ListRegions(ctx context.Context) (identity.ListRegionsResponse, error)
}

// Runner plans on the global home's leader. Each round it reads the regions,
// decides, acts through the lifecycle and saves the decision.
type Runner struct {
	Home regionlifecycle.Home
	// Rollups returns every region's latest rollup as this controller follows
	// it. A region without a rollup, or without a scaling status, is unknown.
	Rollups func() []globalview.Region
	// Roster returns the global roster. A roster that was never written leaves
	// only the summaries.
	Roster func(ctx context.Context) (globalcontrol.Roster, error)
	// Capacity returns the global capacity document, and false when none was written.
	Capacity   func(ctx context.Context) (budget.Capacity, bool, error)
	OCIRegions RegionLister
	State      *Store
	Lifecycle  *regionlifecycle.Store
	Machine    regionlifecycle.Machine
}

// Plan runs one round under the global epoch. It returns the cell a region
// action started for, if one did.
func (runner *Runner) Plan(ctx context.Context, epoch uint64, now time.Time) ([]string, error) {
	state, revision, err := runner.State.Load(ctx)
	if err != nil {
		return nil, err
	}
	records, err := runner.Lifecycle.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list region lifecycle records: %w", err)
	}
	regions, err := runner.regions(ctx, records)
	if err != nil {
		return nil, err
	}
	candidates, err := runner.candidates(ctx, regions, records)
	if err != nil {
		return nil, err
	}
	capacity, found, err := runner.Capacity(ctx)
	if err != nil {
		return nil, fmt.Errorf("read capacity: %w", err)
	}
	monthly := regionMonthlyCents(regions)
	// The admission reads the same headroom and fleet, so an add approved here is admitted there.
	guard := Budget{Fleet: regionlifecycle.FleetOf(records, "", runner.Home), RegionMonthlyCents: monthly}
	if found {
		guard.HeadroomCents, guard.Currency = capacity.Headroom(), capacity.Currency
	}
	decision, memory := Decide(regions, candidates, records, state.Memory, guard, now)
	switch decision.Action {
	case ActionAdd:
		if err := runner.add(ctx, epoch, decision, monthly, now); err != nil {
			return nil, fmt.Errorf("add region %s: %w", decision.Cell, err)
		}
	case ActionRemove:
		if err := runner.remove(ctx, epoch, decision, memory.IdleSince[decision.Cell], now); err != nil {
			return nil, fmt.Errorf("remove region %s: %w", decision.Cell, err)
		}
	case ActionHold:
		if changed(state.Decision, decision) {
			journalHold(ctx, epoch, runner.Home.Cell, decision)
		}
	}
	if _, err := runner.State.Save(ctx, epoch, State{Memory: memory, Decision: decision}, revision); err != nil {
		return nil, err
	}
	if decision.Action == ActionHold {
		return nil, nil
	}
	return []string{decision.Cell}, nil
}

// regions joins the roster, the region summaries and the lifecycle records.
// Every region is a cell; the home is always one.
func (runner *Runner) regions(ctx context.Context, records []regionlifecycle.Record) ([]Region, error) {
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
	home := byCell[runner.Home.Cell]
	home.Cell = runner.Home.Cell
	byCell[home.Cell] = home
	regions := make([]Region, 0, len(byCell))
	// shortcut: globalcontrol lists no database directory, so no partition homed here is seen, and drain must refuse a region that homes one; upgrade when the directory can be listed.
	for cell, region := range byCell {
		region.Home = cell == runner.Home.Cell
		if region.OCIRegion == "" {
			region.OCIRegion = catalog.OCIRegion(strings.ToUpper(cell))
		}
		regions = append(regions, region)
	}
	for index := range regions {
		for _, record := range records {
			if record.Cell == regions[index].Cell {
				regions[index].Record = &record
				break
			}
		}
	}
	slices.SortFunc(regions, func(a, b Region) int { return strings.Compare(a.Cell, b.Cell) })
	return regions, nil
}

// candidates are the OCI regions that serve nothing and have no open lifecycle
// record. Cells come from the product catalog's names, or the OCI key.
func (runner *Runner) candidates(ctx context.Context, regions []Region, records []regionlifecycle.Record,
) ([]Candidate, error) {
	listed, err := runner.OCIRegions.ListRegions(ctx)
	if err != nil {
		return nil, fmt.Errorf("list OCI regions: %w", err)
	}
	taken := map[string]bool{}
	for _, region := range regions {
		taken[region.Cell] = true
		if region.OCIRegion != "" {
			taken[region.OCIRegion] = true
		}
	}
	for _, record := range records {
		if record.Phase.Open() {
			taken[record.Cell] = true
		}
	}
	var candidates []Candidate
	for _, item := range listed.Items {
		if item.Name == nil || item.Key == nil {
			continue
		}
		cell := catalog.CellOf(*item.Name, *item.Key)
		if !regionlifecycle.ValidCell(cell) || taken[cell] || taken[*item.Name] {
			continue
		}
		candidates = append(candidates, Candidate{Cell: cell, OCIRegion: *item.Name})
	}
	slices.SortFunc(candidates, func(a, b Candidate) int { return strings.Compare(a.Cell, b.Cell) })
	return candidates, nil
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
	var monthly uint64
	for range NodesPerNewRegion {
		monthly = regionlifecycle.SaturatingAdd(monthly, perNode)
	}
	return monthly
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

// changed reports a decision that differs from the stored one in action or reason.
func changed(prior, next Decision) bool {
	return prior.Action != next.Action || prior.Reason != next.Reason
}
