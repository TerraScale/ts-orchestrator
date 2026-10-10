package app

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/atlas"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/budget"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/globalcontrol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/globalview"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/insights"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
)

// capacityInterval is how often the home allocates node growth under the budget.
const capacityInterval = time.Minute

// capacityAllocator is the home's allocator. On the global leader it writes the
// capacity document every minute and keeps the last one for the budget insight.
type capacityAllocator struct {
	global  *globalControl
	regions func() []globalview.Region
	alert   budgetAlert

	mu       sync.Mutex
	capacity budget.Capacity
	found    bool
	// journaledState and journaledReason are the last decision journaled. Only
	// tick reads or writes them.
	journaledState  budget.State
	journaledReason string
}

// startCapacityAllocator runs the allocator on the home's global leader. Every
// other region gets an allocator that never runs; its budget insight reads the
// capacity document instead.
func startCapacityAllocator(ctx context.Context, global *globalControl,
	regions func() []globalview.Region, js jetstream.JetStream, replicas int, atlasConfig func() *atlas.Config,
) *capacityAllocator {
	allocator := &capacityAllocator{global: global, regions: regions, alert: newBudgetAlert(js, replicas, atlasConfig)}
	if global == nil || global.writer == nil || global.authority == nil {
		return allocator
	}
	go allocator.run(ctx)
	return allocator
}

func (a *capacityAllocator) run(ctx context.Context) {
	ticker := time.NewTicker(capacityInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := a.tick(ctx, time.Now()); err != nil {
				slog.Warn("capacity allocation failed", observability.ComponentKey, "budget", "error", err)
			}
		}
	}
}

// tick allocates once and writes the capacity document. A follower, or a leader
// that is fenced, does nothing.
func (a *capacityAllocator) tick(ctx context.Context, now time.Time) error {
	snapshot := a.global.authority.Current()
	if !snapshot.CanMutate() {
		return nil
	}
	rollups := a.regions()
	if len(rollups) == 0 {
		// The region view attaches after the controller starts; there is nothing to allocate yet.
		return nil
	}
	monthly, found, err := budget.ReadBudget(ctx, a.global.reader)
	if err != nil {
		return fmt.Errorf("read monthly budget: %w", err)
	}
	var ceiling *budget.Budget
	if found {
		ceiling = &monthly
	}
	regions := capacityRegions(rollups)
	if roster, _, err := a.global.reader.Roster(ctx); err == nil {
		regions = addRosterCells(regions, roster)
	}
	capacity := budget.Allocate(ceiling, regions, now)
	if err := a.global.authority.Guard(ctx, snapshot.Epoch); err != nil {
		return err
	}
	if err := budget.WriteCapacity(ctx, a.global.writer, snapshot.Epoch, capacity); err != nil {
		return fmt.Errorf("write capacity: %w", err)
	}
	a.mu.Lock()
	a.capacity, a.found = capacity, true
	a.mu.Unlock()
	a.journal(ctx, now, snapshot.Epoch, capacity)
	a.alertBudget(ctx, now, snapshot.Epoch, capacity)
	return nil
}

// Capacity returns the last capacity document this allocator wrote, and false before its first write.
func (a *capacityAllocator) Capacity() (budget.Capacity, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.capacity, a.found
}

// journal records a decision when the state or the reason changes. Growth is held in none, unknown and over.
func (a *capacityAllocator) journal(ctx context.Context, now time.Time, epoch uint64, capacity budget.Capacity) {
	if capacity.State == a.journaledState && capacity.Reason == a.journaledReason {
		return
	}
	a.journaledState, a.journaledReason = capacity.State, capacity.Reason
	kind, summary := decisionlog.KindHoldCleared, "allow node growth under the monthly budget"
	switch capacity.State {
	case budget.StateNone, budget.StateUnknown, budget.StateOver:
		kind, summary = decisionlog.KindHeld, "hold node growth under the monthly budget"
	}
	decisionlog.Record(ctx, decisionlog.Decision{Time: now, Region: "global", Epoch: epoch,
		Actor: decisionlog.Actor{Slice: "budget"}, Kind: kind,
		Subject: decisionlog.Subject{Kind: "budget", ID: "monthly"}, Summary: summary, Reason: capacity.Reason})
}

// capacityRegions maps each region's latest rollup to the allocator's input.
// A region without a rollup or a scaling status has unknown spend; the age of
// its cost decides whether a known spend is still fresh.
func capacityRegions(rollups []globalview.Region) []budget.Region {
	regions := make([]budget.Region, 0, len(rollups))
	for _, rollup := range rollups {
		region := budget.Region{Cell: rollup.Cell}
		if rollup.Rollup != nil && rollup.Rollup.Scale != nil {
			scale := rollup.Rollup.Scale
			region = budget.Region{Cell: rollup.Cell, Nodes: scale.Nodes, Want: scale.Want, Pressure: scale.Pressure,
				NodeMonthlyCents: scale.NodeMonthlyCents, ProjectedCents: scale.ProjectedCents,
				Currency: scale.Currency, At: scale.CostAt}
		}
		regions = append(regions, region)
	}
	return regions
}

// addRosterCells adds every roster cell that has no region yet, with unknown spend, so a region
// the view cannot reach still holds growth.
func addRosterCells(regions []budget.Region, roster globalcontrol.Roster) []budget.Region {
	known := make(map[string]bool, len(regions))
	for _, region := range regions {
		known[region.Cell] = true
	}
	for _, entry := range roster.Regions {
		if !known[entry.Cell] {
			known[entry.Cell] = true
			regions = append(regions, budget.Region{Cell: entry.Cell})
		}
	}
	return regions
}

// capacityBudgets is the budget insight's source: the monthly OCI budget from the
// latest capacity document, once its spend is known. The home reads its own
// allocator; every other region reads the document it mirrors.
type capacityBudgets struct {
	global    *globalControl
	allocator *capacityAllocator
}

func (budgets capacityBudgets) Budgets(ctx context.Context) ([]insights.Budget, error) {
	capacity, found, err := budgets.latest(ctx)
	if err != nil || !found {
		return nil, err
	}
	switch capacity.State {
	case budget.StateOK, budget.StateWarn, budget.StateOver:
	default:
		return nil, nil
	}
	return []insights.Budget{{Name: "monthly OCI budget", Used: float64(capacity.ProjectedCents) / 100,
		Ceiling: float64(capacity.CapCents) / 100, Unit: capacity.Currency}}, nil
}

// latest prefers the allocator's own last write, which a home follower lacks,
// then the document every controller can read.
func (budgets capacityBudgets) latest(ctx context.Context) (budget.Capacity, bool, error) {
	if budgets.allocator != nil {
		if capacity, found := budgets.allocator.Capacity(); found {
			return capacity, true, nil
		}
	}
	if budgets.global == nil || budgets.global.reader == nil {
		return budget.Capacity{}, false, nil
	}
	return budget.ReadCapacity(ctx, budgets.global.reader)
}

var _ insights.BudgetProvider = capacityBudgets{}
