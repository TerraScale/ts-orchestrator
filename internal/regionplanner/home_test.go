package regionplanner

import (
	"math"
	"testing"
	"time"
)

// TestPlannerCountsTheHomeRegion: the home region has no lifecycle record,
// yet it takes a slot, and is never proposed.
func TestPlannerCountsTheHomeRegion(t *testing.T) {
	t.Parallel()
	planner := Planner{Policy: testPolicy()}
	both := []Signal{signal(SignalUnplaceableIntent, "sfo", "s", time.Hour), signal(SignalUnplaceableIntent, "fra", "f", time.Hour)}
	// No records at all: the home holds a slot and commits nothing, so both fit.
	proposals, err := planner.Plan(both, nil, now)
	if err != nil || len(proposals) != 2 {
		t.Fatalf("proposals without a home record = %+v, %v", proposals, err)
	}
	limited := planner
	limited.Policy.MaxRegions = 1
	if proposals, _ := limited.Plan(both, nil, now); len(proposals) != 0 {
		t.Fatalf("home region did not take a slot: %+v", proposals)
	}
	home := []Signal{signal(SignalUnplaceableIntent, "gru", "home", time.Hour)}
	if proposals, _ := planner.Plan(home, nil, now); len(proposals) != 0 {
		t.Fatalf("planner proposed the home region: %+v", proposals)
	}
	budgets, err := Budgets{Policy: planner.Policy, Records: staticRecords(nil)}.Budgets(t.Context())
	if err != nil || len(budgets) != 2 || budgets[0].Used != 1 || budgets[1].Used != 0 {
		t.Fatalf("budgets without a home record = %+v, %v", budgets, err)
	}
}

// TestPlannerBudgetCannotWrap: an absurd catalog estimate must not wrap the
// fleet total into something that fits the ceiling.
func TestPlannerBudgetCannotWrap(t *testing.T) {
	t.Parallel()
	policy := testPolicy()
	policy.MaxRegions = 10
	policy.Catalog["fra"] = CatalogEntry{Cell: "fra", OCIRegion: "eu-frankfurt-1", EstimatedMonthlyCents: math.MaxUint64 - 8_999}
	planner := Planner{Policy: policy}
	signals := []Signal{signal(SignalUnplaceableIntent, "fra", "f", time.Hour), signal(SignalUnplaceableIntent, "sfo", "s", time.Hour)}
	proposals, err := planner.Plan(signals, nil, now)
	if err != nil || len(proposals) != 1 || proposals[0].Cell != "sfo" {
		t.Fatalf("proposals = %+v, %v", proposals, err)
	}
}
