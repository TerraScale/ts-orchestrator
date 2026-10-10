package regionops

import (
	"context"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/budget"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionlifecycle"
)

func TestBudgetAdmissionRefusesAnUnknownBudget(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	record := regionlifecycle.Record{Cell: "sfo", Proposal: regionlifecycle.Proposal{
		ID: entityid.Derive("test-proposal", "sfo"), EstimatedMonthlyCents: 9_000}}
	admissions := func(capacity budget.Capacity, found bool) BudgetAdmissions {
		return BudgetAdmissions{Capacity: func(context.Context) (budget.Capacity, bool, error) {
			return capacity, found, nil
		}}
	}
	if _, err := admissions(budget.Capacity{}, false).Estimate(ctx, record, now); err == nil {
		t.Fatal("a missing capacity document admitted a region")
	}
	for _, state := range []budget.State{budget.StateNone, budget.StateUnknown} {
		if _, err := admissions(budget.Capacity{State: state}, true).Estimate(ctx, record, now); err == nil {
			t.Fatalf("state %q admitted a region", state)
		}
	}
	admission, err := admissions(budget.Capacity{State: budget.StateOK, CapCents: 100_000, ProjectedCents: 60_000,
		Currency: "USD"}, true).Estimate(ctx, record, now)
	if err != nil || admission.HeadroomCents != 40_000 || admission.EstimatedMonthlyCents != 9_000 ||
		admission.EvidenceDigest == "" || !admission.AdmittedAt.Equal(now) {
		t.Fatalf("admission = %+v, %v", admission, err)
	}
	over, err := admissions(budget.Capacity{State: budget.StateOver, CapCents: 100_000, ProjectedCents: 120_000,
		Currency: "USD"}, true).Estimate(ctx, record, now)
	if err != nil || over.HeadroomCents != 0 {
		t.Fatalf("over-budget admission = %+v, %v; want zero headroom", over, err)
	}
}
