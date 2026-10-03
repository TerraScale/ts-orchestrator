package regionplanner

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/insights"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionlifecycle"
)

// recordProposal journals one proposal Submit stored as a Proposed lifecycle
// record. It runs after the store write, so a skipped or conflicting
// proposal is never journaled.
func recordProposal(ctx context.Context, epoch uint64, proposal regionlifecycle.Proposal) {
	decisionlog.Record(ctx, decisionlog.Decision{
		Region:  proposal.Cell,
		Actor:   decisionlog.Actor{Slice: "regionplanner"},
		Kind:    decisionlog.KindRegionProposed,
		Subject: decisionlog.Subject{Kind: "region", ID: proposal.Cell, Name: proposal.OCIRegion},
		Summary: fmt.Sprintf("Proposed region %s (%s)", proposal.Cell, proposal.OCIRegion),
		Reason:  proposal.Reason + "; it needs a signed approval before anything is admitted or spent.",
		Rule:    "regionplanner.plan",
		Signals: []decisionlog.Signal{{Name: "evidence", Value: float64(len(proposal.EvidenceDigests))},
			{Name: "estimated_monthly_cost", Value: float64(proposal.EstimatedMonthlyCents) / 100, Unit: "USD"}},
		Status: decisionlog.StatusPending,
		Epoch:  epoch,
		Attrs: map[string]string{"proposal": proposal.ID,
			"evidence": strings.Join(proposal.EvidenceDigests, ","),
			"cents":    strconv.FormatUint(proposal.EstimatedMonthlyCents, 10)},
	})
}

// RecordLister lists the region lifecycle records. *regionlifecycle.Store
// implements it.
type RecordLister interface {
	List(context.Context) ([]regionlifecycle.Record, error)
}

// Budgets reports the planner's two ceilings, the region count and the
// committed monthly spend, against the lifecycle records. It implements
// insights.BudgetProvider for the budget rule.
type Budgets struct {
	Policy  Policy
	Records RecordLister
}

func (budgets Budgets) Budgets(ctx context.Context) ([]insights.Budget, error) {
	if budgets.Records == nil {
		return nil, nil
	}
	records, err := budgets.Records.List(ctx)
	if err != nil {
		return nil, err
	}
	fleet := regionlifecycle.FleetOf(records, "", budgets.Policy.Home)
	var out []insights.Budget
	if budgets.Policy.MaxRegions > 0 {
		out = append(out, insights.Budget{Name: "regions", Used: float64(fleet.Regions),
			Ceiling: float64(budgets.Policy.MaxRegions), Unit: "regions"})
	}
	if budgets.Policy.MonthlyCeilingCents > 0 {
		out = append(out, insights.Budget{Name: "region monthly spend",
			Used:    float64(fleet.CommittedMonthlyCents) / 100,
			Ceiling: float64(budgets.Policy.MonthlyCeilingCents) / 100, Unit: "USD"})
	}
	return out, nil
}

var _ insights.BudgetProvider = Budgets{}

// CatalogFromRegions seeds a planner catalog from the product region catalog,
// so the planner never carries a second, divergent cell to OCI region map.
// Costs and overflow cells are planner policy and supplied by the caller;
// a product cell without a cost is left out.
func CatalogFromRegions(monthlyCents map[string]uint64, overflow map[string]string) map[string]CatalogEntry {
	out := make(map[string]CatalogEntry)
	for _, entry := range catalog.Entries() {
		cell := entry.Name()
		cents := monthlyCents[cell]
		if cents == 0 {
			continue
		}
		out[cell] = CatalogEntry{Cell: cell, OCIRegion: entry.OCIRegion, EstimatedMonthlyCents: cents,
			Overflow: overflow[cell]}
	}
	return out
}
