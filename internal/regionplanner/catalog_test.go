package regionplanner

import (
	"context"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionlifecycle"
)

func TestPolicyRejectsAProductCellBoundToAnotherRegion(t *testing.T) {
	policy := testPolicy()
	entry := policy.Catalog["sfo"]
	entry.OCIRegion = "us-phoenix-1"
	policy.Catalog["sfo"] = entry
	if err := policy.validate(); err == nil {
		t.Fatal("a product cell must keep its catalog OCI region")
	}
	policy = testPolicy()
	policy.Catalog["iad"] = CatalogEntry{Cell: "iad", OCIRegion: "us-ashburn-1", EstimatedMonthlyCents: 1}
	if err := policy.validate(); err != nil {
		t.Fatalf("a new cell outside the product catalog may name a region: %v", err)
	}
}

func TestCatalogFromRegionsUsesTheProductCatalog(t *testing.T) {
	got := CatalogFromRegions(map[string]uint64{"gru": 9_000, "fra": 9_500}, map[string]string{"gru": "fra"})
	if len(got) != 2 || got["gru"].OCIRegion != "sa-saopaulo-1" || got["gru"].Overflow != "fra" ||
		got["fra"].OCIRegion != "eu-frankfurt-1" {
		t.Fatalf("catalog = %+v", got)
	}
}

type staticRecords []regionlifecycle.Record

func (records staticRecords) List(context.Context) ([]regionlifecycle.Record, error) {
	return records, nil
}

func TestBudgetsReportRegionAndSpendCeilings(t *testing.T) {
	policy := testPolicy()
	budgets, err := Budgets{Policy: policy, Records: staticRecords(nil)}.Budgets(t.Context())
	if err != nil || len(budgets) != 2 || budgets[0].Name != "regions" || budgets[0].Ceiling != float64(policy.MaxRegions) ||
		budgets[1].Ceiling != float64(policy.MonthlyCeilingCents)/100 {
		t.Fatalf("budgets = %+v, %v", budgets, err)
	}
	if none, err := (Budgets{Policy: policy}).Budgets(t.Context()); err != nil || none != nil {
		t.Fatalf("budgets without records = %+v, %v", none, err)
	}
}
