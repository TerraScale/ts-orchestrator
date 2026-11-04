package budget

import (
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2026, 10, 10, 20, 0, 0, 0, time.UTC)

func freshRegion(cell string, nodes, want int, pressure float64, price, projected uint64) Region {
	return Region{
		Cell: cell, Nodes: nodes, Want: want, Pressure: pressure,
		NodeMonthlyCents: price, ProjectedCents: projected, Currency: "BRL", At: testNow,
	}
}

func budgetWithCap(capCents uint64) *Budget {
	b := testBudget()
	b.MonthlyCapCents = capCents
	return &b
}

func TestAllocateHoldsEveryRegionWhenSpendIsUnknown(t *testing.T) {
	stale := freshRegion("sjc", 1, 3, 0.9, 100, 500)
	stale.At = testNow.Add(-StatusMaxAge - time.Minute)
	missing := freshRegion("sjc", 1, 3, 0.9, 100, 500)
	missing.At = time.Time{}
	otherCurrency := freshRegion("sjc", 1, 3, 0.9, 100, 500)
	otherCurrency.Currency = "USD"
	future := freshRegion("sjc", 1, 3, 0.9, 100, 500)
	future.At = testNow.Add(AllowanceMaxAge + time.Minute)
	for name, sjc := range map[string]Region{"stale": stale, "missing": missing, "other currency": otherCurrency,
		"from the future": future} {
		t.Run(name, func(t *testing.T) {
			c := Allocate(budgetWithCap(100000), []Region{freshRegion("gru", 1, 3, 0.5, 100, 200), sjc}, nil, testNow)
			if c.State != StateUnknown || !strings.Contains(c.Reason, "sjc") {
				t.Fatalf("capacity = %+v", c)
			}
			if c.ProjectedCents != 200 {
				t.Fatalf("projected = %d, want the known region's 200", c.ProjectedCents)
			}
			for _, region := range c.Regions {
				if region.Allowance != region.Nodes {
					t.Fatalf("%s allowance = %d, want its %d nodes", region.Cell, region.Allowance, region.Nodes)
				}
			}
		})
	}
}

func TestAllocateGrantsByPressureUntilTheCap(t *testing.T) {
	c := Allocate(budgetWithCap(1000), []Region{
		freshRegion("sjc", 1, 2, 0.5, 300, 100),
		freshRegion("gru", 1, 2, 0.9, 300, 100),
		freshRegion("fra", 1, 2, 0.7, 300, 100),
	}, nil, testNow)
	if c.State != StateWarn || c.ProjectedCents != 900 || c.Ratio != 0.9 || c.Headroom() != 100 {
		t.Fatalf("capacity = %+v", c)
	}
	if c.Reason != "granted gru +1, fra +1" {
		t.Fatalf("reason = %q", c.Reason)
	}
	want := map[string]int{"fra": 2, "gru": 2, "sjc": 1}
	for _, region := range c.Regions {
		if region.Allowance != want[region.Cell] {
			t.Fatalf("%s allowance = %d, want %d", region.Cell, region.Allowance, want[region.Cell])
		}
	}
	if c.Regions[0].Cell != "fra" || c.Regions[1].Cell != "gru" || c.Regions[2].Cell != "sjc" {
		t.Fatalf("regions are not sorted by cell: %+v", c.Regions)
	}
}

func TestAllocateNeverGrantsWithoutAPrice(t *testing.T) {
	c := Allocate(budgetWithCap(1000000), []Region{freshRegion("gru", 2, 5, 0.9, 0, 10)}, nil, testNow)
	if c.Regions[0].Allowance != 2 {
		t.Fatalf("allowance = %d, want 2", c.Regions[0].Allowance)
	}
}
