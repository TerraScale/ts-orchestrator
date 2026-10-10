package budget

import (
	"math"
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

func TestAllocateWithoutBudgetHoldsEveryRegion(t *testing.T) {
	c := Allocate(nil, []Region{freshRegion("sfo", 2, 5, 0.9, 100, 10)}, testNow)
	if c.State != StateNone || c.Reason != "no monthly budget is set" || c.CapCents != 0 {
		t.Fatalf("capacity = %+v", c)
	}
	if len(c.Regions) != 1 || c.Regions[0].Allowance != 2 {
		t.Fatalf("regions = %+v", c.Regions)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("unset capacity = %v", err)
	}
}

func TestAllocateHoldsEveryRegionWithAnInvalidBudget(t *testing.T) {
	c := Allocate(budgetWithCap(0), []Region{freshRegion("gru", 3, 4, 0.9, 100, 10)}, testNow)
	if c.State != StateNone || !strings.Contains(c.Reason, "invalid") || c.Regions[0].Allowance != 3 ||
		math.IsNaN(c.Ratio) || c.Validate() != nil {
		t.Fatalf("capacity = %+v, %v", c, c.Validate())
	}
}

func TestAllocateHoldsEveryRegionWhenSpendIsUnknown(t *testing.T) {
	stale := freshRegion("sfo", 1, 3, 0.9, 100, 500)
	stale.At = testNow.Add(-StatusMaxAge - time.Minute)
	missing := freshRegion("sfo", 1, 3, 0.9, 100, 500)
	missing.At = time.Time{}
	otherCurrency := freshRegion("sfo", 1, 3, 0.9, 100, 500)
	otherCurrency.Currency = "USD"
	future := freshRegion("sfo", 1, 3, 0.9, 100, 500)
	future.At = testNow.Add(AllowanceMaxAge + time.Minute)
	for name, sfo := range map[string]Region{"stale": stale, "missing": missing, "other currency": otherCurrency,
		"from the future": future} {
		t.Run(name, func(t *testing.T) {
			c := Allocate(budgetWithCap(100000), []Region{freshRegion("gru", 1, 3, 0.5, 100, 200), sfo}, testNow)
			if c.State != StateUnknown || !strings.Contains(c.Reason, "sfo") {
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
		freshRegion("sfo", 1, 2, 0.5, 300, 100),
		freshRegion("gru", 1, 2, 0.9, 300, 100),
		freshRegion("fra", 1, 2, 0.7, 300, 100),
	}, testNow)
	if c.State != StateOK || c.ProjectedCents != 300 || c.Ratio != 0.3 {
		t.Fatalf("capacity = %+v", c)
	}
	if c.Reason != "granted gru +1, fra +1" {
		t.Fatalf("reason = %q", c.Reason)
	}
	want := map[string]int{"fra": 2, "gru": 2, "sfo": 1}
	for _, region := range c.Regions {
		if region.Allowance != want[region.Cell] {
			t.Fatalf("%s allowance = %d, want %d", region.Cell, region.Allowance, want[region.Cell])
		}
	}
	if c.Regions[0].Cell != "fra" || c.Regions[1].Cell != "gru" || c.Regions[2].Cell != "sfo" {
		t.Fatalf("regions are not sorted by cell: %+v", c.Regions)
	}
}

func TestAllocateNeverGrantsWithoutAPrice(t *testing.T) {
	c := Allocate(budgetWithCap(1000000), []Region{freshRegion("gru", 2, 5, 0.9, 0, 10)}, testNow)
	if c.Regions[0].Allowance != 2 {
		t.Fatalf("allowance = %d, want 2", c.Regions[0].Allowance)
	}
}

func TestAllocateNeverGoesBelowNodes(t *testing.T) {
	c := Allocate(budgetWithCap(1000), []Region{freshRegion("gru", 4, 1, 0, 100, 10)}, testNow)
	if c.Regions[0].Allowance != 4 || c.Regions[0].Want != 1 {
		t.Fatalf("region = %+v, want allowance held at 4 nodes", c.Regions[0])
	}
}

func TestAllocateStateThresholds(t *testing.T) {
	for _, tc := range []struct {
		projected uint64
		want      State
	}{
		{799, StateOK},
		{800, StateWarn},
		{999, StateWarn},
		{1000, StateOver},
		{1200, StateOver},
	} {
		c := Allocate(budgetWithCap(1000), []Region{freshRegion("gru", 1, 1, 0, 0, tc.projected)}, testNow)
		if c.State != tc.want {
			t.Errorf("projected %d: state = %s, want %s", tc.projected, c.State, tc.want)
		}
	}
}

func TestAllocateSaturatesTheProjection(t *testing.T) {
	c := Allocate(budgetWithCap(1000), []Region{
		freshRegion("gru", 1, 1, 0, 0, math.MaxUint64),
		freshRegion("sfo", 1, 1, 0, 0, math.MaxUint64),
	}, testNow)
	if c.State != StateOver || c.ProjectedCents != math.MaxUint64 {
		t.Fatalf("capacity = %+v", c)
	}
}

func TestAllowanceForChecksFreshnessAndCell(t *testing.T) {
	c := Allocate(budgetWithCap(1000000), []Region{freshRegion("gru", 2, 3, 0.9, 100, 10)}, testNow)
	if allowance, ok := AllowanceFor(c, "gru", testNow.Add(AllowanceMaxAge)); !ok || allowance != 3 {
		t.Fatalf("fresh allowance = %d, %v", allowance, ok)
	}
	if _, ok := AllowanceFor(c, "gru", testNow.Add(AllowanceMaxAge+time.Second)); ok {
		t.Fatal("stale allowance was fresh")
	}
	if _, ok := AllowanceFor(c, "fra", testNow); ok {
		t.Fatal("allowance for a region the document does not name")
	}
}

func TestCapacityEncodeDecodeRoundTripsAndRefusesBadAllowances(t *testing.T) {
	c := Allocate(budgetWithCap(1000000), []Region{freshRegion("gru", 2, 3, 0.9, 100, 10)}, testNow)
	encoded, err := c.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeCapacity(encoded)
	if err != nil || got.Regions[0].Allowance != 3 || got.State != StateOK || !got.At.Equal(testNow) {
		t.Fatalf("round trip = %+v, %v", got, err)
	}
	c.Regions[0].Allowance = 5
	if _, err := c.Encode(); err == nil {
		t.Fatal("allowance beyond one node encoded")
	}
	c.Regions[0].Allowance = 3
	c.State = StateNone
	if _, err := c.Encode(); err == nil {
		t.Fatal("capacity naming a cap without a budget encoded")
	}
}

func TestAlertingHysteresisOpensAtWarnAndClosesBelowClear(t *testing.T) {
	at := func(ratio float64) Capacity { return Capacity{State: StateOK, Ratio: ratio} }
	open := Alerting(false, at(0.79))
	if open {
		t.Fatal("alert opened below WarnRatio")
	}
	open = Alerting(open, at(0.8))
	if !open {
		t.Fatal("alert did not open at WarnRatio")
	}
	open = Alerting(open, at(0.77))
	if !open {
		t.Fatal("alert closed above ClearRatio")
	}
	open = Alerting(open, at(0.74))
	if open {
		t.Fatal("alert stayed open below ClearRatio")
	}
	if !Alerting(true, Capacity{State: StateUnknown, Ratio: 0.1}) || Alerting(false, Capacity{State: StateNone, Ratio: 1}) {
		t.Fatal("unknown or unset spend changed the alert")
	}
}
