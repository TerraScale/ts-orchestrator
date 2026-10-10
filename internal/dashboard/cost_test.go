package dashboard

import (
	"bytes"
	"context"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/budget"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/globalview"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ocicost"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionview"
)

func TestMoneyFormatsCentsWithTheCurrency(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		cents    uint64
		currency string
		want     string
	}{
		{1601, "BRL", "BRL 16.01"},
		{5, "USD", "USD 0.05"},
		{0, "", "0.00"},
		{1601, "", "16.01"},
		{0, "BRL", "BRL 0.00"},
	} {
		if got := money(test.cents, test.currency); got != test.want {
			t.Errorf("money(%d, %q) = %q, want %q", test.cents, test.currency, got, test.want)
		}
	}
}

// localCost is a dashboard of region gru whose full cost view is cost.
func localCost(cost *ocicost.View) view {
	return view{Local: &observability.MemberSnapshot{Cell: "gru"},
		LocalSummary: &regionview.Summary{Version: 1, Region: "gru", Local: true, Cost: cost}}
}

// remoteCost is another region's rollup carrying cost; a nil cost is a rollup
// from before the cost section.
func remoteCost(cell string, cost *globalview.Cost, stale bool) globalview.Region {
	return globalview.Region{Cell: cell, Stale: stale, Rollup: &globalview.Rollup{Version: 1, Cell: cell, Cost: cost}}
}

func usdView(mtd, monthEnd uint64) *ocicost.View {
	return &ocicost.View{Cell: "gru", Forecast: ocicost.Forecast{Currency: "USD", MonthToDateCents: mtd,
		MonthEndCents: monthEnd, NextMonthCents: monthEnd - 100, RateCents: 100, PendingDailyCents: 50}}
}

func TestCostTotalsSayWhatIsPartial(t *testing.T) {
	t.Parallel()
	current := localCost(usdView(1000, 3000))
	current.Global = []globalview.Region{
		remoteCost("fra", nil, false),
		remoteCost("sfo", nil, true),
	}
	total := current.costTotals()
	if total.Reported != 1 || total.Expected != 3 || total.Mixed || total.Currency != "USD" {
		t.Fatalf("totals = %+v", total)
	}
	if total.MonthToDate != 1000 || total.MonthEnd != 3000 || total.NextMonth != 2900 || total.Rate != 100 || total.Pending != 50 {
		t.Fatalf("sums = %+v", total)
	}
	if got := total.show(total.MonthToDate); got != "USD 10.00" {
		t.Fatalf("show = %q", got)
	}
	current.Global = append(current.Global, remoteCost("ams", &globalview.Cost{Currency: "USD", PerHour: 0.5,
		MonthToDate: 5, MonthForecast: 15}, false))
	total = current.costTotals()
	if total.MonthToDate != 1500 || total.MonthEnd != 4500 || total.Rate != 1300 || total.Pending != 50 {
		t.Fatalf("sums with a rollup = %+v", total)
	}
	if total.Reported != 2 || total.Expected != 4 || total.Rollups != 1 {
		t.Fatalf("counts with a rollup = %+v", total)
	}
	if got := total.showFull(total.NextMonth); got != "—" {
		t.Fatalf("next month with a rollup shows %q, want —", got)
	}
	if none := (view{Global: []globalview.Region{remoteCost("sfo", nil, true)}}).costTotals(); none.show(0) != "unknown" {
		t.Fatalf("totals with no report show %q, want unknown", none.show(0))
	}
}

func TestCostTotalsLeaveOutAnotherCurrency(t *testing.T) {
	t.Parallel()
	current := localCost(usdView(1000, 3000))
	current.Global = []globalview.Region{remoteCost("fra", &globalview.Cost{Currency: "BRL", PerHour: 1,
		MonthToDate: 50, MonthForecast: 90}, false)}
	total := current.costTotals()
	if !total.Mixed || total.Currency != "USD" || total.Reported != 1 || total.MonthToDate != 1000 {
		t.Fatalf("mixed totals = %+v", total)
	}
}

func TestCostLinesComeFromTheLocalViewAndEndWithUntagged(t *testing.T) {
	t.Parallel()
	gru := usdView(1000, 3000)
	gru.Services = []ocicost.Line{{Name: "compute", Cents: 500}, {Name: "storage", Cents: 100}}
	gru.Components = []ocicost.Line{{Name: "controller", Cents: 300}}
	gru.UntaggedCents = 340
	current := localCost(gru)
	current.Global = []globalview.Region{remoteCost("fra", &globalview.Cost{Currency: "USD", PerHour: 1,
		MonthToDate: 4, MonthForecast: 12}, false)}
	if got, want := current.costLines("services"), []ocicost.Line{{Name: "compute", Cents: 500}, {Name: "storage", Cents: 100}}; !slices.Equal(got, want) {
		t.Fatalf("services = %+v, want %+v", got, want)
	}
	want := []ocicost.Line{{Name: "controller", Cents: 300}, {Name: "untagged", Cents: 340}}
	if got := current.costLines("components"); !slices.Equal(got, want) {
		t.Fatalf("components = %+v, want %+v", got, want)
	}
	untaggedOnly := localCost(usdView(1000, 3000))
	if got := untaggedOnly.costLines("components"); len(got) != 0 {
		t.Fatalf("components with no tags = %+v, want none", got)
	}
}

func TestRollupCostReadsCurrencyUnitsAsCents(t *testing.T) {
	t.Parallel()
	cost := rollupCost("fra", globalview.Cost{Currency: "BRL", PerHour: 0.1, MonthToDate: 16.01, MonthForecast: 54.51})
	forecast := cost.Forecast
	if forecast.Currency != "BRL" || forecast.RateCents != 240 || forecast.MonthToDateCents != 1601 ||
		forecast.MonthEndCents != 5451 {
		t.Fatalf("rollupCost = %+v", cost)
	}
}

func TestCostBodyRendersEveryRegionState(t *testing.T) {
	t.Parallel()
	render := func(current view) string {
		var body bytes.Buffer
		if err := costBody(current).Render(context.Background(), &body); err != nil {
			t.Fatal(err)
		}
		return body.String()
	}
	brazil := &ocicost.View{Cell: "gru", OCIRegion: "sa-saopaulo-1", Forecast: ocicost.Forecast{Currency: "BRL",
		ObservedAt: time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC), Through: time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC),
		MonthToDateCents: 1227, CompleteCents: 1227, RateCents: 176, PendingDailyCents: 0, DaysLeft: 24,
		MonthEndCents: 5451, NextMonthCents: 5300}}
	current := localCost(brazil)
	current.State = parseState(url.Values{})
	current.Now = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	current.Global = []globalview.Region{
		remoteCost("fra", &globalview.Cost{Currency: "BRL", PerHour: 0.1, MonthToDate: 16.01, MonthForecast: 54.51}, false),
		remoteCost("sfo", nil, true),
	}
	page := render(current)
	for _, want := range []string{"OCI cost", "GRU", "Method", "did not answer", "in rate", "BRL 16.01",
		"GRU: 12.27 (complete days) + (1.76 + 0.00) × 24 days = 54.51 BRL", "BRL 54.51", "2 of 3 reported",
		"No component tags yet"} {
		if !strings.Contains(page, want) {
			t.Errorf("cost page lacks %q", want)
		}
	}
	current = localCost(&ocicost.View{Cell: "gru", Missing: "no OCI cost report yet"})
	current.State = parseState(url.Values{})
	current.Now = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	if page := render(current); !strings.Contains(page, "no OCI cost report yet") {
		t.Errorf("cost page with a missing local report lacks the missing text")
	}
}

func TestBudgetCapTileShowsTheGlobalCap(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	fresh := now.Add(-time.Minute)
	for _, test := range []struct {
		name     string
		capacity *budget.Capacity
		want     kpi
	}{
		{"unset", nil, kpi{Value: "not set", Sub: "TS-804 global budget"}},
		{"ok", &budget.Capacity{At: fresh, CapCents: 100000, Currency: "BRL", ProjectedCents: 45000, State: budget.StateOK},
			kpi{Value: "BRL 1000.00", Sub: "projected BRL 450.00 (45%)", Status: "ok"}},
		{"over", &budget.Capacity{At: fresh, CapCents: 100000, Currency: "BRL", ProjectedCents: 120000, State: budget.StateOver},
			kpi{Value: "BRL 1000.00", Sub: "projected BRL 1200.00 (120%)", Status: "bad"}},
		{"stale", &budget.Capacity{At: now.Add(-budget.AllowanceMaxAge - time.Second), CapCents: 100000, Currency: "BRL",
			ProjectedCents: 45000, State: budget.StateOK},
			kpi{Value: "BRL 1000.00", Sub: "projected BRL 450.00 (45%) · stale", Status: "warn"}},
	} {
		current := view{State: parseState(url.Values{}), Now: now, Capacity: test.capacity}
		got := current.costCapKPI()
		if got.Label != "Budget cap" || got.Value != test.want.Value || got.Sub != test.want.Sub || got.Status != test.want.Status {
			t.Errorf("%s: tile = %q %q %q, want %q %q %q", test.name, got.Value, got.Sub, got.Status,
				test.want.Value, test.want.Sub, test.want.Status)
		}
	}
}

func TestCostBodyStatesTheGlobalBudget(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	render := func(current view) string {
		var body bytes.Buffer
		if err := costBody(current).Render(context.Background(), &body); err != nil {
			t.Fatal(err)
		}
		return body.String()
	}
	unset := localCost(usdView(1000, 3000))
	unset.State, unset.Now = parseState(url.Values{}), now
	unsetPage := render(unset)
	if !strings.Contains(unsetPage, "No global budget is set") {
		t.Errorf("unset budget page lacks the no-budget notice")
	}
	capped := localCost(usdView(1000, 3000))
	capped.State, capped.Now = parseState(url.Values{}), now
	capped.Global = []globalview.Region{remoteCost("fra", nil, false)}
	capped.Capacity = &budget.Capacity{At: now, CapCents: 100000, Currency: "BRL", ProjectedCents: 85000, Ratio: 0.85,
		State: budget.StateWarn, Reason: "projected spend is at least 80% of the cap"}
	cappedPage := render(capped)
	for _, want := range []string{"projected spend is at least 80% of the cap", "as of"} {
		if !strings.Contains(cappedPage, want) {
			t.Errorf("capped budget page lacks %q", want)
		}
	}
	if strings.Contains(cappedPage, "No global budget is set") {
		t.Errorf("capped budget page shows the no-budget notice")
	}
}
