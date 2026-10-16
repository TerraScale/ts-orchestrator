package dashboard

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/budget"
	"github.com/TerraScale/ts-orchestrator/internal/globalview"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/ocicost"
	"github.com/TerraScale/ts-orchestrator/internal/regionview"
)

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

func TestCostBodyRendersEveryRegionState(t *testing.T) {
	t.Parallel()
	render := func(current view) string { return fixturePage(t, current, "/cost") }
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

func TestCostPageShowsGlobalBudgetStates(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		capacity *budget.Capacity
		wants    []string
	}{
		{"unset", nil, []string{"not set", "No global budget is set"}},
		{"ok", &budget.Capacity{At: testNow, CapCents: 100000, Currency: "BRL", ProjectedCents: 45000, State: budget.StateOK}, []string{"BRL 1000.00", "projected BRL 450.00 (45%)"}},
		{"over", &budget.Capacity{At: testNow, CapCents: 100000, Currency: "BRL", ProjectedCents: 120000, State: budget.StateOver}, []string{"BRL 1000.00", "projected BRL 1200.00 (120%)"}},
		{"stale", &budget.Capacity{At: testNow.Add(-budget.AllowanceMaxAge - time.Second), CapCents: 100000, Currency: "BRL", ProjectedCents: 45000, State: budget.StateOK}, []string{"stale", "BRL 1000.00"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := fixturePage(t, view{Now: testNow, Capacity: &CapacityView{Capacity: test.capacity}}, "/cost")
			for _, want := range test.wants {
				if !strings.Contains(body, want) {
					t.Errorf("cost page lacks %q", want)
				}
			}
		})
	}
}

func TestCostBodyStatesTheGlobalBudget(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	render := func(current view) string { return fixturePage(t, current, "/cost") }
	unset := localCost(usdView(1000, 3000))
	unset.State, unset.Now = parseState(url.Values{}), now
	unsetPage := render(unset)
	if !strings.Contains(unsetPage, "No global budget is set") {
		t.Errorf("unset budget page lacks the no-budget notice")
	}
	capped := localCost(usdView(1000, 3000))
	capped.State, capped.Now = parseState(url.Values{}), now
	capped.Global = []globalview.Region{remoteCost("fra", nil, false)}
	capped.Capacity = &CapacityView{Capacity: &budget.Capacity{At: now, CapCents: 100000, Currency: "BRL", ProjectedCents: 85000, Ratio: 0.85,
		State: budget.StateWarn, Reason: "projected spend is at least 80% of the cap"}}
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

func TestCostPageAggregatesOnlyCompatibleReports(t *testing.T) {
	t.Parallel()
	cost := usdView(1000, 3000)
	cost.Services = []ocicost.Line{{Name: "compute", Cents: 500}, {Name: "storage", Cents: 5}}
	cost.Components = []ocicost.Line{{Name: "controller", Cents: 300}}
	cost.UntaggedCents = 340
	current := localCost(cost)
	current.Global = []globalview.Region{remoteCost("fra", &globalview.Cost{Currency: "USD", PerHour: .5, MonthToDate: 5, MonthForecast: 15}, false), remoteCost("sfo", nil, true)}
	body := fixturePage(t, current, "/cost")
	for _, want := range []string{"USD 15.00", "USD 45.00", "compute", "storage", "controller", "untagged", "USD 0.05", "2 of 3 reported"} {
		if !strings.Contains(body, want) {
			t.Errorf("cost page lacks %q", want)
		}
	}
	current.Global = []globalview.Region{remoteCost("fra", &globalview.Cost{Currency: "BRL", MonthToDate: 50, MonthForecast: 90}, false)}
	body = fixturePage(t, current, "/cost")
	if !strings.Contains(body, "USD 10.00") || strings.Contains(body, "USD 60.00") {
		t.Fatal("mixed currency leaked into local totals")
	}
}
