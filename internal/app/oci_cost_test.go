package app

import (
	"context"
	"math"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/nodescale"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ocicost"
)

func TestOCICostViewsRollupReadsTheLatestView(t *testing.T) {
	t0 := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	views := &ociCostViews{}
	if views.nodes() != nil {
		t.Fatal("nodes before any node pricing are not nil")
	}
	if views.rollup() != nil {
		t.Fatal("rollup before the first refresh is not nil")
	}
	views.current.Store(&ocicost.View{Cell: "gru", Missing: "no report"})
	if views.rollup() != nil {
		t.Fatal("rollup of a view without a report is not nil")
	}
	views.current.Store(&ocicost.View{Cell: "gru", Forecast: ocicost.Forecast{Currency: "BRL", RateCents: 176,
		PendingDailyCents: 64, MonthToDateCents: 1601, MonthEndCents: 5451, ObservedAt: t0}})
	got := views.rollup()
	if got == nil || got.Currency != "BRL" || !got.ObservedAt.Equal(t0) ||
		math.Abs(got.PerHour-0.1) > 1e-9 || math.Abs(got.MonthToDate-16.01) > 1e-9 || math.Abs(got.MonthForecast-54.51) > 1e-9 {
		t.Fatalf("rollup = %+v", got)
	}
}

func TestOCICostViewWithoutReportSaysWhy(t *testing.T) {
	ctx := context.Background()
	store, err := ocicost.OpenStore(ctx, testRolloutJetStream(t), 1)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	view := ociCostView(ctx, "gru", store, nil, now)
	if view.Missing == "" || view.OCIRegion != "sa-saopaulo-1" || view.Forecast.MonthEndCents != 0 {
		t.Fatalf("view without a report = %+v", view)
	}
}

func TestOCICostViewForecastsTheStoredReport(t *testing.T) {
	ctx := context.Background()
	store, err := ocicost.OpenStore(ctx, testRolloutJetStream(t), 1)
	if err != nil {
		t.Fatal(err)
	}
	report := ocicost.Report{Version: ocicost.Version, Cell: "gru", OCIRegion: "sa-saopaulo-1", Currency: "USD",
		ObservedAt: time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC),
		Through:    time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC),
		Components: []ocicost.Line{{Name: "controller", Cents: 300}}}
	for day := 1; day <= 8; day++ {
		report.Days = append(report.Days, ocicost.Day{Day: time.Date(2026, 10, day, 0, 0, 0, 0, time.UTC), Cents: 100})
	}
	report.Days = append(report.Days, ocicost.Day{Day: time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC), Cents: 40})
	if err := store.Put(ctx, report); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	view := ociCostView(ctx, "gru", store, nil, now)
	if view.Missing != "" || view.Forecast.MonthToDateCents != 840 || view.Forecast.MonthEndCents != 3100 {
		t.Fatalf("view = %+v", view)
	}
	if view.UntaggedCents != 540 || len(view.Components) != 1 {
		t.Fatalf("lines = %+v untagged %d", view.Components, view.UntaggedCents)
	}
}

func TestNodeCostPricesThePoolAndForecasts(t *testing.T) {
	ctx := context.Background()
	store, err := ocicost.OpenStore(ctx, testRolloutJetStream(t), 1)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	reads := 0
	recipe := func(context.Context) (nodescale.Recipe, error) {
		reads++
		return nodescale.Recipe{OCPUs: 4, MemoryGB: 24}, nil
	}
	views := &ociCostViews{store: store}
	cost := views.nodeCost(recipe, func() time.Time { return now })
	pool := nodescale.PoolState{Instances: []nodescale.PoolInstance{
		{Created: time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)},
		{Created: time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)},
	}}

	if _, err := cost(ctx, pool); err == nil {
		t.Fatal("cost without a report is not an error")
	}
	prices := []ocicost.Price{{SKU: "B91961", PerUnit: 0.1335}, {SKU: "B91962", PerUnit: 0.0089},
		{SKU: "B93297", PerUnit: 0}, {SKU: "B93298", PerUnit: 0}}
	if err := store.Put(ctx, nodeCostReport(now.Add(-2*time.Hour), nil)); err != nil {
		t.Fatal(err)
	}
	if _, err := cost(ctx, pool); err == nil {
		t.Fatal("cost without unit prices is not an error")
	}
	if err := store.Put(ctx, nodeCostReport(now.Add(-7*time.Hour), prices)); err != nil {
		t.Fatal(err)
	}
	if _, err := cost(ctx, pool); err == nil {
		t.Fatal("cost from a stale report is not an error")
	}

	report := nodeCostReport(now.Add(-2*time.Hour), prices)
	if err := store.Put(ctx, report); err != nil {
		t.Fatal(err)
	}
	got, err := cost(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	// One node is 1113 cents a month; the pool's two nodes are pending in the forecast.
	hosts := []ocicost.Host{{Created: pool.Instances[0].Created, MonthlyCents: 1113},
		{Created: pool.Instances[1].Created, MonthlyCents: 1113}}
	forecast := ocicost.Project(report, now, hosts)
	want := nodescale.Cost{NodeMonthlyCents: 1113, ProjectedCents: max(forecast.MonthEndCents, forecast.NextMonthCents),
		Currency: "BRL", At: report.ObservedAt}
	if got != want {
		t.Fatalf("cost = %+v, want %+v", got, want)
	}
	if nodes := views.nodes(); len(nodes) != 2 || nodes[1] != hosts[1] {
		t.Fatalf("nodes = %+v, want %+v", nodes, hosts)
	}
	if _, err := cost(ctx, pool); err != nil || reads != 1 {
		t.Fatalf("second cost err = %v, recipe reads = %d, want 1", err, reads)
	}
}

// nodeCostReport has one BRL day in the rate window and the given unit prices.
func nodeCostReport(observed time.Time, prices []ocicost.Price) ocicost.Report {
	return ocicost.Report{Version: ocicost.Version, Cell: "gru", OCIRegion: "sa-saopaulo-1", Currency: "BRL",
		ObservedAt: observed, Through: time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC),
		Days:   []ocicost.Day{{Day: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), Cents: 267}},
		Prices: prices}
}
