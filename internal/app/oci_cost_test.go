package app

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/nodescale"
	"github.com/TerraScale/ts-orchestrator/internal/ocicost"
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

func TestNodeCostHoldsWithoutInfrastructureAuthority(t *testing.T) {
	ctx := t.Context()
	store, err := ocicost.OpenStore(ctx, testRolloutJetStream(t), 1)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	report := ocicost.Report{Version: ocicost.Version, Cell: "gru", OCIRegion: "sa-saopaulo-1", Currency: "BRL",
		ObservedAt: now, Through: now.Add(-24 * time.Hour).Truncate(24 * time.Hour),
		Days:   []ocicost.Day{{Day: now.Add(-24 * time.Hour).Truncate(24 * time.Hour), Cents: 1}},
		Prices: []ocicost.Price{{SKU: "B91961", PerUnit: 0.1335}, {SKU: "B91962", PerUnit: 0.0089}, {SKU: "B93297", PerUnit: 0}, {SKU: "B93298", PerUnit: 0}}}
	if err := store.Put(ctx, report); err != nil {
		t.Fatal(err)
	}
	views := &ociCostViews{store: store, cell: "gru"}
	views.current.Store(ociCostView(ctx, "gru", store, nil, now))
	recipe := func(context.Context) (nodescale.Recipe, error) {
		return nodescale.Recipe{Cell: "gru", Capacity: nodescale.Capacity{Role: nodescale.RoleContainer, Architecture: "arm64", Shape: "VM.Standard.A1.Flex"}, OCPUs: 4, MemoryGB: 24}, nil
	}
	cost := views.nodeCost(nil, "ocid1.compartment.oc1..workload", recipe, func() time.Time { return now })
	if got, err := cost(ctx, nodescale.PoolState{}); err == nil || got.Currency != "" {
		t.Fatalf("Usage forecast admitted infrastructure cost without signed complete facts: %+v %v", got, err)
	}
	if views.nodes() != nil || views.view(ctx) == nil || views.view(ctx).Missing == "" || views.rollup() != nil {
		t.Fatal("pending accounting left stale priced capacity visible")
	}
}
