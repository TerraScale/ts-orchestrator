package app

import (
	"context"
	"math"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ocicost"
)

func TestOCICostViewsRollupReadsTheLatestView(t *testing.T) {
	t0 := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	views := &ociCostViews{}
	if views.nodes() != nil {
		t.Fatal("nodes without a hosts source are not nil")
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
