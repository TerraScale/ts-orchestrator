package app

import (
	"math"
	"testing"
	"time"

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
