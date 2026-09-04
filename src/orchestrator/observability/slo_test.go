package observability

import (
	"context"
	"math"
	"testing"
	"time"
)

func nan() float64 { return math.NaN() }

func inf() float64 { return math.Inf(1) }

func TestBurnRateConvertsErrorRatioToBudgetMultiple(t *testing.T) {
	spec := SLOSpec{Target: SLOAPIAvailabilityTarget}
	rate, err := BurnRate(0.01, spec)
	if err != nil {
		t.Fatal(err)
	}
	if rate < 9.99 || rate > 10.01 {
		t.Fatalf("burn rate is %v, want ~10", rate)
	}
	rate, err = BurnRate(0, spec)
	if err != nil {
		t.Fatal(err)
	}
	if rate != 0 {
		t.Fatalf("zero errors must burn nothing, got %v", rate)
	}
	for name, ratio := range map[string]float64{"negative": -0.1, "above one": 1.1, "NaN": nan(), "Inf": inf()} {
		t.Run("ratio "+name, func(t *testing.T) {
			if _, err := BurnRate(ratio, spec); err == nil {
				t.Fatal("invalid error ratio was accepted")
			}
		})
	}
	for name, target := range map[string]float64{"zero": 0, "one": 1, "above one": 2, "NaN": nan(), "Inf": inf()} {
		t.Run("target "+name, func(t *testing.T) {
			if _, err := BurnRate(0.01, SLOSpec{Target: target}); err == nil {
				t.Fatal("invalid SLO target was accepted")
			}
		})
	}
}

func TestEvaluateSLOBurnPagesOnlyOnConfirmedBurn(t *testing.T) {
	allow := DefaultLabelAllowList.Clone()
	labels := map[string]string{"region": "gru"}
	now := time.Unix(1_700_000_000, 0).UTC()

	t.Run("fast burn pages on 1h", func(t *testing.T) {
		event, err := EvaluateSLOBurn(allow, labels, SLOBurnWindows{
			FastLong: 14.4, FastShort: 14.4, SlowLong: 1, SlowShort: 1,
		}, now)
		if err != nil {
			t.Fatal(err)
		}
		if event == nil || event.Name != SLOAPIBurnMetric || event.Window != FastBurnLongWindow || event.BurnRate != 14.4 {
			t.Fatalf("unexpected fast-burn event: %#v", event)
		}
	})

	t.Run("slow burn pages on 6h", func(t *testing.T) {
		event, err := EvaluateSLOBurn(allow, labels, SLOBurnWindows{
			FastLong: 1, FastShort: 1, SlowLong: 6, SlowShort: 6,
		}, now)
		if err != nil {
			t.Fatal(err)
		}
		if event == nil || event.Window != SlowBurnLongWindow || event.BurnRate != 6 {
			t.Fatalf("unexpected slow-burn event: %#v", event)
		}
	})

	t.Run("fast wins when both burn", func(t *testing.T) {
		event, err := EvaluateSLOBurn(allow, labels, SLOBurnWindows{
			FastLong: 20, FastShort: 20, SlowLong: 10, SlowShort: 10,
		}, now)
		if err != nil {
			t.Fatal(err)
		}
		if event == nil || event.Window != FastBurnLongWindow {
			t.Fatalf("fast tier must win: %#v", event)
		}
	})

	t.Run("short spike alone never pages", func(t *testing.T) {
		for _, windows := range []SLOBurnWindows{
			{FastLong: 1, FastShort: 100, SlowLong: 1, SlowShort: 1},
			{FastLong: 1, FastShort: 1, SlowLong: 1, SlowShort: 100},
		} {
			event, err := EvaluateSLOBurn(allow, labels, windows, now)
			if err != nil {
				t.Fatal(err)
			}
			if event != nil {
				t.Fatalf("unconfirmed spike paged: %#v", event)
			}
		}
	})

	t.Run("healthy burn is dashboard-only", func(t *testing.T) {
		event, err := EvaluateSLOBurn(allow, labels, SLOBurnWindows{
			FastLong: 2, FastShort: 2, SlowLong: 2, SlowShort: 2,
		}, now)
		if err != nil {
			t.Fatal(err)
		}
		if event != nil {
			t.Fatalf("below-threshold burn paged: %#v", event)
		}
	})

	t.Run("invalid inputs fail closed", func(t *testing.T) {
		valid := SLOBurnWindows{FastLong: 1, FastShort: 1, SlowLong: 1, SlowShort: 1}
		if _, err := EvaluateSLOBurn(allow, map[string]string{"region": "iad"}, valid, now); err == nil {
			t.Fatal("unknown region was accepted")
		}
		if _, err := EvaluateSLOBurn(allow, map[string]string{"tenant_id": "c1"}, valid, now); err == nil {
			t.Fatal("customer dimension was accepted")
		}
		if _, err := EvaluateSLOBurn(nil, labels, valid, now); err == nil {
			t.Fatal("nil allow-list was accepted")
		}
		if _, err := EvaluateSLOBurn(allow, labels, SLOBurnWindows{FastLong: -1}, now); err == nil {
			t.Fatal("negative burn was accepted")
		}
		if _, err := EvaluateSLOBurn(allow, labels, SLOBurnWindows{SlowShort: inf()}, now); err == nil {
			t.Fatal("infinite burn was accepted")
		}
	})
}

func TestEvaluateSLOBurnEventReachesOnlyThePageSink(t *testing.T) {
	allow := DefaultLabelAllowList.Clone()
	dashboard := &recordingDashboard{}
	page := &recordingPage{}
	router, err := NewEventRouter(allow, dashboard, page)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	event, err := EvaluateSLOBurn(allow, map[string]string{"region": "sfo"}, SLOBurnWindows{
		FastLong: 14.4, FastShort: 15, SlowLong: 1, SlowShort: 1,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if event == nil {
		t.Fatal("fast burn did not evaluate to a page")
	}
	if err := router.EmitPage(context.Background(), *event); err != nil {
		t.Fatalf("evaluated page was rejected: %v", err)
	}
	if len(page.events) != 1 || len(dashboard.observations) != 0 {
		t.Fatalf("page crossed sinks: dashboard=%d page=%d", len(dashboard.observations), len(page.events))
	}
}

func TestSLOBurnDashboardObservationNeverPages(t *testing.T) {
	allow := DefaultLabelAllowList.Clone()
	dashboard := &recordingDashboard{}
	page := &recordingPage{}
	router, err := NewEventRouter(allow, dashboard, page)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	observation, err := SLOBurnDashboardObservation(allow, map[string]string{"region": "fra"}, 2.5, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := router.EmitObservation(context.Background(), observation); err != nil {
		t.Fatal(err)
	}
	if len(dashboard.observations) != 1 || len(page.events) != 0 {
		t.Fatalf("dashboard burn crossed sinks: dashboard=%d page=%d", len(dashboard.observations), len(page.events))
	}
	if _, err := SLOBurnDashboardObservation(allow, map[string]string{"region": "fra"}, -1, now); err == nil {
		t.Fatal("negative dashboard burn was accepted")
	}
	if _, err := SLOBurnDashboardObservation(allow, map[string]string{"region": "iad"}, 1, now); err == nil {
		t.Fatal("unknown region was accepted")
	}
}
