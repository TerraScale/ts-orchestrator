package observability

import (
	"context"
	"testing"
	"time"
)

func clockTestAllowList(t *testing.T) LabelAllowList {
	t.Helper()
	allow := DefaultLabelAllowList.Clone()
	allow["host"] = []string{"host-1", "host-2"}
	if err := allow.Validate(); err != nil {
		t.Fatalf("clock allow-list invalid: %v", err)
	}
	return allow
}

func TestClockObservationsWireOffsetAndHealth(t *testing.T) {
	allow := clockTestAllowList(t)
	now := time.Unix(1_700_000_000, 0).UTC()

	t.Run("healthy clock", func(t *testing.T) {
		observations, err := ClockObservations(allow, "gru", "host-1",
			ClockSample{OffsetMillis: 12, Measured: true, Unhealthy: false}, now)
		if err != nil {
			t.Fatal(err)
		}
		if len(observations) != 2 {
			t.Fatalf("expected two observations, got %#v", observations)
		}
		if observations[0].Name != ClockOffsetSecondsName || observations[0].Value != 0.012 {
			t.Fatalf("offset observation is %#v", observations[0])
		}
		if observations[1].Name != ClockUnhealthyName || observations[1].Value != 0 {
			t.Fatalf("health observation is %#v", observations[1])
		}
		for _, observation := range observations {
			if observation.Labels["region"] != "gru" || observation.Labels["host"] != "host-1" {
				t.Fatalf("labels are %#v", observation.Labels)
			}
		}
	})

	t.Run("unhealthy clock past refusal", func(t *testing.T) {
		observations, err := ClockObservations(allow, "sfo", "host-2",
			ClockSample{OffsetMillis: -750, Measured: true, Unhealthy: true}, now)
		if err != nil {
			t.Fatal(err)
		}
		if observations[0].Value != -0.75 || observations[1].Value != 1 {
			t.Fatalf("unhealthy clock is %#v", observations)
		}
	})

	t.Run("unreadable clock fails closed to unhealthy", func(t *testing.T) {
		observations, err := ClockObservations(allow, "fra", "host-1",
			ClockSample{OffsetMillis: 0, Measured: false, Unhealthy: true}, now)
		if err != nil {
			t.Fatal(err)
		}
		if observations[0].Value != 0 || observations[1].Value != 1 {
			t.Fatalf("unreadable clock is %#v", observations)
		}
	})

	t.Run("observations reach only the dashboard sink", func(t *testing.T) {
		dashboard := &recordingDashboard{}
		page := &recordingPage{}
		router, err := NewEventRouter(allow, dashboard, page)
		if err != nil {
			t.Fatal(err)
		}
		observations, err := ClockObservations(allow, "gru", "host-1",
			ClockSample{OffsetMillis: 100, Measured: true, Unhealthy: false}, now)
		if err != nil {
			t.Fatal(err)
		}
		for _, observation := range observations {
			if err := router.EmitObservation(context.Background(), observation); err != nil {
				t.Fatal(err)
			}
		}
		if len(dashboard.observations) != 2 || len(page.events) != 0 {
			t.Fatalf("clock crossed sinks: dashboard=%d page=%d", len(dashboard.observations), len(page.events))
		}
	})

	t.Run("invalid samples fail closed", func(t *testing.T) {
		valid := ClockSample{OffsetMillis: 0, Measured: true, Unhealthy: false}
		if _, err := ClockObservations(allow, "iad", "host-1", valid, now); err == nil {
			t.Fatal("unknown region was accepted")
		}
		if _, err := ClockObservations(allow, "gru", "host-9", valid, now); err == nil {
			t.Fatal("unknown host was accepted")
		}
		if _, err := ClockObservations(allow, "gru", "host-1",
			ClockSample{OffsetMillis: 0, Measured: false, Unhealthy: false}, now); err == nil {
			t.Fatal("unreadable healthy clock was accepted")
		}
		if _, err := ClockObservations(allow, "gru", "host-1",
			ClockSample{OffsetMillis: 5, Measured: false, Unhealthy: true}, now); err == nil {
			t.Fatal("unreadable nonzero clock was accepted")
		}
		if _, err := ClockObservations(allow, "gru", "host-1",
			ClockSample{OffsetMillis: maxClockOffsetMillis + 1, Measured: true, Unhealthy: true}, now); err == nil {
			t.Fatal("over-bound offset was accepted")
		}
		if _, err := ClockObservations(allow, "gru", "host-1",
			ClockSample{OffsetMillis: ClockWriteRefusalOffsetMillis + 1, Measured: true, Unhealthy: false}, now); err == nil {
			t.Fatal("contradictory clock health was accepted")
		}
	})
}

func TestClockApproachingRefusalWarnLine(t *testing.T) {
	for _, offset := range []int64{400, -400, 499} {
		approaching, err := ClockApproachingRefusal(ClockSample{OffsetMillis: offset, Measured: true, Unhealthy: offset >= 500 || offset <= -500})
		if err != nil || !approaching {
			t.Fatalf("offset %d: approaching=%v err=%v", offset, approaching, err)
		}
	}
	approaching, err := ClockApproachingRefusal(ClockSample{OffsetMillis: 399, Measured: true})
	if err != nil || approaching {
		t.Fatalf("399 ms must not warn: %v %v", approaching, err)
	}
	approaching, err = ClockApproachingRefusal(ClockSample{Measured: false, Unhealthy: true})
	if err != nil || approaching {
		t.Fatalf("unreadable clock must not use the warn line: %v %v", approaching, err)
	}
	if _, err := ClockApproachingRefusal(ClockSample{Measured: false}); err == nil {
		t.Fatal("invalid sample was accepted")
	}
}
