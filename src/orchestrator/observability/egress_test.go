package observability

import (
	"context"
	"testing"
	"time"
)

func TestEgressObservationIsDashboardOnlyPerRegion(t *testing.T) {
	allow := DefaultLabelAllowList.Clone()
	now := time.Unix(1_700_000_000, 0).UTC()
	for _, region := range []string{"gru", "sfo", "fra"} {
		observation, err := EgressObservation(allow, region, 1.5e12, now)
		if err != nil {
			t.Fatalf("region %s rejected: %v", region, err)
		}
		if observation.Name != EgressBytesTotalName || observation.Labels["region"] != region || observation.Value != 1.5e12 {
			t.Fatalf("unexpected egress observation: %#v", observation)
		}
	}

	t.Run("routes to dashboard sink", func(t *testing.T) {
		dashboard := &recordingDashboard{}
		page := &recordingPage{}
		router, err := NewEventRouter(allow, dashboard, page)
		if err != nil {
			t.Fatal(err)
		}
		observation, err := EgressObservation(allow, "gru", 8e12, now)
		if err != nil {
			t.Fatal(err)
		}
		if err := router.EmitObservation(context.Background(), observation); err != nil {
			t.Fatal(err)
		}
		if len(dashboard.observations) != 1 || len(page.events) != 0 {
			t.Fatalf("egress crossed sinks: dashboard=%d page=%d", len(dashboard.observations), len(page.events))
		}
	})

	t.Run("invalid inputs fail closed", func(t *testing.T) {
		if _, err := EgressObservation(allow, "iad", 1, now); err == nil {
			t.Fatal("unknown region was accepted")
		}
		if _, err := EgressObservation(allow, "gru", -1, now); err == nil {
			t.Fatal("negative egress was accepted")
		}
		for name, value := range map[string]float64{"NaN": nan(), "Inf": inf(), "over bound": 1 << 62} {
			t.Run(name, func(t *testing.T) {
				if _, err := EgressObservation(allow, "gru", value, now); err == nil {
					t.Fatal("unbounded egress was accepted")
				}
			})
		}
		if _, err := EgressObservation(nil, "gru", 1, now); err == nil {
			t.Fatal("nil allow-list was accepted")
		}
	})
}

func TestEgressPaceMatchesMonthlyBudgetAlert(t *testing.T) {
	// The threshold is 8 TB over a 720-hour month, rounded down.
	if EgressHourlyPaceThresholdBytes != 11_111_111_111.0 {
		t.Fatalf("pace threshold is %v", EgressHourlyPaceThresholdBytes)
	}
	burning, err := EgressPaceExceedsMonthlyBudget(EgressHourlyPaceThresholdBytes + 1)
	if err != nil || !burning {
		t.Fatalf("over-pace egress = %v, %v", burning, err)
	}
	burning, err = EgressPaceExceedsMonthlyBudget(EgressHourlyPaceThresholdBytes)
	if err != nil || burning {
		t.Fatalf("at-threshold egress must not fire: %v, %v", burning, err)
	}
	burning, err = EgressPaceExceedsMonthlyBudget(0)
	if err != nil || burning {
		t.Fatalf("idle egress = %v, %v", burning, err)
	}
	for name, value := range map[string]float64{"negative": -1, "NaN": nan(), "Inf": inf()} {
		t.Run(name, func(t *testing.T) {
			if _, err := EgressPaceExceedsMonthlyBudget(value); err == nil {
				t.Fatal("invalid hourly increase was accepted")
			}
		})
	}
}
