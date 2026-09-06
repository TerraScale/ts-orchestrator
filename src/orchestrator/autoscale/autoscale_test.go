package autoscale

import (
	"context"
	"errors"
	"testing"
	"time"
)

type testSource struct{ observations []Observation }

func (s *testSource) Observe(context.Context, string) ([]Observation, error) {
	return append([]Observation(nil), s.observations...), nil
}

type testAuthority struct{ err error }

func (a testAuthority) Check(context.Context) error { return a.err }

type testTargets struct {
	value  Target
	found  bool
	writes int
}

func (s *testTargets) Load(context.Context, string) (Target, bool, error) {
	return s.value, s.found, nil
}
func (s *testTargets) CompareAndSwap(_ context.Context, _ string, expected *Target, next Target) error {
	if expected == nil && s.found || expected != nil && (!s.found || *expected != s.value) {
		return errors.New("conflict")
	}
	s.value, s.found, s.writes = next, true, s.writes+1
	return nil
}

func testController(t *testing.T, source ObservationSource, targets TargetStore, now time.Time) *Controller {
	t.Helper()
	c, err := New(Config{Source: source, Targets: targets, Authority: testAuthority{}, MinMembers: 2, MaxMembers: 5, CPUThreshold: 80, MemoryThreshold: 80, QueueThreshold: 8, HighSamples: 3, Cooldown: time.Hour, ObservationMaxAge: time.Minute, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func highObservations(now time.Time, sequence int64) []Observation {
	return []Observation{{HostID: "host-a", EngineID: "engine-a", Sequence: sequence, ObservedAt: now, CPUPercent: 90, MemoryPercent: 90, QueueDepth: 10, QueueCapacity: 20, Healthy: true, Authenticated: true}, {HostID: "host-b", EngineID: "engine-b", Sequence: sequence, ObservedAt: now, CPUPercent: 90, MemoryPercent: 90, QueueDepth: 10, QueueCapacity: 20, Healthy: true, Authenticated: true}}
}

func TestEvaluateRequiresThreeSamplesAndCreatesOneNodePlan(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	source := &testSource{observations: highObservations(now, 1)}
	targets := &testTargets{value: Target{Region: "gru", Members: 2}, found: true}
	c := testController(t, source, targets, now)
	for sequence := int64(1); sequence <= 2; sequence++ {
		source.observations = highObservations(now, sequence)
		if _, created, err := c.Evaluate(context.Background(), "gru"); err != nil || created {
			t.Fatalf("early plan = %v, %v", created, err)
		}
	}
	source.observations = highObservations(now, 3)
	plan, created, err := c.Evaluate(context.Background(), "gru")
	if err != nil || !created || plan.DesiredMembers != 3 || plan.PreviousMembers != 2 || targets.writes != 3 || plan.OperationID == "" {
		t.Fatalf("scale-out plan = %+v created=%v err=%v writes=%d", plan, created, err, targets.writes)
	}
}

func TestEvaluateCooldownAndInvalidObservationsHoldTarget(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	source := &testSource{observations: highObservations(now, 4)}
	targets := &testTargets{value: Target{Region: "gru", Members: 3, LastScaleAt: now}, found: true}
	c := testController(t, source, targets, now)
	for sequence := int64(4); sequence <= 6; sequence++ {
		source.observations = highObservations(now, sequence)
		if _, created, err := c.Evaluate(context.Background(), "gru"); err != nil || created {
			t.Fatalf("cooldown plan = %v, %v", created, err)
		}
	}
	if targets.value.Members != 3 {
		t.Fatal("cooldown changed target")
	}
	source.observations[0].HostID = source.observations[1].HostID
	if _, created, err := c.Evaluate(context.Background(), "gru"); err != nil || created {
		t.Fatalf("invalid observation plan = %v, %v", created, err)
	}
}
