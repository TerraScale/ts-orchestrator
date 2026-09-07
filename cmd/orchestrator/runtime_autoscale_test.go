package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/autoscale"
)

func TestProductionAutoscaleAppliesOneNodePlan(t *testing.T) {
	now := time.Now().UTC()
	source := &runtimeAutoscaleSource{observations: []autoscale.Observation{{HostID: "h1", EngineID: "e1", Incarnation: "boot-1", Sequence: 1, ObservedAt: now, CPUPercent: 90, MemoryPercent: 90, Healthy: true, Authenticated: true}, {HostID: "h2", EngineID: "e2", Incarnation: "boot-2", Sequence: 1, ObservedAt: now, CPUPercent: 90, MemoryPercent: 90, Healthy: true, Authenticated: true}}}
	store := &runtimeAutoscaleTargets{target: autoscale.Target{Region: "gru", Members: 2}, found: true}
	controller, err := autoscale.New(autoscale.Config{Source: source, Targets: store, Authority: runtimeAutoscaleAuthority{}, MinMembers: 2, MaxMembers: 3, CPUThreshold: 80, MemoryThreshold: 80, HighSamples: 1, ObservationMaxAge: time.Minute, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	var applied int
	var lastTarget int
	runtime := &productionAutoscale{controller: controller, regions: []string{"gru"}, apply: func(region string, target int) error {
		if region != "gru" || target != 2 && target != 3 {
			t.Fatalf("target %s/%d", region, target)
		}
		lastTarget = target
		applied++
		return nil
	}}
	if err := runtime.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if applied != 2 || lastTarget != 3 {
		t.Fatalf("applied=%d", applied)
	}
}

type runtimeAutoscaleAuthority struct{}

func (runtimeAutoscaleAuthority) Check(context.Context) error { return nil }

type runtimeAutoscaleSource struct{ observations []autoscale.Observation }

func (s *runtimeAutoscaleSource) Observe(context.Context, string) ([]autoscale.Observation, error) {
	return s.observations, nil
}

type runtimeAutoscaleTargets struct {
	target autoscale.Target
	found  bool
}

func (s *runtimeAutoscaleTargets) Load(context.Context, string) (autoscale.Target, bool, error) {
	return s.target, s.found, nil
}
func (s *runtimeAutoscaleTargets) CompareAndSwap(_ context.Context, _ string, _ *autoscale.Target, next autoscale.Target) error {
	s.target, s.found = next, true
	return nil
}

func TestProductionAutoscaleHydratesBeforeObservationFailure(t *testing.T) {
	store := &runtimeAutoscaleTargets{target: autoscale.Target{Region: "gru", Members: 3}, found: true}
	var applied int
	source := failingRuntimeAutoscaleSource{check: func() {
		if applied != 3 {
			t.Fatal("telemetry read before durable target restored")
		}
	}}
	controller, err := autoscale.New(autoscale.Config{Source: source, Targets: store, Authority: runtimeAutoscaleAuthority{}, MinMembers: 2, MaxMembers: 6, CPUThreshold: 80, MemoryThreshold: 80, HighSamples: 3, ObservationMaxAge: time.Minute, Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	runtime := &productionAutoscale{controller: controller, regions: []string{"gru"}, apply: func(_ string, target int) error { applied = target; return nil }}
	if err := runtime.Reconcile(t.Context()); err == nil {
		t.Fatal("source failure hidden")
	}
	if applied != 3 {
		t.Fatal("durable target not restored")
	}
}

type failingRuntimeAutoscaleSource struct{ check func() }

func (s failingRuntimeAutoscaleSource) Observe(context.Context, string) ([]autoscale.Observation, error) {
	s.check()
	return nil, errors.New("telemetry unavailable")
}
