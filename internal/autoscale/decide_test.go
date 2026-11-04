package autoscale

import (
	"context"
	"math"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

func cpuPolicy() Policy {
	return Policy{
		Signals:                  []Signal{{Name: SignalCPUUtilization, Target: 0.6}},
		UpStabilizationSeconds:   60,
		DownStabilizationSeconds: 600,
		UpCooldownSeconds:        120,
		DownCooldownSeconds:      900,
		MaxStepUp:                4,
		MaxStepDown:              1,
		Tolerance:                0.1,
	}
}

func cpu(value float64) []Reading {
	return []Reading{{Signal: SignalCPUUtilization, Value: value, Samples: 5}}
}

// TestDecideConvergesWithoutFlapping drives a noisy load around the target and
// requires the replica count to stay put, then follows a sustained step.
func TestDecideConvergesWithoutFlapping(t *testing.T) {
	policy := cpuPolicy()
	bounds := Bounds{Min: 2, Max: 10}
	history := Reset(t0.Add(-time.Hour))
	current := 4
	changes := 0
	now := t0
	for i := range 120 {
		load := 0.6
		if i%2 == 0 {
			load = 0.75 // alternating spikes outside the band
		} else {
			load = 0.45
		}
		decision := Decide(policy, Input{Current: current, Bounds: bounds, Readings: cpu(load), Now: now}, history)
		history = decision.History
		if decision.Changed() {
			changes++
		}
		current = decision.To
		now = now.Add(15 * time.Second)
	}
	if changes > 1 {
		t.Fatalf("noisy load caused %d changes", changes)
	}
	for range 40 {
		decision := Decide(policy, Input{Current: current, Bounds: bounds, Readings: cpu(1.2), Now: now}, history)
		history = decision.History
		current = decision.To
		now = now.Add(15 * time.Second)
	}
	if current != 10 {
		t.Fatalf("sustained double load ended at %d replicas, want max 10", current)
	}
}

func TestWindowStoreAggregatesInsideWindow(t *testing.T) {
	store := NewWindowStore(10*time.Minute, 5)
	target := Target{Cell: "gru", Environment: "prod", Role: "api"}
	for i, value := range []float64{0.1, 0.2, 0.3, 0.4, 0.5, 0.6} {
		store.Record(target, SignalCPUUtilization, Sample{At: t0.Add(time.Duration(i) * time.Second), Value: value})
	}
	store.Record(target, SignalCPUUtilization, Sample{At: t0, Value: math.NaN()})
	signal := Signal{Name: SignalCPUUtilization, Target: 0.5, WindowSeconds: 3, Aggregation: AggregateMax}
	reading, err := store.Read(context.Background(), target, signal, t0.Add(5*time.Second))
	if err != nil || reading.Samples != 4 || reading.Value != 0.6 {
		t.Fatalf("reading = %#v, %v", reading, err)
	}
	other, _ := store.Read(context.Background(), Target{Cell: "gru", Role: "web"}, signal, t0.Add(5*time.Second))
	if other.Samples != 0 {
		t.Fatalf("series leaked across targets: %#v", other)
	}
	readings := Collect(context.Background(), store, target, Policy{Signals: []Signal{signal}}, t0.Add(5*time.Second))
	if len(readings) != 1 || readings[0].Signal != SignalCPUUtilization {
		t.Fatalf("Collect = %#v", readings)
	}
}

// Signals never scale a service to zero: per-replica signals are undefined
// at zero, so nothing could bring it back.
func TestDecideNeverSignalScalesToZero(t *testing.T) {
	policy := Policy{Signals: []Signal{{Name: SignalCPUUtilization, Target: 0.5}}}
	decision := Decide(policy, Input{Current: 3, Bounds: Bounds{Min: 0, Max: 10}, Readings: cpu(0), Now: t0}, History{})
	if decision.To != 1 || decision.Reason != ReasonScaleDown {
		t.Fatalf("idle 3 replicas with min 0 = %+v, want a scale down to 1", decision)
	}
	decision = Decide(policy, Input{Current: 1, Bounds: Bounds{Min: 0, Max: 10}, Readings: cpu(0), Now: t0}, History{})
	if decision.To != 1 || decision.Changed() {
		t.Fatalf("idle single replica with min 0 = %+v, want a hold", decision)
	}
}
