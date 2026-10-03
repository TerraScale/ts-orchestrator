package autoscale

import (
	"context"
	"errors"
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

func TestDecideTable(t *testing.T) {
	bounds := Bounds{Min: 2, Max: 10}
	longAgo := History{LastScaleUp: t0.Add(-time.Hour), LastScaleDown: t0.Add(-time.Hour)}
	steadyHigh := func(replicas int) History {
		h := longAgo
		h.Recommendations = []Recommendation{{At: t0.Add(-time.Minute), Replicas: replicas}}
		return h
	}
	steadyLow := func(replicas int) History {
		h := longAgo
		h.Recommendations = []Recommendation{
			{At: t0.Add(-10 * time.Minute), Replicas: replicas},
			{At: t0.Add(-5 * time.Minute), Replicas: replicas},
		}
		return h
	}
	tests := []struct {
		name       string
		policy     Policy
		current    int
		bounds     Bounds
		readings   []Reading
		history    History
		wantTo     int
		wantReason string
	}{
		{name: "below min corrects immediately", policy: cpuPolicy(), current: 1, bounds: bounds, history: History{LastScaleUp: t0}, wantTo: 2, wantReason: ReasonBelowMin},
		{name: "above max corrects immediately", policy: cpuPolicy(), current: 14, bounds: bounds, history: History{LastScaleDown: t0}, wantTo: 10, wantReason: ReasonAboveMax},
		{name: "zero replicas with zero min stay", policy: cpuPolicy(), current: 0, bounds: Bounds{Min: 0, Max: 3}, readings: cpu(5), history: longAgo, wantTo: 0, wantReason: ReasonScaledToZero},
		{name: "no readings hold", policy: cpuPolicy(), current: 4, bounds: bounds, history: longAgo, wantTo: 4, wantReason: ReasonNoSignalData},
		{name: "insufficient samples hold", policy: Policy{Signals: []Signal{{Name: SignalCPUUtilization, Target: 0.5, MinSamples: 10}}}, current: 4, bounds: bounds, readings: cpu(0.9), history: longAgo, wantTo: 4, wantReason: ReasonNoSignalData},
		{name: "NaN reading unavailable", policy: cpuPolicy(), current: 4, bounds: bounds, readings: cpu(math.NaN()), history: longAgo, wantTo: 4, wantReason: ReasonNoSignalData},
		{name: "negative reading unavailable", policy: cpuPolicy(), current: 4, bounds: bounds, readings: cpu(-1), history: longAgo, wantTo: 4, wantReason: ReasonNoSignalData},
		{name: "inside tolerance band", policy: cpuPolicy(), current: 4, bounds: bounds, readings: cpu(0.65), history: longAgo, wantTo: 4, wantReason: ReasonWithinTolerance},
		{name: "first high sample stabilizes", policy: cpuPolicy(), current: 4, bounds: bounds, readings: cpu(0.9), history: longAgo, wantTo: 4, wantReason: ReasonScaleUpStabilizing},
		{name: "sustained high scales up", policy: cpuPolicy(), current: 4, bounds: bounds, readings: cpu(0.9), history: steadyHigh(6), wantTo: 6, wantReason: ReasonScaleUp},
		{name: "scale up limited by step", policy: cpuPolicy(), current: 2, bounds: bounds, readings: cpu(3), history: steadyHigh(10), wantTo: 6, wantReason: ReasonScaleUp},
		{name: "scale up takes window minimum", policy: cpuPolicy(), current: 4, bounds: bounds, readings: cpu(1.2), history: steadyHigh(5), wantTo: 5, wantReason: ReasonScaleUp},
		{name: "scale up clamped to max", policy: cpuPolicy(), current: 9, bounds: bounds, readings: cpu(1.2), history: steadyHigh(10), wantTo: 10, wantReason: ReasonScaleUp},
		{name: "at max with high load", policy: cpuPolicy(), current: 10, bounds: bounds, readings: cpu(1.2), history: longAgo, wantTo: 10, wantReason: ReasonAtBound},
		{name: "at min with low load", policy: cpuPolicy(), current: 2, bounds: bounds, readings: cpu(0.1), history: longAgo, wantTo: 2, wantReason: ReasonAtBound},
		{name: "scale up cooldown", policy: cpuPolicy(), current: 4, bounds: bounds, readings: cpu(0.9), history: History{Recommendations: steadyHigh(6).Recommendations, LastScaleUp: t0.Add(-time.Minute)}, wantTo: 4, wantReason: ReasonScaleUpCooldown},
		{name: "first low sample stabilizes", policy: cpuPolicy(), current: 6, bounds: bounds, readings: cpu(0.2), history: longAgo, wantTo: 6, wantReason: ReasonScaleDownStabilizing},
		{name: "recent high recommendation blocks scale down", policy: cpuPolicy(), current: 6, bounds: bounds, readings: cpu(0.2), history: steadyHigh(6), wantTo: 6, wantReason: ReasonScaleDownStabilizing},
		{name: "sustained low scales down one step", policy: cpuPolicy(), current: 6, bounds: bounds, readings: cpu(0.2), history: steadyLow(2), wantTo: 5, wantReason: ReasonScaleDown},
		{name: "unbounded down step takes window max", policy: Policy{Signals: cpuPolicy().Signals, DownStabilizationSeconds: 600}, current: 6, bounds: bounds, readings: cpu(0.2), history: steadyLow(3), wantTo: 3, wantReason: ReasonScaleDown},
		{name: "scale down cooldown after any change", policy: cpuPolicy(), current: 6, bounds: bounds, readings: cpu(0.2), history: History{Recommendations: steadyLow(2).Recommendations, LastScaleUp: t0.Add(-10 * time.Minute)}, wantTo: 6, wantReason: ReasonScaleDownCooldown},
		{name: "reset history blocks immediate change", policy: cpuPolicy(), current: 6, bounds: bounds, readings: cpu(0.2), history: func() History { h := Reset(t0); h.Recommendations = steadyLow(2).Recommendations; return h }(), wantTo: 6, wantReason: ReasonScaleDownCooldown},
		{
			name:    "missing signal blocks scale down",
			policy:  Policy{Signals: []Signal{{Name: SignalCPUUtilization, Target: 0.6}, {Name: SignalMemoryUtilization, Target: 0.6}}},
			current: 6, bounds: bounds, readings: cpu(0.1), history: longAgo, wantTo: 6, wantReason: ReasonScaleDownSignalGap,
		},
		{
			name:    "missing signal does not block scale up",
			policy:  Policy{Signals: []Signal{{Name: SignalCPUUtilization, Target: 0.6}, {Name: SignalMemoryUtilization, Target: 0.6}}},
			current: 4, bounds: bounds, readings: cpu(1.2), history: longAgo, wantTo: 8, wantReason: ReasonScaleUp,
		},
		{
			name:    "largest signal wins scale up",
			policy:  Policy{Signals: []Signal{{Name: SignalCPUUtilization, Target: 0.5}, {Name: SignalMemoryUtilization, Target: 0.5}}},
			current: 2, bounds: bounds,
			readings: []Reading{{Signal: SignalCPUUtilization, Value: 0.75, Samples: 1}, {Signal: SignalMemoryUtilization, Value: 1.5, Samples: 1}},
			history:  longAgo, wantTo: 6, wantReason: ReasonScaleUp,
		},
		{
			name:    "one hot signal blocks scale down",
			policy:  Policy{Signals: []Signal{{Name: SignalCPUUtilization, Target: 0.5}, {Name: SignalMemoryUtilization, Target: 0.5}}},
			current: 6, bounds: bounds,
			readings: []Reading{{Signal: SignalCPUUtilization, Value: 0.1, Samples: 1}, {Signal: SignalMemoryUtilization, Value: 0.5, Samples: 1}},
			history:  longAgo, wantTo: 6, wantReason: ReasonWithinTolerance,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.policy.Validate(); err != nil {
				t.Fatalf("test policy invalid: %v", err)
			}
			decision := Decide(test.policy, Input{Current: test.current, Bounds: test.bounds, Readings: test.readings, Now: t0}, test.history)
			if decision.To != test.wantTo || decision.Reason != test.wantReason || decision.From != test.current {
				t.Fatalf("decision = %d->%d (%s), want %d->%d (%s)", decision.From, decision.To, decision.Reason,
					test.current, test.wantTo, test.wantReason)
			}
			if decision.Changed() != (test.wantTo != test.current) {
				t.Fatalf("Changed() = %v", decision.Changed())
			}
			if decision.To > test.current && !decision.History.LastScaleUp.Equal(t0) ||
				decision.To < test.current && !decision.History.LastScaleDown.Equal(t0) {
				t.Fatalf("history did not record the change: %#v", decision.History)
			}
		})
	}
}

func TestDecideDoesNotMutateHistoryAndPrunesOldRecommendations(t *testing.T) {
	policy := cpuPolicy()
	original := History{Recommendations: []Recommendation{
		{At: t0.Add(-time.Hour), Replicas: 9},
		{At: t0.Add(-30 * time.Second), Replicas: 7},
	}}
	snapshot := append([]Recommendation(nil), original.Recommendations...)
	decision := Decide(policy, Input{Current: 4, Bounds: Bounds{Min: 1, Max: 10}, Readings: cpu(0.9), Now: t0}, original)
	for i := range snapshot {
		if original.Recommendations[i] != snapshot[i] {
			t.Fatal("Decide mutated the caller history")
		}
	}
	if len(decision.History.Recommendations) != 2 || decision.History.Recommendations[0].Replicas != 7 ||
		decision.History.Recommendations[1] != (Recommendation{At: t0, Replicas: 6}) {
		t.Fatalf("recommendations = %#v", decision.History.Recommendations)
	}
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

func TestPolicyValidate(t *testing.T) {
	valid := cpuPolicy()
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	mutate := func(change func(*Policy)) Policy {
		p := cpuPolicy()
		p.Signals = append([]Signal(nil), p.Signals...)
		change(&p)
		return p
	}
	invalid := map[string]Policy{
		"no signals":         mutate(func(p *Policy) { p.Signals = nil }),
		"unknown signal":     mutate(func(p *Policy) { p.Signals[0].Name = "load" }),
		"repeated signal":    mutate(func(p *Policy) { p.Signals = append(p.Signals, p.Signals[0]) }),
		"zero target":        mutate(func(p *Policy) { p.Signals[0].Target = 0 }),
		"infinite target":    mutate(func(p *Policy) { p.Signals[0].Target = math.Inf(1) }),
		"long window":        mutate(func(p *Policy) { p.Signals[0].WindowSeconds = 7200 }),
		"bad aggregation":    mutate(func(p *Policy) { p.Signals[0].Aggregation = "median" }),
		"negative cooldown":  mutate(func(p *Policy) { p.DownCooldownSeconds = -1 }),
		"huge stabilization": mutate(func(p *Policy) { p.UpStabilizationSeconds = 100000 }),
		"negative step":      mutate(func(p *Policy) { p.MaxStepDown = -1 }),
		"wide tolerance":     mutate(func(p *Policy) { p.Tolerance = 0.9 }),
		"NaN tolerance":      mutate(func(p *Policy) { p.Tolerance = math.NaN() }),
	}
	for name, policy := range invalid {
		if err := policy.Validate(); !errors.Is(err, ErrInvalidPolicy) {
			t.Errorf("%s: Validate() = %v", name, err)
		}
	}
	for _, bounds := range []Bounds{{Min: -1, Max: 1}, {Min: 3, Max: 2}, {Min: 0, Max: MaxReplicas + 1}} {
		if err := bounds.Validate(); !errors.Is(err, ErrInvalidPolicy) {
			t.Errorf("bounds %#v accepted", bounds)
		}
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

func TestAggregate(t *testing.T) {
	values := []float64{5, 1, 3, 2, 4}
	for aggregation, want := range map[Aggregation]float64{AggregateAverage: 3, AggregateMax: 5, AggregateP95: 5} {
		if got := Aggregate(aggregation, values); got != want {
			t.Errorf("%s = %v, want %v", aggregation, got, want)
		}
	}
	if Aggregate(AggregateAverage, nil) != 0 {
		t.Fatal("empty aggregate is not zero")
	}
}

// A window evaluated at an interval that does not divide it must still become
// covered: the boundary observation older than the window is kept.
func TestDecideCoversWindowAtUnalignedInterval(t *testing.T) {
	policy := Policy{Signals: []Signal{{Name: SignalCPUUtilization, Target: 0.5}}, UpStabilizationSeconds: 60}
	history := History{}
	now := t0
	for range 12 {
		decision := Decide(policy, Input{Current: 2, Bounds: Bounds{Min: 1, Max: 10}, Readings: cpu(1), Now: now}, history)
		if decision.Changed() {
			if decision.To != 4 || decision.Reason != ReasonScaleUp {
				t.Fatalf("decision = %+v", decision)
			}
			return
		}
		history = decision.History
		now = now.Add(17 * time.Second)
	}
	t.Fatal("sustained load evaluated every 17s never covered a 60s window")
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

func TestWindowStoreDefaultRetentionCoversLongestWindow(t *testing.T) {
	store := NewWindowStore(0, 0)
	if store.retention < time.Duration(maxWindowSeconds)*time.Second {
		t.Fatalf("default retention %s is shorter than the longest policy window", store.retention)
	}
}
