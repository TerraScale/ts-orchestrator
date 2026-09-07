package autoscale

import (
	"context"
	"errors"
	"reflect"
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
	if expected == nil && s.found || expected != nil && (!s.found || !reflect.DeepEqual(*expected, s.value)) {
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
	return []Observation{{HostID: "host-a", EngineID: "engine-a", Incarnation: "boot-a", Sequence: sequence, ObservedAt: now, CPUPercent: 90, MemoryPercent: 90, QueueDepth: 10, QueueCapacity: 20, Healthy: true, Authenticated: true}, {HostID: "host-b", EngineID: "engine-b", Incarnation: "boot-b", Sequence: sequence, ObservedAt: now, CPUPercent: 90, MemoryPercent: 90, QueueDepth: 10, QueueCapacity: 20, Healthy: true, Authenticated: true}}
}

func lowObservationsWithProof(now time.Time, sequence int64) []Observation {
	proof := ProofSnapshot{HeadroomMeasured: true, ResidencyVerified: true, QuorumVerified: true, Databases: []DatabaseProof{{
		Tenant: "tenant", Project: "project", Database: "db", RegionalCaughtUp: true, BackupCaughtUp: true,
		CausalCaughtUp: true, SourceSequence: 7, RegionalSequence: 7, BackupSourceSequence: 7, BackupProtectedSequence: 7,
	}}}
	return []Observation{
		{MemberSlot: 1, ProviderResourceID: "oci-a", HostID: "host-a", EngineID: "engine-a", Incarnation: "boot-a", Sequence: sequence, ObservedAt: now, CPUPercent: 10, MemoryPercent: 10, QueueCapacity: 20, Healthy: true, Authenticated: true, Proof: proof},
		{MemberSlot: 2, ProviderResourceID: "oci-b", HostID: "host-b", EngineID: "engine-b", Incarnation: "boot-b", Sequence: sequence, ObservedAt: now, CPUPercent: 20, MemoryPercent: 20, QueueCapacity: 20, Healthy: true, Authenticated: true, Proof: proof},
		{MemberSlot: 3, ProviderResourceID: "oci-c", HostID: "host-c", EngineID: "engine-c", Incarnation: "boot-c", Sequence: sequence, ObservedAt: now, CPUPercent: 30, MemoryPercent: 30, QueueCapacity: 20, Healthy: true, Authenticated: true, Proof: proof},
	}
}

func TestEvaluateCreatesOneDurableScaleDownIntent(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	source := &testSource{observations: lowObservationsWithProof(now, 1)}
	targets := &testTargets{value: Target{Region: "gru", Members: 3}, found: true}
	c := testController(t, source, targets, now)
	for sequence := int64(1); sequence <= 2; sequence++ {
		source.observations = lowObservationsWithProof(now, sequence)
		if _, created, err := c.Evaluate(t.Context(), "gru"); err != nil || created {
			t.Fatalf("early scale-down = %v, %v", created, err)
		}
	}
	source.observations = lowObservationsWithProof(now, 3)
	plan, created, err := c.Evaluate(t.Context(), "gru")
	if err != nil || !created || plan.DesiredMembers != 2 || plan.PreviousMembers != 3 || plan.RemovalHostID != "host-c" || plan.RemovalSlot != 3 || plan.RemovalResourceID != "oci-c" || plan.RemovalPhase != "intent" || plan.OperationID == "" {
		t.Fatalf("scale-down plan = %+v created=%v err=%v", plan, created, err)
	}
	if targets.value.Members != 2 || targets.value.RemovalOperationID != plan.OperationID {
		t.Fatalf("durable removal state = %+v", targets.value)
	}
	// A restarted controller replays the retained operation without another
	// target write or a second decrement.
	writes := targets.writes
	c = testController(t, source, targets, now)
	replay, created, err := c.Evaluate(t.Context(), "gru")
	if err != nil || !created || replay.OperationID != plan.OperationID || replay.DesiredMembers != 2 || targets.writes != writes {
		t.Fatalf("removal replay = %+v created=%v writes=%d/%d err=%v", replay, created, targets.writes, writes, err)
	}
}

func TestEvaluateScaleDownFailsClosedWithoutProof(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	source := &testSource{observations: lowObservationsWithProof(now, 1)}
	source.observations[0].Proof.HeadroomMeasured = false
	targets := &testTargets{value: Target{Region: "gru", Members: 3}, found: true}
	c := testController(t, source, targets, now)
	for sequence := int64(1); sequence <= 3; sequence++ {
		source.observations = lowObservationsWithProof(now, sequence)
		source.observations[0].Proof.HeadroomMeasured = false
		if _, created, err := c.Evaluate(t.Context(), "gru"); err != nil || created {
			t.Fatalf("unqualified scale-down = %v, %v", created, err)
		}
	}
	if targets.value.Members != 3 || targets.value.RemovalOperationID != "" {
		t.Fatalf("unqualified target changed = %+v", targets.value)
	}
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

func TestEvaluateAcceptsIndependentHostSequences(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	source := &testSource{observations: []Observation{
		{HostID: "host-a", EngineID: "engine-a", Incarnation: "boot-a", Sequence: 17, ObservedAt: now, CPUPercent: 90, MemoryPercent: 90, Healthy: true, Authenticated: true},
		{HostID: "host-b", EngineID: "engine-b", Incarnation: "boot-b", Sequence: 12, ObservedAt: now, CPUPercent: 90, MemoryPercent: 90, Healthy: true, Authenticated: true},
	}}
	targets := &testTargets{value: Target{Region: "gru", Members: 2}, found: true}
	c := testController(t, source, targets, now)
	_, created, err := c.Evaluate(context.Background(), "gru")
	if err != nil || created {
		t.Fatalf("first independent sample = created %v, err %v", created, err)
	}
	source.observations[0].Sequence = 18
	source.observations[1].Sequence = 13
	_, created, err = c.Evaluate(context.Background(), "gru")
	if err != nil || created {
		t.Fatalf("second independent sample = created %v, err %v", created, err)
	}
	source.observations[0].Sequence = 19
	source.observations[1].Sequence = 14
	plan, created, err := c.Evaluate(context.Background(), "gru")
	if err != nil || !created || plan.ObservationSeq != 19 || plan.DesiredMembers != 3 {
		t.Fatalf("independent sample plan = %+v, created %v, err %v", plan, created, err)
	}
}

func TestEvaluateHoldsWhenOneHostIsStaleOrRebootedAlone(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	source := &testSource{observations: highObservations(now, 1)}
	targets := &testTargets{value: Target{Region: "gru", Members: 2}, found: true}
	c := testController(t, source, targets, now)
	for sequence := int64(1); sequence <= 2; sequence++ {
		source.observations = highObservations(now, sequence)
		if _, _, err := c.Evaluate(context.Background(), "gru"); err != nil {
			t.Fatal(err)
		}
	}
	source.observations = highObservations(now, 3)
	source.observations[1].Sequence = 2
	if _, created, err := c.Evaluate(context.Background(), "gru"); err != nil || created {
		t.Fatalf("stale host created=%v err=%v", created, err)
	}
	source.observations = highObservations(now, 4)
	source.observations[0].Incarnation = "boot-a-new"
	source.observations[0].Sequence = 1
	source.observations[1].Sequence = 2
	if _, created, err := c.Evaluate(context.Background(), "gru"); err != nil || created {
		t.Fatalf("single-host reboot created=%v err=%v", created, err)
	}
}

func TestMembershipChangeRebaselinesAndPreservesRemovedHostFreshness(t *testing.T) {
	now := time.Now().UTC()
	source := &testSource{observations: highObservations(now, 1)}
	targets := &testTargets{value: Target{Region: "gru", Members: 3}, found: true}
	c := testController(t, source, targets, now)
	evaluate := func() bool {
		t.Helper()
		_, created, err := c.Evaluate(t.Context(), "gru")
		if err != nil {
			t.Fatal(err)
		}
		return created
	}
	evaluate()
	source.observations = highObservations(now, 2)
	evaluate()
	source.observations = append(highObservations(now, 3), Observation{HostID: "host-c", EngineID: "engine-c", Incarnation: "boot-c", Sequence: 1, ObservedAt: now, CPUPercent: 90, MemoryPercent: 90, QueueDepth: 10, QueueCapacity: 20, Healthy: true, Authenticated: true})
	if evaluate() || targets.value.ConsecutiveHighSamples != 0 || len(targets.value.ActiveHosts) != 3 {
		t.Fatalf("membership transition did not baseline: %+v", targets.value)
	}
	for i := range 3 {
		for j := range source.observations {
			source.observations[j].Sequence++
		}
		if got := evaluate(); got != (i == 2) {
			t.Fatalf("fresh sample %d created=%v", i, got)
		}
	}
	// Remove C, then replay its consumed sample on re-admission. Tombstones
	// survive the membership baseline, including after controller restart.
	oldC := source.observations[2]
	source.observations = highObservations(now, 7)
	evaluate()
	c = testController(t, source, targets, now)
	source.observations = append(highObservations(now, 8), oldC)
	writes := targets.writes
	if evaluate() || targets.writes != writes {
		t.Fatal("removed host replay was admitted")
	}
	source.observations[2].Sequence++
	evaluate()
	if len(targets.value.ActiveHosts) != 3 || targets.value.ConsecutiveHighSamples != 0 {
		t.Fatal("fresh returning member did not baseline")
	}
}

func TestRebootBaselinesAndRetiredBootReplayCannotAccumulatePressure(t *testing.T) {
	now := time.Now().UTC()
	source := &testSource{observations: highObservations(now.Add(-30*time.Second), 10)}
	targets := &testTargets{value: Target{Region: "gru", Members: 2}, found: true}
	c := testController(t, source, targets, now)
	evaluate := func() bool {
		t.Helper()
		_, created, err := c.Evaluate(t.Context(), "gru")
		if err != nil {
			t.Fatal(err)
		}
		return created
	}
	evaluate()
	source.observations = highObservations(now.Add(-20*time.Second), 11)
	evaluate()
	source.observations[0].Incarnation, source.observations[0].Sequence = "boot-a-new", 1
	source.observations[0].ObservedAt = now.Add(-10 * time.Second)
	source.observations[1].Sequence++
	if evaluate() || targets.value.ConsecutiveHighSamples != 0 {
		t.Fatal("reboot counted pressure instead of baseline")
	}
	// Restart the controller: retired boot knowledge must be durable.
	c = testController(t, source, targets, now)
	fresh := append([]Observation(nil), source.observations...)
	source.observations[0].Incarnation, source.observations[0].Sequence = "boot-a", 99
	source.observations[1].Sequence++
	writes := targets.writes
	if evaluate() || targets.writes != writes {
		t.Fatal("retired boot replay was admitted")
	}
	source.observations = fresh
	for i := range 3 {
		for j := range source.observations {
			source.observations[j].Sequence++
		}
		if got := evaluate(); got != (i == 2) {
			t.Fatalf("new boot fresh sample %d created=%v", i, got)
		}
	}
	// Retention is bounded by signed-report freshness; after expiry the old
	// report itself is stale, even after the retired-ID entry is pruned.
	now = now.Add(2 * time.Minute)
	c = testController(t, source, targets, now)
	for j := range source.observations {
		source.observations[j].Sequence++
		source.observations[j].ObservedAt = now
	}
	evaluate()
	if len(targets.value.RetiredIncarnations) != 0 {
		t.Fatal("expired boot tombstones retained")
	}
	source.observations[0].Incarnation = "boot-a"
	source.observations[0].ObservedAt = now.Add(-2 * time.Minute)
	writes = targets.writes
	if evaluate() || targets.writes != writes {
		t.Fatal("expired retired boot report passed freshness")
	}
}

func TestRemovalCompletionSurvivesRestartAndReleasesFreshPressure(t *testing.T) {
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	source := &testSource{observations: lowObservationsWithProof(now, 1)}
	targets := &testTargets{value: Target{Region: "gru", Members: 3}, found: true}
	config := Config{Source: source, Targets: targets, Authority: testAuthority{}, MinMembers: 2, MaxMembers: 5, CPUThreshold: 80, MemoryThreshold: 80, QueueThreshold: 8, HighSamples: 3, LowSamples: 1, ObservationMaxAge: time.Minute, Now: func() time.Time { return now }}
	c, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	plan, created, err := c.Evaluate(t.Context(), "gru")
	if err != nil || !created {
		t.Fatalf("intent: %+v %v %v", plan, created, err)
	}
	retained := targets.value
	complete := false
	config.RemovalComplete = func(_ context.Context, target Target) (bool, error) {
		if target.RemovalOperationID != plan.OperationID || target.RemovalResourceID != "oci-c" || target.RemovalIncarnation != "boot-c" {
			t.Fatalf("completion identity: %+v", target)
		}
		return complete, nil
	}
	// A successor with high-pressure telemetry still retains an unknown removal.
	c, err = New(config)
	if err != nil {
		t.Fatal(err)
	}
	for sequence := int64(2); sequence <= 5; sequence++ {
		source.observations = highObservations(now, sequence)
		replay, created, err := c.Evaluate(t.Context(), "gru")
		if err != nil || !created || replay.OperationID != plan.OperationID || !reflect.DeepEqual(targets.value, retained) {
			t.Fatalf("unknown outcome changed intent: %+v %v %v", replay, created, err)
		}
	}
	complete = true
	// The first complete survivor set establishes a baseline. The same old
	// pressure samples cannot immediately trigger another resize after removal.
	if _, created, err := c.Evaluate(t.Context(), "gru"); err != nil || created {
		t.Fatalf("completion: %v %v", created, err)
	}
	if targets.value.RemovalOperationID != "" || targets.value.RemovalResourceID != "" || targets.value.RemovalSlot != 0 || targets.value.Members != 2 {
		t.Fatalf("completion target: %+v", targets.value)
	}
	if completed := targets.value.CompletedRemovals[3]; completed.OperationID != plan.OperationID || completed.ResourceID != "oci-c" {
		t.Fatalf("exact completion receipt was not retained for slot reuse: %+v", completed)
	}
	for sequence := int64(6); sequence <= 8; sequence++ {
		source.observations = highObservations(now, sequence)
		plan, created, err = c.Evaluate(t.Context(), "gru")
		if err != nil || created != (sequence == 8) {
			t.Fatalf("fresh pressure %d: %+v %v %v", sequence, plan, created, err)
		}
	}
	if plan.DesiredMembers != 3 {
		t.Fatalf("scale-out remained frozen: %+v", plan)
	}
}

func TestRemovalCompletionRechecksAuthorityAndRetainsFailedRead(t *testing.T) {
	for _, denied := range []bool{false, true} {
		t.Run(map[bool]string{false: "unknown journal", true: "lost authority"}[denied], func(t *testing.T) {
			now := time.Now().UTC()
			targets := &testTargets{value: Target{Region: "gru", Members: 2, RemovalOperationID: "operation", RemovalHostID: "host-c", RemovalIncarnation: "boot-c", RemovalResourceID: "oci-c", RemovalSlot: 3}, found: true}
			c := testController(t, &testSource{}, targets, now)
			retained := targets.value
			c.config.RemovalComplete = func(context.Context, Target) (bool, error) {
				if denied {
					c.config.Authority = testAuthority{err: errors.New("lease lost")}
					return true, nil
				}
				return false, errors.New("journal unavailable")
			}
			if _, _, err := c.Evaluate(t.Context(), "gru"); err == nil {
				t.Fatal("failure hidden")
			}
			if !reflect.DeepEqual(targets.value, retained) || targets.writes != 0 {
				t.Fatal("unverified completion cleared intent")
			}
		})
	}
}

func TestRemovalRequiresCompleteAuthoritativeSlotBindings(t *testing.T) {
	now := time.Now().UTC()
	for _, corrupt := range []string{"missing resource", "duplicate slot", "partial membership"} {
		t.Run(corrupt, func(t *testing.T) {
			observations := lowObservationsWithProof(now, 1)
			switch corrupt {
			case "missing resource":
				observations[2].ProviderResourceID = ""
			case "duplicate slot":
				observations[2].MemberSlot = 2
			case "partial membership":
				observations = observations[:2]
			}
			targets := &testTargets{value: Target{Region: "gru", Members: 3}, found: true}
			c := testController(t, &testSource{observations: observations}, targets, now)
			c.config.LowSamples = 1
			if _, created, err := c.Evaluate(t.Context(), "gru"); err != nil || created {
				t.Fatalf("unbound removal: %v %v", created, err)
			}
			if targets.value.Members != 3 || targets.value.RemovalOperationID != "" {
				t.Fatal("unbound target decremented")
			}
		})
	}
}
