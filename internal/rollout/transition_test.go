package rollout

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"
)

var (
	fromDigest = strings.Repeat("a", 64)
	toDigest   = strings.Repeat("b", 64)
	otherBad   = strings.Repeat("c", 64)
	testStart  = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
)

func controllers() []Unit {
	return []Unit{{ID: "ctrl-a", Group: "controllers", Seed: true}, {ID: "ctrl-b", Group: "controllers"}, {ID: "ctrl-c", Group: "controllers"}}
}

func seats() []Unit {
	return []Unit{
		{ID: "p1-a", Group: "p1"}, {ID: "p1-b", Group: "p1"},
		{ID: "p2-a", Group: "p2"}, {ID: "p2-b", Group: "p2"},
	}
}

func testPolicy() Policy {
	policy := DefaultPolicy()
	policy.MinHealthyReports = 2
	return policy
}

func newRecord(t *testing.T, units []Unit, policy Policy) Record {
	t.Helper()
	record, err := New(Spec{
		RolloutID: "0000000000039PRXZD4Z9STA2E", Kind: KindController, Cell: "gru", FromDigest: fromDigest, ToDigest: toDigest,
		Units: units, Policy: policy, AuthorityEpoch: 7,
	}, testStart)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func apply(t *testing.T, record Record, event Event) Record {
	t.Helper()
	next, err := Apply(record, event)
	if err != nil {
		t.Fatalf("%s at %s: %v", event.Kind, record.Phase, err)
	}
	return next
}

func health(at time.Time, pid int64) Health {
	return Health{Digest: toDigest, ProcessID: pid, StartNonce: fmt.Sprintf("%032x", pid), ObservedAt: at}
}

// soakWave prepares every unit of the current wave and feeds reports from
// one incarnation until the soak passes.
func soakWave(t *testing.T, record Record, at time.Time) (Record, time.Time) {
	t.Helper()
	wave := record.WaveIndex
	for _, id := range record.Waves[wave] {
		record = apply(t, record, Event{Kind: EventPrepared, Unit: id, At: at})
	}
	soak := record.soakDuration()
	for report := range record.Policy.MinHealthyReports {
		at = at.Add(time.Second)
		for _, id := range record.Waves[wave] {
			if record.Phase.Terminal() || record.WaveIndex != wave {
				break
			}
			record = apply(t, record, Event{Kind: EventHealthy, Unit: id, Health: health(at, 100), At: at})
		}
		_ = report
	}
	// The observations themselves must span the soak window: every unit
	// reports again once the window has passed.
	at = at.Add(soak)
	for _, id := range record.Waves[wave] {
		if record.Phase.Terminal() || record.WaveIndex != wave {
			break
		}
		record = apply(t, record, Event{Kind: EventHealthy, Unit: id, Health: health(at, 100), At: at})
	}
	if record.Phase.Terminal() {
		return record, at
	}
	return apply(t, record, Event{Kind: EventTick, At: at}), at
}

func TestPlanWavesKeepsQuorumAndSeedLast(t *testing.T) {
	policy := DefaultPolicy()
	waves, err := PlanWaves(controllers(), policy)
	if err != nil {
		t.Fatal(err)
	}
	if want := [][]string{{"ctrl-b"}, {"ctrl-c"}, {"ctrl-a"}}; !slices.EqualFunc(waves, want, slices.Equal) {
		t.Fatalf("controller waves = %v, want %v", waves, want)
	}
	policy.BatchSize = 4
	waves, err = PlanWaves(seats(), policy)
	if err != nil {
		t.Fatal(err)
	}
	if want := [][]string{{"p1-a"}, {"p1-b", "p2-a"}, {"p2-b"}}; !slices.EqualFunc(waves, want, slices.Equal) {
		t.Fatalf("seat waves = %v, want %v", waves, want)
	}
	for _, wave := range waves {
		groups := map[string]bool{}
		for _, id := range wave {
			group := id[:2]
			if groups[group] {
				t.Fatalf("wave %v takes both seats of %s", wave, group)
			}
			groups[group] = true
		}
	}
	reversed := slices.Clone(seats())
	slices.Reverse(reversed)
	again, err := PlanWaves(reversed, policy)
	if err != nil || !slices.EqualFunc(again, waves, slices.Equal) {
		t.Fatalf("plan depends on input order: %v %v", again, err)
	}
	// A seed is never batched with another unit, even with a large batch.
	waves, err = PlanWaves(append(controllers(), Unit{ID: "host-1", Group: "h1"}), policy)
	if err != nil || !slices.Equal(waves[len(waves)-1], []string{"ctrl-a"}) {
		t.Fatalf("seed is not last and alone: %v %v", waves, err)
	}
}

// After one canary, the default moves as many units at once as quorum
// allows: no wave takes two units of a group, so a TerraBase pair keeps a
// serving seat and three controllers a majority, and the seed goes last and
// alone.
func TestDefaultPolicyMovesAsManyUnitsAsQuorumAllows(t *testing.T) {
	policy := DefaultPolicy()
	if err := policy.Validate(); err != nil || policy.CanarySoakSeconds != 300 || policy.BatchSoakSeconds != 120 ||
		policy.ProofDeadlineSeconds != 600 {
		t.Fatalf("default policy = %+v %v", policy, err)
	}
	waves, err := PlanWaves(controllers(), policy)
	if want := [][]string{{"ctrl-b"}, {"ctrl-c"}, {"ctrl-a"}}; err != nil || !slices.EqualFunc(waves, want, slices.Equal) {
		t.Fatalf("controller waves = %v %v, want %v", waves, err, want)
	}
	hosts := []Unit{{ID: "h1", Group: "h1"}, {ID: "h2", Group: "h2"}, {ID: "h3", Group: "h3"}}
	waves, err = PlanWaves(append(seats(), hosts...), policy)
	if want := [][]string{{"h1"}, {"h2", "h3", "p1-a", "p2-a"}, {"p1-b", "p2-b"}}; err != nil || !slices.EqualFunc(waves, want, slices.Equal) {
		t.Fatalf("host waves = %v %v, want %v", waves, err, want)
	}
}

func TestPlanWavesRejectsInvalidUnits(t *testing.T) {
	for name, units := range map[string][]Unit{
		"empty":     nil,
		"duplicate": {{ID: "a", Group: "g"}, {ID: "a", Group: "h"}},
		"two seeds": {{ID: "a", Group: "g", Seed: true}, {ID: "b", Group: "g", Seed: true}},
		"bad id":    {{ID: "A B", Group: "g"}},
		"no group":  {{ID: "a"}},
	} {
		if _, err := PlanWaves(units, DefaultPolicy()); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
	policy := DefaultPolicy()
	policy.CanaryUnits = 0
	if _, err := PlanWaves(controllers(), policy); !errors.Is(err, ErrInvalid) {
		t.Fatalf("zero canary policy accepted: %v", err)
	}
}

func TestNewRejectsKnownBadAndInvalidSpecs(t *testing.T) {
	spec := Spec{RolloutID: "0000000000039PRXZD4Z9STA2E", Kind: KindHost, Cell: "gru", FromDigest: fromDigest, ToDigest: toDigest,
		Units: seats(), Policy: DefaultPolicy(), AuthorityEpoch: 1, KnownBad: []string{toDigest}}
	if _, err := New(spec, testStart); !errors.Is(err, ErrKnownBad) {
		t.Fatalf("known-bad target started: %v", err)
	}
	spec.KnownBad = []string{fromDigest}
	if _, err := New(spec, testStart); !errors.Is(err, ErrInvalid) {
		t.Fatalf("known-bad rollback target accepted: %v", err)
	}
	spec.KnownBad = nil
	spec.ToDigest = fromDigest
	if _, err := New(spec, testStart); !errors.Is(err, ErrInvalid) {
		t.Fatalf("no-op rollout accepted: %v", err)
	}
	spec.ToDigest, spec.AuthorityEpoch = toDigest, 0
	if _, err := New(spec, testStart); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unfenced rollout accepted: %v", err)
	}
}


func startedCanary(t *testing.T, units []Unit) (Record, time.Time) {
	t.Helper()
	record := newRecord(t, units, testPolicy())
	record = apply(t, record, Event{Kind: EventStart, At: testStart})
	record = apply(t, record, Event{Kind: EventPreflightPassed, At: testStart})
	return record, testStart
}

func requireRollingBack(t *testing.T, record Record, reason string) {
	t.Helper()
	if record.Phase != PhaseRollingBack || !slices.Contains(record.KnownBad, toDigest) || !strings.Contains(record.Reason, reason) {
		t.Fatalf("phase=%s known_bad=%v reason=%q; want rolling-back with %q", record.Phase, record.KnownBad, record.Reason, reason)
	}
	for _, action := range NextActions(record) {
		if action.Kind != ActionRollback || action.Digest != fromDigest {
			t.Fatalf("rollback emitted %+v", action)
		}
	}
}


func TestDeadlinesRollBack(t *testing.T) {
	record, at := startedCanary(t, controllers())
	deadline := at.Add(seconds(record.Policy.ProofDeadlineSeconds))
	if next := apply(t, record, Event{Kind: EventTick, At: deadline.Add(-time.Second)}); next.Phase != PhaseCanary {
		t.Fatalf("tick before the prepare deadline changed phase: %s", next.Phase)
	}
	requireRollingBack(t, apply(t, record, Event{Kind: EventTick, At: deadline}), "prepare deadline")

	record = apply(t, record, Event{Kind: EventPrepared, Unit: "ctrl-b", At: at})
	requireRollingBack(t, apply(t, record, Event{Kind: EventTick, At: deadline}), "serving-proof deadline")

	// One healthy report followed by silence must not stall the soak forever.
	silent := apply(t, record, Event{Kind: EventHealthy, Unit: "ctrl-b", Health: health(at.Add(time.Second), 10), At: at.Add(time.Second)})
	soakEnd := deadline.Add(silent.soakDuration()).Add(minSoakGap)
	if next := apply(t, silent, Event{Kind: EventTick, At: soakEnd.Add(-time.Second)}); next.Phase != PhaseCanarySoak {
		t.Fatalf("tick before the soak deadline changed phase: %s", next.Phase)
	}
	requireRollingBack(t, apply(t, silent, Event{Kind: EventTick, At: soakEnd}), "soak did not complete")

	record = newRecord(t, controllers(), testPolicy())
	record = apply(t, record, Event{Kind: EventStart, At: at})
	record = apply(t, record, Event{Kind: EventTick, At: at.Add(seconds(record.Policy.PreflightSeconds))})
	if record.Phase != PhaseAborted || len(record.KnownBad) != 0 {
		t.Fatalf("preflight timeout = %s %v", record.Phase, record.KnownBad)
	}
}

func TestRollbackReturnsEveryTouchedUnitNewestFirst(t *testing.T) {
	policy := testPolicy()
	policy.BatchSize = 2
	record := newRecord(t, seats(), policy)
	at := testStart
	record = apply(t, record, Event{Kind: EventStart, At: at})
	record = apply(t, record, Event{Kind: EventPreflightPassed, At: at})
	record, at = soakWave(t, record, at)
	if record.Phase != PhaseBatch || !slices.Equal(record.Waves[1], []string{"p1-b", "p2-a"}) {
		t.Fatalf("unexpected batch: %s %v", record.Phase, record.Waves)
	}
	record = apply(t, record, Event{Kind: EventPrepared, Unit: "p1-b", At: at})
	if inFlight := record.InFlight(); len(inFlight) != 2 {
		t.Fatalf("in-flight units = %v", inFlight)
	}
	// The second seat of p1 fails: the promoted first seat must come back too.
	record = apply(t, record, Event{Kind: EventHeld, Unit: "p1-b", At: at})
	requireRollingBack(t, record, "held")
	if want := []string{"p2-a", "p1-b", "p1-a"}; !slices.Equal(record.RollbackOrder, want) {
		t.Fatalf("rollback order = %v, want %v", record.RollbackOrder, want)
	}
	for _, id := range record.RollbackOrder {
		actions := NextActions(record)
		if len(actions) != 1 || actions[0].Unit != id {
			t.Fatalf("rollback actions = %+v, want only %s", actions, id)
		}
		if _, err := Apply(record, Event{Kind: EventRollbackServing, Unit: "p2-b", At: at}); err == nil {
			t.Fatal("untouched unit accepted as rollback head")
		}
		record = apply(t, record, Event{Kind: EventRollbackServing, Unit: id, At: at})
	}
	if record.Phase != PhaseRolledBack || record.Units["p2-b"].State != UnitPending {
		t.Fatalf("rollback finished as %s with p2-b %s", record.Phase, record.Units["p2-b"].State)
	}
}

func TestHeldRollbackFreezesAndResumeNeverRetargets(t *testing.T) {
	record, at := startedCanary(t, controllers())
	record = apply(t, record, Event{Kind: EventPrepared, Unit: "ctrl-b", At: at})
	record = apply(t, record, Event{Kind: EventUnhealthy, Unit: "ctrl-b", At: at})
	firstOperation := NextActions(record)[0].OperationID
	record = apply(t, record, Event{Kind: EventRollbackHeld, Unit: "ctrl-b", At: at})
	if record.Phase != PhaseFrozen || record.Units["ctrl-b"].State != UnitHeld {
		t.Fatalf("held rollback did not freeze: %s", record.Phase)
	}
	if actions := NextActions(record); len(actions) != 1 || actions[0].Kind != ActionPage {
		t.Fatalf("frozen actions = %v", actions)
	}
	for _, kind := range []EventKind{EventPrepared, EventHealthy, EventRollbackServing, EventAbort, EventPreflightPassed} {
		if _, err := Apply(record, Event{Kind: kind, Unit: "ctrl-b", Health: health(at, 1), At: at}); err == nil {
			t.Fatalf("frozen rollout accepted %s", kind)
		}
	}
	for attempt := 1; attempt <= record.Policy.MaxRollbackRetries; attempt++ {
		record = apply(t, record, Event{Kind: EventResume, At: at})
		actions := NextActions(record)
		if len(actions) != 1 || actions[0].Kind != ActionRollback || actions[0].Digest != fromDigest ||
			actions[0].OperationID == firstOperation || record.Units["ctrl-b"].Attempts != attempt {
			t.Fatalf("resume %d actions = %+v", attempt, actions)
		}
		record = apply(t, record, Event{Kind: EventTick, At: at.Add(time.Hour)})
		if record.Phase != PhaseFrozen {
			t.Fatalf("rollback deadline did not freeze: %s", record.Phase)
		}
	}
	if _, err := Apply(record, Event{Kind: EventResume, At: at}); !errors.Is(err, ErrAttemptsExhausted) {
		t.Fatalf("resume beyond retry budget: %v", err)
	}
	// A unit an operator moved off the target by hand is done, retries or not.
	ended := apply(t, record, Event{Kind: EventResume, At: at, Left: []string{"ctrl-b"}})
	if ended.Phase != PhaseAborted || ended.Units["ctrl-b"].State != UnitRolledBack || len(NextActions(ended)) != 0 {
		t.Fatalf("resume of a unit moved off the target = %s, ctrl-b %s", ended.Phase, ended.Units["ctrl-b"].State)
	}
}

func TestAbortAndFreeze(t *testing.T) {
	record := newRecord(t, controllers(), testPolicy())
	aborted := apply(t, record, Event{Kind: EventAbort, At: testStart})
	if aborted.Phase != PhaseAborted || len(aborted.KnownBad) != 0 {
		t.Fatalf("pending abort = %s", aborted.Phase)
	}
	canary, at := startedCanary(t, controllers())
	canary = apply(t, canary, Event{Kind: EventPrepared, Unit: "ctrl-b", At: at})
	requireRollingBack(t, apply(t, canary, Event{Kind: EventAbort, At: at}), "operator abort")

	frozen := apply(t, canary, Event{Kind: EventFreeze, Reason: "host session lost", At: at})
	if frozen.Phase != PhaseFrozen || NextActions(frozen)[0].Kind != ActionPage {
		t.Fatalf("freeze = %s", frozen.Phase)
	}
	if _, err := Apply(frozen, Event{Kind: EventFreeze, At: at}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("double freeze: %v", err)
	}
	// Resuming a forward rollout frozen mid-canary rolls it back.
	requireRollingBack(t, apply(t, frozen, Event{Kind: EventResume, At: at}), "host session lost")

	pendingFrozen := apply(t, newRecord(t, controllers(), testPolicy()), Event{Kind: EventFreeze, At: at})
	if resumed := apply(t, pendingFrozen, Event{Kind: EventResume, At: at}); resumed.Phase != PhaseAborted {
		t.Fatalf("resume of an untouched rollout = %s", resumed.Phase)
	}
}

func TestApplyRejectsInvalidEventsWithoutMutation(t *testing.T) {
	record, at := startedCanary(t, controllers())
	snapshot := record.Clone()
	for name, event := range map[string]Event{
		"no time":           {Kind: EventTick},
		"unknown kind":      {Kind: "bogus", At: at},
		"outside wave":      {Kind: EventPrepared, Unit: "ctrl-a", At: at},
		"unknown unit":      {Kind: EventPrepared, Unit: "nope", At: at},
		"health unprepared": {Kind: EventHealthy, Unit: "ctrl-b", Health: health(at, 1), At: at},
		"rollback forward":  {Kind: EventRollbackServing, Unit: "ctrl-b", At: at},
		"preflight twice":   {Kind: EventPreflightPassed, At: at},
		"long reason":       {Kind: EventAbort, Reason: strings.Repeat("x", maxReason+1), At: at},
	} {
		if _, err := Apply(record, event); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	record = apply(t, record, Event{Kind: EventPrepared, Unit: "ctrl-b", At: at})
	bad := health(at, 1)
	bad.StartNonce = ""
	if _, err := Apply(record, Event{Kind: EventHealthy, Unit: "ctrl-b", Health: bad, At: at}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("anonymous health report accepted: %v", err)
	}
	if snapshot.Units["ctrl-b"].State != UnitPreparing {
		t.Fatal("Apply mutated its input record")
	}
	if again := apply(t, record, Event{Kind: EventPrepared, Unit: "ctrl-b", At: at}); again.Units["ctrl-b"].State != UnitSoaking {
		t.Fatal("duplicate prepared report is not idempotent")
	}
}

// TestRandomWalkInvariants drives every event kind in random order and checks
// the safety invariants after each accepted transition.
func TestRandomWalkInvariants(t *testing.T) {
	kinds := []EventKind{EventStart, EventPreflightPassed, EventPreflightFailed, EventPrepared, EventHealthy,
		EventUnhealthy, EventHeld, EventRollbackServing, EventRollbackHeld, EventTick, EventAbort, EventFreeze, EventResume}
	unitSets := [][]Unit{controllers(), seats(), append(controllers(), seats()...)}
	for seed := range uint64(300) {
		random := rand.New(rand.NewPCG(seed, 99))
		policy := testPolicy()
		policy.BatchSize = 1 + random.IntN(3)
		policy.CanaryUnits = 1 + random.IntN(2)
		units := unitSets[random.IntN(len(unitSets))]
		record := newRecord(t, units, policy)
		at := testStart
		sawRollback := false
		for range 400 {
			if record.Phase.Terminal() {
				break
			}
			at = at.Add(time.Duration(random.IntN(400)) * time.Second)
			unit := units[random.IntN(len(units))].ID
			kind := kinds[random.IntN(len(kinds))]
			if actions := NextActions(record); len(actions) > 0 && random.IntN(2) == 0 && actions[0].Unit != "" {
				unit = actions[0].Unit
			}
			pid := int64(1)
			if random.IntN(20) == 0 {
				pid = 2
			}
			next, err := Apply(record, Event{Kind: kind, Unit: unit, Health: health(at, pid), At: at})
			if err != nil {
				continue
			}
			checkInvariants(t, seed, record, next)
			if next.Phase == PhaseRollingBack {
				sawRollback = true
			}
			record = next
		}
		if sawRollback && record.Phase == PhaseComplete {
			t.Fatalf("seed %d: a rolled-back target completed", seed)
		}
	}
}

func checkInvariants(t *testing.T, seed uint64, before, after Record) {
	t.Helper()
	if err := after.Validate(); err != nil {
		t.Fatalf("seed %d: invalid record: %v", seed, err)
	}
	limit := max(after.Policy.BatchSize, after.Policy.CanaryUnits)
	inFlight := after.InFlight()
	if len(inFlight) > limit {
		t.Fatalf("seed %d: %d units in flight exceeds %d", seed, len(inFlight), limit)
	}
	groups := map[string]bool{}
	for _, id := range inFlight {
		group := after.Units[id].Group
		if groups[group] {
			t.Fatalf("seed %d: two units of %s in flight", seed, group)
		}
		groups[group] = true
	}
	knownBad := slices.Contains(after.KnownBad, after.ToDigest)
	if slices.Contains(before.KnownBad, before.ToDigest) && !knownBad {
		t.Fatalf("seed %d: known-bad target was forgotten", seed)
	}
	for _, action := range NextActions(after) {
		if knownBad && action.Kind == ActionPrepare {
			t.Fatalf("seed %d: prepare of a known-bad target", seed)
		}
		if action.Kind == ActionRollback && action.Digest != after.FromDigest {
			t.Fatalf("seed %d: rollback towards %s", seed, action.Digest)
		}
	}
	if after.Phase == PhaseRollingBack && !knownBad {
		t.Fatalf("seed %d: rollback started before the target was known bad", seed)
	}
	if after.AuthorityEpoch != before.AuthorityEpoch {
		t.Fatalf("seed %d: a transition changed the authority epoch", seed)
	}
	if after.Phase.preparing() || after.Phase.soaking() {
		for id, progress := range after.Units {
			if progress.Seed && progress.State != UnitPending && after.WaveIndex != len(after.Waves)-1 {
				t.Fatalf("seed %d: seed %s moved before the last wave", seed, id)
			}
		}
	}
}

func TestOperationIDIsStableAndDistinct(t *testing.T) {
	first := OperationID("0000000000GBSYKHMNVHNRT6RH", "ctrl-b", PhaseCanary, 0)
	if first != OperationID("0000000000GBSYKHMNVHNRT6RH", "ctrl-b", PhaseCanary, 0) {
		t.Fatal("operation ID is not deterministic")
	}
	for _, other := range []string{
		OperationID("0000000000VDVZT0DFJNS2394R", "ctrl-b", PhaseCanary, 0), OperationID("0000000000GBSYKHMNVHNRT6RH", "ctrl-c", PhaseCanary, 0),
		OperationID("0000000000GBSYKHMNVHNRT6RH", "ctrl-b", PhaseRollingBack, 0), OperationID("0000000000GBSYKHMNVHNRT6RH", "ctrl-b", PhaseCanary, 1),
	} {
		if other == first {
			t.Fatal("operation IDs collide")
		}
	}
}


func TestValidateRejectsContradictoryAndMalformedRecords(t *testing.T) {
	record := newRecord(t, controllers(), testPolicy())
	at := testStart.Add(time.Minute)
	record = apply(t, record, Event{Kind: EventStart, At: at})
	record = apply(t, record, Event{Kind: EventPreflightPassed, At: at})
	soak := record.Clone()
	soak.Phase = PhaseCanarySoak
	if err := soak.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a soak phase with preparing units validated: %v", err)
	}
	rolling := record.Clone()
	rolling.Phase = PhaseRollingBack
	if err := rolling.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("rolling back with no rollback order validated: %v", err)
	}
	malformed := record.Clone()
	malformed.KnownBad = []string{"not-a-digest"}
	if err := malformed.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a malformed known-bad digest validated: %v", err)
	}
	if err := record.Validate(); err != nil {
		t.Fatalf("an Apply-produced record does not validate: %v", err)
	}
}
