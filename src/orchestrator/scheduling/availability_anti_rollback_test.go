// This file ports tests/TerraScale.Orchestrator.Scheduler.Tests/
// AvailabilityGenerationAntiRollbackTests.cs.
//
// Skipped from the C# suite: the CultureInfo permutation loops (Go has no
// ambient culture); permutation invariance is fully ported.
package scheduling

import (
	"strings"
	"testing"
)

var antiRollbackReplayPolicy = func() *ServiceAvailabilityPolicy {
	policy, err := NewServiceAvailabilityPolicy(
		availabilityTestService,
		NewAvailabilityCount(3), NewAvailabilityCount(2), NewAvailabilityCount(2),
		NewAvailabilityCount(1), ServiceCriticalityCritical, true,
		NewAvailabilityCount(2), ResourceVectorZero, ReserveDispositionPreserve)
	if err != nil {
		panic(err)
	}
	return policy
}()

var antiRollbackPolicy = func() *ServiceAvailabilityPolicy {
	policy, err := NewServiceAvailabilityPolicy(
		availabilityTestService,
		NewAvailabilityCount(4), NewAvailabilityCount(0), NewAvailabilityCount(0),
		NewAvailabilityCount(4), ServiceCriticalityCritical, false,
		NewAvailabilityCount(0), ResourceVectorZero, ReserveDispositionMayConsume)
	if err != nil {
		panic(err)
	}
	return policy
}()

func antiRollbackEvaluate(
	t *testing.T,
	evaluator AvailabilityPolicyEvaluator,
	change AvailabilityChange,
	observations []ReplicaObservation,
	observationGeneration, currentGeneration uint64,
	policy *ServiceAvailabilityPolicy,
) AvailabilityDecision {
	t.Helper()
	if policy == nil {
		policy = antiRollbackPolicy
	}
	observation, err := NewAvailabilityGeneration(observationGeneration)
	if err != nil {
		t.Fatalf("generation: %v", err)
	}
	current, err := NewAvailabilityGeneration(currentGeneration)
	if err != nil {
		t.Fatalf("generation: %v", err)
	}
	request, err := NewAvailabilityEvaluationRequest(policy, change,
		ObservationCompletenessComplete, observation, current, observations)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	return evaluator.Evaluate(request)
}

func antiRollbackChange(t *testing.T, seed uint64) AvailabilityChange {
	switch seed % 3 {
	case 0:
		return PlaceReplicaChange{
			ReplicaId:             mustReplicaId(t, "replica-d"),
			TargetNodeId:          mustAvailabilityNodeId(t, "node-d"),
			TargetFailureDomainId: mustFailureDomainId(t, "fd-d"),
			RequestedResources:    ResourceVectorZero,
			AvailableResources:    ResourceVectorZero,
		}
	case 1:
		return MaintainReplicaChange{ReplicaId: mustReplicaId(t, "replica-b")}
	default:
		return DrainNodeChange{NodeId: mustAvailabilityNodeId(t, "node-a")}
	}
}

func antiRollbackSerialize(decision AvailabilityDecision) string {
	rows := make([]string, len(decision.Trace))
	for index, reason := range decision.Trace {
		rows[index] = strings.Join([]string{
			reason.Code.String(), reason.Outcome.String(),
			formatUint(reason.Observed), formatUint(reason.Required),
		}, ":")
	}
	return strings.Join(rows, ";")
}

func antiRollbackAssertGeneration(
	t *testing.T,
	decision AvailabilityDecision,
	code AvailabilityReasonCode,
	outcome AvailabilityReasonOutcome,
	observed, required uint64,
) {
	t.Helper()
	reason := availabilityReason(t, decision, code)
	if reason.Outcome != outcome || reason.Observed != observed || reason.Required != required {
		t.Fatalf("generation reason mismatch for %v: %+v", code, reason)
	}
}

func TestOlderHealthySnapshotCannotReauthorizeASecondDisruption(t *testing.T) {
	evaluator := AvailabilityPolicyEvaluator{}
	healthyGenerationThree := availabilityHealthyThree(t)
	maintainB := MaintainReplicaChange{ReplicaId: mustReplicaId(t, "replica-b")}
	initiallyAccepted := antiRollbackEvaluate(t, evaluator, maintainB, healthyGenerationThree, 3, 3, antiRollbackReplayPolicy)
	if !initiallyAccepted.Admitted() {
		t.Fatal("expected initial admission")
	}

	generationFour := availabilityHealthyThree(t)
	generationFour[0] = availabilityTestObservation(t, "replica-a", "node-a", "fd-a", ReplicaAvailabilityStateDisrupting)
	current := antiRollbackEvaluate(t, evaluator, maintainB, generationFour, 4, 4, antiRollbackReplayPolicy)
	if current.Admitted() {
		t.Fatal("expected denial at generation 4")
	}
	if reason := availabilityReason(t, current, AvailabilityReasonCodeQuorum); reason.Outcome != AvailabilityReasonOutcomeRejected {
		t.Fatal("quorum must reject")
	}
	if reason := availabilityReason(t, current, AvailabilityReasonCodeDisruptionBudget); reason.Outcome != AvailabilityReasonOutcomeRejected {
		t.Fatal("disruption budget must reject")
	}

	replay := antiRollbackEvaluate(t, evaluator, maintainB, healthyGenerationThree, 3, 4, antiRollbackReplayPolicy)
	if replay.Admitted() {
		t.Fatal("a replayed older snapshot must not re-authorize")
	}
	antiRollbackAssertGeneration(t, replay, AvailabilityReasonCodeObservationGenerationNotRollback,
		AvailabilityReasonOutcomeHeld, 3, 4)
	antiRollbackAssertGeneration(t, replay, AvailabilityReasonCodeObservationGenerationNotFuture,
		AvailabilityReasonOutcomePassed, 3, 4)
	for _, reason := range replay.Trace[5:28] {
		if reason.Outcome != AvailabilityReasonOutcomeHeld && reason.Outcome != AvailabilityReasonOutcomeNotApplicable {
			t.Fatalf("held rows must stay held or not-applicable: %+v", reason)
		}
	}
}

func TestFutureSnapshotIsNotTreatedAsAlreadyAcceptedEvidence(t *testing.T) {
	evaluator := AvailabilityPolicyEvaluator{}
	decision := antiRollbackEvaluate(t, evaluator,
		MaintainReplicaChange{ReplicaId: mustReplicaId(t, "replica-b")},
		availabilityHealthyThree(t), 5, 4, nil)

	if decision.Admitted() {
		t.Fatal("expected denial")
	}
	antiRollbackAssertGeneration(t, decision, AvailabilityReasonCodeObservationGenerationNotRollback,
		AvailabilityReasonOutcomePassed, 5, 4)
	antiRollbackAssertGeneration(t, decision, AvailabilityReasonCodeObservationGenerationNotFuture,
		AvailabilityReasonOutcomeHeld, 5, 4)
	if reason := availabilityReason(t, decision, AvailabilityReasonCodeChangeTargetValid); reason.Outcome != AvailabilityReasonOutcomeHeld {
		t.Fatal("target row must hold for a future snapshot")
	}
}

func TestGenerationContractAndTraceNumericSurfaceAreExact(t *testing.T) {
	if _, err := NewAvailabilityGeneration(0); err == nil {
		t.Fatal("zero generation must be rejected")
	}
	evaluator := AvailabilityPolicyEvaluator{}
	generation, err := NewAvailabilityGeneration(1)
	if err != nil {
		t.Fatalf("generation: %v", err)
	}
	if _, err := NewAvailabilityEvaluationRequest(antiRollbackReplayPolicy,
		MaintainReplicaChange{ReplicaId: mustReplicaId(t, "replica-b")},
		ObservationCompletenessComplete, generation, generation, nil); err == nil {
		t.Fatal("nil observations must be rejected")
	}
	if _, err := NewAvailabilityEvaluationRequest(antiRollbackReplayPolicy,
		MaintainReplicaChange{ReplicaId: mustReplicaId(t, "replica-b")},
		ObservationCompletenessComplete, generation, generation, availabilityHealthyThree(t)); err != nil {
		t.Fatalf("request: %v", err)
	}
	for index, code := range AllAvailabilityReasonCodes {
		if int(code) != index+1 {
			t.Fatalf("reason code values must be exactly 1..30, got %d at %d", int(code), index)
		}
	}

	decision := antiRollbackEvaluate(t, evaluator,
		MaintainReplicaChange{ReplicaId: mustReplicaId(t, "replica-b")},
		availabilityHealthyThree(t), 7, 7, nil)
	if !decision.Admitted() {
		t.Fatal("expected admission")
	}
	for index, reason := range decision.Trace {
		if int(reason.Code) != index+1 {
			t.Fatalf("trace code order mismatch at %d", index)
		}
	}
	antiRollbackAssertGeneration(t, decision, AvailabilityReasonCodeObservationGenerationNotRollback,
		AvailabilityReasonOutcomePassed, 7, 7)
	antiRollbackAssertGeneration(t, decision, AvailabilityReasonCodeObservationGenerationNotFuture,
		AvailabilityReasonOutcomePassed, 7, 7)
	serialized := antiRollbackSerialize(decision)
	if !strings.HasSuffix(serialized,
		"ObservationGenerationNotRollback:Passed:7:7;ObservationGenerationNotFuture:Passed:7:7") {
		t.Fatalf("unexpected serialized suffix: %s", serialized)
	}
	if suffix := propertySerializeAvailability(decision); !strings.HasSuffix(suffix, "29:1:7:7;30:1:7:7") {
		t.Fatalf("unexpected numeric suffix: %s", suffix)
	}
}

func TestEqualGenerationRetriesOnlyAppendGenerationDistinctPassedRows(t *testing.T) {
	evaluator := AvailabilityPolicyEvaluator{}
	generationThree := antiRollbackEvaluate(t, evaluator,
		MaintainReplicaChange{ReplicaId: mustReplicaId(t, "replica-b")},
		availabilityHealthyThree(t), 3, 3, nil)
	generationFour := antiRollbackEvaluate(t, evaluator,
		MaintainReplicaChange{ReplicaId: mustReplicaId(t, "replica-b")},
		availabilityHealthyThree(t), 4, 4, nil)

	if !generationThree.Admitted() || !generationFour.Admitted() {
		t.Fatal("equal generations must both be admitted")
	}
	rows := func(decision AvailabilityDecision, from, to int) string {
		parts := make([]string, 0, to-from)
		for _, reason := range decision.Trace[from:to] {
			parts = append(parts, strings.Join([]string{
				reason.Code.String(), reason.Outcome.String(),
				formatUint(reason.Observed), formatUint(reason.Required),
			}, ":"))
		}
		return strings.Join(parts, ";")
	}
	if rows(generationThree, 0, 28) != rows(generationFour, 0, 28) {
		t.Fatal("the 28-row prefix must be generation-independent")
	}
	if rows(generationThree, 28, 30) == rows(generationFour, 28, 30) {
		t.Fatal("the generation rows must be generation-distinct")
	}
}

func TestLowerEqualAndHigherGenerationsHaveExactInvariantPrecedenceAcrossOneThousandSeeds(t *testing.T) {
	evaluator := AvailabilityPolicyEvaluator{}
	for seed := uint64(140_001); seed < 141_001; seed++ {
		observations := availabilityHealthyThree(t)
		change := antiRollbackChange(t, seed)
		current := seed + 10
		relation := seed % 3
		observed := current - 1
		switch relation {
		case 1:
			observed = current
		case 2:
			observed = current + 1
		}
		baseline := antiRollbackEvaluate(t, evaluator, change, observations, observed, current, nil)

		for index, reason := range baseline.Trace {
			if int(reason.Code) != index+1 {
				t.Fatalf("seed %d: trace code order mismatch at %d", seed, index)
			}
		}
		if baseline.Admitted() != (relation == 1) {
			t.Fatalf("seed %d: admission mismatch for relation %d", seed, relation)
		}
		if (baseline.AcceptedRequest != nil) != (relation == 1) {
			t.Fatalf("seed %d: accepted request mismatch for relation %d", seed, relation)
		}
		notRollbackOutcome := AvailabilityReasonOutcomePassed
		if relation == 0 {
			notRollbackOutcome = AvailabilityReasonOutcomeHeld
		}
		antiRollbackAssertGeneration(t, baseline, AvailabilityReasonCodeObservationGenerationNotRollback,
			notRollbackOutcome, observed, current)
		notFutureOutcome := AvailabilityReasonOutcomePassed
		if relation == 2 {
			notFutureOutcome = AvailabilityReasonOutcomeHeld
		}
		antiRollbackAssertGeneration(t, baseline, AvailabilityReasonCodeObservationGenerationNotFuture,
			notFutureOutcome, observed, current)

		if relation != 1 {
			if baseline.AcceptedRequest != nil {
				t.Fatalf("seed %d: denied decision must not retain a request", seed)
			}
			for _, reason := range baseline.Trace[5:28] {
				if reason.Outcome != AvailabilityReasonOutcomeHeld && reason.Outcome != AvailabilityReasonOutcomeNotApplicable {
					t.Fatalf("seed %d: held rows must stay held: %+v", seed, reason)
				}
			}
		}

		reversed := []ReplicaObservation{observations[2], observations[1], observations[0]}
		permuted := antiRollbackEvaluate(t, evaluator, change, reversed, observed, current, nil)
		if antiRollbackSerialize(permuted) != antiRollbackSerialize(baseline) {
			t.Fatalf("seed %d: permutation changed the decision", seed)
		}
	}
}
