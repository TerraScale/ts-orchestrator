package scheduling

import (
	"testing"
)

func availabilityPropertyEvaluate(
	t *testing.T,
	evaluator AvailabilityPolicyEvaluator,
	policy *ServiceAvailabilityPolicy,
	change AvailabilityChange,
	observations []ReplicaObservation,
) AvailabilityDecision {
	t.Helper()
	generation, err := NewAvailabilityGeneration(1)
	if err != nil {
		t.Fatalf("generation: %v", err)
	}
	request, err := NewAvailabilityEvaluationRequest(policy, change,
		ObservationCompletenessComplete, generation, generation, observations)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	return evaluator.Evaluate(request)
}

func availabilityPropertyRejected(t *testing.T, decision AvailabilityDecision, code AvailabilityReasonCode) {
	t.Helper()
	found := false
	for _, reason := range decision.Trace {
		if reason.Code == code {
			found = true
			if reason.Outcome != AvailabilityReasonOutcomeRejected {
				t.Fatalf("code %v must be rejected, got %v", code, reason.Outcome)
			}
		}
	}
	if !found {
		t.Fatalf("missing reason for code %v", code)
	}
	if decision.AcceptedRequest != nil {
		t.Fatal("rejected decisions must not retain a request")
	}
}

func TestMaintenancePreservesMinimumQuorumDisruptionAndTopologyFloorsAcrossOneThousandSeeds(t *testing.T) {
	evaluator := AvailabilityPolicyEvaluator{}
	for seed := uint64(40_001); seed < 40_001+propertyFeatureCases; seed++ {
		property, err := availabilityPropertyMaintenance(seed)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		admitted := availabilityPropertyEvaluate(t, evaluator, property.Policy, property.Maintenance, property.Observations)
		if !admitted.Admitted() {
			t.Fatalf("seed %d: expected admission", seed)
		}
		count := uint64(len(property.Observations))
		minimum, err := availabilityPropertyPolicy(count, count, count-1, 1, count-1, true, ResourceVectorZero)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		quorum, err := availabilityPropertyPolicy(count, count-1, count, 1, count-1, true, ResourceVectorZero)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		disruption, err := availabilityPropertyPolicy(count, count-1, count-1, 0, count-1, true, ResourceVectorZero)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		topology, err := availabilityPropertyPolicy(count, count-1, count-1, 1, count, true, ResourceVectorZero)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		availabilityPropertyRejected(t,
			availabilityPropertyEvaluate(t, evaluator, minimum, property.Maintenance, property.Observations),
			AvailabilityReasonCodeMinimumAvailable)
		availabilityPropertyRejected(t,
			availabilityPropertyEvaluate(t, evaluator, quorum, property.Maintenance, property.Observations),
			AvailabilityReasonCodeQuorum)
		availabilityPropertyRejected(t,
			availabilityPropertyEvaluate(t, evaluator, disruption, property.Maintenance, property.Observations),
			AvailabilityReasonCodeDisruptionBudget)
		availabilityPropertyRejected(t,
			availabilityPropertyEvaluate(t, evaluator, topology, property.Maintenance, property.Observations),
			AvailabilityReasonCodeFailureDomainSpread)
	}
}

func TestAvailabilityDecisionsAreDeterministicAndPermutationInvariant(t *testing.T) {
	evaluator := AvailabilityPolicyEvaluator{}
	for seed := uint64(50_001); seed < 50_001+propertyFeatureCases; seed++ {
		property, err := availabilityPropertyMaintenance(seed)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		baseline := propertySerializeAvailability(
			availabilityPropertyEvaluate(t, evaluator, property.Policy, property.Maintenance, property.Observations))
		for _, observations := range [][]ReplicaObservation{
			propertyReverse(property.Observations),
			propertyRotate(property.Observations),
		} {
			decision := availabilityPropertyEvaluate(t, evaluator, property.Policy, property.Maintenance, observations)
			if propertySerializeAvailability(decision) != baseline {
				t.Fatalf("seed %d: permutation changed the decision", seed)
			}
		}
	}
}

func TestPlacementEnforcesOnePerHostAndExactReserveConservationInEveryDimension(t *testing.T) {
	evaluator := AvailabilityPolicyEvaluator{}
	reserveCodes := []AvailabilityReasonCode{
		AvailabilityReasonCodeReserveCpu, AvailabilityReasonCodeReserveMemory,
		AvailabilityReasonCodeReserveBlockIo, AvailabilityReasonCodeReserveEphemeralDisk,
		AvailabilityReasonCodeReserveBandwidth, AvailabilityReasonCodeReservePids,
		AvailabilityReasonCodeReserveFileDescriptors, AvailabilityReasonCodeReserveHugePages,
	}
	reserveSet := map[AvailabilityReasonCode]bool{}
	for _, code := range reserveCodes {
		reserveSet[code] = true
	}
	for seed := uint64(60_001); seed < 60_001+propertyFeatureCases; seed++ {
		property, err := availabilityPropertyMaintenance(seed)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		count := uint64(len(property.Observations))
		amount := int64(seed%20 + 1)
		requested := availabilityResources(amount)
		reserve := availabilityResources(amount + 1)
		available, err := propertyAdd(requested, amount+1)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		policy, err := availabilityPropertyPolicy(count+1, count, count, 1, count+1, true, reserve)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		colocated := PlaceReplicaChange{
			ReplicaId:             mustReplicaId(t, "replica-"+formatUint(count)),
			TargetNodeId:          mustAvailabilityNodeId(t, "node-0"),
			TargetFailureDomainId: mustFailureDomainId(t, "fd-"+formatUint(count)),
			RequestedResources:    requested,
			AvailableResources:    available,
		}
		availabilityPropertyRejected(t,
			availabilityPropertyEvaluate(t, evaluator, policy, colocated, property.Observations),
			AvailabilityReasonCodeOnePerHost)
		exact := PlaceReplicaChange{
			ReplicaId:             mustReplicaId(t, "replica-"+formatUint(count)),
			TargetNodeId:          mustAvailabilityNodeId(t, "node-"+formatUint(count)),
			TargetFailureDomainId: mustFailureDomainId(t, "fd-"+formatUint(count)),
			RequestedResources:    requested,
			AvailableResources:    available,
		}
		if decision := availabilityPropertyEvaluate(t, evaluator, policy, exact, property.Observations); !decision.Admitted() {
			t.Fatalf("seed %d: exact placement should be admitted", seed)
		}
		dimension := int(seed % 8)
		shortAvailable := propertyWithOneDimension(available, dimension, -1)
		shortPlacement := PlaceReplicaChange{
			ReplicaId:             mustReplicaId(t, "replica-"+formatUint(count)),
			TargetNodeId:          mustAvailabilityNodeId(t, "node-"+formatUint(count)),
			TargetFailureDomainId: mustFailureDomainId(t, "fd-"+formatUint(count)),
			RequestedResources:    requested,
			AvailableResources:    shortAvailable,
		}
		shortDecision := availabilityPropertyEvaluate(t, evaluator, policy, shortPlacement, property.Observations)
		availabilityPropertyRejected(t, shortDecision, reserveCodes[dimension])
		for _, reason := range shortDecision.Trace {
			if reserveSet[reason.Code] && reason.Code != reserveCodes[dimension] &&
				reason.Outcome != AvailabilityReasonOutcomePassed {
				t.Fatalf("seed %d: other reserves should pass: %+v", seed, reason)
			}
		}
	}
}

func TestIncompleteDuplicateAndConflictingObservationEvidenceHoldsBeforePolicyArithmetic(t *testing.T) {
	evaluator := AvailabilityPolicyEvaluator{}
	generation, err := NewAvailabilityGeneration(1)
	if err != nil {
		t.Fatalf("generation: %v", err)
	}
	for seed := uint64(70_001); seed < 70_001+propertyFeatureCases; seed++ {
		property, err := availabilityPropertyMaintenance(seed)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		var request *AvailabilityEvaluationRequest
		switch seed % 3 {
		case 0:
			request, err = NewAvailabilityEvaluationRequest(property.Policy, property.Maintenance,
				ObservationCompletenessIncomplete, generation, generation, property.Observations)
		case 1:
			request, err = NewAvailabilityEvaluationRequest(property.Policy, property.Maintenance,
				ObservationCompletenessComplete, generation, generation,
				append(append([]ReplicaObservation{}, property.Observations...), property.Observations[0]))
		default:
			conflictNode := mustAvailabilityNodeId(t, "node-conflict")
			conflictDomain := mustFailureDomainId(t, "fd-conflict")
			conflict, conflictErr := NewReplicaObservation(property.Observations[0].ReplicaId,
				property.Observations[0].ServiceId, &conflictNode, &conflictDomain,
				ReplicaAvailabilityStateAvailable)
			if conflictErr != nil {
				t.Fatalf("seed %d: %v", seed, conflictErr)
			}
			request, err = NewAvailabilityEvaluationRequest(property.Policy, property.Maintenance,
				ObservationCompletenessComplete, generation, generation,
				append(append([]ReplicaObservation{}, property.Observations...), conflict))
		}
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		decision := evaluator.Evaluate(request)
		if decision.Admitted() || decision.AcceptedRequest != nil {
			t.Fatalf("seed %d: held evidence must not admit", seed)
		}
		heldPrefix := false
		for _, reason := range decision.Trace[:5] {
			if reason.Outcome == AvailabilityReasonOutcomeHeld {
				heldPrefix = true
			}
		}
		if !heldPrefix {
			t.Fatalf("seed %d: one of the first five rows must hold", seed)
		}
		for _, reason := range decision.Trace[5:28] {
			if reason.Outcome != AvailabilityReasonOutcomeHeld && reason.Outcome != AvailabilityReasonOutcomeNotApplicable {
				t.Fatalf("seed %d: held policy rows must stay held: %+v", seed, reason)
			}
		}
		for _, reason := range decision.Trace[28:] {
			if reason.Outcome != AvailabilityReasonOutcomePassed {
				t.Fatalf("seed %d: generation rows must pass: %+v", seed, reason)
			}
		}
	}
}

func TestRandomizedInvalidInputsRejectAllConstructorValidationFamilies(t *testing.T) {
	hits := make(map[availabilityValidatorFamily]int)
	for seed := uint64(80_001); seed < 80_001+propertyFeatureCases; seed++ {
		family, rejected, err := availabilityPropertyInvalidValidator(seed)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		hits[family]++
		if !rejected {
			t.Fatalf("seed %d: family %d must be rejected", seed, family)
		}
	}
	// 1000 seeds over 11 representable families: every family must be hit at
	// least 70 times (1000/11 ≈ 90).
	for family, count := range hits {
		if count < 70 {
			t.Fatalf("family %d only hit %d times", family, count)
		}
	}
}

func TestCheckedAvailabilityCountsRoundTripWithoutCreationOrLoss(t *testing.T) {
	for seed := uint64(85_001); seed < 85_001+propertyFeatureCases; seed++ {
		left := NewAvailabilityCount(seed)
		right := NewAvailabilityCount(seed % 1_000)
		total, err := left.AddChecked(right)
		if err != nil {
			t.Fatalf("seed %d: add: %v", seed, err)
		}
		difference, err := total.SubtractChecked(right)
		if err != nil {
			t.Fatalf("seed %d: subtract: %v", seed, err)
		}
		if difference != left {
			t.Fatalf("seed %d: round trip mismatch", seed)
		}
	}
}

func TestAvailabilityOutputsUseClosedObservableValues(t *testing.T) {
	property, err := availabilityPropertyMaintenance(90_001)
	if err != nil {
		t.Fatalf("property: %v", err)
	}
	evaluator := AvailabilityPolicyEvaluator{}
	decision := availabilityPropertyEvaluate(t, evaluator, property.Policy, property.Maintenance, property.Observations)
	for _, reason := range decision.Trace {
		if !reason.Code.defined() || !reason.Outcome.defined() {
			t.Fatalf("undefined trace values: %+v", reason)
		}
	}
}

func TestObservationSnapshotAcceptsExactMaximumAndPreservesCanonicalEvaluationOrder(t *testing.T) {
	evaluator := AvailabilityPolicyEvaluator{}
	count := SchedulerTechnicalInputLimits.MaximumAvailabilityObservationCount
	observations := make([]ReplicaObservation, 0, count)
	for index := 0; index < count; index++ {
		observation, err := NewReplicaObservation(
			mustReplicaId(t, "replica-"+formatUint(uint64(index))), availabilityPropertyService,
			ptrNodeId(t, index), ptrDomainId(t, index), ReplicaAvailabilityStateAvailable)
		if err != nil {
			t.Fatalf("observation: %v", err)
		}
		observations = append(observations, observation)
	}
	policy, err := availabilityPropertyPolicy(uint64(count), 0, 0, uint64(count), 0, false, ResourceVectorZero)
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	generation, err := NewAvailabilityGeneration(1)
	if err != nil {
		t.Fatalf("generation: %v", err)
	}
	change := MaintainReplicaChange{ReplicaId: mustReplicaId(t, "replica-0")}
	forward, err := NewAvailabilityEvaluationRequest(policy, change,
		ObservationCompletenessComplete, generation, generation, observations)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	reversed, err := NewAvailabilityEvaluationRequest(policy, change,
		ObservationCompletenessComplete, generation, generation, propertyReverse(observations))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	forwardDecision := evaluator.Evaluate(forward)
	if !forwardDecision.Admitted() {
		t.Fatal("expected admission at the exact observation bound")
	}
	if propertySerializeAvailability(evaluator.Evaluate(reversed)) != propertySerializeAvailability(forwardDecision) {
		t.Fatal("evaluation order must be canonical regardless of observation order")
	}
}

func ptrNodeId(t *testing.T, index int) *AvailabilityNodeId {
	t.Helper()
	id := mustAvailabilityNodeId(t, "node-"+formatUint(uint64(index)))
	return &id
}

func ptrDomainId(t *testing.T, index int) *FailureDomainId {
	t.Helper()
	id := mustFailureDomainId(t, "fd-"+formatUint(uint64(index)))
	return &id
}

func TestObservationSnapshotRejectsMaximumPlusOne(t *testing.T) {
	policy, err := availabilityPropertyPolicy(1, 0, 0, 1, 0, false, ResourceVectorZero)
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	generation, err := NewAvailabilityGeneration(1)
	if err != nil {
		t.Fatalf("generation: %v", err)
	}
	change := MaintainReplicaChange{ReplicaId: mustReplicaId(t, "replica-0")}
	observations := make([]ReplicaObservation, 0, SchedulerTechnicalInputLimits.MaximumAvailabilityObservationCount+1)
	for index := 0; index < SchedulerTechnicalInputLimits.MaximumAvailabilityObservationCount+1; index++ {
		observation, observationErr := NewReplicaObservation(
			mustReplicaId(t, "replica-"+formatUint(uint64(index))), availabilityPropertyService,
			ptrNodeId(t, index), ptrDomainId(t, index), ReplicaAvailabilityStateAvailable)
		if observationErr != nil {
			t.Fatalf("observation: %v", observationErr)
		}
		observations = append(observations, observation)
	}
	if _, err := NewAvailabilityEvaluationRequest(policy, change,
		ObservationCompletenessComplete, generation, generation, observations); err == nil {
		t.Fatal("maximum plus one observations must be rejected")
	}
}

func TestObservationSnapshotIsDefensiveAgainstSourceMutation(t *testing.T) {
	values := make([]ReplicaObservation, 0, 3)
	for index := 0; index < 3; index++ {
		observation, observationErr := NewReplicaObservation(
			mustReplicaId(t, "replica-"+formatUint(uint64(index))), availabilityPropertyService,
			ptrNodeId(t, index), ptrDomainId(t, index), ReplicaAvailabilityStateAvailable)
		if observationErr != nil {
			t.Fatalf("observation: %v", observationErr)
		}
		values = append(values, observation)
	}
	policy, err := availabilityPropertyPolicy(3, 0, 0, 3, 0, false, ResourceVectorZero)
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	generation, err := NewAvailabilityGeneration(1)
	if err != nil {
		t.Fatalf("generation: %v", err)
	}
	request, err := NewAvailabilityEvaluationRequest(policy,
		MaintainReplicaChange{ReplicaId: mustReplicaId(t, "replica-0")},
		ObservationCompletenessComplete, generation, generation, values)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	values = values[:0]
	if len(request.Observations) != 3 {
		t.Fatalf("expected 3 snapshot observations, got %d", len(request.Observations))
	}
	if !(AvailabilityPolicyEvaluator{}).Evaluate(request).Admitted() {
		t.Fatal("expected admission after clearing the source slice")
	}
}
