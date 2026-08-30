// This file ports tests/TerraScale.Orchestrator.Scheduler.Tests/Properties/
// SchedulerPolicyCompletenessPropertyTests.cs.
package scheduling

import (
	"testing"
)

var completenessService = mustServiceId("critical-service")

func completenessPolicy(
	t *testing.T,
	disposition ReserveDisposition,
) *ServiceAvailabilityPolicy {
	t.Helper()
	policy, err := NewServiceAvailabilityPolicy(
		completenessService,
		NewAvailabilityCount(1), NewAvailabilityCount(1), NewAvailabilityCount(1),
		NewAvailabilityCount(0), ServiceCriticalityCritical, true,
		NewAvailabilityCount(1), ResourceVectorZero, disposition)
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	return policy
}

func completenessMutationPolicy(t *testing.T) *ServiceAvailabilityPolicy {
	t.Helper()
	policy, err := NewServiceAvailabilityPolicy(
		completenessService,
		NewAvailabilityCount(1), NewAvailabilityCount(0), NewAvailabilityCount(0),
		NewAvailabilityCount(1), ServiceCriticalityCritical, true,
		NewAvailabilityCount(0), ResourceVectorZero, ReserveDispositionPreserve)
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	return policy
}

func completenessEvaluate(
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

func completenessReason(t *testing.T, decision AvailabilityDecision, code AvailabilityReasonCode) AvailabilityReason {
	t.Helper()
	for _, reason := range decision.Trace {
		if reason.Code == code {
			return reason
		}
	}
	t.Fatalf("missing reason %v", code)
	return AvailabilityReason{}
}

func TestConsumableReserveNeverPermitsPlacementBeyondCapacityAcrossOneThousandSeeds(t *testing.T) {
	evaluator := AvailabilityPolicyEvaluator{}
	reserveCodes := []AvailabilityReasonCode{
		AvailabilityReasonCodeReserveCpu, AvailabilityReasonCodeReserveMemory,
		AvailabilityReasonCodeReserveBlockIo, AvailabilityReasonCodeReserveEphemeralDisk,
		AvailabilityReasonCodeReserveBandwidth, AvailabilityReasonCodeReservePids,
		AvailabilityReasonCodeReserveFileDescriptors, AvailabilityReasonCodeReserveHugePages,
	}
	capacityCodes := []AvailabilityReasonCode{
		AvailabilityReasonCodeCapacityCpu, AvailabilityReasonCodeCapacityMemory,
		AvailabilityReasonCodeCapacityBlockIo, AvailabilityReasonCodeCapacityEphemeralDisk,
		AvailabilityReasonCodeCapacityBandwidth, AvailabilityReasonCodeCapacityPids,
		AvailabilityReasonCodeCapacityFileDescriptors, AvailabilityReasonCodeCapacityHugePages,
	}
	isReserve := func(code AvailabilityReasonCode) bool {
		for _, candidate := range reserveCodes {
			if candidate == code {
				return true
			}
		}
		return false
	}
	isCapacity := func(code AvailabilityReasonCode) bool {
		for _, candidate := range capacityCodes {
			if candidate == code {
				return true
			}
		}
		return false
	}
	place := func(requested, available ResourceVector) PlaceReplicaChange {
		return PlaceReplicaChange{
			ReplicaId:             mustReplicaId(t, "replica-a"),
			TargetNodeId:          mustAvailabilityNodeId(t, "node-a"),
			TargetFailureDomainId: mustFailureDomainId(t, "fd-a"),
			RequestedResources:    requested,
			AvailableResources:   available,
		}
	}
	for seed := uint64(110_001); seed < 110_001+propertyFeatureCases; seed++ {
		dimension := int(seed % 8)
		requestedAmount := int64(seed%100) + 1
		requested := availabilityResources(requestedAmount)
		exact := completenessEvaluate(t, evaluator, completenessPolicy(t, ReserveDispositionMayConsume),
			place(requested, requested), []ReplicaObservation{})
		if !exact.Admitted() {
			t.Fatalf("seed %d: exact placement must be admitted", seed)
		}
		for index, code := range AllAvailabilityReasonCodes {
			if exact.Trace[index].Code != code {
				t.Fatalf("seed %d: trace code order mismatch at %d", seed, index)
			}
		}
		for _, reason := range exact.Trace {
			if isReserve(reason.Code) && reason.Outcome != AvailabilityReasonOutcomeNotApplicable {
				t.Fatalf("seed %d: consumable reserve must be not applicable", seed)
			}
			if isCapacity(reason.Code) && (reason.Outcome != AvailabilityReasonOutcomePassed ||
				reason.Observed != uint64(requestedAmount) || reason.Required != uint64(requestedAmount)) {
				t.Fatalf("seed %d: capacity row mismatch: %+v", seed, reason)
			}
		}

		available := propertyWithOneDimension(requested, dimension, -1)
		rejected := completenessEvaluate(t, evaluator, completenessPolicy(t, ReserveDispositionMayConsume),
			place(requested, available), []ReplicaObservation{})
		rejectedCapacity := completenessReason(t, rejected, capacityCodes[dimension])
		if rejected.Admitted() {
			t.Fatalf("seed %d: beyond-capacity placement must be rejected", seed)
		}
		if rejectedCapacity.Outcome != AvailabilityReasonOutcomeRejected ||
			rejectedCapacity.Observed != uint64(requestedAmount-1) ||
			rejectedCapacity.Required != uint64(requestedAmount) {
			t.Fatalf("seed %d: capacity mismatch: %+v", seed, rejectedCapacity)
		}
		for _, reason := range rejected.Trace {
			if isCapacity(reason.Code) && reason.Code != capacityCodes[dimension] &&
				reason.Outcome != AvailabilityReasonOutcomePassed {
				t.Fatalf("seed %d: other capacities should pass: %+v", seed, reason)
			}
			if isReserve(reason.Code) && reason.Outcome != AvailabilityReasonOutcomeNotApplicable {
				t.Fatalf("seed %d: consumable reserve must stay not applicable", seed)
			}
		}
	}
}

func TestEveryAvailabilityPathPreservesTheExactTwentyEightRowPrefixAndAppendsGenerationRows(t *testing.T) {
	evaluator := AvailabilityPolicyEvaluator{}
	observation := availabilityTestObservation(t, "replica-a", "node-a", "fd-a", ReplicaAvailabilityStateAvailable)
	generation, err := NewAvailabilityGeneration(1)
	if err != nil {
		t.Fatalf("generation: %v", err)
	}
	for seed := uint64(120_001); seed < 120_001+propertyFeatureCases; seed++ {
		var request *AvailabilityEvaluationRequest
		switch seed % 5 {
		case 0:
			request, err = NewAvailabilityEvaluationRequest(
				completenessPolicy(t, ReserveDispositionPreserve),
				PlaceReplicaChange{
					ReplicaId:             mustReplicaId(t, "replica-a"),
					TargetNodeId:          mustAvailabilityNodeId(t, "node-a"),
					TargetFailureDomainId: mustFailureDomainId(t, "fd-a"),
					RequestedResources:    availabilityResources(1),
					AvailableResources:   availabilityResources(1),
				},
				ObservationCompletenessComplete, generation, generation, []ReplicaObservation{})
		case 1:
			request, err = NewAvailabilityEvaluationRequest(
				completenessMutationPolicy(t), MaintainReplicaChange{ReplicaId: observation.ReplicaId},
				ObservationCompletenessComplete, generation, generation, []ReplicaObservation{observation})
		case 2:
			request, err = NewAvailabilityEvaluationRequest(
				completenessMutationPolicy(t), DrainNodeChange{NodeId: *observation.NodeId},
				ObservationCompletenessComplete, generation, generation, []ReplicaObservation{observation})
		case 3:
			request, err = NewAvailabilityEvaluationRequest(
				completenessMutationPolicy(t), MaintainReplicaChange{ReplicaId: observation.ReplicaId},
				ObservationCompletenessIncomplete, generation, generation, []ReplicaObservation{observation})
		default:
			request, err = NewAvailabilityEvaluationRequest(
				completenessMutationPolicy(t), MaintainReplicaChange{ReplicaId: mustReplicaId(t, "replica-missing")},
				ObservationCompletenessComplete, generation, generation, []ReplicaObservation{observation})
		}
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}

		decision := evaluator.Evaluate(request)
		if decision.Admitted() != (decision.AcceptedRequest != nil) {
			t.Fatalf("seed %d: admission must be iff an accepted request exists", seed)
		}
		if decision.Admitted() && decision.AcceptedRequest != request {
			t.Fatalf("seed %d: the exact request must be retained", seed)
		}
		if len(decision.Trace) != 30 {
			t.Fatalf("seed %d: expected 30 rows, got %d", seed, len(decision.Trace))
		}
		for index, reason := range decision.Trace {
			if reason.Code != AllAvailabilityReasonCodes[index] {
				t.Fatalf("seed %d: trace code order mismatch at %d", seed, index)
			}
		}
		for index := 0; index < 28; index++ {
			if int(decision.Trace[index].Code) != index+1 {
				t.Fatalf("seed %d: 28-row prefix mismatch at %d", seed, index)
			}
		}
		if int(decision.Trace[28].Code) != 29 || int(decision.Trace[29].Code) != 30 {
			t.Fatalf("seed %d: generation rows must be appended last", seed)
		}
		distinct := map[AvailabilityReasonCode]bool{}
		for _, reason := range decision.Trace {
			distinct[reason.Code] = true
		}
		if len(distinct) != 30 {
			t.Fatalf("seed %d: expected 30 distinct codes, got %d", seed, len(distinct))
		}
	}
}

func TestEveryClosedCandidateVetoProducesTheExactCallerHoldAcrossOneThousandSeeds(t *testing.T) {
	scheduler := DeterministicScheduler{}
	hits := make(map[CandidateVetoCode]int)
	for seed := uint64(130_001); seed < 130_001+propertyFeatureCases; seed++ {
		property, err := schedulerPropertyValid(seed)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		veto := AllCandidateVetoCodes[seed%uint64(len(AllCandidateVetoCodes))]
		hits[veto]++
		vetoed, err := schedulerPropertyVetoed(property.Workload, veto)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		result, err := scheduler.Schedule(property.Workload,
			[]*NodeCandidate{vetoed}, property.Policy)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		if _, ok := result.(Unschedulable); !ok {
			t.Fatalf("seed %d: expected Unschedulable", seed)
		}
		found := PlacementReason{}
		for _, reason := range resultCandidates(result)[0].Reasons {
			if reason.Check == PlacementCheckCallerVeto {
				found = reason
			}
		}
		expected := PlacementReason{
			Check:   PlacementCheckCallerVeto,
			Outcome: CheckOutcomeRejected,
			Detail:  "code=" + veto.String(),
		}
		if found != expected {
			t.Fatalf("seed %d: veto reason mismatch: %+v", seed, found)
		}
	}
	if len(hits) != len(AllCandidateVetoCodes) {
		t.Fatal("every veto code must be exercised")
	}
	for veto, count := range hits {
		if count != propertyFeatureCases/len(AllCandidateVetoCodes) {
			t.Fatalf("veto %v hit %d times", veto, count)
		}
	}
}
