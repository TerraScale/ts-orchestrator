package scheduling

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

var availabilityTestService = mustServiceId("control-service")

func availabilityTestPolicy(
	t *testing.T,
	desired, minimum, quorum, disruptions, domains uint64,
	onePerHost bool,
	reserve ResourceVector,
	reserveDisposition ReserveDisposition,
) *ServiceAvailabilityPolicy {
	t.Helper()
	policy, err := NewServiceAvailabilityPolicy(
		availabilityTestService,
		NewAvailabilityCount(desired), NewAvailabilityCount(minimum),
		NewAvailabilityCount(quorum), NewAvailabilityCount(disruptions),
		ServiceCriticalityCritical, onePerHost, NewAvailabilityCount(domains),
		reserve, reserveDisposition)
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	return policy
}

func availabilityTestObservation(
	t *testing.T,
	replica, node, domain string,
	state ReplicaAvailabilityState,
) ReplicaObservation {
	t.Helper()
	replicaId := mustReplicaId(t, replica)
	serviceId := availabilityTestService
	nodeId := mustAvailabilityNodeId(t, node)
	domainId := mustFailureDomainId(t, domain)
	observation, err := NewReplicaObservation(replicaId, serviceId, &nodeId, &domainId, state)
	if err != nil {
		t.Fatalf("observation: %v", err)
	}
	return observation
}

func mustReplicaId(t *testing.T, value string) ReplicaId {
	t.Helper()
	id, err := NewReplicaId(value)
	if err != nil {
		t.Fatalf("replica id: %v", err)
	}
	return id
}

func mustAvailabilityNodeId(t *testing.T, value string) AvailabilityNodeId {
	t.Helper()
	id, err := NewAvailabilityNodeId(value)
	if err != nil {
		t.Fatalf("node id: %v", err)
	}
	return id
}

func mustFailureDomainId(t *testing.T, value string) FailureDomainId {
	t.Helper()
	id, err := NewFailureDomainId(value)
	if err != nil {
		t.Fatalf("failure domain id: %v", err)
	}
	return id
}

func availabilityHealthyThree(t *testing.T) []ReplicaObservation {
	t.Helper()
	return []ReplicaObservation{
		availabilityTestObservation(t, "replica-a", "node-a", "fd-a", ReplicaAvailabilityStateAvailable),
		availabilityTestObservation(t, "replica-b", "node-b", "fd-b", ReplicaAvailabilityStateAvailable),
		availabilityTestObservation(t, "replica-c", "node-c", "fd-c", ReplicaAvailabilityStateAvailable),
	}
}

func availabilityEvaluate(
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

func availabilityReason(t *testing.T, decision AvailabilityDecision, code AvailabilityReasonCode) AvailabilityReason {
	t.Helper()
	for _, reason := range decision.Trace {
		if reason.Code == code {
			return reason
		}
	}
	t.Fatalf("no reason for code %v", code)
	return AvailabilityReason{}
}

func availabilityResources(value int64) ResourceVector {
	return ResourceVector{Cpu: value, Memory: value, BlockIo: value, EphemeralDisk: value,
		Bandwidth: value, Pids: value, FileDescriptors: value, HugePages: value}
}

func availabilityResourceWithOneShortDimension(t *testing.T, index int) ResourceVector {
	t.Helper()
	values := [8]int64{5, 5, 5, 5, 5, 5, 5, 5}
	values[index] = 4
	vector, err := NewResourceVector(values[0], values[1], values[2], values[3],
		values[4], values[5], values[6], values[7])
	if err != nil {
		t.Fatalf("vector: %v", err)
	}
	return vector
}

func availabilityPlace(t *testing.T, replica, node, domain string, requested, available ResourceVector) PlaceReplicaChange {
	t.Helper()
	return PlaceReplicaChange{
		ReplicaId:             mustReplicaId(t, replica),
		TargetNodeId:          mustAvailabilityNodeId(t, node),
		TargetFailureDomainId: mustFailureDomainId(t, domain),
		RequestedResources:    requested,
		AvailableResources:    available,
	}
}

func TestThreeNodeExplicitTwoOfThreeQuorumAllowsOneMaintenance(t *testing.T) {
	evaluator := AvailabilityPolicyEvaluator{}
	decision := availabilityEvaluate(t, evaluator,
		availabilityTestPolicy(t, 3, 2, 2, 1, 2, true, ResourceVectorZero, ReserveDispositionPreserve),
		MaintainReplicaChange{ReplicaId: mustReplicaId(t, "replica-a")},
		availabilityHealthyThree(t))

	if !decision.Admitted() {
		t.Fatal("expected admission")
	}
	if reason := availabilityReason(t, decision, AvailabilityReasonCodeQuorum); reason.Observed != 2 || reason.Required != 2 {
		t.Fatalf("quorum mismatch: %+v", reason)
	}
	if reason := availabilityReason(t, decision, AvailabilityReasonCodeDisruptionBudget); reason.Observed != 1 {
		t.Fatalf("disruption mismatch: %+v", reason)
	}
	if len(decision.Trace) != 30 {
		t.Fatalf("expected 30 trace rows, got %d", len(decision.Trace))
	}
}

func TestSecondLossFromTwoOfThreeRejectsQuorumAndDisruptionBudget(t *testing.T) {
	evaluator := AvailabilityPolicyEvaluator{}
	observations := availabilityHealthyThree(t)
	observations[0] = availabilityTestObservation(t, "replica-a", "node-a", "fd-a", ReplicaAvailabilityStateDisrupting)
	decision := availabilityEvaluate(t, evaluator,
		availabilityTestPolicy(t, 3, 2, 2, 1, 1, true, ResourceVectorZero, ReserveDispositionPreserve),
		MaintainReplicaChange{ReplicaId: mustReplicaId(t, "replica-b")},
		observations)

	if decision.Admitted() {
		t.Fatal("expected denial")
	}
	if reason := availabilityReason(t, decision, AvailabilityReasonCodeQuorum); reason.Outcome != AvailabilityReasonOutcomeRejected || reason.Observed != 1 {
		t.Fatalf("quorum mismatch: %+v", reason)
	}
	if reason := availabilityReason(t, decision, AvailabilityReasonCodeDisruptionBudget); reason.Outcome != AvailabilityReasonOutcomeRejected || reason.Observed != 2 {
		t.Fatalf("disruption mismatch: %+v", reason)
	}
}

func TestOneAtATimeMaintenanceRejectsConcurrentDisruptionEvenWhenQuorumAllowsIt(t *testing.T) {
	evaluator := AvailabilityPolicyEvaluator{}
	observations := availabilityHealthyThree(t)
	observations[0] = availabilityTestObservation(t, "replica-a", "node-a", "fd-a", ReplicaAvailabilityStateDisrupting)
	decision := availabilityEvaluate(t, evaluator,
		availabilityTestPolicy(t, 3, 1, 1, 1, 1, true, ResourceVectorZero, ReserveDispositionPreserve),
		MaintainReplicaChange{ReplicaId: mustReplicaId(t, "replica-b")},
		observations)

	if reason := availabilityReason(t, decision, AvailabilityReasonCodeQuorum); reason.Outcome != AvailabilityReasonOutcomePassed {
		t.Fatal("quorum should pass")
	}
	if reason := availabilityReason(t, decision, AvailabilityReasonCodeDisruptionBudget); reason.Outcome != AvailabilityReasonOutcomeRejected {
		t.Fatal("disruption budget should reject")
	}
}

func TestLastFailureDomainMarginRejectsMaintenance(t *testing.T) {
	evaluator := AvailabilityPolicyEvaluator{}
	decision := availabilityEvaluate(t, evaluator,
		availabilityTestPolicy(t, 3, 2, 2, 1, 3, true, ResourceVectorZero, ReserveDispositionPreserve),
		MaintainReplicaChange{ReplicaId: mustReplicaId(t, "replica-a")},
		availabilityHealthyThree(t))

	if decision.Admitted() {
		t.Fatal("expected denial")
	}
	reason := availabilityReason(t, decision, AvailabilityReasonCodeFailureDomainSpread)
	if reason.Outcome != AvailabilityReasonOutcomeRejected || reason.Observed != 2 {
		t.Fatalf("failure domain spread mismatch: %+v", reason)
	}
}

func TestPlacementRejectsHostColocationAndDomainCollapseIndependently(t *testing.T) {
	evaluator := AvailabilityPolicyEvaluator{}
	placement := availabilityPlace(t, "replica-d", "node-a", "fd-a",
		availabilityResources(1), availabilityResources(10))
	decision := availabilityEvaluate(t, evaluator,
		availabilityTestPolicy(t, 4, 2, 2, 1, 4, true, ResourceVectorZero, ReserveDispositionPreserve),
		placement, availabilityHealthyThree(t))

	if decision.Admitted() {
		t.Fatal("expected denial")
	}
	if reason := availabilityReason(t, decision, AvailabilityReasonCodeOnePerHost); reason.Outcome != AvailabilityReasonOutcomeRejected {
		t.Fatal("one per host should reject")
	}
	spreadReason := availabilityReason(t, decision, AvailabilityReasonCodeFailureDomainSpread)
	if spreadReason.Outcome != AvailabilityReasonOutcomeRejected || spreadReason.Observed != 3 {
		t.Fatalf("failure domain spread mismatch: %+v", spreadReason)
	}
}

func TestPlacementRestoresExplicitMinimumAndQuorumFromTwoToThree(t *testing.T) {
	evaluator := AvailabilityPolicyEvaluator{}
	observations := availabilityHealthyThree(t)[:2]
	placement := availabilityPlace(t, "replica-c", "node-c", "fd-c", ResourceVectorZero, ResourceVectorZero)
	decision := availabilityEvaluate(t, evaluator,
		availabilityTestPolicy(t, 3, 3, 3, 0, 3, true, ResourceVectorZero, ReserveDispositionPreserve),
		placement, observations)

	if !decision.Admitted() {
		t.Fatal("expected admission")
	}
	if reason := availabilityReason(t, decision, AvailabilityReasonCodeMinimumAvailable); reason.Observed != 3 || reason.Outcome != AvailabilityReasonOutcomePassed {
		t.Fatalf("minimum mismatch: %+v", reason)
	}
	if reason := availabilityReason(t, decision, AvailabilityReasonCodeQuorum); reason.Observed != 3 || reason.Outcome != AvailabilityReasonOutcomePassed {
		t.Fatalf("quorum mismatch: %+v", reason)
	}
}

func TestCheckedProjectedAvailabilityAdditionFailsClosedAtMaximumBoundary(t *testing.T) {
	maximumProjectedAvailable := NewAvailabilityCount(^uint64(0))
	if _, err := maximumProjectedAvailable.AddChecked(NewAvailabilityCount(1)); err == nil {
		t.Fatal("overflowing availability count must fail closed")
	}
}

func TestUnavailableAllocationStillBlocksOnePerHostPlacement(t *testing.T) {
	evaluator := AvailabilityPolicyEvaluator{}
	observations := availabilityHealthyThree(t)
	observations[0] = availabilityTestObservation(t, "replica-a", "node-a", "fd-a", ReplicaAvailabilityStateUnavailable)
	placement := availabilityPlace(t, "replica-d", "node-a", "fd-d",
		availabilityResources(1), availabilityResources(10))
	decision := availabilityEvaluate(t, evaluator,
		availabilityTestPolicy(t, 4, 1, 1, 1, 1, true, ResourceVectorZero, ReserveDispositionPreserve),
		placement, observations)

	if reason := availabilityReason(t, decision, AvailabilityReasonCodeOnePerHost); reason.Outcome != AvailabilityReasonOutcomeRejected {
		t.Fatal("one per host should reject against an unavailable allocation")
	}
}

func TestDrainAccountsForEveryAvailableReplicaOnTargetNode(t *testing.T) {
	evaluator := AvailabilityPolicyEvaluator{}
	observations := []ReplicaObservation{
		availabilityTestObservation(t, "replica-a", "node-a", "fd-a", ReplicaAvailabilityStateAvailable),
		availabilityTestObservation(t, "replica-b", "node-a", "fd-a", ReplicaAvailabilityStateAvailable),
		availabilityTestObservation(t, "replica-c", "node-c", "fd-c", ReplicaAvailabilityStateAvailable),
	}
	decision := availabilityEvaluate(t, evaluator,
		availabilityTestPolicy(t, 3, 2, 2, 1, 1, false, ResourceVectorZero, ReserveDispositionPreserve),
		DrainNodeChange{NodeId: mustAvailabilityNodeId(t, "node-a")},
		observations)

	if reason := availabilityReason(t, decision, AvailabilityReasonCodeMinimumAvailable); reason.Observed != 1 || reason.Outcome != AvailabilityReasonOutcomeRejected {
		t.Fatalf("minimum mismatch: %+v", reason)
	}
	if reason := availabilityReason(t, decision, AvailabilityReasonCodeDisruptionBudget); reason.Observed != 2 {
		t.Fatalf("disruption mismatch: %+v", reason)
	}
}

func TestReserveExactBoundaryPassesAndOneUnitConsumptionRejectsExactDimension(t *testing.T) {
	evaluator := AvailabilityPolicyEvaluator{}
	policy := availabilityTestPolicy(t, 4, 2, 2, 1, 3, true,
		availabilityResources(2), ReserveDispositionPreserve)
	exact := availabilityEvaluate(t, evaluator, policy,
		availabilityPlace(t, "replica-d", "node-d", "fd-d",
			availabilityResources(3), availabilityResources(5)),
		availabilityHealthyThree(t))
	if !exact.Admitted() {
		t.Fatal("exact reserve boundary should be admitted")
	}

	reserveCodes := []AvailabilityReasonCode{
		AvailabilityReasonCodeReserveCpu, AvailabilityReasonCodeReserveMemory,
		AvailabilityReasonCodeReserveBlockIo, AvailabilityReasonCodeReserveEphemeralDisk,
		AvailabilityReasonCodeReserveBandwidth, AvailabilityReasonCodeReservePids,
		AvailabilityReasonCodeReserveFileDescriptors, AvailabilityReasonCodeReserveHugePages,
	}
	for index, code := range reserveCodes {
		shortDecision := availabilityEvaluate(t, evaluator, policy,
			availabilityPlace(t, "replica-d", "node-d", "fd-d",
				availabilityResources(3), availabilityResourceWithOneShortDimension(t, index)),
			availabilityHealthyThree(t))
		if reason := availabilityReason(t, shortDecision, code); reason.Outcome != AvailabilityReasonOutcomeRejected {
			t.Fatalf("dimension %d reserve should reject", index)
		}
		for _, other := range shortDecision.Trace {
			isReserve := false
			for _, reserveCode := range reserveCodes {
				if other.Code == reserveCode {
					isReserve = true
					break
				}
			}
			if isReserve && other.Code != code && other.Outcome != AvailabilityReasonOutcomePassed {
				t.Fatalf("dimension %d: other reserves should pass: %+v", index, other)
			}
		}
	}
}

func TestExplicitMayConsumeReserveMakesEveryReserveCheckNotApplicable(t *testing.T) {
	evaluator := AvailabilityPolicyEvaluator{}
	maximumInt64 := int64(^uint64(0) >> 1)
	decision := availabilityEvaluate(t, evaluator,
		availabilityTestPolicy(t, 4, 2, 2, 1, 3, true,
			availabilityResources(maximumInt64), ReserveDispositionMayConsume),
		availabilityPlace(t, "replica-d", "node-d", "fd-d",
			availabilityResources(1), availabilityResources(1)),
		availabilityHealthyThree(t))

	reserveSet := map[AvailabilityReasonCode]bool{
		AvailabilityReasonCodeReserveCpu: true, AvailabilityReasonCodeReserveMemory: true,
		AvailabilityReasonCodeReserveBlockIo: true, AvailabilityReasonCodeReserveEphemeralDisk: true,
		AvailabilityReasonCodeReserveBandwidth: true, AvailabilityReasonCodeReservePids: true,
		AvailabilityReasonCodeReserveFileDescriptors: true, AvailabilityReasonCodeReserveHugePages: true,
	}
	capacitySet := map[AvailabilityReasonCode]bool{
		AvailabilityReasonCodeCapacityCpu: true, AvailabilityReasonCodeCapacityMemory: true,
		AvailabilityReasonCodeCapacityBlockIo: true, AvailabilityReasonCodeCapacityEphemeralDisk: true,
		AvailabilityReasonCodeCapacityBandwidth: true, AvailabilityReasonCodeCapacityPids: true,
		AvailabilityReasonCodeCapacityFileDescriptors: true, AvailabilityReasonCodeCapacityHugePages: true,
	}
	for _, reason := range decision.Trace {
		if reserveSet[reason.Code] && reason.Outcome != AvailabilityReasonOutcomeNotApplicable {
			t.Fatalf("reserve %v should be not applicable", reason.Code)
		}
		if capacitySet[reason.Code] && reason.Outcome != AvailabilityReasonOutcomePassed {
			t.Fatalf("capacity %v should pass", reason.Code)
		}
	}
}

func TestDuplicateAndConflictingObservationsHoldBeforePolicyArithmetic(t *testing.T) {
	evaluator := AvailabilityPolicyEvaluator{}
	policy := availabilityTestPolicy(t, 3, 2, 2, 1, 2, true, ResourceVectorZero, ReserveDispositionPreserve)
	healthy := availabilityHealthyThree(t)
	exactDuplicate := append(append([]ReplicaObservation{}, healthy...), healthy[0])
	duplicateDecision := availabilityEvaluate(t, evaluator, policy,
		MaintainReplicaChange{ReplicaId: mustReplicaId(t, "replica-a")}, exactDuplicate)
	conflict := append(append([]ReplicaObservation{}, healthy...),
		availabilityTestObservation(t, "replica-a", "node-z", "fd-z", ReplicaAvailabilityStateAvailable))
	conflictDecision := availabilityEvaluate(t, evaluator, policy,
		MaintainReplicaChange{ReplicaId: mustReplicaId(t, "replica-a")}, conflict)

	if reason := availabilityReason(t, duplicateDecision, AvailabilityReasonCodeReplicaObservationsUnique); reason.Outcome != AvailabilityReasonOutcomeHeld {
		t.Fatal("duplicates must hold")
	}
	if reason := availabilityReason(t, duplicateDecision, AvailabilityReasonCodeReplicaObservationsConsistent); reason.Outcome != AvailabilityReasonOutcomePassed {
		t.Fatal("exact duplicates stay consistent")
	}
	if reason := availabilityReason(t, conflictDecision, AvailabilityReasonCodeReplicaObservationsUnique); reason.Outcome != AvailabilityReasonOutcomeHeld {
		t.Fatal("conflicts must hold unique")
	}
	if reason := availabilityReason(t, conflictDecision, AvailabilityReasonCodeReplicaObservationsConsistent); reason.Outcome != AvailabilityReasonOutcomeHeld {
		t.Fatal("conflicts must hold consistent")
	}
	if reason := availabilityReason(t, conflictDecision, AvailabilityReasonCodeQuorum); reason.Outcome != AvailabilityReasonOutcomeHeld {
		t.Fatal("held evidence must hold the policy rows")
	}
}

func TestIncompleteSetMissingIdentitiesAndWrongServiceAllHold(t *testing.T) {
	evaluator := AvailabilityPolicyEvaluator{}
	missingIdentity := []ReplicaObservation{
		func() ReplicaObservation {
			replicaId := mustReplicaId(t, "replica-a")
			domainId := mustFailureDomainId(t, "fd-a")
			observation, err := NewReplicaObservation(replicaId, availabilityTestService, nil, &domainId, ReplicaAvailabilityStateAvailable)
			if err != nil {
				t.Fatalf("observation: %v", err)
			}
			return observation
		}(),
	}
	missingDecision := availabilityEvaluate(t, evaluator,
		availabilityTestPolicy(t, 1, 1, 1, 0, 1, true, ResourceVectorZero, ReserveDispositionPreserve),
		MaintainReplicaChange{ReplicaId: mustReplicaId(t, "replica-a")}, missingIdentity)

	generation, err := NewAvailabilityGeneration(1)
	if err != nil {
		t.Fatalf("generation: %v", err)
	}
	incomplete, err := NewAvailabilityEvaluationRequest(
		availabilityTestPolicy(t, 3, 2, 2, 1, 2, true, ResourceVectorZero, ReserveDispositionPreserve),
		MaintainReplicaChange{ReplicaId: mustReplicaId(t, "replica-a")},
		ObservationCompletenessIncomplete, generation, generation, availabilityHealthyThree(t))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	wrongService := []ReplicaObservation{func() ReplicaObservation {
		other := mustServiceId("other-service")
		nodeId := mustAvailabilityNodeId(t, "node-a")
		domainId := mustFailureDomainId(t, "fd-a")
		observation, observationErr := NewReplicaObservation(
			mustReplicaId(t, "replica-a"), other, &nodeId, &domainId, ReplicaAvailabilityStateAvailable)
		if observationErr != nil {
			t.Fatalf("observation: %v", observationErr)
		}
		return observation
	}()}

	if reason := availabilityReason(t, missingDecision, AvailabilityReasonCodeReplicaIdentitiesComplete); reason.Outcome != AvailabilityReasonOutcomeHeld {
		t.Fatal("missing identity must hold")
	}
	if reason := availabilityReason(t, evaluator.Evaluate(incomplete), AvailabilityReasonCodeObservationSetComplete); reason.Outcome != AvailabilityReasonOutcomeHeld {
		t.Fatal("incomplete set must hold")
	}
	if reason := availabilityReason(t, availabilityEvaluate(t, evaluator,
		availabilityTestPolicy(t, 1, 1, 1, 0, 1, true, ResourceVectorZero, ReserveDispositionPreserve),
		MaintainReplicaChange{ReplicaId: mustReplicaId(t, "replica-a")}, wrongService),
		AvailabilityReasonCodeServiceIdentityConsistent); reason.Outcome != AvailabilityReasonOutcomeHeld {
		t.Fatal("wrong service must hold")
	}
}

func TestZeroMaximumAndOverflowCountBoundariesAreExact(t *testing.T) {
	evaluator := AvailabilityPolicyEvaluator{}
	zeroPolicy := availabilityTestPolicy(t, 0, 0, 0, 0, 0, true, ResourceVectorZero, ReserveDispositionPreserve)
	zeroPlacement := availabilityEvaluate(t, evaluator, zeroPolicy,
		availabilityPlace(t, "replica-a", "node-a", "fd-a", ResourceVectorZero, ResourceVectorZero),
		[]ReplicaObservation{})
	maximum := NewAvailabilityCount(^uint64(0))
	maximumInt64 := int64(^uint64(0) >> 1)
	maximumPolicy := availabilityTestPolicy(t, ^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0),
		^uint64(0), true, availabilityResources(maximumInt64), ReserveDispositionPreserve)

	if reason := availabilityReason(t, zeroPlacement, AvailabilityReasonCodeDesiredCount); reason.Outcome != AvailabilityReasonOutcomeRejected {
		t.Fatal("zero desired count must reject")
	}
	if _, err := maximum.AddChecked(NewAvailabilityCount(1)); err == nil {
		t.Fatal("count addition must overflow")
	}
	if _, err := NewAvailabilityCount(0).SubtractChecked(NewAvailabilityCount(1)); err == nil {
		t.Fatal("count subtraction must underflow")
	}
	if difference, err := maximum.SubtractChecked(maximum); err != nil || difference.Value != 0 {
		t.Fatal("exact subtraction must produce zero")
	}
	if maximumPolicy.Desired.Value != ^uint64(0) || maximumPolicy.RequiredDistinctFailureDomains.Value != ^uint64(0) {
		t.Fatal("maximum policy counts must be exact")
	}
	if _, err := NewServiceAvailabilityPolicy(
		availabilityTestService, NewAvailabilityCount(2), NewAvailabilityCount(3),
		NewAvailabilityCount(1), NewAvailabilityCount(1), ServiceCriticalityCritical, true,
		NewAvailabilityCount(1), ResourceVectorZero, ReserveDispositionPreserve); err == nil {
		t.Fatal("counts above desired must be rejected")
	}
}

func TestDuplicatePlacementIdentityAndUnavailableMaintenanceTargetReject(t *testing.T) {
	evaluator := AvailabilityPolicyEvaluator{}
	duplicate := availabilityEvaluate(t, evaluator,
		availabilityTestPolicy(t, 4, 2, 2, 1, 2, true, ResourceVectorZero, ReserveDispositionPreserve),
		availabilityPlace(t, "replica-a", "node-d", "fd-d", availabilityResources(1), availabilityResources(10)),
		availabilityHealthyThree(t))
	observations := availabilityHealthyThree(t)
	observations[0] = availabilityTestObservation(t, "replica-a", "node-a", "fd-a", ReplicaAvailabilityStateDisrupting)
	unavailableTarget := availabilityEvaluate(t, evaluator,
		availabilityTestPolicy(t, 3, 1, 1, 2, 1, true, ResourceVectorZero, ReserveDispositionPreserve),
		MaintainReplicaChange{ReplicaId: mustReplicaId(t, "replica-a")}, observations)

	if reason := availabilityReason(t, duplicate, AvailabilityReasonCodeChangeTargetValid); reason.Outcome != AvailabilityReasonOutcomeRejected {
		t.Fatal("duplicate placement target must reject")
	}
	if reason := availabilityReason(t, unavailableTarget, AvailabilityReasonCodeChangeTargetValid); reason.Outcome != AvailabilityReasonOutcomeRejected {
		t.Fatal("unavailable maintenance target must reject")
	}
}

func TestDecisionsAndTraceAreInvariantToAllObservationPermutations(t *testing.T) {
	evaluator := AvailabilityPolicyEvaluator{}
	baseline := ""
	healthy := availabilityHealthyThree(t)
	for first := 0; first < 3; first++ {
		for second := 0; second < 3; second++ {
			if first == second {
				continue
			}
			third := 3 - first - second
			permutation := []ReplicaObservation{healthy[first], healthy[second], healthy[third]}
			decision := availabilityEvaluate(t, evaluator,
				availabilityTestPolicy(t, 3, 2, 2, 1, 2, true, ResourceVectorZero, ReserveDispositionPreserve),
				MaintainReplicaChange{ReplicaId: mustReplicaId(t, "replica-a")}, permutation)
			serialized := propertySerializeAvailability(decision)
			if baseline == "" {
				baseline = serialized
			} else if serialized != baseline {
				t.Fatalf("permutation changed the decision:\n%s\n%s", baseline, serialized)
			}
		}
	}
}

func TestRequestDefensivelyCopiesObservations(t *testing.T) {
	evaluator := AvailabilityPolicyEvaluator{}
	observations := availabilityHealthyThree(t)
	generation, err := NewAvailabilityGeneration(1)
	if err != nil {
		t.Fatalf("generation: %v", err)
	}
	request, err := NewAvailabilityEvaluationRequest(
		availabilityTestPolicy(t, 3, 2, 2, 1, 2, true, ResourceVectorZero, ReserveDispositionPreserve),
		MaintainReplicaChange{ReplicaId: mustReplicaId(t, "replica-a")},
		ObservationCompletenessComplete, generation, generation, observations)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	observations = nil

	if len(request.Observations) != 3 {
		t.Fatalf("expected 3 snapshot observations, got %d", len(request.Observations))
	}
	if !evaluator.Evaluate(request).Admitted() {
		t.Fatal("expected admission after clearing the source slice")
	}
}

func TestTraceIsClosedNumericAndCannotCarryCallerTextOrSecrets(t *testing.T) {
	evaluator := AvailabilityPolicyEvaluator{}
	decision := availabilityEvaluate(t, evaluator,
		availabilityTestPolicy(t, 3, 2, 2, 1, 2, true, ResourceVectorZero, ReserveDispositionPreserve),
		MaintainReplicaChange{ReplicaId: mustReplicaId(t, "replica-a")},
		availabilityHealthyThree(t))

	serialized := propertySerializeAvailability(decision)
	if strings.Contains(serialized, "secret") {
		t.Fatal("the serialized trace must not carry secrets")
	}
	for index, reason := range decision.Trace {
		if !reason.Code.defined() || !reason.Outcome.defined() {
			t.Fatalf("undefined trace values at %d", index)
		}
		expected := AvailabilityReasonCode(index + 1)
		if reason.Code != expected {
			t.Fatalf("trace code order mismatch at %d: got %v want %v", index, reason.Code, expected)
		}
	}
	if len(decision.Trace) != len(AllAvailabilityReasonCodes) {
		t.Fatalf("trace must contain every reason code: %d", len(decision.Trace))
	}
}

func TestUnknownEnumsAndNoncanonicalIdentitiesFailClosed(t *testing.T) {
	if _, err := NewServiceAvailabilityPolicy(
		availabilityTestService, NewAvailabilityCount(3), NewAvailabilityCount(2),
		NewAvailabilityCount(2), NewAvailabilityCount(1), ServiceCriticality(0), true,
		NewAvailabilityCount(2), ResourceVectorZero, ReserveDispositionPreserve); err == nil {
		t.Fatal("unknown criticality must be rejected")
	}
	if _, err := NewServiceAvailabilityPolicy(
		availabilityTestService, NewAvailabilityCount(3), NewAvailabilityCount(2),
		NewAvailabilityCount(2), NewAvailabilityCount(1), ServiceCriticalityCritical, true,
		NewAvailabilityCount(2), ResourceVectorZero, ReserveDisposition(999)); err == nil {
		t.Fatal("unknown reserve disposition must be rejected")
	}
	nodeId := mustAvailabilityNodeId(t, "node-a")
	domainId := mustFailureDomainId(t, "fd-a")
	if _, err := NewReplicaObservation(mustReplicaId(t, "replica-a"), availabilityTestService,
		&nodeId, &domainId, ReplicaAvailabilityState(0)); err == nil {
		t.Fatal("unknown replica state must be rejected")
	}
	generation, err := NewAvailabilityGeneration(1)
	if err != nil {
		t.Fatalf("generation: %v", err)
	}
	var rangeError *errs.ArgumentOutOfRangeError
	_, err = NewAvailabilityEvaluationRequest(
		availabilityTestPolicy(t, 3, 2, 2, 1, 2, true, ResourceVectorZero, ReserveDispositionPreserve),
		MaintainReplicaChange{ReplicaId: mustReplicaId(t, "replica-a")},
		ObservationCompleteness(0), generation, generation, availabilityHealthyThree(t))
	if !errors.As(err, &rangeError) {
		t.Fatalf("expected errs.ArgumentOutOfRangeError, got %v", err)
	}
	if _, err := NewReplicaId("secret\nvalue"); err == nil {
		t.Fatal("noncanonical identity must be rejected")
	}
	_ = fmt.Sprint()
}
