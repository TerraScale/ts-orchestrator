package scheduling

import (
	"strings"
	"testing"
)

func auditTestEvaluate(t *testing.T, evaluator AvailabilityPolicyEvaluator, request *AvailabilityEvaluationRequest) AvailabilityDecision {
	t.Helper()
	return evaluator.Evaluate(request)
}

func auditTestRequest(
	t *testing.T,
	policy *ServiceAvailabilityPolicy,
	change AvailabilityChange,
	observations []ReplicaObservation,
	completeness ObservationCompleteness,
	observationGeneration, currentGeneration uint64,
) *AvailabilityEvaluationRequest {
	t.Helper()
	if policy == nil {
		policy = auditTestPolicy(t, "control-service", 4, 0, 0, 4, ServiceCriticalityOrdinary, false, 0, ResourceVectorZero, ReserveDispositionMayConsume)
	}
	if change == nil {
		change = auditTestPlace(t, "replica-d", "node-d", "fd-d", nil, nil)
	}
	if observations == nil {
		observations = auditTestHealthyThree(t, "control-service")
	}
	observation, err := NewAvailabilityGeneration(observationGeneration)
	if err != nil {
		t.Fatalf("generation: %v", err)
	}
	current, err := NewAvailabilityGeneration(currentGeneration)
	if err != nil {
		t.Fatalf("generation: %v", err)
	}
	request, err := NewAvailabilityEvaluationRequest(policy, change, completeness, observation, current, observations)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	return request
}

func auditTestPolicy(
	t *testing.T,
	service string,
	desired, minimum, quorum, disruptions uint64,
	criticality ServiceCriticality,
	onePerHost bool,
	domains uint64,
	reserve ResourceVector,
	reserveDisposition ReserveDisposition,
) *ServiceAvailabilityPolicy {
	t.Helper()
	serviceId := mustServiceId(service)
	policy, err := NewServiceAvailabilityPolicy(serviceId,
		NewAvailabilityCount(desired), NewAvailabilityCount(minimum),
		NewAvailabilityCount(quorum), NewAvailabilityCount(disruptions),
		criticality, onePerHost, NewAvailabilityCount(domains), reserve, reserveDisposition)
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	return policy
}

func auditTestPlace(t *testing.T, replica, node, domain string, requested, available *ResourceVector) PlaceReplicaChange {
	t.Helper()
	requestedValue := ResourceVectorZero
	if requested != nil {
		requestedValue = *requested
	}
	availableValue := ResourceVector{Cpu: 10, Memory: 10, BlockIo: 10, EphemeralDisk: 10,
		Bandwidth: 10, Pids: 10, FileDescriptors: 10, HugePages: 10}
	if available != nil {
		availableValue = *available
	}
	return PlaceReplicaChange{
		ReplicaId:             mustReplicaId(t, replica),
		TargetNodeId:          mustAvailabilityNodeId(t, node),
		TargetFailureDomainId: mustFailureDomainId(t, domain),
		RequestedResources:    requestedValue,
		AvailableResources:    availableValue,
	}
}

func auditTestHealthyThree(t *testing.T, service string) []ReplicaObservation {
	t.Helper()
	serviceId := mustServiceId(service)
	observations := make([]ReplicaObservation, 0, 3)
	for _, tuple := range [][3]string{
		{"replica-a", "node-a", "fd-a"},
		{"replica-b", "node-b", "fd-b"},
		{"replica-c", "node-c", "fd-c"},
	} {
		nodeId := mustAvailabilityNodeId(t, tuple[1])
		domainId := mustFailureDomainId(t, tuple[2])
		observation, err := NewReplicaObservation(mustReplicaId(t, tuple[0]), serviceId,
			&nodeId, &domainId, ReplicaAvailabilityStateAvailable)
		if err != nil {
			t.Fatalf("observation: %v", err)
		}
		observations = append(observations, observation)
	}
	return observations
}

func auditTestMutateObservation(t *testing.T, replica, node, domain string, state ReplicaAvailabilityState) []ReplicaObservation {
	t.Helper()
	return []ReplicaObservation{
		availabilityTestObservation(t, replica, node, domain, state),
		availabilityTestObservation(t, "replica-b", "node-b", "fd-b", ReplicaAvailabilityStateAvailable),
		availabilityTestObservation(t, "replica-c", "node-c", "fd-c", ReplicaAvailabilityStateAvailable),
	}
}

func auditTestTrace(decision AvailabilityDecision) string {
	rows := make([]string, len(decision.Trace))
	for index, reason := range decision.Trace {
		rows[index] = strings.Join([]string{
			formatUint(uint64(reason.Code)),
			formatUint(uint64(reason.Outcome)),
			formatUint(reason.Observed),
			formatUint(reason.Required),
		}, ":")
	}
	return strings.Join(rows, ";")
}

func TestDistinctAdmittedPlacementTargetsNoLongerCollapseToTheSameOutput(t *testing.T) {
	evaluator := AvailabilityPolicyEvaluator{}
	first := evaluator.Evaluate(auditTestRequest(t, nil, auditTestPlace(t, "replica-d", "node-d", "fd-d", nil, nil),
		auditTestHealthyThree(t, "control-service"), ObservationCompletenessComplete, 1, 1))
	second := evaluator.Evaluate(auditTestRequest(t, nil, auditTestPlace(t, "replica-e", "node-e", "fd-e", nil, nil),
		auditTestHealthyThree(t, "control-service"), ObservationCompletenessComplete, 1, 1))

	if auditTestTrace(first) != auditTestTrace(second) {
		t.Fatal("traces of equivalent shapes should stay identical")
	}
	if availabilityAcceptedRequestFingerprint(first) == availabilityAcceptedRequestFingerprint(second) {
		t.Fatal("distinct accepted requests must have distinct fingerprints")
	}
}

func TestAdmissionRetainsTheExactRequestAndItsDefensiveObservationSnapshot(t *testing.T) {
	evaluator := AvailabilityPolicyEvaluator{}
	policy := auditTestPolicy(t, "control-service", 4, 0, 0, 4, ServiceCriticalityOrdinary, false, 0, ResourceVectorZero, ReserveDispositionMayConsume)
	change := auditTestPlace(t, "replica-d", "node-d", "fd-d", nil, nil)
	observations := auditTestHealthyThree(t, "control-service")
	firstObservation := observations[0]
	request := auditTestRequest(t, policy, change, observations, ObservationCompletenessComplete, 1, 1)
	decision := evaluator.Evaluate(request)
	observations = nil

	if !decision.Admitted() {
		t.Fatal("expected admission")
	}
	if decision.AcceptedRequest != request {
		t.Fatal("the accepted request must be the exact request instance")
	}
	if decision.AcceptedRequest.Policy != *policy {
		t.Fatal("the accepted policy must be the exact policy value")
	}
	if len(decision.AcceptedRequest.Observations) != 3 {
		t.Fatalf("expected 3 snapshot observations, got %d", len(decision.AcceptedRequest.Observations))
	}
	if decision.AcceptedRequest.Observations[0] != firstObservation {
		t.Fatal("the observation snapshot must be the original value")
	}
}

func TestPlaceMaintainAndDrainAdmissionsAllRetainTheirExactRequest(t *testing.T) {
	evaluator := AvailabilityPolicyEvaluator{}
	requests := []*AvailabilityEvaluationRequest{
		auditTestRequest(t, nil, auditTestPlace(t, "replica-d", "node-d", "fd-d", nil, nil), nil, ObservationCompletenessComplete, 1, 1),
		auditTestRequest(t, nil, MaintainReplicaChange{ReplicaId: mustReplicaId(t, "replica-a")}, nil, ObservationCompletenessComplete, 1, 1),
		auditTestRequest(t, nil, DrainNodeChange{NodeId: mustAvailabilityNodeId(t, "node-a")}, nil, ObservationCompletenessComplete, 1, 1),
	}
	for _, request := range requests {
		decision := evaluator.Evaluate(request)
		if !decision.Admitted() {
			t.Fatal("expected admission")
		}
		if decision.AcceptedRequest != request {
			t.Fatal("the accepted request must be the exact request instance")
		}
	}
}

func auditTestDimension(t *testing.T, index int, value, other int64) ResourceVector {
	t.Helper()
	values := [8]int64{other, other, other, other, other, other, other, other}
	values[index] = value
	vector, err := NewResourceVector(values[0], values[1], values[2], values[3],
		values[4], values[5], values[6], values[7])
	if err != nil {
		t.Fatalf("vector: %v", err)
	}
	return vector
}

func TestCompleteProjectionIsSensitiveToEveryAcceptedRequestFieldFamily(t *testing.T) {
	evaluator := AvailabilityPolicyEvaluator{}
	healthy := auditTestHealthyThree(t, "control-service")
	baseline := evaluator.Evaluate(auditTestRequest(t, nil, nil, healthy, ObservationCompletenessComplete, 1, 1))
	otherServiceHealthy := auditTestHealthyThree(t, "other-service")
	variants := []AvailabilityDecision{
		evaluator.Evaluate(auditTestRequest(t, auditTestPolicy(t, "other-service", 4, 0, 0, 4, ServiceCriticalityOrdinary, false, 0, ResourceVectorZero, ReserveDispositionMayConsume), nil, otherServiceHealthy, ObservationCompletenessComplete, 1, 1)),
		evaluator.Evaluate(auditTestRequest(t, auditTestPolicy(t, "control-service", 5, 0, 0, 4, ServiceCriticalityOrdinary, false, 0, ResourceVectorZero, ReserveDispositionMayConsume), nil, healthy, ObservationCompletenessComplete, 1, 1)),
		evaluator.Evaluate(auditTestRequest(t, auditTestPolicy(t, "control-service", 4, 1, 0, 4, ServiceCriticalityOrdinary, false, 0, ResourceVectorZero, ReserveDispositionMayConsume), nil, healthy, ObservationCompletenessComplete, 1, 1)),
		evaluator.Evaluate(auditTestRequest(t, auditTestPolicy(t, "control-service", 4, 0, 1, 4, ServiceCriticalityOrdinary, false, 0, ResourceVectorZero, ReserveDispositionMayConsume), nil, healthy, ObservationCompletenessComplete, 1, 1)),
		evaluator.Evaluate(auditTestRequest(t, auditTestPolicy(t, "control-service", 4, 0, 0, 3, ServiceCriticalityOrdinary, false, 0, ResourceVectorZero, ReserveDispositionMayConsume), nil, healthy, ObservationCompletenessComplete, 1, 1)),
		evaluator.Evaluate(auditTestRequest(t, auditTestPolicy(t, "control-service", 4, 0, 0, 4, ServiceCriticalityCritical, false, 0, ResourceVectorZero, ReserveDispositionMayConsume), nil, healthy, ObservationCompletenessComplete, 1, 1)),
		evaluator.Evaluate(auditTestRequest(t, auditTestPolicy(t, "control-service", 4, 0, 0, 4, ServiceCriticalityOrdinary, true, 0, ResourceVectorZero, ReserveDispositionMayConsume), nil, healthy, ObservationCompletenessComplete, 1, 1)),
		evaluator.Evaluate(auditTestRequest(t, auditTestPolicy(t, "control-service", 4, 0, 0, 4, ServiceCriticalityOrdinary, false, 1, ResourceVectorZero, ReserveDispositionMayConsume), nil, healthy, ObservationCompletenessComplete, 1, 1)),
		evaluator.Evaluate(auditTestRequest(t, auditTestPolicy(t, "control-service", 4, 0, 0, 4, ServiceCriticalityOrdinary, false, 0, ResourceVectorZero, ReserveDispositionPreserve), nil, healthy, ObservationCompletenessComplete, 1, 1)),
		evaluator.Evaluate(auditTestRequest(t, nil, auditTestPlace(t, "other-replica", "node-d", "fd-d", nil, nil), healthy, ObservationCompletenessComplete, 1, 1)),
		evaluator.Evaluate(auditTestRequest(t, nil, auditTestPlace(t, "replica-d", "other-node", "fd-d", nil, nil), healthy, ObservationCompletenessComplete, 1, 1)),
		evaluator.Evaluate(auditTestRequest(t, nil, auditTestPlace(t, "replica-d", "node-d", "other-domain", nil, nil), healthy, ObservationCompletenessComplete, 1, 1)),
		evaluator.Evaluate(auditTestRequest(t, nil, MaintainReplicaChange{ReplicaId: mustReplicaId(t, "replica-a")}, healthy, ObservationCompletenessComplete, 1, 1)),
		evaluator.Evaluate(auditTestRequest(t, nil, DrainNodeChange{NodeId: mustAvailabilityNodeId(t, "node-a")}, healthy, ObservationCompletenessComplete, 1, 1)),
		evaluator.Evaluate(auditTestRequest(t, nil, nil, healthy, ObservationCompletenessComplete, 2, 2)),
		evaluator.Evaluate(auditTestRequest(t, nil, nil, auditTestMutateObservation(t, "other-replica", "node-a", "fd-a", ReplicaAvailabilityStateAvailable), ObservationCompletenessComplete, 1, 1)),
		evaluator.Evaluate(auditTestRequest(t, nil, nil, auditTestMutateObservation(t, "replica-a", "other-node", "fd-a", ReplicaAvailabilityStateAvailable), ObservationCompletenessComplete, 1, 1)),
		evaluator.Evaluate(auditTestRequest(t, nil, nil, auditTestMutateObservation(t, "replica-a", "node-a", "other-domain", ReplicaAvailabilityStateAvailable), ObservationCompletenessComplete, 1, 1)),
		evaluator.Evaluate(auditTestRequest(t, nil, nil, auditTestMutateObservation(t, "replica-a", "node-a", "fd-a", ReplicaAvailabilityStateUnavailable), ObservationCompletenessComplete, 1, 1)),
	}
	for dimension := 0; dimension < 8; dimension++ {
		reserveVariant := auditTestDimension(t, dimension, 1, 0)
		variants = append(variants, evaluator.Evaluate(auditTestRequest(t,
			auditTestPolicy(t, "control-service", 4, 0, 0, 4, ServiceCriticalityOrdinary, false, 0,
				reserveVariant, ReserveDispositionMayConsume),
			nil, healthy, ObservationCompletenessComplete, 1, 1)))
		requested := auditTestDimension(t, dimension, 1, 0)
		variants = append(variants, evaluator.Evaluate(auditTestRequest(t, nil,
			auditTestPlace(t, "replica-d", "node-d", "fd-d", &requested, nil), healthy,
			ObservationCompletenessComplete, 1, 1)))
		available := auditTestDimension(t, dimension, 9, 10)
		variants = append(variants, evaluator.Evaluate(auditTestRequest(t, nil,
			auditTestPlace(t, "replica-d", "node-d", "fd-d", &ResourceVectorZero, &available), healthy,
			ObservationCompletenessComplete, 1, 1)))
	}

	fingerprint := availabilityAcceptedRequestFingerprint(baseline)
	if !baseline.Admitted() {
		t.Fatal("baseline must be admitted")
	}
	for index, variant := range variants {
		if !variant.Admitted() {
			t.Fatalf("variant %d must be admitted", index)
		}
		if availabilityAcceptedRequestFingerprint(variant) == fingerprint {
			t.Fatalf("variant %d must change the fingerprint", index)
		}
	}
}

func TestSemanticObservationPermutationsHaveOneCanonicalFingerprint(t *testing.T) {
	evaluator := AvailabilityPolicyEvaluator{}
	observations := auditTestHealthyThree(t, "control-service")
	permutations := [][]ReplicaObservation{
		observations,
		{observations[2], observations[1], observations[0]},
		{observations[1], observations[2], observations[0]},
	}
	expected := ""
	for _, permutation := range permutations {
		decision := evaluator.Evaluate(auditTestRequest(t, nil, nil, permutation, ObservationCompletenessComplete, 1, 1))
		fingerprint := availabilityAcceptedRequestFingerprint(decision)
		if expected == "" {
			expected = fingerprint
		} else if fingerprint != expected {
			t.Fatalf("semantic permutation changed the fingerprint:\n%s\n%s", expected, fingerprint)
		}
	}
}

func TestEveryHeldOrRejectedResultHasNoAcceptedRequestAndAdmissionIsIff(t *testing.T) {
	evaluator := AvailabilityPolicyEvaluator{}
	healthy := auditTestHealthyThree(t, "control-service")
	conflictNode := mustAvailabilityNodeId(t, "conflict-node")
	conflictDomain := mustFailureDomainId(t, "conflict-domain")
	conflict, err := NewReplicaObservation(mustReplicaId(t, "replica-a"), mustServiceId("control-service"),
		&conflictNode, &conflictDomain, ReplicaAvailabilityStateAvailable)
	if err != nil {
		t.Fatalf("conflict: %v", err)
	}
	missingNodeObservation := func() ReplicaObservation {
		domainId := mustFailureDomainId(t, "fd-a")
		observation, observationErr := NewReplicaObservation(mustReplicaId(t, "replica-a"),
			mustServiceId("control-service"), nil, &domainId, ReplicaAvailabilityStateAvailable)
		if observationErr != nil {
			t.Fatalf("observation: %v", observationErr)
		}
		return observation
	}()
	requests := []*AvailabilityEvaluationRequest{
		auditTestRequest(t, nil, nil, healthy, ObservationCompletenessIncomplete, 1, 1),
		auditTestRequest(t, nil, nil, healthy, ObservationCompletenessComplete, 1, 2),
		auditTestRequest(t, nil, nil, healthy, ObservationCompletenessComplete, 2, 1),
		auditTestRequest(t, nil, nil, append(append([]ReplicaObservation{}, healthy...), healthy[0]), ObservationCompletenessComplete, 1, 1),
		auditTestRequest(t, nil, nil, append(append([]ReplicaObservation{}, healthy...), conflict), ObservationCompletenessComplete, 1, 1),
		auditTestRequest(t, nil, nil, []ReplicaObservation{missingNodeObservation}, ObservationCompletenessComplete, 1, 1),
		auditTestRequest(t, nil, nil, []ReplicaObservation{func() ReplicaObservation {
			other := mustServiceId("other-service")
			nodeId := mustAvailabilityNodeId(t, "node-a")
			domainId := mustFailureDomainId(t, "fd-a")
			observation, observationErr := NewReplicaObservation(mustReplicaId(t, "replica-a"),
				other, &nodeId, &domainId, ReplicaAvailabilityStateAvailable)
			if observationErr != nil {
				t.Fatalf("observation: %v", observationErr)
			}
			return observation
		}()}, ObservationCompletenessComplete, 1, 1),
		auditTestRequest(t, nil, MaintainReplicaChange{ReplicaId: mustReplicaId(t, "missing-replica")}, healthy, ObservationCompletenessComplete, 1, 1),
		auditTestRequest(t, auditTestPolicy(t, "control-service", 3, 0, 0, 3, ServiceCriticalityOrdinary, false, 0, ResourceVectorZero, ReserveDispositionMayConsume), nil, healthy, ObservationCompletenessComplete, 1, 1),
		auditTestRequest(t, auditTestPolicy(t, "control-service", 4, 4, 0, 4, ServiceCriticalityOrdinary, false, 0, ResourceVectorZero, ReserveDispositionMayConsume), nil, auditTestMutateObservation(t, "replica-a", "node-a", "fd-a", ReplicaAvailabilityStateUnavailable), ObservationCompletenessComplete, 1, 1),
		auditTestRequest(t, auditTestPolicy(t, "control-service", 4, 0, 4, 4, ServiceCriticalityOrdinary, false, 0, ResourceVectorZero, ReserveDispositionMayConsume), nil, auditTestMutateObservation(t, "replica-a", "node-a", "fd-a", ReplicaAvailabilityStateUnavailable), ObservationCompletenessComplete, 1, 1),
		auditTestRequest(t, auditTestPolicy(t, "control-service", 4, 0, 0, 0, ServiceCriticalityOrdinary, false, 0, ResourceVectorZero, ReserveDispositionMayConsume), MaintainReplicaChange{ReplicaId: mustReplicaId(t, "replica-a")}, healthy, ObservationCompletenessComplete, 1, 1),
		auditTestRequest(t, auditTestPolicy(t, "control-service", 4, 0, 0, 4, ServiceCriticalityOrdinary, true, 0, ResourceVectorZero, ReserveDispositionMayConsume), auditTestPlace(t, "replica-d", "node-a", "fd-d", nil, nil), healthy, ObservationCompletenessComplete, 1, 1),
		auditTestRequest(t, auditTestPolicy(t, "control-service", 4, 0, 0, 4, ServiceCriticalityOrdinary, false, 4, ResourceVectorZero, ReserveDispositionMayConsume), auditTestPlace(t, "replica-d", "node-d", "fd-a", nil, nil), healthy, ObservationCompletenessComplete, 1, 1),
		auditTestRequest(t, auditTestPolicy(t, "control-service", 4, 0, 0, 4, ServiceCriticalityOrdinary, false, 0, availabilityResources(11), ReserveDispositionPreserve), nil, healthy, ObservationCompletenessComplete, 1, 1),
		auditTestRequest(t, nil, auditTestPlace(t, "replica-d", "node-d", "fd-d", &[]ResourceVector{availabilityResources(11)}[0], &[]ResourceVector{availabilityResources(10)}[0]), healthy, ObservationCompletenessComplete, 1, 1),
	}
	for _, request := range requests {
		decision := evaluator.Evaluate(request)
		if decision.Admitted() {
			t.Fatal("expected denial")
		}
		if decision.AcceptedRequest != nil {
			t.Fatal("denied decisions must not retain a request")
		}
		if fingerprint := availabilityAcceptedRequestFingerprint(decision); fingerprint != "denied" {
			t.Fatalf("denied fingerprint must be \"denied\", got %q", fingerprint)
		}
	}
	admitted := evaluator.Evaluate(auditTestRequest(t, nil, nil, healthy, ObservationCompletenessComplete, 1, 1))
	if admitted.Admitted() != (admitted.AcceptedRequest != nil) {
		t.Fatal("admission must be exactly iff an accepted request exists")
	}
}
