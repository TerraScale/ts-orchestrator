// This file ports tests/TerraScale.Orchestrator.Scheduler.Tests/
// DeterministicSchedulerTests.cs.
//
// Skipped from the C# suite:
//   - PublicSchedulerSurfaceCannotBecomeASecondProductPlacementAuthority: it
//     reflects over the exported .NET surface; the Go package has no
//     ProjectId/ProjectRegions/PlacementGeneration/DatabaseId/DatabaseRegions
//     members anywhere, so the reflection sweep has no equivalent.
package scheduling

import (
	"errors"
	"math/big"
	"strings"
	"testing"
)

func schedulerTestTiny() ResourceVector {
	return ResourceVector{Cpu: 1, Memory: 1, BlockIo: 1, EphemeralDisk: 1,
		Bandwidth: 1, Pids: 1, FileDescriptors: 1, HugePages: 1}
}

func schedulerTestAbundant() ResourceVector {
	return ResourceVector{Cpu: 100, Memory: 100, BlockIo: 100, EphemeralDisk: 100,
		Bandwidth: 100, Pids: 100, FileDescriptors: 100, HugePages: 100}
}

func schedulerTestPolicy(t *testing.T) *LeastWastePolicy {
	t.Helper()
	dimensions := make([]ScoreDimension, 0, len(AllResourceDimensions))
	for _, dimension := range AllResourceDimensions {
		dimensions = append(dimensions, ScoreDimension{Dimension: dimension, Weight: 1})
	}
	policy, err := NewLeastWastePolicy(dimensions)
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	return policy
}

func schedulerTestNode(
	t *testing.T,
	id string,
	available ResourceVector,
	occupiedPorts []int,
	labels map[string]string,
	affinityFacts []string,
	safetyCap *AllocationSafetyCap,
	veto *CandidateVeto,
) *NodeCandidate {
	t.Helper()
	node, err := NewNodeCandidate(id, "compact", "arm64", "fd-1", available,
		occupiedPorts, labels, []string{"trusted"}, []string{"private"}, []string{"vault"},
		affinityFacts, safetyCap, veto)
	if err != nil {
		t.Fatalf("node %s: %v", id, err)
	}
	return node
}

func schedulerTestWorkload(
	t *testing.T,
	resources ResourceVector,
	requiredPorts []int,
	requiredLabels map[string]string,
	requiredAffinityFacts []string,
	prohibitedAffinityFacts []string,
) *WorkloadRequest {
	t.Helper()
	workload, err := NewWorkloadRequest("api", "arm64", resources, requiredPorts, nil,
		requiredLabels, []string{"trusted"}, []string{"private"}, []string{"vault"}, nil,
		requiredAffinityFacts, prohibitedAffinityFacts)
	if err != nil {
		t.Fatalf("workload: %v", err)
	}
	return workload
}

func schedulerTestVector(dimension ResourceDimension, value int64) ResourceVector {
	vector := ResourceVector{}
	switch dimension {
	case ResourceDimensionCpu:
		vector.Cpu = value
	case ResourceDimensionMemory:
		vector.Memory = value
	case ResourceDimensionBlockIo:
		vector.BlockIo = value
	case ResourceDimensionEphemeralDisk:
		vector.EphemeralDisk = value
	case ResourceDimensionBandwidth:
		vector.Bandwidth = value
	case ResourceDimensionPids:
		vector.Pids = value
	case ResourceDimensionFileDescriptors:
		vector.FileDescriptors = value
	case ResourceDimensionHugePages:
		vector.HugePages = value
	}
	return vector
}

func schedulerTestScale(t *testing.T, value ResourceVector, multiplier int64) ResourceVector {
	t.Helper()
	scaled, err := NewResourceVector(
		value.Cpu*multiplier, value.Memory*multiplier, value.BlockIo*multiplier,
		value.EphemeralDisk*multiplier, value.Bandwidth*multiplier, value.Pids*multiplier,
		value.FileDescriptors*multiplier, value.HugePages*multiplier)
	if err != nil {
		t.Fatalf("scale: %v", err)
	}
	return scaled
}

func schedulerTestCheckFor(dimension ResourceDimension) PlacementCheck {
	return PlacementCheck(int(PlacementCheckCpu) + int(dimension))
}

func resultCandidates(result ScheduleResult) []CandidateTrace {
	switch typed := result.(type) {
	case PlacementSelected:
		return typed.Candidates
	case Unschedulable:
		return typed.Candidates
	default:
		return nil
	}
}

func schedulerTestReason(t *testing.T, trace CandidateTrace, check PlacementCheck) PlacementReason {
	t.Helper()
	for _, reason := range trace.Reasons {
		if reason.Check == check {
			return reason
		}
	}
	t.Fatalf("no reason for check %v", check)
	return PlacementReason{}
}

func TestEveryResourceDimensionAcceptsExactFitAndRejectsOneUnitShort(t *testing.T) {
	scheduler := DeterministicScheduler{}
	for _, dimension := range AllResourceDimensions {
		request := schedulerTestVector(dimension, 10)
		exact := schedulerTestNode(t, "exact", request, nil, nil, nil, nil, nil)
		result, err := scheduler.Schedule(schedulerTestWorkload(t, request, nil, nil, nil, nil),
			[]*NodeCandidate{exact}, schedulerTestPolicy(t))
		if err != nil {
			t.Fatalf("schedule: %v", err)
		}
		selected, ok := result.(PlacementSelected)
		if !ok {
			t.Fatalf("dimension %v: expected PlacementSelected", dimension)
		}
		if selected.SelectedCandidateId != "exact" {
			t.Fatalf("dimension %v: expected exact, got %s", dimension, selected.SelectedCandidateId)
		}
		if reason := schedulerTestReason(t, selected.Candidates[0], schedulerTestCheckFor(dimension)); reason.Outcome != CheckOutcomePassed {
			t.Fatalf("dimension %v: exact fit should pass", dimension)
		}

		shortNode := schedulerTestNode(t, "short", schedulerTestVector(dimension, 9), nil, nil, nil, nil, nil)
		rejected, err := scheduler.Schedule(schedulerTestWorkload(t, request, nil, nil, nil, nil),
			[]*NodeCandidate{shortNode}, schedulerTestPolicy(t))
		if err != nil {
			t.Fatalf("schedule: %v", err)
		}
		if _, ok := rejected.(Unschedulable); !ok {
			t.Fatalf("dimension %v: expected Unschedulable", dimension)
		}
		if reason := schedulerTestReason(t, resultCandidates(rejected)[0], schedulerTestCheckFor(dimension)); reason.Outcome != CheckOutcomeRejected {
			t.Fatalf("dimension %v: one unit short should be rejected", dimension)
		}
	}
}

func TestResourceQuantitiesAndSafetyCapsMustBeNonNegative(t *testing.T) {
	if _, err := NewResourceVector(-1, 0, 0, 0, 0, 0, 0, 0); err == nil {
		t.Fatal("negative resource vector must be rejected")
	}
	var rangeError *ArgumentOutOfRangeError
	if _, err := NewResourceVector(-1, 0, 0, 0, 0, 0, 0, 0); !errors.As(err, &rangeError) {
		t.Fatalf("expected ArgumentOutOfRangeError, got %v", err)
	}
	if _, err := NewAllocationSafetyCap(-1, 1); !errors.As(err, &rangeError) {
		t.Fatalf("expected ArgumentOutOfRangeError, got %v", err)
	}
}

func TestCheckedResourceArithmeticRejectsOverflowAndUnderflow(t *testing.T) {
	maximum := ResourceVector{Cpu: int64(^uint64(0) >> 1)}
	one := ResourceVector{Cpu: 1}
	if _, err := maximum.AddChecked(one); err == nil {
		t.Fatal("overflowing addition must fail")
	}
	if _, err := ResourceVectorZero.SubtractChecked(one); err == nil {
		t.Fatal("underflowing subtraction must fail")
	}
}

func TestPortCollisionIsExplicitAndAllOtherChecksStillRun(t *testing.T) {
	scheduler := DeterministicScheduler{}
	node := schedulerTestNode(t, "node-a", schedulerTestAbundant(), []int{443, 8443}, nil, nil, nil, nil)
	result, err := scheduler.Schedule(
		schedulerTestWorkload(t, schedulerTestTiny(), []int{8443, 9000}, nil, nil, nil),
		[]*NodeCandidate{node}, schedulerTestPolicy(t))
	if err != nil {
		t.Fatalf("schedule: %v", err)
	}
	if _, ok := result.(Unschedulable); !ok {
		t.Fatal("expected Unschedulable")
	}
	trace := resultCandidates(result)[0]
	if len(trace.Reasons) != 22 {
		t.Fatalf("expected 22 reasons, got %d", len(trace.Reasons))
	}
	if reason := schedulerTestReason(t, trace, PlacementCheckPorts); !strings.Contains(reason.Detail, "8443") {
		t.Fatalf("port detail must name 8443, got %q", reason.Detail)
	}
	if reason := schedulerTestReason(t, trace, PlacementCheckHugePages); reason.Outcome != CheckOutcomePassed {
		t.Fatal("HugePages check should still run and pass")
	}
}

func TestArchitectureNodeClassLabelsZonesAndFailureDomainAreHardConstraints(t *testing.T) {
	scheduler := DeterministicScheduler{}
	node, err := NewNodeCandidate("node-a", "compact", "x64", "fd-2", schedulerTestAbundant(),
		nil, map[string]string{"disk": "standard"}, []string{"public"}, []string{"edge"},
		[]string{"none"}, nil, nil, nil)
	if err != nil {
		t.Fatalf("node: %v", err)
	}
	workload, err := NewWorkloadRequest("api", "arm64", schedulerTestTiny(), nil,
		ptr("isolated"), map[string]string{"disk": "balanced", "role": "api"},
		[]string{"trusted"}, []string{"private"}, []string{"vault"}, []string{"fd-1"}, nil, nil)
	if err != nil {
		t.Fatalf("workload: %v", err)
	}
	result, err := scheduler.Schedule(workload, []*NodeCandidate{node}, schedulerTestPolicy(t))
	if err != nil {
		t.Fatalf("schedule: %v", err)
	}
	trace := resultCandidates(result)[0]
	expectedRejected := map[PlacementCheck]bool{
		PlacementCheckArchitecture:  true,
		PlacementCheckNodeClass:     true,
		PlacementCheckLabels:        true,
		PlacementCheckTrustZones:    true,
		PlacementCheckNetworkZones:  true,
		PlacementCheckSecretZones:   true,
		PlacementCheckFailureDomain: true,
	}
	actualRejected := map[PlacementCheck]bool{}
	for _, reason := range trace.Reasons {
		if reason.Outcome == CheckOutcomeRejected {
			actualRejected[reason.Check] = true
		}
	}
	if len(actualRejected) != len(expectedRejected) {
		t.Fatalf("expected %d rejected checks, got %d", len(expectedRejected), len(actualRejected))
	}
	for check := range expectedRejected {
		if !actualRejected[check] {
			t.Fatalf("expected check %v to be rejected", check)
		}
	}
	expectedOrder := []PlacementCheck{
		PlacementCheckCallerVeto, PlacementCheckArchitecture, PlacementCheckNodeClass, PlacementCheckLabels,
		PlacementCheckTrustZones, PlacementCheckNetworkZones, PlacementCheckSecretZones, PlacementCheckFailureDomain,
		PlacementCheckAffinity, PlacementCheckAntiAffinity, PlacementCheckPorts, PlacementCheckSafetyCap,
		PlacementCheckCpu, PlacementCheckMemory, PlacementCheckBlockIo, PlacementCheckEphemeralDisk,
		PlacementCheckBandwidth, PlacementCheckPids, PlacementCheckFileDescriptors, PlacementCheckHugePages,
		PlacementCheckScore, PlacementCheckSelection,
	}
	if len(trace.Reasons) != len(expectedOrder) {
		t.Fatalf("trace length mismatch: %d", len(trace.Reasons))
	}
	for index, check := range expectedOrder {
		if trace.Reasons[index].Check != check {
			t.Fatalf("trace order mismatch at %d: got %v want %v", index, trace.Reasons[index].Check, check)
		}
	}
}

func TestAffinityAndAntiAffinityFactsAreCallerSuppliedHardConstraints(t *testing.T) {
	scheduler := DeterministicScheduler{}
	node := schedulerTestNode(t, "node-a", schedulerTestAbundant(), nil, nil,
		[]string{"rack:r1", "workload:database"}, nil, nil)
	workload := schedulerTestWorkload(t, schedulerTestTiny(), nil, nil,
		[]string{"rack:r2"}, []string{"workload:database"})
	result, err := scheduler.Schedule(workload, []*NodeCandidate{node}, schedulerTestPolicy(t))
	if err != nil {
		t.Fatalf("schedule: %v", err)
	}
	trace := resultCandidates(result)[0]
	if reason := schedulerTestReason(t, trace, PlacementCheckAffinity); reason.Outcome != CheckOutcomeRejected {
		t.Fatal("affinity should reject")
	}
	if reason := schedulerTestReason(t, trace, PlacementCheckAntiAffinity); reason.Outcome != CheckOutcomeRejected {
		t.Fatal("anti-affinity should reject")
	}
}

func TestCallerVetoAndCallerSafetyCapAreExplicitAndIndependent(t *testing.T) {
	scheduler := DeterministicScheduler{}
	veto, err := NewCandidateVeto(CandidateVetoCodeStatefulSafetyHold)
	if err != nil {
		t.Fatalf("veto: %v", err)
	}
	vetoed := schedulerTestNode(t, "vetoed", schedulerTestAbundant(), nil, nil, nil, nil, &veto)
	capped := schedulerTestNode(t, "capped", schedulerTestAbundant(), nil, nil, nil,
		&AllocationSafetyCap{CurrentAllocations: 7, MaximumAllocations: 7}, nil)
	result, err := scheduler.Schedule(schedulerTestWorkload(t, schedulerTestTiny(), nil, nil, nil, nil),
		[]*NodeCandidate{vetoed, capped}, schedulerTestPolicy(t))
	if err != nil {
		t.Fatalf("schedule: %v", err)
	}
	if _, ok := result.(Unschedulable); !ok {
		t.Fatal("expected Unschedulable")
	}
	var vetoTrace *CandidateTrace
	var cappedTrace *CandidateTrace
	traces := resultCandidates(result)
	for index := range traces {
		switch traces[index].CandidateId {
		case "vetoed":
			vetoTrace = &traces[index]
		case "capped":
			cappedTrace = &resultCandidates(result)[index]
		}
	}
	if vetoTrace == nil || cappedTrace == nil {
		t.Fatal("both candidates must be traced")
	}
	if detail := schedulerTestReason(t, *vetoTrace, PlacementCheckCallerVeto).Detail; detail != "code=StatefulSafetyHold" {
		t.Fatalf("unexpected veto detail %q", detail)
	}
	if strings.Contains(schedulerTestReason(t, *vetoTrace, PlacementCheckCallerVeto).Detail,
		"Controller has not approved a move.") {
		t.Fatal("veto detail must not carry free text")
	}
	if _, err := NewCandidateVeto(CandidateVetoCode(999)); err == nil {
		t.Fatal("unknown veto code must be rejected")
	}
	if reason := schedulerTestReason(t, *cappedTrace, PlacementCheckSafetyCap); reason.Outcome != CheckOutcomeRejected {
		t.Fatal("exhausted safety cap should reject")
	}
}

func TestNoImplicitAllocationLimitExistsWhenCallerOmitsSafetyCap(t *testing.T) {
	scheduler := DeterministicScheduler{}
	node := schedulerTestNode(t, "node-a", schedulerTestTiny(), nil, nil, nil, nil, nil)
	result, err := scheduler.Schedule(
		schedulerTestWorkload(t, schedulerTestTiny(), nil, nil, nil, nil),
		[]*NodeCandidate{node}, schedulerTestPolicy(t))
	if err != nil {
		t.Fatalf("schedule: %v", err)
	}
	if _, ok := result.(PlacementSelected); !ok {
		t.Fatal("expected PlacementSelected without an implicit cap")
	}
	if reason := schedulerTestReason(t, resultCandidates(result)[0], PlacementCheckSafetyCap); reason.Outcome != CheckOutcomePassed {
		t.Fatal("absent safety cap should pass")
	}
}

func TestCallerWeightedLeastWasteSelectsTighterEligibleNode(t *testing.T) {
	scheduler := DeterministicScheduler{}
	roomy := schedulerTestNode(t, "roomy", schedulerTestScale(t, schedulerTestTiny(), 4), nil, nil, nil, nil, nil)
	tight := schedulerTestNode(t, "tight", schedulerTestScale(t, schedulerTestTiny(), 2), nil, nil, nil, nil, nil)
	result, err := scheduler.Schedule(
		schedulerTestWorkload(t, schedulerTestTiny(), nil, nil, nil, nil),
		[]*NodeCandidate{roomy, tight}, schedulerTestPolicy(t))
	if err != nil {
		t.Fatalf("schedule: %v", err)
	}
	selected, ok := result.(PlacementSelected)
	if !ok {
		t.Fatal("expected PlacementSelected")
	}
	if selected.SelectedCandidateId != "tight" {
		t.Fatalf("expected tight, got %s", selected.SelectedCandidateId)
	}
	for _, trace := range resultCandidates(result) {
		if trace.CandidateId == "roomy" {
			if reason := schedulerTestReason(t, trace, PlacementCheckSelection); reason.Outcome != CheckOutcomeRejected {
				t.Fatal("roomy should rank after tight")
			}
		}
	}
}

func TestEqualScoresUseOrdinalCandidateIdTieBreak(t *testing.T) {
	scheduler := DeterministicScheduler{}
	zNode := schedulerTestNode(t, "z-node", schedulerTestAbundant(), nil, nil, nil, nil, nil)
	aNode := schedulerTestNode(t, "A-node", schedulerTestAbundant(), nil, nil, nil, nil, nil)
	result, err := scheduler.Schedule(
		schedulerTestWorkload(t, schedulerTestTiny(), nil, nil, nil, nil),
		[]*NodeCandidate{zNode, aNode}, schedulerTestPolicy(t))
	if err != nil {
		t.Fatalf("schedule: %v", err)
	}
	selected, ok := result.(PlacementSelected)
	if !ok {
		t.Fatal("expected PlacementSelected")
	}
	if selected.SelectedCandidateId != "A-node" {
		t.Fatalf("expected A-node, got %s", selected.SelectedCandidateId)
	}
	if got := strings.Join([]string{resultCandidates(result)[0].CandidateId, resultCandidates(result)[1].CandidateId}, ","); got != "A-node,z-node" {
		t.Fatalf("unexpected candidate order %s", got)
	}
}

func TestSelectionAndCompleteReasonOutputAreIndependentOfEveryInputPermutation(t *testing.T) {
	scheduler := DeterministicScheduler{}
	candidates := []*NodeCandidate{
		schedulerTestNode(t, "c", schedulerTestScale(t, schedulerTestTiny(), 3), nil, nil, nil, nil, nil),
		schedulerTestNode(t, "a", schedulerTestScale(t, schedulerTestTiny(), 2), nil, nil, nil, nil, nil),
		schedulerTestNode(t, "b", schedulerTestScale(t, schedulerTestTiny(), 2), nil, nil, nil, nil, nil),
	}
	baseline := ""
	for first := 0; first < 3; first++ {
		for second := 0; second < 3; second++ {
			if second == first {
				continue
			}
			third := 3 - first - second
			permutation := []*NodeCandidate{candidates[first], candidates[second], candidates[third]}
			result, err := scheduler.Schedule(
				schedulerTestWorkload(t, schedulerTestTiny(), nil, nil, nil, nil),
				permutation, schedulerTestPolicy(t))
			if err != nil {
				t.Fatalf("schedule: %v", err)
			}
			selected, ok := result.(PlacementSelected)
			if !ok {
				t.Fatal("expected PlacementSelected")
			}
			if selected.SelectedCandidateId != "a" {
				t.Fatalf("expected a, got %s", selected.SelectedCandidateId)
			}
			serialized := propertySerializeSchedule(result)
			if baseline == "" {
				baseline = serialized
			} else if serialized != baseline {
				t.Fatalf("permutation changed the serialized result:\n%s\n%s", baseline, serialized)
			}
		}
	}
}

func TestUnschedulableIsTypedAndContainsEveryCandidateInStableOrder(t *testing.T) {
	scheduler := DeterministicScheduler{}
	z := schedulerTestNode(t, "z", ResourceVectorZero, nil, nil, nil, nil, nil)
	a := schedulerTestNode(t, "a", ResourceVectorZero, nil, nil, nil, nil, nil)
	result, err := scheduler.Schedule(
		schedulerTestWorkload(t, schedulerTestTiny(), nil, nil, nil, nil),
		[]*NodeCandidate{z, a}, schedulerTestPolicy(t))
	if err != nil {
		t.Fatalf("schedule: %v", err)
	}
	if _, ok := result.(Unschedulable); !ok {
		t.Fatal("expected Unschedulable")
	}
	if got := strings.Join([]string{resultCandidates(result)[0].CandidateId, resultCandidates(result)[1].CandidateId}, ","); got != "a,z" {
		t.Fatalf("unexpected candidate order %s", got)
	}
	for _, trace := range resultCandidates(result) {
		if len(trace.Reasons) != 22 {
			t.Fatalf("expected 22 reasons, got %d", len(trace.Reasons))
		}
	}
}

func TestEmptyCandidateSetReturnsTypedUnschedulableWithoutInventingCapacity(t *testing.T) {
	scheduler := DeterministicScheduler{}
	result, err := scheduler.Schedule(
		schedulerTestWorkload(t, schedulerTestTiny(), nil, nil, nil, nil),
		[]*NodeCandidate{}, schedulerTestPolicy(t))
	if err != nil {
		t.Fatalf("schedule: %v", err)
	}
	if _, ok := result.(Unschedulable); !ok {
		t.Fatal("expected Unschedulable")
	}
	if len(resultCandidates(result)) != 0 {
		t.Fatalf("expected no candidates, got %d", len(resultCandidates(result)))
	}
}

func TestConstructorSnapshotsMutableCollectionsAndSchedulingMutatesNothing(t *testing.T) {
	labels := map[string]string{"role": "api"}
	ports := []int{443}
	facts := []string{"rack:r1"}
	node := schedulerTestNode(t, "node-a", schedulerTestAbundant(), ports, labels, facts, nil, nil)
	workloadLabels := map[string]string{"role": "api"}
	workload := schedulerTestWorkload(t, schedulerTestTiny(), []int{8443}, workloadLabels,
		[]string{"rack:r1"}, nil)

	labels["role"] = "changed"
	ports = append(ports, 8443)
	facts = facts[:0]
	workloadLabels["role"] = "changed"

	before := (node.Labels["role"] + string(rune(len(node.OccupiedPorts))) +
		string(rune(len(node.AffinityFacts))) + workload.RequiredLabels["role"] +
		string(rune(len(workload.RequiredPorts))))
	scheduler := DeterministicScheduler{}
	result, err := scheduler.Schedule(workload, []*NodeCandidate{node}, schedulerTestPolicy(t))
	if err != nil {
		t.Fatalf("schedule: %v", err)
	}
	after := (node.Labels["role"] + string(rune(len(node.OccupiedPorts))) +
		string(rune(len(node.AffinityFacts))) + workload.RequiredLabels["role"] +
		string(rune(len(workload.RequiredPorts))))
	if _, ok := result.(PlacementSelected); !ok {
		t.Fatal("expected PlacementSelected")
	}
	if after != before {
		t.Fatalf("snapshots mutated: before %q after %q", before, after)
	}
}

func TestInvalidPortsAndDuplicateCandidateIdsFailClosed(t *testing.T) {
	scheduler := DeterministicScheduler{}
	if _, err := NewNodeCandidate("bad", "compact", "arm64", "fd-1", schedulerTestAbundant(), []int{0}, nil, nil, nil, nil, nil, nil, nil); err == nil {
		t.Fatal("port 0 must be rejected")
	}
	if _, err := NewWorkloadRequest("api", "arm64", schedulerTestTiny(), []int{65_536}, nil, nil, nil, nil, nil, nil, nil, nil); err == nil {
		t.Fatal("port 65536 must be rejected")
	}
	if _, err := NewWorkloadRequest("api", "arm64", schedulerTestTiny(), []int{443, 443}, nil, nil, nil, nil, nil, nil, nil, nil); err == nil {
		t.Fatal("duplicate ports must be rejected")
	}
	if _, err := NewWorkloadRequest("api", "arm64", schedulerTestTiny(), nil, nil, nil, nil, nil, nil, nil, []string{"rack:r1", "rack:r1"}, nil); err == nil {
		t.Fatal("duplicate affinity facts must be rejected")
	}
	sameA := schedulerTestNode(t, "same", schedulerTestAbundant(), nil, nil, nil, nil, nil)
	sameB := schedulerTestNode(t, "same", schedulerTestAbundant(), nil, nil, nil, nil, nil)
	if _, err := scheduler.Schedule(schedulerTestWorkload(t, schedulerTestTiny(), nil, nil, nil, nil),
		[]*NodeCandidate{sameA, sameB}, schedulerTestPolicy(t)); err == nil {
		t.Fatal("duplicate candidate ids must be rejected")
	}
}

func TestOptionalNodeClassDistinguishesAbsentFromSuppliedBlank(t *testing.T) {
	absent, err := NewWorkloadRequest("api", "arm64", schedulerTestTiny(), nil, nil, nil, nil, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("workload: %v", err)
	}
	if absent.RequiredNodeClass != nil {
		t.Fatal("absent node class must stay nil")
	}
	if _, err := NewWorkloadRequest("api", "arm64", schedulerTestTiny(), nil, ptr(""), nil, nil, nil, nil, nil, nil, nil); err == nil {
		t.Fatal("blank node class must be rejected")
	}
	if _, err := NewWorkloadRequest("api", "arm64", schedulerTestTiny(), nil, ptr(" \t\r\n"), nil, nil, nil, nil, nil, nil, nil); err == nil {
		t.Fatal("whitespace node class must be rejected")
	}
}

func TestEveryOptionalStringCollectionRejectsSuppliedWhitespace(t *testing.T) {
	blankCollections := [][]string{{" "}, {"\n"}, {"\t"}, {""}}
	for index, collection := range blankCollections {
		// index 0..3 map to trust, network, secret, allowed failure domains.
		_, err0 := NewWorkloadRequest("api", "arm64", schedulerTestTiny(), nil, nil, nil, collection, nil, nil, nil, nil, nil)
		_, err1 := NewWorkloadRequest("api", "arm64", schedulerTestTiny(), nil, nil, nil, nil, collection, nil, nil, nil, nil)
		_, err2 := NewWorkloadRequest("api", "arm64", schedulerTestTiny(), nil, nil, nil, nil, nil, collection, nil, nil, nil)
		_, err3 := NewWorkloadRequest("api", "arm64", schedulerTestTiny(), nil, nil, nil, nil, nil, nil, collection, nil, nil)
		_, err4 := NewWorkloadRequest("api", "arm64", schedulerTestTiny(), nil, nil, nil, nil, nil, nil, nil, collection, nil)
		_, err5 := NewWorkloadRequest("api", "arm64", schedulerTestTiny(), nil, nil, nil, nil, nil, nil, nil, nil, collection)
		for position, err := range []*error{&err0, &err1, &err2, &err3, &err4, &err5} {
			if *err == nil {
				t.Fatalf("collection %d position %d must be rejected", index, position)
			}
		}
	}
}

func TestZeroRequestFitsZeroCapacityAndProducesExactZeroScore(t *testing.T) {
	scheduler := DeterministicScheduler{}
	node := schedulerTestNode(t, "zero", ResourceVectorZero, nil, nil, nil, nil, nil)
	result, err := scheduler.Schedule(
		schedulerTestWorkload(t, ResourceVectorZero, nil, nil, nil, nil),
		[]*NodeCandidate{node}, schedulerTestPolicy(t))
	if err != nil {
		t.Fatalf("schedule: %v", err)
	}
	selected, ok := result.(PlacementSelected)
	if !ok {
		t.Fatal("expected PlacementSelected")
	}
	if selected.SelectedCandidateId != "zero" {
		t.Fatalf("expected zero, got %s", selected.SelectedCandidateId)
	}
	score := resultCandidates(result)[0].Score
	if score == nil || score.WeightedWaste.Cmp(big.NewInt(0)) != 0 {
		t.Fatal("expected exactly zero weighted waste")
	}
}

func TestCallerPolicyControlsWeightsAndTieBreakOrderWithoutProductionDefault(t *testing.T) {
	scheduler := DeterministicScheduler{}
	cpuFirst, err := NewLeastWastePolicy([]ScoreDimension{
		{Dimension: ResourceDimensionCpu, Weight: 1}, {Dimension: ResourceDimensionMemory, Weight: 0},
		{Dimension: ResourceDimensionBlockIo, Weight: 0}, {Dimension: ResourceDimensionEphemeralDisk, Weight: 0},
		{Dimension: ResourceDimensionBandwidth, Weight: 0}, {Dimension: ResourceDimensionPids, Weight: 0},
		{Dimension: ResourceDimensionFileDescriptors, Weight: 0}, {Dimension: ResourceDimensionHugePages, Weight: 0},
	})
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	cpuTight := schedulerTestNode(t, "cpu-tight",
		ResourceVector{Cpu: 2, Memory: 100, BlockIo: 1, EphemeralDisk: 1, Bandwidth: 1, Pids: 1, FileDescriptors: 1, HugePages: 1},
		nil, nil, nil, nil, nil)
	memoryTight := schedulerTestNode(t, "memory-tight",
		ResourceVector{Cpu: 100, Memory: 2, BlockIo: 1, EphemeralDisk: 1, Bandwidth: 1, Pids: 1, FileDescriptors: 1, HugePages: 1},
		nil, nil, nil, nil, nil)
	result, err := scheduler.Schedule(schedulerTestWorkload(t, schedulerTestTiny(), nil, nil, nil, nil),
		[]*NodeCandidate{memoryTight, cpuTight}, cpuFirst)
	if err != nil {
		t.Fatalf("schedule: %v", err)
	}
	selected, ok := result.(PlacementSelected)
	if !ok {
		t.Fatal("expected PlacementSelected")
	}
	if selected.SelectedCandidateId != "cpu-tight" {
		t.Fatalf("expected cpu-tight, got %s", selected.SelectedCandidateId)
	}
	for _, trace := range resultCandidates(result) {
		if trace.CandidateId == "cpu-tight" {
			if detail := schedulerTestReason(t, trace, PlacementCheckScore).Detail; !strings.Contains(detail, "Cpu:1*1=1") {
				t.Fatalf("score detail must carry the weighted component, got %q", detail)
			}
		}
	}
	if _, err := NewLeastWastePolicy([]ScoreDimension{{Dimension: ResourceDimensionCpu, Weight: 1}}); err == nil {
		t.Fatal("incomplete policy must be rejected")
	}
}

func TestNearMaximumValuesAndWeightsUseExactUnboundedScoreArithmetic(t *testing.T) {
	scheduler := DeterministicScheduler{}
	maximumInt64 := int64(^uint64(0) >> 1)
	dimensions := make([]ScoreDimension, 0, len(AllResourceDimensions))
	for _, dimension := range AllResourceDimensions {
		dimensions = append(dimensions, ScoreDimension{Dimension: dimension, Weight: maximumInt64})
	}
	maximumPolicy, err := NewLeastWastePolicy(dimensions)
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	maximum := ResourceVector{Cpu: maximumInt64, Memory: maximumInt64, BlockIo: maximumInt64,
		EphemeralDisk: maximumInt64, Bandwidth: maximumInt64, Pids: maximumInt64,
		FileDescriptors: maximumInt64, HugePages: maximumInt64}
	node := schedulerTestNode(t, "maximum", maximum, nil, nil, nil, nil, nil)
	result, err := scheduler.Schedule(
		schedulerTestWorkload(t, ResourceVectorZero, nil, nil, nil, nil),
		[]*NodeCandidate{node}, maximumPolicy)
	if err != nil {
		t.Fatalf("schedule: %v", err)
	}
	if _, ok := result.(PlacementSelected); !ok {
		t.Fatal("expected PlacementSelected")
	}
	score := resultCandidates(result)[0].Score
	if score == nil || score.WeightedWaste.Cmp(big.NewInt(maximumInt64)) <= 0 {
		t.Fatal("weighted waste must exceed int64 exactly")
	}
	if len(score.Components) != 8 {
		t.Fatalf("expected 8 components, got %d", len(score.Components))
	}
}

func TestMaximumCallerCountIsComparedWithoutIncrementOverflow(t *testing.T) {
	scheduler := DeterministicScheduler{}
	maximumInt64 := int64(^uint64(0) >> 1)
	node := schedulerTestNode(t, "at-cap", schedulerTestAbundant(), nil, nil, nil,
		&AllocationSafetyCap{CurrentAllocations: maximumInt64, MaximumAllocations: maximumInt64}, nil)
	result, err := scheduler.Schedule(schedulerTestWorkload(t, schedulerTestTiny(), nil, nil, nil, nil),
		[]*NodeCandidate{node}, schedulerTestPolicy(t))
	if err != nil {
		t.Fatalf("schedule: %v", err)
	}
	if _, ok := result.(Unschedulable); !ok {
		t.Fatal("expected Unschedulable at cap")
	}
	detail := schedulerTestReason(t, resultCandidates(result)[0], PlacementCheckSafetyCap).Detail
	if !strings.Contains(detail, "9223372036854775807") {
		t.Fatalf("cap detail must carry the exact maximum, got %q", detail)
	}
}
