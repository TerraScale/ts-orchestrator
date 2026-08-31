package scheduling

import (
	"fmt"
	"strings"
	"testing"
)

func decisionSurfaceCandidates(t *testing.T, property *schedulerPropertyCase, count int) []*NodeCandidate {
	t.Helper()
	candidates := make([]*NodeCandidate, 0, count)
	available, err := propertyAdd(property.Workload.Resources, 10)
	if err != nil {
		t.Fatalf("available: %v", err)
	}
	for index := 0; index < count; index++ {
		candidate, candidateErr := NewNodeCandidate(
			fmt.Sprintf("bounded-%04d", index), "compute", "linux-amd64", "fd-a",
			available, []int{}, map[string]string{"region": "gru"},
			[]string{"trusted"}, []string{"product"}, []string{"runtime"},
			[]string{"service"}, &AllocationSafetyCap{CurrentAllocations: 0, MaximumAllocations: 10_000}, nil)
		if candidateErr != nil {
			t.Fatalf("candidate: %v", candidateErr)
		}
		candidates = append(candidates, candidate)
	}
	return candidates
}

func TestEmptyCandidateSetIsCanonicalClosedAndUnschedulable(t *testing.T) {
	property, err := schedulerPropertyValid(100_001)
	if err != nil {
		t.Fatalf("property: %v", err)
	}
	result, err := DeterministicScheduler{}.Schedule(property.Workload, []*NodeCandidate{}, property.Policy)
	if err != nil {
		t.Fatalf("schedule: %v", err)
	}
	if _, ok := result.(Unschedulable); !ok {
		t.Fatal("expected Unschedulable")
	}
	if len(resultCandidates(result)) != 0 {
		t.Fatal("expected no candidates")
	}
}

func TestCandidateSnapshotAcceptsExactMaximumAndPreservesCanonicalOrder(t *testing.T) {
	property, err := schedulerPropertyValid(100_002)
	if err != nil {
		t.Fatalf("property: %v", err)
	}
	candidates := decisionSurfaceCandidates(t, property, SchedulerTechnicalInputLimits.MaximumCandidateCount)
	reversed := propertyReverse(candidates)
	result, err := DeterministicScheduler{}.Schedule(property.Workload, reversed, property.Policy)
	if err != nil {
		t.Fatalf("schedule: %v", err)
	}
	selected, ok := result.(PlacementSelected)
	if !ok {
		t.Fatal("expected PlacementSelected")
	}
	if len(selected.Candidates) != SchedulerTechnicalInputLimits.MaximumCandidateCount {
		t.Fatalf("expected %d candidates, got %d",
			SchedulerTechnicalInputLimits.MaximumCandidateCount, len(selected.Candidates))
	}
	if selected.SelectedCandidateId != "bounded-0000" {
		t.Fatalf("expected bounded-0000, got %s", selected.SelectedCandidateId)
	}
	ids := make([]string, len(selected.Candidates))
	for index, trace := range selected.Candidates {
		ids[index] = trace.CandidateId
	}
	sorted := sortedCopy(ids)
	if strings.Join(ids, ",") != strings.Join(sorted, ",") {
		t.Fatal("candidates must be returned in canonical ordinal order")
	}
}

func TestCandidateSnapshotRejectsMaximumPlusOneWithoutPartialScheduling(t *testing.T) {
	property, err := schedulerPropertyValid(100_003)
	if err != nil {
		t.Fatalf("property: %v", err)
	}
	oversized := decisionSurfaceCandidates(t, property, SchedulerTechnicalInputLimits.MaximumCandidateCount+1)
	if _, err := (DeterministicScheduler{}).Schedule(property.Workload, oversized, property.Policy); err == nil {
		t.Fatal("maximum plus one candidates must be rejected")
	}
}

func TestSnapshotIsDefensiveAgainstSourceMutation(t *testing.T) {
	property, err := schedulerPropertyValid(100_005)
	if err != nil {
		t.Fatalf("property: %v", err)
	}
	source := decisionSurfaceCandidates(t, property, 2)
	result, err := DeterministicScheduler{}.Schedule(property.Workload,
		append([]*NodeCandidate{}, source...), property.Policy)
	if err != nil {
		t.Fatalf("schedule: %v", err)
	}
	source = source[:0]
	if len(resultCandidates(result)) != 2 {
		t.Fatal("the result must keep its own candidate snapshot")
	}
}

func TestNestedSchedulerEnumerableValidatorsApplyNamedTechnicalBounds(t *testing.T) {
	property, err := schedulerPropertyValid(100_007)
	if err != nil {
		t.Fatalf("property: %v", err)
	}
	exactPorts := make([]int, 0, SchedulerTechnicalInputLimits.MaximumPortCount)
	for port := 1; port <= SchedulerTechnicalInputLimits.MaximumPortCount; port++ {
		exactPorts = append(exactPorts, port)
	}
	exactFacts := make([]string, 0, SchedulerTechnicalInputLimits.MaximumFactCount)
	for index := 0; index < SchedulerTechnicalInputLimits.MaximumFactCount; index++ {
		exactFacts = append(exactFacts, fmt.Sprintf("fact-%d", index))
	}
	exactLabels := make(map[string]string, SchedulerTechnicalInputLimits.MaximumLabelCount)
	for index := 0; index < SchedulerTechnicalInputLimits.MaximumLabelCount; index++ {
		exactLabels[fmt.Sprintf("key-%d", index)] = fmt.Sprintf("value-%d", index)
	}
	node, err := NewNodeCandidate("bounded-node", "compute", "linux-amd64", "fd-a",
		property.Workload.Resources, exactPorts, exactLabels, exactFacts, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("node: %v", err)
	}
	if len(node.OccupiedPorts) != SchedulerTechnicalInputLimits.MaximumPortCount {
		t.Fatalf("expected %d ports, got %d", SchedulerTechnicalInputLimits.MaximumPortCount, len(node.OccupiedPorts))
	}
	if len(node.TrustZones) != SchedulerTechnicalInputLimits.MaximumFactCount {
		t.Fatalf("expected %d facts, got %d", SchedulerTechnicalInputLimits.MaximumFactCount, len(node.TrustZones))
	}
	if len(node.Labels) != SchedulerTechnicalInputLimits.MaximumLabelCount {
		t.Fatalf("expected %d labels, got %d", SchedulerTechnicalInputLimits.MaximumLabelCount, len(node.Labels))
	}
	tooManyPorts := make([]int, 0, SchedulerTechnicalInputLimits.MaximumPortCount+1)
	for port := 1; port <= SchedulerTechnicalInputLimits.MaximumPortCount+1; port++ {
		tooManyPorts = append(tooManyPorts, port)
	}
	if _, err := NewNodeCandidate("node", "compute", "linux-amd64", "fd-a",
		property.Workload.Resources, tooManyPorts, nil, nil, nil, nil, nil, nil, nil); err == nil {
		t.Fatal("maximum plus one ports must be rejected")
	}
	tooManyFacts := make([]string, 0, SchedulerTechnicalInputLimits.MaximumFactCount+1)
	for index := 0; index <= SchedulerTechnicalInputLimits.MaximumFactCount; index++ {
		tooManyFacts = append(tooManyFacts, fmt.Sprintf("fact-%d", index))
	}
	if _, err := NewWorkloadRequest("workload", "linux-amd64", property.Workload.Resources,
		nil, nil, nil, tooManyFacts, nil, nil, nil, nil, nil); err == nil {
		t.Fatal("maximum plus one facts must be rejected")
	}
	repeatingDimensions := make([]ScoreDimension, 0, SchedulerTechnicalInputLimits.ScoreDimensionCount+1)
	for index := 0; ; index++ {
		repeatingDimensions = append(repeatingDimensions,
			ScoreDimension{Dimension: AllResourceDimensions[index%len(AllResourceDimensions)], Weight: 1})
		if len(repeatingDimensions) > SchedulerTechnicalInputLimits.ScoreDimensionCount {
			break
		}
	}
	if _, err := NewLeastWastePolicy(repeatingDimensions); err == nil {
		t.Fatal("an unbounded score dimension input must be rejected")
	}
	tooManyLabels := make(map[string]string, SchedulerTechnicalInputLimits.MaximumLabelCount+1)
	for index := 0; index <= SchedulerTechnicalInputLimits.MaximumLabelCount; index++ {
		tooManyLabels[fmt.Sprintf("key-%d", index)] = fmt.Sprintf("value-%d", index)
	}
	if _, err := NewWorkloadRequest("workload", "linux-amd64", property.Workload.Resources,
		nil, nil, tooManyLabels, nil, nil, nil, nil, nil, nil); err == nil {
		t.Fatal("maximum plus one labels must be rejected")
	}
}
