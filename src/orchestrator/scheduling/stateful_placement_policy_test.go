package scheduling

import (
	"errors"
	"math/big"
	"reflect"
	"strings"
	"testing"
)

// statefulTestPolicy builds one validated stateful placement policy.
func statefulTestPolicy(t *testing.T, localityPenalty int64) *StatefulPlacementPolicy {
	t.Helper()
	policy, err := NewStatefulPlacementPolicy(localityPenalty)
	if err != nil {
		t.Fatalf("stateful policy: %v", err)
	}
	return policy
}

// statefulTestDetail returns the detail of the trace row carrying the exact
// detail text, failing when absent.
func statefulTestDetail(t *testing.T, trace CandidateTrace, detail string) PlacementReason {
	t.Helper()
	for _, reason := range trace.Reasons {
		if reason.Detail == detail {
			return reason
		}
	}
	t.Fatalf("no reason with detail %q", detail)
	return PlacementReason{}
}

func TestStatefulPlacementFacts(t *testing.T) {
	replicaFact, err := StatefulReplicaFact("terrabase", "terrabase-1")
	if err != nil {
		t.Fatalf("replica fact: %v", err)
	}
	if replicaFact != "terrascale.stateful.terrabase.terrabase-1" {
		t.Fatalf("replica fact = %q", replicaFact)
	}
	volumeFact, err := StatefulVolumeFact("terrabase", "terrabase-1")
	if err != nil {
		t.Fatalf("volume fact: %v", err)
	}
	if volumeFact != "terrascale.volume.terrabase.terrabase-1" {
		t.Fatalf("volume fact = %q", volumeFact)
	}

	for _, invalid := range []struct {
		roleKind     string
		allocationId string
		expectParam  string
	}{
		{roleKind: "TerraBase", allocationId: "terrabase-1", expectParam: "roleKind"},
		{roleKind: "terrabase", allocationId: "", expectParam: "allocationId"},
		{roleKind: "terrabase", allocationId: "tb_1", expectParam: "allocationId"},
	} {
		if _, err := StatefulReplicaFact(invalid.roleKind, invalid.allocationId); !statefulTestParam(err, invalid.expectParam) {
			t.Fatalf("replica fact error %v does not reference param %s", err, invalid.expectParam)
		}
		if _, err := StatefulVolumeFact(invalid.roleKind, invalid.allocationId); !statefulTestParam(err, invalid.expectParam) {
			t.Fatalf("volume fact error %v does not reference param %s", err, invalid.expectParam)
		}
	}
}

// statefulTestParam reports whether err names the given parameter in one of
// the argument error families.
func statefulTestParam(err error, param string) bool {
	var argumentError *ArgumentError
	if errors.As(err, &argumentError) {
		return argumentError.Param == param
	}
	var outOfRange *ArgumentOutOfRangeError
	if errors.As(err, &outOfRange) {
		return outOfRange.Param == param
	}
	return false
}

func TestNewStatefulPlacementPolicy(t *testing.T) {
	if _, err := NewStatefulPlacementPolicy(-1); !statefulTestParam(err, "localityPenalty") {
		t.Fatalf("error %v does not reference param localityPenalty", err)
	}
	for _, valid := range []int64{0, 1, 1_000_000} {
		if _, err := NewStatefulPlacementPolicy(valid); err != nil {
			t.Fatalf("penalty %d: %v", valid, err)
		}
	}
}

func TestStatefulAntiAffinityReason(t *testing.T) {
	policy := statefulTestPolicy(t, 0)

	tests := []struct {
		name         string
		roleKind     string
		allocationId string
		facts        []string
		expectReject bool
		expectDetail string
	}{
		{
			name:         "same role kind elsewhere on the node rejects",
			roleKind:     "terrabase",
			allocationId: "terrabase-1",
			facts: []string{
				"terrascale.stateful.terrabase.terrabase-2",
				"terrascale.stateful.other.other-1",
			},
			expectReject: true,
			expectDetail: "conflicts=terrascale.stateful.terrabase.terrabase-2",
		},
		{
			name:         "the placement's own running replica rejects fail closed",
			roleKind:     "terrabase",
			allocationId: "terrabase-1",
			facts:        []string{"terrascale.stateful.terrabase.terrabase-1"},
			expectReject: true,
			expectDetail: "conflicts=terrascale.stateful.terrabase.terrabase-1",
		},
		{
			name:         "conflicts are listed in canonical order",
			roleKind:     "terrabase",
			allocationId: "terrabase-1",
			facts: []string{
				"terrascale.stateful.terrabase.terrabase-2",
				"terrascale.stateful.terrabase.terrabase-0",
			},
			expectReject: true,
			expectDetail: "conflicts=terrascale.stateful.terrabase.terrabase-0," +
				"terrascale.stateful.terrabase.terrabase-2",
		},
		{
			name:         "other role kinds and volume facts pass",
			roleKind:     "terrabase",
			allocationId: "terrabase-1",
			facts: []string{
				"terrascale.stateful.other.other-1",
				"terrascale.volume.terrabase.terrabase-1",
			},
			expectDetail: "No stateful anti-affinity conflict.",
		},
		{
			name:         "no facts passes",
			roleKind:     "terrabase",
			allocationId: "terrabase-1",
			expectDetail: "No stateful anti-affinity conflict.",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := schedulerTestNode(t, "node-a", schedulerTestAbundant(), nil, nil,
				test.facts, nil, nil)
			reason, err := policy.StatefulAntiAffinityReason(
				test.roleKind, test.allocationId, candidate)
			if err != nil {
				t.Fatalf("reason: %v", err)
			}
			if reason.Check != PlacementCheckAntiAffinity {
				t.Fatalf("check = %v", reason.Check)
			}
			if reason.Detail != test.expectDetail {
				t.Fatalf("detail = %q, want %q", reason.Detail, test.expectDetail)
			}
			if test.expectReject && reason.Outcome != CheckOutcomeRejected {
				t.Fatalf("outcome = %v, want Rejected", reason.Outcome)
			}
			if !test.expectReject && reason.Outcome != CheckOutcomePassed {
				t.Fatalf("outcome = %v, want Passed", reason.Outcome)
			}
		})
	}

	if _, err := policy.StatefulAntiAffinityReason("terrabase", "terrabase-1", nil); !statefulTestParam(err, "candidate") {
		t.Fatalf("error %v does not reference param candidate", err)
	}
	if _, err := policy.StatefulAntiAffinityReason("TerraBase", "terrabase-1",
		schedulerTestNode(t, "node-a", schedulerTestAbundant(), nil, nil, nil, nil,
			nil)); !statefulTestParam(err, "roleKind") {
		t.Fatalf("error %v does not reference param roleKind", err)
	}
}

func TestScheduleStatefulRejectsCoLocatedReplicas(t *testing.T) {
	workload := schedulerTestWorkload(t, schedulerTestTiny(), nil, nil, nil, nil)
	policy := schedulerTestPolicy(t)
	stateful := statefulTestPolicy(t, 0)
	conflict := schedulerTestNode(t, "node-a", schedulerTestAbundant(), nil, nil,
		[]string{"terrascale.stateful.terrabase.terrabase-9"}, nil, nil)
	clean := schedulerTestNode(t, "node-b", schedulerTestAbundant(), nil, nil, nil, nil, nil)

	result, err := ScheduleStateful(workload, []*NodeCandidate{conflict, clean},
		policy, stateful, "terrabase", "terrabase-1")
	if err != nil {
		t.Fatalf("schedule: %v", err)
	}
	selected, ok := result.(PlacementSelected)
	if !ok {
		t.Fatalf("expected PlacementSelected, got %T", result)
	}
	if selected.SelectedCandidateId != "node-b" {
		t.Fatalf("selected = %q, want node-b", selected.SelectedCandidateId)
	}
	conflictTrace := resultCandidates(result)[0]
	if conflictTrace.Eligible {
		t.Fatal("a node running a same-role-kind replica must be ineligible")
	}
	reason := statefulTestDetail(t, conflictTrace,
		"conflicts=terrascale.stateful.terrabase.terrabase-9")
	if reason.Outcome != CheckOutcomeRejected {
		t.Fatalf("outcome = %v", reason.Outcome)
	}
	if reason := schedulerTestReason(t, conflictTrace, PlacementCheckScore); reason.Outcome !=
		CheckOutcomeNotApplicable {
		t.Fatalf("score outcome = %v, want NotApplicable", reason.Outcome)
	}

	unschedulable, err := ScheduleStateful(workload,
		[]*NodeCandidate{conflict, conflictWithOtherId(t)}, policy, stateful,
		"terrabase", "terrabase-1")
	if err != nil {
		t.Fatalf("schedule: %v", err)
	}
	if _, ok := unschedulable.(Unschedulable); !ok {
		t.Fatalf("expected Unschedulable, got %T", unschedulable)
	}
}

// conflictWithOtherId builds a second node also running a terrabase replica.
func conflictWithOtherId(t *testing.T) *NodeCandidate {
	t.Helper()
	return schedulerTestNode(t, "node-c", schedulerTestAbundant(), nil, nil,
		[]string{"terrascale.stateful.terrabase.terrabase-8"}, nil, nil)
}

func TestScheduleStatefulLocalityPrefersTheVolumeNode(t *testing.T) {
	workload := schedulerTestWorkload(t, schedulerTestTiny(), nil, nil, nil, nil)
	policy := schedulerTestPolicy(t)
	// node-a leaves less waste after placement, so the baseline scheduler
	// ranks it first; node-b hosts the persistent volume.
	lean := schedulerTestNode(t, "node-a", ResourceVector{
		Cpu: 20, Memory: 100, BlockIo: 100, EphemeralDisk: 100,
		Bandwidth: 100, Pids: 100, FileDescriptors: 100, HugePages: 100,
	}, nil, nil, nil, nil, nil)
	volumeHost := schedulerTestNode(t, "node-b", schedulerTestAbundant(), nil, nil,
		[]string{"terrascale.volume.terrabase.terrabase-1"}, nil, nil)

	baseline, err := DeterministicScheduler{}.Schedule(workload,
		[]*NodeCandidate{lean, volumeHost}, policy)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	if baseline.(PlacementSelected).SelectedCandidateId != "node-a" {
		t.Fatal("baseline must rank the lean node first")
	}

	result, err := ScheduleStateful(workload, []*NodeCandidate{lean, volumeHost},
		policy, statefulTestPolicy(t, 1000), "terrabase", "terrabase-1")
	if err != nil {
		t.Fatalf("schedule: %v", err)
	}
	selected := result.(PlacementSelected)
	if selected.SelectedCandidateId != "node-b" {
		t.Fatalf("selected = %q, want the volume host node-b", selected.SelectedCandidateId)
	}
	traces := resultCandidates(result)
	remoteDetail := schedulerTestReason(t, traces[0], PlacementCheckScore).Detail
	if !strings.HasSuffix(remoteDetail, "; statefulLocality=remote; localityPenalty=1000") {
		t.Fatalf("remote score detail = %q", remoteDetail)
	}
	localDetail := schedulerTestReason(t, traces[1], PlacementCheckScore).Detail
	if !strings.HasSuffix(localDetail, "; statefulLocality=local") {
		t.Fatalf("local score detail = %q", localDetail)
	}
}

func TestScheduleStatefulZeroPenaltyKeepsBaselineRanking(t *testing.T) {
	workload := schedulerTestWorkload(t, schedulerTestTiny(), nil, nil, nil, nil)
	policy := schedulerTestPolicy(t)
	lean := schedulerTestNode(t, "node-a", ResourceVector{
		Cpu: 20, Memory: 100, BlockIo: 100, EphemeralDisk: 100,
		Bandwidth: 100, Pids: 100, FileDescriptors: 100, HugePages: 100,
	}, nil, nil, nil, nil, nil)
	volumeHost := schedulerTestNode(t, "node-b", schedulerTestAbundant(), nil, nil,
		[]string{"terrascale.volume.terrabase.terrabase-1"}, nil, nil)

	baseline, err := DeterministicScheduler{}.Schedule(workload,
		[]*NodeCandidate{lean, volumeHost}, policy)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	stateful, err := ScheduleStateful(workload, []*NodeCandidate{lean, volumeHost},
		policy, statefulTestPolicy(t, 0), "terrabase", "terrabase-1")
	if err != nil {
		t.Fatalf("schedule: %v", err)
	}
	if stateful.(PlacementSelected).SelectedCandidateId !=
		baseline.(PlacementSelected).SelectedCandidateId {
		t.Fatalf("zero penalty changed the ranking: %q vs %q",
			stateful.(PlacementSelected).SelectedCandidateId,
			baseline.(PlacementSelected).SelectedCandidateId)
	}
}

func TestScheduleStatefulLocalityNeverOverridesHardConstraints(t *testing.T) {
	workload := schedulerTestWorkload(t, schedulerTestTiny(), nil, nil, nil, nil)
	policy := schedulerTestPolicy(t)

	// The only fitting candidate does not host the volume: locality penalizes
	// it but must not disqualify it.
	remoteOnly := schedulerTestNode(t, "node-a", schedulerTestAbundant(), nil, nil,
		nil, nil, nil)
	result, err := ScheduleStateful(workload, []*NodeCandidate{remoteOnly}, policy,
		statefulTestPolicy(t, 1_000_000), "terrabase", "terrabase-1")
	if err != nil {
		t.Fatalf("schedule: %v", err)
	}
	if result.(PlacementSelected).SelectedCandidateId != "node-a" {
		t.Fatal("a penalized but fitting candidate must stay selectable")
	}

	// A volume-hosting candidate that cannot fit the workload must stay
	// ineligible no matter how strong the locality preference is.
	starvedLocal := schedulerTestNode(t, "node-b", ResourceVector{}, nil, nil,
		[]string{"terrascale.volume.terrabase.terrabase-1"}, nil, nil)
	result, err = ScheduleStateful(workload, []*NodeCandidate{remoteOnly, starvedLocal},
		policy, statefulTestPolicy(t, 1_000_000), "terrabase", "terrabase-1")
	if err != nil {
		t.Fatalf("schedule: %v", err)
	}
	if result.(PlacementSelected).SelectedCandidateId != "node-a" {
		t.Fatal("locality must not override the resource hard constraints")
	}
	for _, trace := range resultCandidates(result) {
		if trace.CandidateId == "node-b" && trace.Eligible {
			t.Fatal("the starved volume host must be ineligible")
		}
	}
}

func TestScheduleStatefulValidation(t *testing.T) {
	workload := schedulerTestWorkload(t, schedulerTestTiny(), nil, nil, nil, nil)
	policy := schedulerTestPolicy(t)
	stateful := statefulTestPolicy(t, 0)
	candidate := schedulerTestNode(t, "node-a", schedulerTestAbundant(), nil, nil,
		nil, nil, nil)

	tests := []struct {
		name         string
		workload     *WorkloadRequest
		candidates   []*NodeCandidate
		policy       *LeastWastePolicy
		stateful     *StatefulPlacementPolicy
		roleKind     string
		allocationId string
		expectParam  string
	}{
		{name: "nil workload", candidates: []*NodeCandidate{candidate}, policy: policy,
			stateful: stateful, roleKind: "terrabase", allocationId: "terrabase-1",
			expectParam: "workload"},
		{name: "nil candidates", workload: workload, policy: policy,
			stateful: stateful, roleKind: "terrabase", allocationId: "terrabase-1",
			expectParam: "candidates"},
		{name: "nil policy", workload: workload, candidates: []*NodeCandidate{candidate},
			stateful: stateful, roleKind: "terrabase", allocationId: "terrabase-1",
			expectParam: "policy"},
		{name: "nil stateful policy", workload: workload,
			candidates: []*NodeCandidate{candidate}, policy: policy,
			roleKind: "terrabase", allocationId: "terrabase-1",
			expectParam: "statefulPolicy"},
		{name: "malformed role kind", workload: workload,
			candidates: []*NodeCandidate{candidate}, policy: policy, stateful: stateful,
			roleKind: "TerraBase", allocationId: "terrabase-1",
			expectParam: "roleKind"},
		{name: "malformed allocation id", workload: workload,
			candidates: []*NodeCandidate{candidate}, policy: policy, stateful: stateful,
			roleKind: "terrabase", allocationId: "tb_1",
			expectParam: "allocationId"},
		{name: "duplicate candidate ids", workload: workload,
			candidates: []*NodeCandidate{candidate, candidate}, policy: policy,
			stateful: stateful, roleKind: "terrabase", allocationId: "terrabase-1",
			expectParam: "candidates"},
		{name: "null candidate", workload: workload,
			candidates: []*NodeCandidate{candidate, nil}, policy: policy,
			stateful: stateful, roleKind: "terrabase", allocationId: "terrabase-1",
			expectParam: "candidates"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ScheduleStateful(test.workload, test.candidates, test.policy,
				test.stateful, test.roleKind, test.allocationId)
			if !statefulTestParam(err, test.expectParam) {
				t.Fatalf("error %v does not reference param %s", err, test.expectParam)
			}
		})
	}
}

func TestScheduleStatefulIsDeterministic(t *testing.T) {
	workload := schedulerTestWorkload(t, schedulerTestTiny(), nil, nil, nil, nil)
	policy := schedulerTestPolicy(t)
	stateful := statefulTestPolicy(t, 100)
	candidates := []*NodeCandidate{
		schedulerTestNode(t, "node-b", schedulerTestAbundant(), nil, nil, nil, nil, nil),
		schedulerTestNode(t, "node-a", schedulerTestAbundant(), nil, nil,
			[]string{"terrascale.stateful.terrabase.terrabase-2"}, nil, nil),
		schedulerTestNode(t, "node-c", schedulerTestAbundant(), nil, nil,
			[]string{"terrascale.volume.terrabase.terrabase-1"}, nil, nil),
	}

	first, err := ScheduleStateful(workload, candidates, policy, stateful,
		"terrabase", "terrabase-1")
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := ScheduleStateful(workload, candidates, policy, stateful,
		"terrabase", "terrabase-1")
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("repeated stateful scheduling must be byte-identical")
	}
	if first.(PlacementSelected).SelectedCandidateId != "node-c" {
		t.Fatalf("selected = %q, want node-c", first.(PlacementSelected).SelectedCandidateId)
	}
}

func TestApplyStatefulLocalityValidation(t *testing.T) {
	policy := statefulTestPolicy(t, 100)
	candidate := schedulerTestNode(t, "node-a", schedulerTestAbundant(), nil, nil,
		[]string{"terrascale.volume.terrabase.terrabase-1"}, nil, nil)

	if _, err := policy.ApplyStatefulLocality("terrabase", "terrabase-1", candidate, nil); !statefulTestParam(err, "score") {
		t.Fatalf("error %v does not reference param score", err)
	}
	if _, err := policy.ApplyStatefulLocality("terrabase", "terrabase-1", nil,
		&WasteScore{WeightedWaste: big.NewInt(1)}); !statefulTestParam(err, "candidate") {
		t.Fatalf("error %v does not reference param candidate", err)
	}

	base := &WasteScore{WeightedWaste: big.NewInt(10), Components: []WasteComponent{}}
	localScore, err := policy.ApplyStatefulLocality("terrabase", "terrabase-1",
		candidate, base)
	if err != nil {
		t.Fatalf("local: %v", err)
	}
	if localScore.WeightedWaste.Cmp(big.NewInt(10)) != 0 {
		t.Fatalf("local score = %v", localScore.WeightedWaste)
	}
	remoteCandidate := schedulerTestNode(t, "node-b", schedulerTestAbundant(), nil, nil,
		nil, nil, nil)
	remoteScore, err := policy.ApplyStatefulLocality("terrabase", "terrabase-1",
		remoteCandidate, base)
	if err != nil {
		t.Fatalf("remote: %v", err)
	}
	if remoteScore.WeightedWaste.Cmp(big.NewInt(110)) != 0 {
		t.Fatalf("remote score = %v", remoteScore.WeightedWaste)
	}
	if base.WeightedWaste.Cmp(big.NewInt(10)) != 0 {
		t.Fatal("the base score must not be mutated")
	}
}
