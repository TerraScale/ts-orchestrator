package scheduling

import (
	"strings"
	"testing"
)

// residencyLock builds one validated residency placement policy.
func residencyLock(t *testing.T, regions ...string) *ResidencyPlacementPolicy {
	t.Helper()
	policy, err := NewResidencyPlacementPolicy(regions)
	if err != nil {
		t.Fatalf("residency policy %v: %v", regions, err)
	}
	return policy
}

// residencyLeastWastePolicy weights every dimension equally.
func residencyLeastWastePolicy(t *testing.T) *LeastWastePolicy {
	t.Helper()
	scores := make([]ScoreDimension, 0, len(AllResourceDimensions))
	for _, dimension := range AllResourceDimensions {
		scores = append(scores, ScoreDimension{Dimension: dimension, Weight: 1})
	}
	policy, err := NewLeastWastePolicy(scores)
	if err != nil {
		t.Fatalf("least-waste policy: %v", err)
	}
	return policy
}

// residencyWorkload requests a small fixed footprint with no constraints
// beyond the scheduler defaults.
func residencyWorkload(t *testing.T, id string) *WorkloadRequest {
	t.Helper()
	resources, err := NewResourceVector(1, 1, 1, 1, 1, 1, 1, 1)
	if err != nil {
		t.Fatalf("resources: %v", err)
	}
	workload, err := NewWorkloadRequest(id, "linux-amd64", resources, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("workload: %v", err)
	}
	return workload
}

// residencyCandidate builds one candidate in a Region with the given spare
// capacity in every dimension. A blank region omits the Region label.
func residencyCandidate(t *testing.T, id, region string, spare int64) *NodeCandidate {
	t.Helper()
	available, err := NewResourceVector(1+spare, 1+spare, 1+spare, 1+spare, 1+spare, 1+spare, 1+spare, 1+spare)
	if err != nil {
		t.Fatalf("available: %v", err)
	}
	labels := map[string]string{}
	if region != "" {
		labels[ResidencyRegionLabel] = region
	}
	cap := AllocationSafetyCap{CurrentAllocations: 0, MaximumAllocations: 100}
	candidate, err := NewNodeCandidate(id, "compute", "linux-amd64", "fd-a", available,
		nil, labels, nil, nil, nil, nil, &cap, nil)
	if err != nil {
		t.Fatalf("candidate %s: %v", id, err)
	}
	return candidate
}

// residencyTrace finds the trace of one candidate id.
func residencyTrace(t *testing.T, result ScheduleResult, candidateId string) CandidateTrace {
	t.Helper()
	var found []CandidateTrace
	switch selected := result.(type) {
	case PlacementSelected:
		found = selected.Candidates
	case Unschedulable:
		found = selected.Candidates
	}
	for _, trace := range found {
		if trace.CandidateId == candidateId {
			return trace
		}
	}
	t.Fatalf("no trace for candidate %s", candidateId)
	return CandidateTrace{}
}

// residencyRow finds the residency trace row of one trace.
func residencyRow(t *testing.T, trace CandidateTrace) PlacementReason {
	t.Helper()
	for _, reason := range trace.Reasons {
		if strings.HasPrefix(reason.Detail, "residency:") {
			return reason
		}
	}
	t.Fatalf("no residency row for candidate %s", trace.CandidateId)
	return PlacementReason{}
}

func TestNewResidencyPlacementPolicy(t *testing.T) {
	if _, err := NewResidencyPlacementPolicy(nil); err == nil {
		t.Fatal("empty lock set accepted")
	}
	if _, err := NewResidencyPlacementPolicy([]string{"gru", "gru"}); err == nil {
		t.Fatal("duplicate region accepted")
	}
	if _, err := NewResidencyPlacementPolicy([]string{"GRU"}); err == nil {
		t.Fatal("uppercase region accepted")
	}
	if _, err := NewResidencyPlacementPolicy([]string{"gru"}); err != nil {
		t.Fatalf("valid lock set rejected: %v", err)
	}
	policy := residencyLock(t, "sfo", "gru")
	regions := policy.ResidencyRegions()
	if len(regions) != 2 || regions[0] != "gru" || regions[1] != "sfo" {
		t.Fatalf("ResidencyRegions() = %v, want sorted [gru sfo]", regions)
	}
}

func TestResidencyReason(t *testing.T) {
	policy := residencyLock(t, "gru", "fra")

	reason, err := policy.ResidencyReason(residencyCandidate(t, "gru-1", "gru", 4))
	if err != nil || reason.Outcome != CheckOutcomePassed {
		t.Fatalf("inside-lock reason = %+v, %v", reason, err)
	}
	reason, err = policy.ResidencyReason(residencyCandidate(t, "sfo-1", "sfo", 4))
	if err != nil || reason.Outcome != CheckOutcomeRejected {
		t.Fatalf("outside-lock reason = %+v, %v", reason, err)
	}
	if !strings.Contains(reason.Detail, "outside the placement lock") {
		t.Fatalf("outside-lock detail = %q", reason.Detail)
	}
	reason, err = policy.ResidencyReason(residencyCandidate(t, "mystery-1", "", 4))
	if err != nil || reason.Outcome != CheckOutcomeRejected {
		t.Fatalf("missing-label reason = %+v, %v", reason, err)
	}
	if !strings.Contains(reason.Detail, "missing") {
		t.Fatalf("missing-label detail = %q", reason.Detail)
	}
	if _, err := policy.ResidencyReason(nil); err == nil {
		t.Fatal("nil candidate accepted")
	}
	if !policy.RegionAllowed("fra") || policy.RegionAllowed("sfo") {
		t.Fatal("RegionAllowed disagrees with the lock set")
	}
}

func TestScheduleResidencyHonoursLockOverWaste(t *testing.T) {
	workload := residencyWorkload(t, "terrabase-1")
	// sfo-1 offers strictly less waste, so the base scheduler would select it.
	candidates := []*NodeCandidate{
		residencyCandidate(t, "gru-1", "gru", 40),
		residencyCandidate(t, "sfo-1", "sfo", 4),
	}
	policy := residencyLeastWastePolicy(t)

	result, err := ScheduleResidency(workload, candidates, policy, residencyLock(t, "gru"))
	if err != nil {
		t.Fatalf("ScheduleResidency: %v", err)
	}
	selected, ok := result.(PlacementSelected)
	if !ok || selected.SelectedCandidateId != "gru-1" {
		t.Fatalf("result = %#v, want gru-1 selected under the gru-only lock", result)
	}
	sfo := residencyTrace(t, result, "sfo-1")
	if sfo.Eligible {
		t.Fatal("candidate outside the placement lock stayed eligible")
	}
	if row := residencyRow(t, sfo); row.Outcome != CheckOutcomeRejected {
		t.Fatalf("sfo residency row = %+v", row)
	}
	if row := residencyRow(t, residencyTrace(t, result, "gru-1")); row.Outcome != CheckOutcomePassed {
		t.Fatal("inside-lock candidate has no passing residency row")
	}

	result, err = ScheduleResidency(workload, candidates, policy, residencyLock(t, "sfo"))
	if err != nil {
		t.Fatalf("ScheduleResidency: %v", err)
	}
	if selected, ok := result.(PlacementSelected); !ok || selected.SelectedCandidateId != "sfo-1" {
		t.Fatalf("result = %#v, want sfo-1 selected under the sfo-only lock", result)
	}
}

func TestScheduleResidencyNamedLockRegionSet(t *testing.T) {
	// A resolved eu-only lock names exactly the eu Regions; the same
	// candidates, gated by that set, keep only the eu candidate.
	workload := residencyWorkload(t, "terrabase-1")
	candidates := []*NodeCandidate{
		residencyCandidate(t, "gru-1", "gru", 4),
		residencyCandidate(t, "fra-1", "fra", 4),
	}
	result, err := ScheduleResidency(workload, candidates, residencyLeastWastePolicy(t), residencyLock(t, "fra"))
	if err != nil {
		t.Fatalf("ScheduleResidency: %v", err)
	}
	selected, ok := result.(PlacementSelected)
	if !ok || selected.SelectedCandidateId != "fra-1" {
		t.Fatalf("result = %#v, want fra-1 selected under the eu-only region set", result)
	}
	gru := residencyTrace(t, result, "gru-1")
	if gru.Eligible {
		t.Fatal("br Region stayed eligible under an eu-only region set")
	}
}

func TestScheduleResidencyFailsClosed(t *testing.T) {
	workload := residencyWorkload(t, "terrabase-1")
	policy := residencyLeastWastePolicy(t)

	// No Region label: residency cannot be proven, so the only candidate is
	// refused even though nothing else constrains it.
	unlabelled := []*NodeCandidate{residencyCandidate(t, "mystery-1", "", 4)}
	result, err := ScheduleResidency(workload, unlabelled, policy, residencyLock(t, "gru"))
	if err != nil {
		t.Fatalf("ScheduleResidency: %v", err)
	}
	if _, ok := result.(PlacementSelected); ok {
		t.Fatal("candidate without a Region label was placed")
	}
	if row := residencyRow(t, residencyTrace(t, result, "mystery-1")); row.Outcome != CheckOutcomeRejected {
		t.Fatal("missing-label candidate has no rejected residency row")
	}

	// Every candidate outside the lock: unschedulable, never widened.
	outside := []*NodeCandidate{
		residencyCandidate(t, "gru-1", "gru", 4),
		residencyCandidate(t, "sfo-1", "sfo", 4),
	}
	result, err = ScheduleResidency(workload, outside, policy, residencyLock(t, "fra"))
	if err != nil {
		t.Fatalf("ScheduleResidency: %v", err)
	}
	unschedulable, ok := result.(Unschedulable)
	if !ok {
		t.Fatalf("result = %#v, want unschedulable", result)
	}
	for _, trace := range unschedulable.Candidates {
		if trace.Eligible {
			t.Fatalf("candidate %s stayed eligible outside the lock", trace.CandidateId)
		}
		if row := residencyRow(t, trace); row.Outcome != CheckOutcomeRejected {
			t.Fatalf("candidate %s has no rejected residency row", trace.CandidateId)
		}
	}

	if _, err := ScheduleResidency(workload, outside, policy, nil); err == nil {
		t.Fatal("nil residency policy accepted")
	}
	if _, err := ScheduleResidency(nil, outside, policy, residencyLock(t, "gru")); err == nil {
		t.Fatal("nil workload accepted")
	}
}
