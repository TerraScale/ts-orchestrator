// This file implements the residency placement policy of the placement-lock
// lane (D-52): the hard rule that a node candidate whose Region is outside a
// database's placement lock is never eligible, no matter how little waste it
// offers, and the ScheduleResidency composition hook the deterministic
// scheduler calls into.
package scheduling

import (
	"sort"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

// ResidencyRegionLabel is the node label a candidate publishes with the
// Region code it is placed in. The label is required: a candidate that cannot
// prove its Region fails residency closed.
const ResidencyRegionLabel = "region"

// ResidencyPlacementPolicy is the D-52 placement lock at the node scheduler:
// the hard constraint that a workload's bytes may only land on candidates
// whose Region label is inside the lock's resolved Region set. Region
// membership changes eligibility only; scores and every other constraint are
// untouched. The Region set is a snapshot of the resolved lock at
// construction and is never widened.
type ResidencyPlacementPolicy struct {
	regions map[string]struct{}
}

// NewResidencyPlacementPolicy validates and snapshots one resolved placement
// lock Region set. Region codes are canonical lowercase DNS-style tokens;
// empty input, duplicates, and uppercase aliases are refused.
func NewResidencyPlacementPolicy(regions []string) (*ResidencyPlacementPolicy, error) {
	values, err := schedulerInputSnapshotCopy(
		regions,
		SchedulerTechnicalInputLimits.MaximumFactCount,
		"regions",
		"Residency region input",
	)
	if err != nil {
		return nil, err
	}
	if len(values) == 0 {
		return nil, &errs.Argument{
			Param:   "regions",
			Message: "A residency placement policy must name at least one Region.",
		}
	}
	seen := make(map[string]struct{}, len(values))
	for _, region := range values {
		if len(region) > statefulMaximumTokenLength || !statefulTokenPattern.MatchString(region) {
			return nil, &errs.Argument{
				Param:   "regions",
				Message: "Region codes must be lowercase DNS-style tokens.",
			}
		}
		if _, duplicate := seen[region]; duplicate {
			return nil, &errs.Argument{
				Param:   "regions",
				Message: "Region codes cannot contain duplicates.",
			}
		}
		seen[region] = struct{}{}
	}
	return &ResidencyPlacementPolicy{regions: seen}, nil
}

// ResidencyRegions returns the locked Region set in stable sorted order.
func (p *ResidencyPlacementPolicy) ResidencyRegions() []string {
	regions := make([]string, 0, len(p.regions))
	for region := range p.regions {
		regions = append(regions, region)
	}
	sort.Strings(regions)
	return regions
}

// RegionAllowed reports whether one Region code is inside the lock. A nil
// policy allows nothing.
func (p *ResidencyPlacementPolicy) RegionAllowed(region string) bool {
	if p == nil {
		return false
	}
	_, allowed := p.regions[region]
	return allowed
}

// ResidencyReason returns the hard residency trace row of one candidate: the
// candidate is rejected when it does not publish a Region label or its Region
// is outside the placement lock. The row rides the Labels check because the
// Region is a candidate label and the trace vocabulary is closed; the detail
// names residency so traces stay auditable.
func (p *ResidencyPlacementPolicy) ResidencyReason(candidate *NodeCandidate) (PlacementReason, error) {
	if candidate == nil {
		return PlacementReason{}, &errs.Argument{
			Param:   "candidate",
			Message: "A node candidate is required.",
		}
	}
	region, present := candidate.Labels[ResidencyRegionLabel]
	if !present || strings.TrimSpace(region) == "" {
		return PlacementReason{
			Check:   PlacementCheckLabels,
			Outcome: CheckOutcomeRejected,
			Detail:  "residency: Region label is missing; residency cannot be proven",
		}, nil
	}
	if !p.RegionAllowed(region) {
		return PlacementReason{
			Check:   PlacementCheckLabels,
			Outcome: CheckOutcomeRejected,
			Detail:  "residency: region=" + region + " is outside the placement lock",
		}, nil
	}
	return PlacementReason{
		Check:   PlacementCheckLabels,
		Outcome: CheckOutcomePassed,
		Detail:  "residency: region=" + region + " is inside the placement lock",
	}, nil
}

// ScheduleResidency places one workload through the deterministic scheduler
// with the residency placement policy applied: every candidate whose Region is
// outside the placement lock is made ineligible by a hard residency row
// inserted directly after the scheduler's own labels row. The result
// vocabulary and trace shape are exactly those of
// DeterministicScheduler.Schedule.
func ScheduleResidency(
	workload *WorkloadRequest,
	candidates []*NodeCandidate,
	policy *LeastWastePolicy,
	residency *ResidencyPlacementPolicy,
) (ScheduleResult, error) {
	if workload == nil {
		return nil, &errs.Argument{Param: "workload"}
	}
	if candidates == nil {
		return nil, &errs.Argument{Param: "candidates"}
	}
	if policy == nil {
		return nil, &errs.Argument{Param: "policy"}
	}
	if residency == nil {
		return nil, &errs.Argument{Param: "residency"}
	}
	// snapshotStatefulCandidates enforces exactly the clone, bound, order,
	// and uniqueness rules of DeterministicScheduler.Schedule.
	suppliedCandidates, err := snapshotStatefulCandidates(candidates)
	if err != nil {
		return nil, err
	}
	evaluations := make([]scheduleEvaluation, len(suppliedCandidates))
	for index, candidate := range suppliedCandidates {
		evaluations[index] = applyResidencyPolicy(
			evaluateWorkload(workload, candidate, policy),
			residency,
			candidate)
	}
	selected := -1
	for index, evaluation := range evaluations {
		if evaluation.score == nil {
			continue
		}
		if selected == -1 || compareEvaluations(evaluation, evaluations[selected]) < 0 {
			selected = index
		}
	}
	traces := make([]CandidateTrace, len(evaluations))
	for index, evaluation := range evaluations {
		traces[index] = finishTrace(evaluation, selected != -1 && index == selected)
	}
	if selected == -1 {
		return Unschedulable{WorkloadId: workload.Id, Candidates: traces}, nil
	}
	return PlacementSelected{
		WorkloadId:          workload.Id,
		SelectedCandidateId: evaluations[selected].candidate.Id,
		Candidates:          traces,
	}, nil
}

// applyResidencyPolicy post-processes one deterministic scheduler evaluation
// with the residency policy: the hard residency row is inserted directly
// after the scheduler's own labels row, and a candidate outside the placement
// lock is made ineligible.
func applyResidencyPolicy(
	evaluation scheduleEvaluation,
	policy *ResidencyPlacementPolicy,
	candidate *NodeCandidate,
) scheduleEvaluation {
	residency, err := policy.ResidencyReason(candidate)
	if err != nil {
		return scheduleEvaluation{candidate: candidate, score: nil, reasons: evaluation.reasons}
	}
	reasons := make([]PlacementReason, 0, len(evaluation.reasons)+1)
	inserted := false
	for _, reason := range evaluation.reasons {
		reasons = append(reasons, reason)
		if reason.Check == PlacementCheckLabels && !inserted {
			reasons = append(reasons, residency)
			inserted = true
		}
	}
	if !inserted {
		reasons = append(reasons, residency)
	}
	if residency.Outcome == CheckOutcomeRejected {
		last := len(reasons) - 1
		if evaluation.score != nil && last >= 0 && reasons[last].Check == PlacementCheckScore {
			reasons[last] = PlacementReason{
				Check:   PlacementCheckScore,
				Outcome: CheckOutcomeNotApplicable,
				Detail:  "Hard constraints rejected the candidate.",
			}
		}
		return scheduleEvaluation{candidate: candidate, score: nil, reasons: reasons}
	}
	return scheduleEvaluation{candidate: candidate, score: evaluation.score, reasons: reasons}
}
