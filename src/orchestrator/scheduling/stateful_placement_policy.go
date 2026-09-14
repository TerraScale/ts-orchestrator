// This file implements the stateful-first placement policy of the
// rootless-hosting and autoscaling lane: the hard rule that two running
// replicas of one role kind never share a node, the soft persistent-volume
// data-locality preference in the least-waste shape, and the ScheduleStateful
// composition hook the deterministic scheduler calls into.
package scheduling

import (
	"math/big"
	"regexp"
	"sort"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

// statefulTokenPattern accepts the bounded canonical token vocabulary of
// stateful role kinds and allocation IDs, the same DNS-style shape the
// stateful package enforces.
var statefulTokenPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)

const (
	statefulMaximumTokenLength = 63
	// statefulFactPrefix is the shared prefix of every stateful placement fact.
	statefulFactPrefix = "terrascale"
	// statefulFactNamespaceReplica marks a node as hosting one running
	// stateful replica of one allocation.
	statefulFactNamespaceReplica = "stateful"
	// statefulFactNamespaceVolume marks a node as hosting the persistent
	// volume of one stateful allocation.
	statefulFactNamespaceVolume = "volume"
)

// requireStatefulToken enforces the bounded canonical token vocabulary of
// stateful placement facts.
func requireStatefulToken(value, param, message string) (string, error) {
	if len(value) < 1 || len(value) > statefulMaximumTokenLength ||
		!statefulTokenPattern.MatchString(value) {
		return "", &errs.Argument{Param: param, Message: message}
	}
	return value, nil
}

// StatefulReplicaFact returns the canonical affinity fact a node publishes
// for each running stateful replica it hosts:
// terrascale.stateful.<roleKind>.<allocationId>. A node publishes the fact
// only while the replica runs; a stopped or crashed replica keeps only its
// volume fact, so the same allocation can be rescheduled onto its own node.
func StatefulReplicaFact(roleKind string, allocationId string) (string, error) {
	validatedRole, err := requireStatefulToken(roleKind, "roleKind",
		"Role kind must be a lowercase DNS-style token.")
	if err != nil {
		return "", err
	}
	validatedAllocation, err := requireStatefulToken(allocationId, "allocationId",
		"Allocation ID must be a lowercase DNS-style token.")
	if err != nil {
		return "", err
	}
	return strings.Join([]string{
		statefulFactPrefix, statefulFactNamespaceReplica, validatedRole, validatedAllocation,
	}, "."), nil
}

// StatefulVolumeFact returns the canonical affinity fact a node publishes for
// hosting the persistent volume of one stateful allocation:
// terrascale.volume.<roleKind>.<allocationId>.
func StatefulVolumeFact(roleKind string, allocationId string) (string, error) {
	validatedRole, err := requireStatefulToken(roleKind, "roleKind",
		"Role kind must be a lowercase DNS-style token.")
	if err != nil {
		return "", err
	}
	validatedAllocation, err := requireStatefulToken(allocationId, "allocationId",
		"Allocation ID must be a lowercase DNS-style token.")
	if err != nil {
		return "", err
	}
	return strings.Join([]string{
		statefulFactPrefix, statefulFactNamespaceVolume, validatedRole, validatedAllocation,
	}, "."), nil
}

// StatefulPlacementPolicy is the composable stateful placement policy of the
// deterministic scheduler: the hard rule that two running replicas of one
// role kind never share a node, and the soft rule that a rescheduled replica
// prefers the node already hosting its persistent volume. Locality changes
// ranking only; eligibility and every hard constraint stay untouched.
type StatefulPlacementPolicy struct {
	localityPenalty *big.Int
}

// NewStatefulPlacementPolicy validates one policy. The locality penalty is
// the non-negative waste added to every candidate that does not host the
// allocation's persistent volume; zero disables the locality preference.
func NewStatefulPlacementPolicy(localityPenalty int64) (*StatefulPlacementPolicy, error) {
	if localityPenalty < 0 {
		return nil, &errs.ArgumentOutOfRangeError{
			Param:   "localityPenalty",
			Message: "The locality penalty must be non-negative.",
		}
	}
	return &StatefulPlacementPolicy{localityPenalty: big.NewInt(localityPenalty)}, nil
}

// StatefulAntiAffinityReason returns the hard anti-affinity trace row of one
// candidate for placing one stateful replica: the candidate is rejected when
// it already hosts a running replica of the same role kind. The conflicting
// replica facts are named in canonical order; even the placement's own
// allocation counts as a conflict, so a double placement of one allocation
// fails closed.
func (p *StatefulPlacementPolicy) StatefulAntiAffinityReason(
	roleKind string,
	allocationId string,
	candidate *NodeCandidate,
) (PlacementReason, error) {
	if _, err := requireStatefulToken(roleKind, "roleKind",
		"Role kind must be a lowercase DNS-style token."); err != nil {
		return PlacementReason{}, err
	}
	if _, err := requireStatefulToken(allocationId, "allocationId",
		"Allocation ID must be a lowercase DNS-style token."); err != nil {
		return PlacementReason{}, err
	}
	if candidate == nil {
		return PlacementReason{}, &errs.Argument{
			Param:   "candidate",
			Message: "A node candidate is required.",
		}
	}
	return statefulAntiAffinityReason(roleKind, candidate), nil
}

// ApplyStatefulLocality returns the locality-adjusted least-waste score of
// one candidate: a candidate hosting the allocation's persistent volume keeps
// its score, every other candidate is penalized by the configured locality
// penalty. The adjustment never changes eligibility.
func (p *StatefulPlacementPolicy) ApplyStatefulLocality(
	roleKind string,
	allocationId string,
	candidate *NodeCandidate,
	score *WasteScore,
) (*WasteScore, error) {
	if _, err := requireStatefulToken(roleKind, "roleKind",
		"Role kind must be a lowercase DNS-style token."); err != nil {
		return nil, err
	}
	if _, err := requireStatefulToken(allocationId, "allocationId",
		"Allocation ID must be a lowercase DNS-style token."); err != nil {
		return nil, err
	}
	if candidate == nil {
		return nil, &errs.Argument{
			Param:   "candidate",
			Message: "A node candidate is required.",
		}
	}
	if score == nil || score.WeightedWaste == nil {
		return nil, &errs.Argument{
			Param:   "score",
			Message: "A weighted waste score is required.",
		}
	}
	adjusted := &WasteScore{
		WeightedWaste: new(big.Int).Set(score.WeightedWaste),
		Remaining:     score.Remaining,
		Components:    append([]WasteComponent(nil), score.Components...),
	}
	if !statefulHostsVolume(roleKind, allocationId, candidate) {
		adjusted.WeightedWaste.Add(adjusted.WeightedWaste, p.localityPenalty)
	}
	return adjusted, nil
}

// ScheduleStateful places one stateful replica through the deterministic
// scheduler with the stateful placement policy applied: every candidate
// already running a replica of the same role kind is made ineligible by a
// hard anti-affinity row inserted after the scheduler's own anti-affinity
// row, and every eligible candidate not hosting the allocation's persistent
// volume is penalized by the locality penalty. The result vocabulary and
// trace shape are exactly those of DeterministicScheduler.Schedule.
func ScheduleStateful(
	workload *WorkloadRequest,
	candidates []*NodeCandidate,
	policy *LeastWastePolicy,
	statefulPolicy *StatefulPlacementPolicy,
	roleKind string,
	allocationId string,
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
	if statefulPolicy == nil {
		return nil, &errs.Argument{Param: "statefulPolicy"}
	}
	validatedRole, err := requireStatefulToken(roleKind, "roleKind",
		"Role kind must be a lowercase DNS-style token.")
	if err != nil {
		return nil, err
	}
	validatedAllocation, err := requireStatefulToken(allocationId, "allocationId",
		"Allocation ID must be a lowercase DNS-style token.")
	if err != nil {
		return nil, err
	}
	suppliedCandidates, err := snapshotStatefulCandidates(candidates)
	if err != nil {
		return nil, err
	}
	evaluations := make([]scheduleEvaluation, len(suppliedCandidates))
	for index, candidate := range suppliedCandidates {
		evaluations[index] = applyStatefulPolicy(
			evaluateWorkload(workload, candidate, policy),
			statefulPolicy, validatedRole, validatedAllocation, candidate)
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

// statefulAntiAffinityReason builds the stateful anti-affinity trace row over
// prevalidated inputs.
func statefulAntiAffinityReason(roleKind string, candidate *NodeCandidate) PlacementReason {
	prefix := strings.Join([]string{
		statefulFactPrefix, statefulFactNamespaceReplica, roleKind,
	}, ".") + "."
	conflicts := make([]string, 0, len(candidate.AffinityFacts))
	for fact := range candidate.AffinityFacts {
		if len(fact) > len(prefix) && strings.HasPrefix(fact, prefix) {
			conflicts = append(conflicts, fact)
		}
	}
	sort.Strings(conflicts)
	if len(conflicts) == 0 {
		return PlacementReason{
			Check:   PlacementCheckAntiAffinity,
			Outcome: CheckOutcomePassed,
			Detail:  "No stateful anti-affinity conflict.",
		}
	}
	return PlacementReason{
		Check:   PlacementCheckAntiAffinity,
		Outcome: CheckOutcomeRejected,
		Detail:  "conflicts=" + strings.Join(conflicts, ","),
	}
}

// statefulHostsVolume reports whether one candidate publishes the volume fact
// of the given stateful allocation.
func statefulHostsVolume(roleKind string, allocationId string, candidate *NodeCandidate) bool {
	volumeFact, err := StatefulVolumeFact(roleKind, allocationId)
	if err != nil {
		return false
	}
	_, hosted := candidate.AffinityFacts[volumeFact]
	return hosted
}

// applyStatefulPolicy post-processes one deterministic scheduler evaluation
// with the stateful policy: the hard anti-affinity row is inserted directly
// after the scheduler's own anti-affinity row, a conflicting candidate is
// made ineligible, and an eligible candidate's score row records the locality
// adjustment.
func applyStatefulPolicy(
	evaluation scheduleEvaluation,
	policy *StatefulPlacementPolicy,
	roleKind string,
	allocationId string,
	candidate *NodeCandidate,
) scheduleEvaluation {
	antiAffinity := statefulAntiAffinityReason(roleKind, candidate)
	reasons := make([]PlacementReason, 0, len(evaluation.reasons)+1)
	inserted := false
	for _, reason := range evaluation.reasons {
		reasons = append(reasons, reason)
		if reason.Check == PlacementCheckAntiAffinity && !inserted {
			reasons = append(reasons, antiAffinity)
			inserted = true
		}
	}
	if !inserted {
		reasons = append(reasons, antiAffinity)
	}
	if antiAffinity.Outcome == CheckOutcomeRejected {
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
	if evaluation.score == nil {
		return scheduleEvaluation{candidate: candidate, score: nil, reasons: reasons}
	}
	// evaluateWorkload appended exactly one passed score row at the tail of a
	// scored evaluation; the locality adjustment rewrites that row.
	last := len(reasons) - 1
	if last < 0 || reasons[last].Check != PlacementCheckScore {
		return scheduleEvaluation{candidate: candidate, score: nil, reasons: reasons}
	}
	adjusted, err := policy.ApplyStatefulLocality(roleKind, allocationId, candidate, evaluation.score)
	if err != nil {
		reasons[last] = PlacementReason{
			Check:   PlacementCheckScore,
			Outcome: CheckOutcomeNotApplicable,
			Detail:  "Hard constraints rejected the candidate.",
		}
		return scheduleEvaluation{candidate: candidate, score: nil, reasons: reasons}
	}
	if statefulHostsVolume(roleKind, allocationId, candidate) {
		reasons[last].Detail += "; statefulLocality=local"
	} else {
		reasons[last].Detail += "; statefulLocality=remote; localityPenalty=" +
			policy.localityPenalty.String()
	}
	return scheduleEvaluation{candidate: candidate, score: adjusted, reasons: reasons}
}

// snapshotStatefulCandidates clones, bounds, orders, and uniqueness-checks
// the candidate input exactly like DeterministicScheduler.Schedule.
func snapshotStatefulCandidates(candidates []*NodeCandidate) ([]*NodeCandidate, error) {
	supplied, err := schedulerInputSnapshotCopy(
		candidates,
		SchedulerTechnicalInputLimits.MaximumCandidateCount,
		"candidates",
		"Candidate input")
	if err != nil {
		return nil, err
	}
	for _, candidate := range supplied {
		if candidate == nil {
			return nil, &errs.Argument{
				Param:   "candidates",
				Message: "Candidate collections cannot contain null.",
			}
		}
	}
	sort.SliceStable(supplied, func(left, right int) bool {
		return strings.Compare(supplied[left].Id, supplied[right].Id) < 0
	})
	for index := 1; index < len(supplied); index++ {
		if supplied[index-1].Id == supplied[index].Id {
			return nil, &errs.Argument{
				Param:   "candidates",
				Message: "Candidate IDs must be unique.",
			}
		}
	}
	return supplied, nil
}
