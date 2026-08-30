// This file ports Scheduling/DeterministicScheduler.cs.
package scheduling

import (
	"math/big"
	"sort"
	"strconv"
	"strings"
)

// DeterministicScheduler performs pure regional constrained least-waste
// placement. Project geography and stateful move safety are deliberately
// caller-owned constraints/vetoes (INV-013).
type DeterministicScheduler struct{}

// Schedule evaluates every candidate and returns the closed typed result.
func (DeterministicScheduler) Schedule(
	workload *WorkloadRequest,
	candidates []*NodeCandidate,
	policy *LeastWastePolicy,
) (ScheduleResult, error) {
	if workload == nil {
		return nil, &ArgumentError{Param: "workload"}
	}
	if candidates == nil {
		return nil, &ArgumentError{Param: "candidates"}
	}
	if policy == nil {
		return nil, &ArgumentError{Param: "policy"}
	}

	suppliedCandidates, err := schedulerInputSnapshotCopy(
		candidates,
		SchedulerTechnicalInputLimits.MaximumCandidateCount,
		"candidates",
		"Candidate input")
	if err != nil {
		return nil, err
	}
	for _, candidate := range suppliedCandidates {
		if candidate == nil {
			return nil, &ArgumentError{
				Param:   "candidates",
				Message: "Candidate collections cannot contain null.",
			}
		}
	}

	sort.SliceStable(suppliedCandidates, func(left, right int) bool {
		return strings.Compare(suppliedCandidates[left].Id, suppliedCandidates[right].Id) < 0
	})
	for index := 1; index < len(suppliedCandidates); index++ {
		if suppliedCandidates[index-1].Id == suppliedCandidates[index].Id {
			return nil, &ArgumentError{
				Param:   "candidates",
				Message: "Candidate IDs must be unique.",
			}
		}
	}

	evaluations := make([]scheduleEvaluation, len(suppliedCandidates))
	for index, candidate := range suppliedCandidates {
		evaluations[index] = evaluateWorkload(workload, candidate, policy)
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

type scheduleEvaluation struct {
	candidate *NodeCandidate
	score     *WasteScore
	reasons   []PlacementReason
}

func evaluateWorkload(workload *WorkloadRequest, candidate *NodeCandidate, policy *LeastWastePolicy) scheduleEvaluation {
	reasons := make([]PlacementReason, 0, 22)

	if candidate.Veto == nil {
		addPlacementReason(&reasons, PlacementCheckCallerVeto, true, "No caller veto.")
	} else {
		addPlacementReason(&reasons, PlacementCheckCallerVeto, false, "code="+candidate.Veto.Code.String())
	}
	addPlacementReason(&reasons, PlacementCheckArchitecture,
		candidate.Architecture == workload.Architecture,
		"required="+workload.Architecture+"; actual="+candidate.Architecture)
	if workload.RequiredNodeClass == nil {
		addPlacementReason(&reasons, PlacementCheckNodeClass, true, "No node class required.")
	} else {
		addPlacementReason(&reasons, PlacementCheckNodeClass,
			candidate.NodeClass == *workload.RequiredNodeClass,
			"required="+*workload.RequiredNodeClass+"; actual="+candidate.NodeClass)
	}

	var missingLabels []string
	for key, value := range workload.RequiredLabels {
		actual, exists := candidate.Labels[key]
		if !exists || actual != value {
			missingLabels = append(missingLabels, key+"="+value)
		}
	}
	sort.Strings(missingLabels)
	if len(missingLabels) == 0 {
		addPlacementReason(&reasons, PlacementCheckLabels, true, "All required labels match.")
	} else {
		addPlacementReason(&reasons, PlacementCheckLabels, false, "missing/mismatched="+strings.Join(missingLabels, ","))
	}

	addSubsetCheck(&reasons, PlacementCheckTrustZones, "trust", workload.RequiredTrustZones, candidate.TrustZones)
	addSubsetCheck(&reasons, PlacementCheckNetworkZones, "network", workload.RequiredNetworkZones, candidate.NetworkZones)
	addSubsetCheck(&reasons, PlacementCheckSecretZones, "secret", workload.RequiredSecretZones, candidate.SecretZones)

	failureDomainAllowed := len(workload.AllowedFailureDomains) == 0 ||
		containsString(workload.AllowedFailureDomains, candidate.FailureDomain)
	if len(workload.AllowedFailureDomains) == 0 {
		addPlacementReason(&reasons, PlacementCheckFailureDomain, failureDomainAllowed, "No failure-domain restriction.")
	} else {
		addPlacementReason(&reasons, PlacementCheckFailureDomain, failureDomainAllowed,
			"actual="+candidate.FailureDomain+"; allowed="+joinOrdered(workload.AllowedFailureDomains))
	}

	addSubsetCheck(&reasons, PlacementCheckAffinity, "affinity", workload.RequiredAffinityFacts, candidate.AffinityFacts)
	var antiAffinityConflicts []string
	for fact := range workload.ProhibitedAffinityFacts {
		if _, conflict := candidate.AffinityFacts[fact]; conflict {
			antiAffinityConflicts = append(antiAffinityConflicts, fact)
		}
	}
	sort.Strings(antiAffinityConflicts)
	if len(antiAffinityConflicts) == 0 {
		addPlacementReason(&reasons, PlacementCheckAntiAffinity, true, "No anti-affinity conflict.")
	} else {
		addPlacementReason(&reasons, PlacementCheckAntiAffinity, false, "conflicts="+strings.Join(antiAffinityConflicts, ","))
	}

	var portConflicts []int
	for port := range workload.RequiredPorts {
		if _, occupied := candidate.OccupiedPorts[port]; occupied {
			portConflicts = append(portConflicts, port)
		}
	}
	sort.Ints(portConflicts)
	if len(portConflicts) == 0 {
		addPlacementReason(&reasons, PlacementCheckPorts, true, "All requested ports are free.")
	} else {
		addPlacementReason(&reasons, PlacementCheckPorts, false, "conflicts="+joinInts(portConflicts))
	}
	if candidate.SafetyCap == nil {
		addPlacementReason(&reasons, PlacementCheckSafetyCap, true, "No caller-provided safety cap.")
	} else {
		addPlacementReason(&reasons, PlacementCheckSafetyCap, candidate.SafetyCap.CanAdmit(),
			"current="+formatInt64(candidate.SafetyCap.CurrentAllocations)+
				"; maximum="+formatInt64(candidate.SafetyCap.MaximumAllocations))
	}

	available := candidate.Available.orderedValues()
	requested := workload.Resources.orderedValues()
	for index := range available {
		passes := available[index].Value >= requested[index].Value
		addPlacementReason(&reasons, toCheck(available[index].Dimension), passes,
			"required="+formatInt64(requested[index].Value)+"; available="+formatInt64(available[index].Value))
	}

	for _, reason := range reasons {
		if reason.Outcome == CheckOutcomeRejected {
			reasons = append(reasons, PlacementReason{
				Check:   PlacementCheckScore,
				Outcome: CheckOutcomeNotApplicable,
				Detail:  "Hard constraints rejected the candidate.",
			})
			return scheduleEvaluation{candidate: candidate, score: nil, reasons: reasons}
		}
	}

	remaining, err := candidate.Available.SubtractChecked(workload.Resources)
	if err != nil {
		// A rejected hard constraint above already fences underflow; a checked
		// overflow cannot occur for admitted inputs, but fail closed regardless.
		reasons = append(reasons, PlacementReason{
			Check:   PlacementCheckScore,
			Outcome: CheckOutcomeNotApplicable,
			Detail:  "Hard constraints rejected the candidate.",
		})
		return scheduleEvaluation{candidate: candidate, score: nil, reasons: reasons}
	}
	score := calculateWaste(policy, remaining)
	reasons = append(reasons, PlacementReason{
		Check:   PlacementCheckScore,
		Outcome: CheckOutcomePassed,
		Detail: "weightedWaste=" + score.WeightedWaste.String() +
			"; components=" + formatWasteComponents(score.Components) +
			"; componentTieBreakOrder=" + joinDimensions(policy.Dimensions),
	})
	return scheduleEvaluation{candidate: candidate, score: &score, reasons: reasons}
}

func finishTrace(evaluation scheduleEvaluation, selected bool) CandidateTrace {
	reasons := make([]PlacementReason, 0, len(evaluation.reasons)+1)
	reasons = append(reasons, evaluation.reasons...)
	if evaluation.score == nil {
		reasons = append(reasons, PlacementReason{
			Check:   PlacementCheckSelection,
			Outcome: CheckOutcomeNotApplicable,
			Detail:  "Candidate was ineligible.",
		})
	} else if selected {
		var remaining []string
		for _, component := range evaluation.score.Components {
			remaining = append(remaining, formatInt64(component.Remaining))
		}
		reasons = append(reasons, PlacementReason{
			Check:   PlacementCheckSelection,
			Outcome: CheckOutcomePassed,
			Detail: "Selected by tuple (weightedWaste, orderedRemaining, candidateId)=(" +
				evaluation.score.WeightedWaste.String() + "," +
				strings.Join(remaining, ",") + "," +
				evaluation.candidate.Id + ").",
		})
	} else {
		reasons = append(reasons, PlacementReason{
			Check:   PlacementCheckSelection,
			Outcome: CheckOutcomeRejected,
			Detail:  "Eligible but ranked after the selected candidate.",
		})
	}

	return CandidateTrace{
		CandidateId: evaluation.candidate.Id,
		Eligible:    evaluation.score != nil,
		Score:       evaluation.score,
		Reasons:     reasons,
	}
}

func calculateWaste(policy *LeastWastePolicy, remaining ResourceVector) WasteScore {
	remainingByDimension := make(map[ResourceDimension]int64, 8)
	for _, item := range remaining.orderedValues() {
		remainingByDimension[item.Dimension] = item.Value
	}
	components := make([]WasteComponent, len(policy.Dimensions))
	total := new(big.Int)
	for index, item := range policy.Dimensions {
		value := remainingByDimension[item.Dimension]
		weighted := new(big.Int).Mul(big.NewInt(value), big.NewInt(item.Weight))
		components[index] = WasteComponent{
			Dimension:     item.Dimension,
			Remaining:     value,
			Weight:        item.Weight,
			WeightedWaste: weighted,
		}
		total.Add(total, weighted)
	}
	return WasteScore{
		WeightedWaste: total,
		Remaining:     remaining,
		Components:    components,
	}
}

func addSubsetCheck(
	reasons *[]PlacementReason,
	check PlacementCheck,
	name string,
	required map[string]struct{},
	actual map[string]struct{},
) {
	var missing []string
	for fact := range required {
		if _, present := actual[fact]; !present {
			missing = append(missing, fact)
		}
	}
	sort.Strings(missing)
	if len(missing) == 0 {
		*reasons = append(*reasons, PlacementReason{
			Check:   check,
			Outcome: CheckOutcomePassed,
			Detail:  "All required " + name + " facts match.",
		})
	} else {
		*reasons = append(*reasons, PlacementReason{
			Check:   check,
			Outcome: CheckOutcomeRejected,
			Detail:  "missing=" + strings.Join(missing, ","),
		})
	}
}

func addPlacementReason(reasons *[]PlacementReason, check PlacementCheck, passed bool, detail string) {
	outcome := CheckOutcomeRejected
	if passed {
		outcome = CheckOutcomePassed
	}
	*reasons = append(*reasons, PlacementReason{Check: check, Outcome: outcome, Detail: detail})
}

func toCheck(dimension ResourceDimension) PlacementCheck {
	switch dimension {
	case ResourceDimensionCpu:
		return PlacementCheckCpu
	case ResourceDimensionMemory:
		return PlacementCheckMemory
	case ResourceDimensionBlockIo:
		return PlacementCheckBlockIo
	case ResourceDimensionEphemeralDisk:
		return PlacementCheckEphemeralDisk
	case ResourceDimensionBandwidth:
		return PlacementCheckBandwidth
	case ResourceDimensionPids:
		return PlacementCheckPids
	case ResourceDimensionFileDescriptors:
		return PlacementCheckFileDescriptors
	case ResourceDimensionHugePages:
		return PlacementCheckHugePages
	default:
		panic("dimension out of range")
	}
}

func containsString(set map[string]struct{}, value string) bool {
	_, present := set[value]
	return present
}

func joinOrdered(values map[string]struct{}) string {
	ordered := make([]string, 0, len(values))
	for value := range values {
		ordered = append(ordered, value)
	}
	sort.Strings(ordered)
	return strings.Join(ordered, ",")
}

func joinInts(values []int) string {
	texts := make([]string, len(values))
	for index, value := range values {
		texts[index] = formatInt(value)
	}
	return strings.Join(texts, ",")
}

func joinDimensions(dimensions []ScoreDimension) string {
	texts := make([]string, len(dimensions))
	for index, item := range dimensions {
		texts[index] = item.Dimension.String()
	}
	return strings.Join(texts, ",")
}

func formatWasteComponents(components []WasteComponent) string {
	texts := make([]string, len(components))
	for index, component := range components {
		texts[index] = component.Dimension.String() + ":" +
			formatInt64(component.Remaining) + "*" +
			formatInt64(component.Weight) + "=" +
			component.WeightedWaste.String()
	}
	return strings.Join(texts, ",")
}

// compareEvaluations ports ScoreComparer: weighted waste, then each component's
// remaining value in policy order, then the ordinal candidate id.
func compareEvaluations(left, right scheduleEvaluation) int {
	comparison := left.score.WeightedWaste.Cmp(right.score.WeightedWaste)
	if comparison != 0 {
		return comparison
	}
	for index := range left.score.Components {
		switch {
		case left.score.Components[index].Remaining < right.score.Components[index].Remaining:
			return -1
		case left.score.Components[index].Remaining > right.score.Components[index].Remaining:
			return 1
		}
	}
	return strings.Compare(left.candidate.Id, right.candidate.Id)
}

func formatInt64(value int64) string { return strconv.FormatInt(value, 10) }

func formatInt(value int) string { return strconv.Itoa(value) }
