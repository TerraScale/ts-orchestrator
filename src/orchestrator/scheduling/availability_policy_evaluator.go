package scheduling

// AvailabilityPolicyEvaluator is the pure explicit-input availability policy.
// It never infers stateful safety or product/project geography (INV-013) and
// emits no caller free text.
type AvailabilityPolicyEvaluator struct{}

// Evaluate runs the closed trace and admission decision for one request.
func (AvailabilityPolicyEvaluator) Evaluate(request *AvailabilityEvaluationRequest) AvailabilityDecision {
	observations := make([]ReplicaObservation, len(request.Observations))
	copy(observations, request.Observations)
	sortReplicaObservations(observations)

	groups := make(map[string][]ReplicaObservation)
	var groupOrder []string
	for _, observation := range observations {
		if _, seen := groups[observation.ReplicaId.Value]; !seen {
			groupOrder = append(groupOrder, observation.ReplicaId.Value)
		}
		groups[observation.ReplicaId.Value] = append(groups[observation.ReplicaId.Value], observation)
	}

	duplicateCount := 0
	conflictCount := 0
	missingIdentityCount := 0
	wrongServiceCount := 0
	for _, replica := range observations {
		if replica.NodeId == nil || replica.FailureDomainId == nil {
			missingIdentityCount++
		}
		if replica.ServiceId != request.Policy.ServiceId {
			wrongServiceCount++
		}
	}
	for _, key := range groupOrder {
		members := groups[key]
		if len(members) > 1 {
			duplicateCount += len(members) - 1
		}
		distinctKeys := make(map[string]struct{}, len(members))
		for _, member := range members {
			distinctKeys[member.canonicalKey()] = struct{}{}
		}
		if len(distinctKeys) > 1 {
			conflictCount++
		}
	}

	complete := request.ObservationCompleteness == ObservationCompletenessComplete
	trace := make([]AvailabilityReason, 0, 28)
	trace = append(trace,
		holdReason(AvailabilityReasonCodeObservationSetComplete, complete, boolToUint64(complete), 1),
		holdReason(AvailabilityReasonCodeReplicaObservationsUnique, duplicateCount == 0, uint64(duplicateCount), 0),
		holdReason(AvailabilityReasonCodeReplicaObservationsConsistent, conflictCount == 0, uint64(conflictCount), 0),
		holdReason(AvailabilityReasonCodeReplicaIdentitiesComplete, missingIdentityCount == 0, uint64(missingIdentityCount), 0),
		holdReason(AvailabilityReasonCodeServiceIdentityConsistent, wrongServiceCount == 0, uint64(wrongServiceCount), 0),
	)

	generationTrace := []AvailabilityReason{
		holdReason(AvailabilityReasonCodeObservationGenerationNotRollback,
			request.ObservationGeneration.Value >= request.CurrentAcceptedObservationGeneration.Value,
			request.ObservationGeneration.Value, request.CurrentAcceptedObservationGeneration.Value),
		holdReason(AvailabilityReasonCodeObservationGenerationNotFuture,
			request.ObservationGeneration.Value <= request.CurrentAcceptedObservationGeneration.Value,
			request.ObservationGeneration.Value, request.CurrentAcceptedObservationGeneration.Value),
	}

	held := false
	for _, reason := range trace {
		if reason.Outcome == AvailabilityReasonOutcomeHeld {
			held = true
			break
		}
	}
	if !held {
		for _, reason := range generationTrace {
			if reason.Outcome == AvailabilityReasonOutcomeHeld {
				held = true
				break
			}
		}
	}

	unique := make([]ReplicaObservation, 0, len(groupOrder))
	for _, key := range groupOrder {
		unique = append(unique, groups[key][0])
	}

	targetReason, targetValid := evaluateTarget(request.Change, unique, held)
	trace = append(trace, targetReason)

	if held || !targetValid {
		unavailableOutcome := AvailabilityReasonOutcomeNotApplicable
		if held {
			unavailableOutcome = AvailabilityReasonOutcomeHeld
		}
		addUnavailablePolicyTrace(&trace, unavailableOutcome)
		return availabilityDecision(request, trace, generationTrace)
	}

	var available []ReplicaObservation
	disrupting := 0
	for _, observation := range unique {
		switch observation.State {
		case ReplicaAvailabilityStateAvailable:
			available = append(available, observation)
		case ReplicaAvailabilityStateDisrupting:
			disrupting++
		}
	}
	projectedAvailable := NewAvailabilityCount(uint64(len(available)))
	projectedDisrupting := NewAvailabilityCount(uint64(disrupting))
	projectedReplicaCount := NewAvailabilityCount(uint64(len(unique)))
	availableTopologyReplicas := available
	antiAffinityReplicas := unique

	switch change := request.Change.(type) {
	case PlaceReplicaChange:
		projectedReplicaCount = mustAdd(projectedReplicaCount, NewAvailabilityCount(1))
		projectedAvailable = mustAdd(projectedAvailable, NewAvailabilityCount(1))
		planned, _ := NewReplicaObservation(
			change.ReplicaId,
			request.Policy.ServiceId,
			&change.TargetNodeId,
			&change.TargetFailureDomainId,
			ReplicaAvailabilityStateAvailable)
		availableTopologyReplicas = append(append([]ReplicaObservation{}, available...), planned)
		antiAffinityReplicas = append(append([]ReplicaObservation{}, unique...), planned)
	case MaintainReplicaChange:
		var affected ReplicaObservation
		for _, observation := range unique {
			if observation.ReplicaId == change.ReplicaId {
				affected = observation
			}
		}
		if affected.State == ReplicaAvailabilityStateAvailable {
			projectedAvailable = mustSubtract(projectedAvailable, NewAvailabilityCount(1))
			projectedDisrupting = mustAdd(projectedDisrupting, NewAvailabilityCount(1))
		}
		availableTopologyReplicas = filterReplicaObservations(availableTopologyReplicas, func(observation ReplicaObservation) bool {
			return observation.ReplicaId != change.ReplicaId
		})
	case DrainNodeChange:
		newlyDisrupted := 0
		for _, observation := range available {
			if observation.NodeId != nil && *observation.NodeId == change.NodeId {
				newlyDisrupted++
			}
		}
		projectedAvailable = mustSubtract(projectedAvailable, NewAvailabilityCount(uint64(newlyDisrupted)))
		projectedDisrupting = mustAdd(projectedDisrupting, NewAvailabilityCount(uint64(newlyDisrupted)))
		availableTopologyReplicas = filterReplicaObservations(availableTopologyReplicas, func(observation ReplicaObservation) bool {
			return observation.NodeId == nil || *observation.NodeId != change.NodeId
		})
		antiAffinityReplicas = filterReplicaObservations(antiAffinityReplicas, func(observation ReplicaObservation) bool {
			return observation.NodeId == nil || *observation.NodeId != change.NodeId
		})
	}

	trace = append(trace,
		rejectReason(AvailabilityReasonCodeDesiredCount,
			projectedReplicaCount.Value <= request.Policy.Desired.Value,
			projectedReplicaCount.Value, request.Policy.Desired.Value),
		rejectReason(AvailabilityReasonCodeMinimumAvailable,
			projectedAvailable.Value >= request.Policy.MinimumAvailable.Value,
			projectedAvailable.Value, request.Policy.MinimumAvailable.Value),
		rejectReason(AvailabilityReasonCodeQuorum,
			projectedAvailable.Value >= request.Policy.Quorum.Value,
			projectedAvailable.Value, request.Policy.Quorum.Value),
		rejectReason(AvailabilityReasonCodeDisruptionBudget,
			projectedDisrupting.Value <= request.Policy.MaximumConcurrentDisruptions.Value,
			projectedDisrupting.Value, request.Policy.MaximumConcurrentDisruptions.Value),
	)

	hostCounts := make(map[string]int)
	for _, observation := range antiAffinityReplicas {
		if observation.NodeId != nil {
			hostCounts[observation.NodeId.Value]++
		}
	}
	colocated := 0
	for _, count := range hostCounts {
		if count > 1 {
			colocated += count - 1
		}
	}
	if request.Policy.OnePerHost {
		trace = append(trace, rejectReason(AvailabilityReasonCodeOnePerHost,
			colocated == 0, uint64(colocated), 0))
	} else {
		trace = append(trace, notApplicable(AvailabilityReasonCodeOnePerHost))
	}

	distinctDomains := make(map[string]struct{})
	for _, observation := range availableTopologyReplicas {
		if observation.FailureDomainId != nil {
			distinctDomains[observation.FailureDomainId.Value] = struct{}{}
		}
	}
	trace = append(trace, rejectReason(AvailabilityReasonCodeFailureDomainSpread,
		uint64(len(distinctDomains)) >= request.Policy.RequiredDistinctFailureDomains.Value,
		uint64(len(distinctDomains)), request.Policy.RequiredDistinctFailureDomains.Value))

	addResourceTrace(&trace, request.Change, &request.Policy)
	return availabilityDecision(request, trace, generationTrace)
}

func evaluateTarget(change AvailabilityChange, observations []ReplicaObservation, held bool) (AvailabilityReason, bool) {
	if held {
		reason := newAvailabilityReason(AvailabilityReasonCodeChangeTargetValid, AvailabilityReasonOutcomeHeld, 0, 1)
		return reason, false
	}

	switch typed := change.(type) {
	case PlaceReplicaChange:
		any := false
		for _, observation := range observations {
			if observation.ReplicaId == typed.ReplicaId {
				any = true
				break
			}
		}
		observed := uint64(1)
		if any {
			observed = 0
		}
		reason := rejectReason(AvailabilityReasonCodeChangeTargetValid, !any, observed, 1)
		return reason, !any
	case MaintainReplicaChange:
		var matches []ReplicaObservation
		for _, observation := range observations {
			if observation.ReplicaId == typed.ReplicaId {
				matches = append(matches, observation)
			}
		}
		valid := len(matches) == 1 && matches[0].State == ReplicaAvailabilityStateAvailable
		observed := uint64(0)
		if valid {
			observed = 1
		}
		reason := rejectReason(AvailabilityReasonCodeChangeTargetValid, valid, observed, 1)
		return reason, valid
	case DrainNodeChange:
		count := 0
		for _, observation := range observations {
			if observation.NodeId != nil && *observation.NodeId == typed.NodeId {
				count++
			}
		}
		reason := rejectReason(AvailabilityReasonCodeChangeTargetValid, count > 0, uint64(count), 1)
		return reason, count > 0
	default:
		panic("change out of range")
	}
}

func addResourceTrace(trace *[]AvailabilityReason, change AvailabilityChange, policy *ServiceAvailabilityPolicy) {
	placement, isPlacement := change.(PlaceReplicaChange)
	if !isPlacement {
		for _, code := range reserveReasonCodes {
			*trace = append(*trace, notApplicable(code))
		}
		for _, code := range capacityReasonCodes {
			*trace = append(*trace, notApplicable(code))
		}
		return
	}

	available := placement.AvailableResources.orderedValues()
	requested := placement.RequestedResources.orderedValues()
	reserve := policy.Reserve.orderedValues()

	if policy.ReserveDisposition == ReserveDispositionMayConsume {
		for _, code := range reserveReasonCodes {
			*trace = append(*trace, notApplicable(code))
		}
	} else {
		for index := range available {
			canSubtract := available[index].Value >= requested[index].Value
			remaining := int64(0)
			if canSubtract {
				remaining = available[index].Value - requested[index].Value
			}
			passes := canSubtract && remaining >= reserve[index].Value
			*trace = append(*trace, rejectReason(reserveReasonCodes[index], passes,
				uint64(remaining), uint64(reserve[index].Value)))
		}
	}

	for index := range available {
		*trace = append(*trace, rejectReason(capacityReasonCodes[index],
			available[index].Value >= requested[index].Value,
			uint64(available[index].Value), uint64(requested[index].Value)))
	}
}

func addUnavailablePolicyTrace(trace *[]AvailabilityReason, outcome AvailabilityReasonOutcome) {
	for _, code := range policyReasonCodes {
		*trace = append(*trace, newAvailabilityReason(code, outcome, 0, 0))
	}
}

func availabilityDecision(
	request *AvailabilityEvaluationRequest,
	trace []AvailabilityReason,
	generationTrace []AvailabilityReason,
) AvailabilityDecision {
	trace = append(trace, generationTrace...)
	admitted := true
	for _, reason := range trace {
		if reason.Outcome != AvailabilityReasonOutcomePassed && reason.Outcome != AvailabilityReasonOutcomeNotApplicable {
			admitted = false
			break
		}
	}
	if admitted {
		return AvailabilityDecision{AcceptedRequest: request, Trace: trace}
	}
	return AvailabilityDecision{AcceptedRequest: nil, Trace: trace}
}

func holdReason(code AvailabilityReasonCode, passes bool, observed, required uint64) AvailabilityReason {
	outcome := AvailabilityReasonOutcomeHeld
	if passes {
		outcome = AvailabilityReasonOutcomePassed
	}
	return newAvailabilityReason(code, outcome, observed, required)
}

func rejectReason(code AvailabilityReasonCode, passes bool, observed, required uint64) AvailabilityReason {
	outcome := AvailabilityReasonOutcomeRejected
	if passes {
		outcome = AvailabilityReasonOutcomePassed
	}
	return newAvailabilityReason(code, outcome, observed, required)
}

func notApplicable(code AvailabilityReasonCode) AvailabilityReason {
	return newAvailabilityReason(code, AvailabilityReasonOutcomeNotApplicable, 0, 0)
}

func boolToUint64(value bool) uint64 {
	if value {
		return 1
	}
	return 0
}

func filterReplicaObservations(values []ReplicaObservation, keep func(ReplicaObservation) bool) []ReplicaObservation {
	filtered := make([]ReplicaObservation, 0, len(values))
	for _, value := range values {
		if keep(value) {
			filtered = append(filtered, value)
		}
	}
	return filtered
}

func mustAdd(left, right AvailabilityCount) AvailabilityCount {
	sum, err := left.AddChecked(right)
	if err != nil {
		panic(err)
	}
	return sum
}

func mustSubtract(left, right AvailabilityCount) AvailabilityCount {
	difference, err := left.SubtractChecked(right)
	if err != nil {
		panic(err)
	}
	return difference
}

var reserveReasonCodes = []AvailabilityReasonCode{
	AvailabilityReasonCodeReserveCpu,
	AvailabilityReasonCodeReserveMemory,
	AvailabilityReasonCodeReserveBlockIo,
	AvailabilityReasonCodeReserveEphemeralDisk,
	AvailabilityReasonCodeReserveBandwidth,
	AvailabilityReasonCodeReservePids,
	AvailabilityReasonCodeReserveFileDescriptors,
	AvailabilityReasonCodeReserveHugePages,
}

var capacityReasonCodes = []AvailabilityReasonCode{
	AvailabilityReasonCodeCapacityCpu,
	AvailabilityReasonCodeCapacityMemory,
	AvailabilityReasonCodeCapacityBlockIo,
	AvailabilityReasonCodeCapacityEphemeralDisk,
	AvailabilityReasonCodeCapacityBandwidth,
	AvailabilityReasonCodeCapacityPids,
	AvailabilityReasonCodeCapacityFileDescriptors,
	AvailabilityReasonCodeCapacityHugePages,
}

var policyReasonCodes = append(append([]AvailabilityReasonCode{
	AvailabilityReasonCodeDesiredCount,
	AvailabilityReasonCodeMinimumAvailable,
	AvailabilityReasonCodeQuorum,
	AvailabilityReasonCodeDisruptionBudget,
	AvailabilityReasonCodeOnePerHost,
	AvailabilityReasonCodeFailureDomainSpread,
}, reserveReasonCodes...), capacityReasonCodes...)
