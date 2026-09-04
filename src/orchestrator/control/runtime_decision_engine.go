package control

import (
	"terrascale.tech/orchestrator/src/orchestrator/control/internal/shared"
)

var RuntimeDecisionEngine runtimeDecisionEngine

type runtimeDecisionEngine struct{}

func (runtimeDecisionEngine) EvaluateLifecycle(request *RuntimeLifecycleRequest) (*RuntimeDecision, error) {
	if request == nil {
		return nil, shared.ArgumentNil("request")
	}
	var trace []RuntimeDecisionReason
	healthGroups := make(map[HealthDimension][]RuntimeHealthEvidence)
	for _, health := range request.Health {
		healthGroups[health.Dimension] = append(healthGroups[health.Dimension], health)
	}
	duplicates := 0
	for _, group := range healthGroups {
		if len(group) > 1 {
			duplicates += len(group) - 1
		}
	}
	conflicts := 0
	for _, group := range healthGroups {
		distinct := map[RuntimeHealthEvidence]struct{}{}
		for _, health := range group {
			distinct[health] = struct{}{}
		}
		if len(distinct) >= 2 {
			conflicts++
		}
	}
	trace = append(trace, runtimeDecisionHold(RuntimeDecisionCodeEvidenceUnique, duplicates == 0, uint64(duplicates), 0))
	trace = append(trace, runtimeDecisionHold(RuntimeDecisionCodeEvidenceConsistent, conflicts == 0, uint64(conflicts), 0))
	if runtimeTraceAnyHeld(trace) {
		return runtimeDecisionDeny(request.OperationId, trace), nil
	}

	observation := request.Observation
	operationExact := observation.OperationId == request.OperationId &&
		observation.AllocationId == request.Spec.AllocationId
	trace = append(trace, runtimeDecisionReject(RuntimeDecisionCodeOperationExact, operationExact,
		boolToU64(operationExact), 1))
	epochExact := request.Epoch == request.CurrentEpoch && observation.Epoch == request.Epoch
	if observation.Epoch.Value > request.CurrentEpoch.Value {
		trace = append(trace, runtimeDecisionHold(RuntimeDecisionCodeEpochCurrent, false,
			observation.Epoch.Value, request.CurrentEpoch.Value))
	} else {
		trace = append(trace, runtimeDecisionReject(RuntimeDecisionCodeEpochCurrent, epochExact,
			observation.Epoch.Value, request.CurrentEpoch.Value))
	}
	generation := request.Spec.Generation == request.CurrentGeneration &&
		observation.Generation == request.Spec.Generation
	if observation.Generation.Value > request.CurrentGeneration.Value {
		trace = append(trace, runtimeDecisionHold(RuntimeDecisionCodeGenerationCurrent, false,
			observation.Generation.Value, request.CurrentGeneration.Value))
	} else {
		trace = append(trace, runtimeDecisionReject(RuntimeDecisionCodeGenerationCurrent, generation,
			observation.Generation.Value, request.CurrentGeneration.Value))
	}
	admission := request.Admission.Role == request.Spec.Role &&
		request.Admission.Driver == request.Spec.Payload.Driver() &&
		request.Admission.Architecture == request.Spec.Payload.PayloadArchitecture() &&
		request.Admission.PolicyGeneration == request.AdmissionPolicyGeneration &&
		runtimeDescriptorMatches(request.Spec)
	trace = append(trace, runtimeDecisionReject(RuntimeDecisionCodeAdmissionExact, admission,
		boolToU64(admission), 1))
	architectureExact := request.Admission.Architecture == request.Spec.Payload.PayloadArchitecture()
	trace = append(trace, runtimeDecisionReject(RuntimeDecisionCodeArchitectureExact, architectureExact,
		boolToU64(architectureExact), 1))
	artifactExact := observation.ArtifactDigest == request.Spec.Payload.ActivationDigest()
	trace = append(trace, runtimeDecisionReject(RuntimeDecisionCodeArtifactExact, artifactExact,
		boolToU64(artifactExact), 1))
	safetyAction := request.Action == LifecycleActionDrain || request.Action == LifecycleActionStop ||
		request.Action == LifecycleActionCleanup
	inventoryExact := request.Inventory.OperationId == request.OperationId &&
		request.Inventory.NodeId == request.Spec.NodeId &&
		request.Inventory.Generation == request.CurrentGeneration
	if safetyAction {
		trace = append(trace, runtimeDecisionNotApplicable(RuntimeDecisionCodeEvidenceComplete))
	} else if !inventoryExact {
		trace = append(trace, runtimeDecisionReject(RuntimeDecisionCodeEvidenceComplete, false, 0, 1))
	} else {
		complete := request.Inventory.Completeness == EvidenceCompletenessComplete
		trace = append(trace, runtimeDecisionHold(RuntimeDecisionCodeEvidenceComplete, complete,
			boolToU64(complete), 1))
	}
	var sameNode []RuntimeConflictEvidence
	for _, conflict := range request.Inventory.Allocations {
		if conflict.NodeId == request.Spec.NodeId && conflict.AllocationId != request.Spec.AllocationId {
			sameNode = append(sameNode, conflict)
		}
	}
	portConflicts := 0
	for _, conflict := range sameNode {
		for _, port := range conflict.Ports {
			for _, specPort := range request.Spec.Ports {
				if specPort == port {
					portConflicts++
					break
				}
			}
		}
	}
	volumeConflicts := 0
	for _, conflict := range sameNode {
		for _, volume := range conflict.Volumes {
			for _, binding := range request.Spec.Volumes {
				if binding.VolumeId == volume {
					volumeConflicts++
					break
				}
			}
		}
	}
	if safetyAction {
		trace = append(trace, runtimeDecisionNotApplicable(RuntimeDecisionCodePortConflictFree))
	} else {
		trace = append(trace, runtimeDecisionReject(RuntimeDecisionCodePortConflictFree, portConflicts == 0,
			uint64(portConflicts), 0))
	}
	if safetyAction {
		trace = append(trace, runtimeDecisionNotApplicable(RuntimeDecisionCodeVolumeConflictFree))
	} else {
		trace = append(trace, runtimeDecisionReject(RuntimeDecisionCodeVolumeConflictFree, volumeConflicts == 0,
			uint64(volumeConflicts), 0))
	}
	healthExact := true
	for _, health := range request.Health {
		if health.OperationId != request.OperationId || health.AllocationId != request.Spec.AllocationId ||
			health.Generation != request.Spec.Generation {
			healthExact = false
			break
		}
	}
	if safetyAction {
		trace = append(trace, runtimeDecisionNotApplicable(RuntimeDecisionCodeHealthExact))
	} else {
		healthCount := uint64(len(request.Health))
		trace = append(trace, runtimeDecisionReject(RuntimeDecisionCodeHealthExact, healthExact,
			boolToU64(healthExact)*healthCount, healthCount))
	}
	readiness := true
	for _, required := range request.Spec.RequiredHealth {
		found := false
		for _, health := range request.Health {
			if health.Dimension == required && health.Status == HealthStatusReady {
				found = true
				break
			}
		}
		if !found {
			readiness = false
			break
		}
	}
	requiresReadiness := request.Action == LifecycleActionConverge &&
		(observation.Phase == LifecyclePhaseStarted || observation.Phase == LifecyclePhaseServing)
	if requiresReadiness {
		requiredCount := uint64(len(request.Spec.RequiredHealth))
		anyFailed := false
		for _, health := range request.Health {
			if health.Status == HealthStatusFailed {
				anyFailed = true
				break
			}
		}
		if anyFailed {
			trace = append(trace, runtimeDecisionReject(RuntimeDecisionCodeReadinessComplete, false, 0, requiredCount))
		} else {
			trace = append(trace, runtimeDecisionHold(RuntimeDecisionCodeReadinessComplete, readiness,
				boolToU64(readiness)*requiredCount, requiredCount))
		}
	} else {
		trace = append(trace, runtimeDecisionNotApplicable(RuntimeDecisionCodeReadinessComplete))
	}
	processConsistent := runtimeProcessConsistent(request.Action, observation.Phase, observation.ProcessStatus)
	trace = append(trace, runtimeDecisionReject(RuntimeDecisionCodeProcessConsistent, processConsistent,
		boolToU64(processConsistent), 1))
	callSafe := observation.CallStatus == ExecutorCallStatusNotCalled || observation.CallStatus == ExecutorCallStatusCompleted
	if callSafe {
		trace = append(trace, runtimeDecisionPass(RuntimeDecisionCodeCallSafe))
	} else {
		trace = append(trace, runtimeDecisionHold(RuntimeDecisionCodeCallSafe, false, 0, 1))
	}

	if runtimeTraceAnyRejected(trace) {
		return runtimeDecisionDeny(request.OperationId, trace), nil
	}
	if !callSafe {
		return runtimeDecision(true, trace, NewObserveExecutorIntent(request)), nil
	}
	if runtimeTraceAnyHeld(trace) {
		var held []RuntimeDecisionReason
		for _, reason := range trace {
			if reason.Outcome == RuntimeDecisionOutcomeHeld {
				held = append(held, reason)
			}
		}
		if request.Action == LifecycleActionConverge &&
			(observation.Phase == LifecyclePhaseStarted || observation.Phase == LifecyclePhaseServing) &&
			len(held) == 1 && held[0].Code == RuntimeDecisionCodeReadinessComplete {
			return runtimeDecision(true, trace, NewCheckRuntimeHealthIntent(request)), nil
		}
		return runtimeDecisionDeny(request.OperationId, trace), nil
	}

	var intent RuntimeIntent
	switch request.Action {
	case LifecycleActionConverge:
		switch observation.Phase {
		case LifecyclePhaseNone:
			intent = NewFetchRuntimeArtifactIntent(request)
		case LifecyclePhaseArtifactFetched:
			intent = NewVerifyRuntimeArtifactIntent(request)
		case LifecyclePhaseArtifactVerified:
			intent = NewStageRuntimeIntent(request)
		case LifecyclePhaseStaged:
			intent = NewMountRuntimeIntent(request)
		case LifecyclePhaseMounted:
			intent = NewStartRuntimeIntent(request)
		case LifecyclePhaseStarted, LifecyclePhaseServing:
			intent = NewCheckRuntimeHealthIntent(request)
		default:
			intent = NewHoldRuntimeIntent(request.OperationId)
		}
	case LifecycleActionDrain:
		if observation.Phase == LifecyclePhaseServing {
			intent = NewDrainRuntimeIntent(request)
		} else {
			intent = NewHoldRuntimeIntent(request.OperationId)
		}
	case LifecycleActionStop:
		if observation.Phase == LifecyclePhaseStarted || observation.Phase == LifecyclePhaseServing ||
			observation.Phase == LifecyclePhaseDraining {
			intent = NewStopRuntimeIntent(request)
		} else {
			intent = NewHoldRuntimeIntent(request.OperationId)
		}
	case LifecycleActionCleanup:
		if observation.Phase == LifecyclePhaseStopped {
			intent = NewCleanupRuntimeIntent(request)
		} else {
			intent = NewHoldRuntimeIntent(request.OperationId)
		}
	default:
		intent = NewHoldRuntimeIntent(request.OperationId)
	}
	if _, isHold := intent.(*HoldRuntimeIntent); isHold {
		return runtimeDecision(false, trace, intent), nil
	}
	return runtimeDecision(true, trace, intent), nil
}

func runtimeProcessConsistent(action LifecycleAction, phase LifecyclePhase, status ProcessStatus) bool {
	if action == LifecycleActionStop &&
		(phase == LifecyclePhaseStarted || phase == LifecyclePhaseServing || phase == LifecyclePhaseDraining) {
		return status == ProcessStatusRunning || status == ProcessStatusFailed
	}
	switch phase {
	case LifecyclePhaseNone, LifecyclePhaseArtifactFetched, LifecyclePhaseArtifactVerified,
		LifecyclePhaseStaged, LifecyclePhaseMounted:
		return status == ProcessStatusAbsent
	case LifecyclePhaseStarted, LifecyclePhaseServing, LifecyclePhaseDraining:
		return status == ProcessStatusRunning
	case LifecyclePhaseStopped:
		return status == ProcessStatusAbsent || status == ProcessStatusExitedSuccessfully || status == ProcessStatusFailed
	case LifecyclePhaseCleaned:
		return status == ProcessStatusAbsent
	default:
		return false
	}
}

func (runtimeDecisionEngine) EvaluateSelfUpdate(request *SelfUpdateRequest) (*RuntimeDecision, error) {
	if request == nil {
		return nil, shared.ArgumentNil("request")
	}
	var trace []RuntimeDecisionReason
	observation := request.Observation
	operation := observation.OperationId == request.OperationId && observation.NodeId == request.NodeId &&
		observation.TargetGeneration == request.TargetGeneration
	trace = append(trace, runtimeDecisionReject(RuntimeDecisionCodeOperationExact, operation,
		boolToU64(operation), 1))
	trace = append(trace, runtimeDecisionReject(RuntimeDecisionCodeEpochCurrent,
		request.Epoch == request.CurrentEpoch && observation.Epoch == request.Epoch,
		observation.Epoch.Value, request.CurrentEpoch.Value))
	next := request.CurrentGeneration.Value < ^uint64(0) &&
		request.TargetGeneration.Value == request.CurrentGeneration.Value+1
	trace = append(trace, runtimeDecisionReject(RuntimeDecisionCodeGenerationCurrent, next,
		request.TargetGeneration.Value, request.CurrentGeneration.Value))
	slotDistinct := observation.ActiveSlot != observation.InactiveSlot &&
		observation.ActiveSlot == request.ExpectedActiveSlot &&
		observation.InactiveSlot == request.ExpectedInactiveSlot
	trace = append(trace, runtimeDecisionReject(RuntimeDecisionCodeSlotDistinct, slotDistinct,
		boolToU64(slotDistinct), 1))
	forwardExact := runtimeArtifactMatches(request.ExpectedForwardArtifact, request.ForwardArtifact) &&
		request.ExpectedForwardArtifact.Generation == request.TargetGeneration &&
		request.ExpectedForwardArtifact.Architecture == request.Architecture &&
		request.ForwardArtifact.Verification == ArtifactVerificationStatusVerified
	trace = append(trace, runtimeDecisionReject(RuntimeDecisionCodeArtifactExact, forwardExact,
		boolToU64(forwardExact), 1))
	if request.ForwardArtifact.Availability == ArtifactAvailabilityAvailable {
		trace = append(trace, runtimeDecisionPass(RuntimeDecisionCodeForwardAvailable))
	} else {
		trace = append(trace, runtimeDecisionHold(RuntimeDecisionCodeForwardAvailable, false, 0, 1))
	}
	rollback := runtimeArtifactMatches(request.ExpectedRollbackArtifact, request.RollbackArtifact) &&
		request.ExpectedRollbackArtifact.Generation == request.CurrentGeneration &&
		request.ExpectedRollbackArtifact.Architecture == request.Architecture &&
		request.RollbackArtifact.Availability == ArtifactAvailabilityAvailable &&
		request.RollbackArtifact.Verification == ArtifactVerificationStatusVerified
	if rollback {
		trace = append(trace, runtimeDecisionPass(RuntimeDecisionCodeRollbackAvailable))
	} else {
		trace = append(trace, runtimeDecisionHold(RuntimeDecisionCodeRollbackAvailable, false, 0, 1))
	}
	compatibilityScopeExact := request.Compatibility.OperationId == request.OperationId &&
		request.Compatibility.CurrentGeneration == request.CurrentGeneration &&
		request.Compatibility.TargetGeneration == request.TargetGeneration &&
		request.Compatibility.ProtocolGeneration == request.CurrentProtocolGeneration &&
		request.Compatibility.SchemaGeneration == request.CurrentSchemaGeneration
	compatibility := compatibilityScopeExact &&
		request.Compatibility.NToNMinusOne == CompatibilityStatusCompatible &&
		request.Compatibility.Status == CompatibilityStatusCompatible
	trace = append(trace, runtimeDecisionReject(RuntimeDecisionCodeCompatibilityExact, compatibility,
		boolToU64(compatibility), 1))

	healthUnique := true
	healthSeen := map[HealthDimension]int{}
	for _, health := range request.Health {
		healthSeen[health.Dimension]++
		if healthSeen[health.Dimension] > 1 {
			healthUnique = false
		}
	}
	trace = append(trace, runtimeDecisionHold(RuntimeDecisionCodeEvidenceUnique, healthUnique,
		boolToU64(!healthUnique), 0))
	expectedHealthGeneration := request.TargetGeneration
	if observation.Phase == UpdatePhaseRolledBack {
		expectedHealthGeneration = request.CurrentGeneration
	}
	healthExact := true
	for _, health := range request.Health {
		if health.OperationId != request.OperationId || health.AllocationId != request.AllocationId ||
			health.Generation != expectedHealthGeneration {
			healthExact = false
			break
		}
	}
	healthCount := uint64(len(request.Health))
	trace = append(trace, runtimeDecisionReject(RuntimeDecisionCodeHealthExact, healthExact,
		boolToU64(healthExact)*healthCount, healthCount))
	requiresNewHealth := observation.Phase == UpdatePhaseLocalHealthVerified ||
		observation.Phase == UpdatePhaseRegionalCompatibilityVerified ||
		observation.Phase == UpdatePhaseSlotCommitted ||
		observation.Phase == UpdatePhaseOldSlotRetainedUntilSoak
	requiresRollbackHealth := observation.Phase == UpdatePhaseRolledBack
	requiredHealthReady := len(request.Health) > 0 &&
		runtimeReadyForDimension(request, HealthDimensionLiveness) &&
		runtimeReadyForDimension(request, HealthDimensionLocalReadiness) &&
		runtimeReadyForDimension(request, HealthDimensionDependencyReadiness)
	requiredHealthFailed := false
	for _, health := range request.Health {
		if (health.Dimension == HealthDimensionLiveness || health.Dimension == HealthDimensionLocalReadiness ||
			health.Dimension == HealthDimensionDependencyReadiness) && health.Status == HealthStatusFailed {
			requiredHealthFailed = true
			break
		}
	}
	if requiresNewHealth || requiresRollbackHealth {
		if requiredHealthFailed {
			trace = append(trace, runtimeDecisionReject(RuntimeDecisionCodeReadinessComplete, false, 0, 3))
		} else {
			trace = append(trace, runtimeDecisionHold(RuntimeDecisionCodeReadinessComplete,
				requiredHealthReady, boolToU64(requiredHealthReady)*3, 3))
		}
	} else {
		trace = append(trace, runtimeDecisionNotApplicable(RuntimeDecisionCodeReadinessComplete))
	}
	callSafe := observation.CallStatus == ExecutorCallStatusNotCalled || observation.CallStatus == ExecutorCallStatusCompleted
	if callSafe {
		trace = append(trace, runtimeDecisionPass(RuntimeDecisionCodeCallSafe))
	} else {
		trace = append(trace, runtimeDecisionHold(RuntimeDecisionCodeCallSafe, false, 0, 1))
	}
	if observation.Phase == UpdatePhaseRollbackFailed {
		trace = append(trace, runtimeDecisionReject(RuntimeDecisionCodeRollbackPossible, false, 0, 1))
	} else if rollback {
		trace = append(trace, runtimeDecisionPass(RuntimeDecisionCodeRollbackPossible))
	} else {
		trace = append(trace, runtimeDecisionHold(RuntimeDecisionCodeRollbackPossible, false, 0, 1))
	}

	requiresCompatibilityRecovery := observation.Phase == UpdatePhaseLocalHealthVerified ||
		observation.Phase == UpdatePhaseRegionalCompatibilityVerified ||
		observation.Phase == UpdatePhaseSlotCommitted ||
		observation.Phase == UpdatePhaseOldSlotRetainedUntilSoak
	compatibilityFailed := compatibilityScopeExact &&
		(request.Compatibility.NToNMinusOne == CompatibilityStatusIncompatible ||
			request.Compatibility.Status == CompatibilityStatusIncompatible)
	recoverableFailure := (requiresNewHealth && healthExact && requiredHealthFailed) ||
		(requiresCompatibilityRecovery && compatibilityFailed)
	soakPhase := observation.Phase == UpdatePhaseOldSlotRetainedUntilSoak
	if soakPhase && recoverableFailure {
		trace = append(trace, runtimeDecisionNotApplicable(RuntimeDecisionCodeSoakComplete))
	} else if !soakPhase {
		if request.Soak == nil {
			trace = append(trace, runtimeDecisionNotApplicable(RuntimeDecisionCodeSoakComplete))
		} else {
			trace = append(trace, runtimeDecisionReject(RuntimeDecisionCodeSoakComplete, false,
				request.Soak.ObservedDuration.Value, 0))
		}
	} else if request.Soak == nil {
		trace = append(trace, runtimeDecisionHold(RuntimeDecisionCodeSoakComplete, false, 0, request.SoakDuration.Value))
	} else {
		soakScopeExact := request.Soak.OperationId == request.OperationId &&
			request.Soak.NodeId == request.NodeId &&
			request.Soak.AllocationId == request.AllocationId &&
			request.Soak.Epoch == request.Epoch &&
			request.Soak.TargetGeneration == request.TargetGeneration &&
			request.Soak.ActiveSlot == observation.ActiveSlot
		if !soakScopeExact {
			trace = append(trace, runtimeDecisionReject(RuntimeDecisionCodeSoakComplete, false,
				request.Soak.ObservedDuration.Value, request.SoakDuration.Value))
		} else {
			trace = append(trace, runtimeDecisionHold(RuntimeDecisionCodeSoakComplete,
				request.Soak.ObservedDuration.Value >= request.SoakDuration.Value,
				request.Soak.ObservedDuration.Value, request.SoakDuration.Value))
		}
	}
	hardRejected := false
	for _, reason := range trace {
		if reason.Outcome == RuntimeDecisionOutcomeRejected &&
			reason.Code != RuntimeDecisionCodeReadinessComplete &&
			!(reason.Code == RuntimeDecisionCodeCompatibilityExact && requiresCompatibilityRecovery && compatibilityFailed) {
			hardRejected = true
			break
		}
	}
	anyRejected := runtimeTraceAnyRejected(trace)
	if hardRejected || (anyRejected && !recoverableFailure) {
		return runtimeDecisionDeny(request.OperationId, trace), nil
	}
	if !callSafe {
		return runtimeDecision(true, trace, NewObserveUpdateIntent(request)), nil
	}
	if runtimeTraceAnyHeld(trace) {
		return runtimeDecisionDeny(request.OperationId, trace), nil
	}
	if requiresNewHealth && healthExact && requiredHealthFailed {
		return runtimeDecision(true, trace, NewRollbackUpdateIntent(request)), nil
	}
	if requiresCompatibilityRecovery && compatibilityFailed {
		return runtimeDecision(true, trace, NewRollbackUpdateIntent(request)), nil
	}

	localReady := runtimeReadyForDimension(request, HealthDimensionLiveness) &&
		runtimeReadyForDimension(request, HealthDimensionLocalReadiness) &&
		runtimeReadyForDimension(request, HealthDimensionDependencyReadiness)
	localFailed := false
	for _, health := range request.Health {
		if (health.Dimension == HealthDimensionLiveness || health.Dimension == HealthDimensionLocalReadiness ||
			health.Dimension == HealthDimensionDependencyReadiness) && health.Status == HealthStatusFailed {
			localFailed = true
			break
		}
	}
	var intent RuntimeIntent
	switch observation.Phase {
	case UpdatePhaseUpgradePlanned:
		intent = NewVerifyUpdateArtifactIntent(request)
	case UpdatePhaseArtifactVerified:
		intent = NewStageInactiveSlotIntent(request)
	case UpdatePhaseInactiveSlotStaged:
		intent = NewArmRollbackIntent(request)
	case UpdatePhaseRollbackTimerArmed:
		intent = NewSwitchUpdateSlotIntent(request)
	case UpdatePhaseProcessRestarted:
		if localFailed {
			intent = NewRollbackUpdateIntent(request)
		} else {
			intent = NewCheckRuntimeHealthIntentFromSelfUpdate(request)
		}
	case UpdatePhaseLocalHealthVerified:
		intent = NewVerifyRegionalCompatibilityIntent(request)
	case UpdatePhaseRegionalCompatibilityVerified:
		intent = NewCommitUpdateSlotIntent(request)
	case UpdatePhaseSlotCommitted:
		intent = NewRetainOldUpdateSlotIntent(request)
	case UpdatePhaseOldSlotRetainedUntilSoak:
		intent = NewCompleteSelfUpdateIntent(request)
	case UpdatePhaseRollingBack:
		intent = NewObserveUpdateIntent(request)
	case UpdatePhaseRolledBack:
		if localReady {
			intent = NewCompleteSelfUpdateIntent(request)
		} else {
			intent = NewHoldRuntimeIntent(request.OperationId)
		}
	default:
		intent = NewHoldRuntimeIntent(request.OperationId)
	}
	if _, isHold := intent.(*HoldRuntimeIntent); isHold {
		return runtimeDecision(false, trace, intent), nil
	}
	return runtimeDecision(true, trace, intent), nil
}

func runtimeArtifactMatches(expected UpdateArtifactSubject, evidence UpdateArtifactEvidence) bool {
	return expected.ReleaseId == evidence.ReleaseId && expected.ArtifactId == evidence.ArtifactId &&
		expected.Digest == evidence.Digest && expected.SignatureId == evidence.SignatureId &&
		expected.SigningProfileId == evidence.SigningProfileId &&
		expected.Architecture == evidence.Architecture && expected.Generation == evidence.Generation
}

func runtimeDescriptorMatches(spec WorkloadRuntimeSpec) bool {
	native, isNative := spec.Payload.(NativeRuntimePayload)
	switch spec.Role {
	case RuntimeRoleOrchestrator:
		return isNative && native.Descriptor == NativeUnitDescriptorOrchestrator
	case RuntimeRoleTerraBase:
		return isNative && native.Descriptor == NativeUnitDescriptorTerraBase
	case RuntimeRoleNatsServer:
		return isNative && native.Descriptor == NativeUnitDescriptorNatsServer
	default:
		// Removed roles and every unknown value fail closed, including when a
		// caller hand-builds a WorkloadRuntimeSpec around a legacy payload.
		return false
	}
}

func runtimeReadyForDimension(r *SelfUpdateRequest, d HealthDimension) bool {
	for _, health := range r.Health {
		if health.Dimension == d && health.Status == HealthStatusReady {
			return true
		}
	}
	return false
}

func runtimeDecisionPass(c RuntimeDecisionCode) RuntimeDecisionReason {
	return RuntimeDecisionReason{Code: c, Outcome: RuntimeDecisionOutcomePassed, Observed: 1, Required: 1}
}

func runtimeDecisionHold(c RuntimeDecisionCode, pass bool, o, required uint64) RuntimeDecisionReason {
	outcome := RuntimeDecisionOutcomeHeld
	if pass {
		outcome = RuntimeDecisionOutcomePassed
	}
	return RuntimeDecisionReason{Code: c, Outcome: outcome, Observed: o, Required: required}
}

func runtimeDecisionReject(c RuntimeDecisionCode, pass bool, o, required uint64) RuntimeDecisionReason {
	outcome := RuntimeDecisionOutcomeRejected
	if pass {
		outcome = RuntimeDecisionOutcomePassed
	}
	return RuntimeDecisionReason{Code: c, Outcome: outcome, Observed: o, Required: required}
}

func runtimeDecisionNotApplicable(c RuntimeDecisionCode) RuntimeDecisionReason {
	return RuntimeDecisionReason{Code: c, Outcome: RuntimeDecisionOutcomeNotApplicable, Observed: 0, Required: 0}
}

func runtimeDecision(authorized bool, trace []RuntimeDecisionReason, intent RuntimeIntent) *RuntimeDecision {
	return &RuntimeDecision{Authorized: authorized, Trace: trace, Intent: intent}
}

func runtimeDecisionDeny(operationId RuntimeOperationId, trace []RuntimeDecisionReason) *RuntimeDecision {
	return runtimeDecision(false, trace, NewHoldRuntimeIntent(operationId))
}

func runtimeTraceAnyHeld(trace []RuntimeDecisionReason) bool {
	for _, reason := range trace {
		if reason.Outcome == RuntimeDecisionOutcomeHeld {
			return true
		}
	}
	return false
}

func runtimeTraceAnyRejected(trace []RuntimeDecisionReason) bool {
	for _, reason := range trace {
		if reason.Outcome == RuntimeDecisionOutcomeRejected {
			return true
		}
	}
	return false
}

func boolToU64(value bool) uint64 {
	if value {
		return 1
	}
	return 0
}
