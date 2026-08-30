// Port of src/TerraScale.Orchestrator/ControlPlane/Runtime/RuntimeLifecycleCoordinator.cs
package control

import (
	"context"
)

// RuntimeLifecycleCoordinator coordinates one fenced host mutation. The
// journal is the source of truth: an executor is never called before its
// dispatch is durable, and every post-dispatch path re-observes before it can
// report success.
type RuntimeLifecycleCoordinator struct {
	journal   IRuntimeLifecycleJournal
	authority IRuntimeLifecycleAuthorityGate
	executor  IRuntimeLifecycleHostExecutor
}

func NewRuntimeLifecycleCoordinator(journal IRuntimeLifecycleJournal, authority IRuntimeLifecycleAuthorityGate,
	executor IRuntimeLifecycleHostExecutor) (*RuntimeLifecycleCoordinator, error) {
	if journal == nil {
		return nil, argumentNil("journal")
	}
	if authority == nil {
		return nil, argumentNil("authority")
	}
	if executor == nil {
		return nil, argumentNil("executor")
	}
	return &RuntimeLifecycleCoordinator{journal: journal, authority: authority, executor: executor}, nil
}

func (c *RuntimeLifecycleCoordinator) ExecuteAsync(ctx context.Context,
	request RuntimeLifecycleOperationRequest) (RuntimeLifecycleResult, error) {
	for step := 0; step < RuntimeLifecycleContractMaximumCoordinatorSteps; step++ {
		loaded, err := c.loadAsync(ctx, request.OperationKey)
		if err != nil {
			return RuntimeLifecycleResult{}, err
		}
		if loaded.err != RuntimeLifecycleErrorCodeNone {
			return runtimeLifecycleResult(loaded.checkpoint, RuntimeLifecycleTerminalStatusFailed, loaded.err), nil
		}
		checkpoint := loaded.checkpoint
		if checkpoint == nil {
			if ctx.Err() != nil {
				return RuntimeLifecycleResult{}, ctx.Err()
			}
			proposed, err := RuntimeLifecycleCheckpointProposed(request)
			if err != nil {
				return RuntimeLifecycleResult{}, err
			}
			written, err := c.writeAsync(ctx, nil, proposed)
			if err != nil {
				return RuntimeLifecycleResult{}, err
			}
			if written.retry {
				continue
			}
			if written.err != RuntimeLifecycleErrorCodeNone {
				return runtimeLifecycleResult(nil, RuntimeLifecycleTerminalStatusFailed, written.err), nil
			}
			continue
		}

		if !checkpoint.Matches(request) || !runtimeLifecycleValid(*checkpoint) {
			if !checkpoint.Matches(request) {
				return runtimeLifecycleResult(checkpoint, RuntimeLifecycleTerminalStatusFailed,
					RuntimeLifecycleErrorCodeIdentityMismatch), nil
			}
			return runtimeLifecycleResult(checkpoint, RuntimeLifecycleTerminalStatusFailed,
				RuntimeLifecycleErrorCodeInvalidCheckpoint), nil
		}

		if checkpoint.Phase == RuntimeLifecyclePhaseTerminal {
			return runtimeLifecycleResult(checkpoint, checkpoint.TerminalStatus, checkpoint.ErrorCode), nil
		}

		switch checkpoint.Phase {
		case RuntimeLifecyclePhaseProposed:
			if ctx.Err() != nil {
				return RuntimeLifecycleResult{}, ctx.Err()
			}
			gate, err := c.exactAuthorityAsync(ctx, request)
			if err != nil {
				return RuntimeLifecycleResult{}, err
			}
			if gate != RuntimeLifecycleErrorCodeNone {
				return runtimeLifecycleResult(checkpoint, RuntimeLifecycleTerminalStatusFailed, gate), nil
			}
			advanced, err := c.advanceAsync(ctx, *checkpoint, RuntimeLifecyclePhaseAuthorized,
				RuntimeLifecycleCallStatusNotCalled, nil, 0, RuntimeLifecycleTerminalStatusNone,
				RuntimeLifecycleErrorCodeNone)
			if err != nil {
				return RuntimeLifecycleResult{}, err
			}
			if advanced.retry {
				continue
			}
			if advanced.err != RuntimeLifecycleErrorCodeNone {
				return runtimeLifecycleResult(checkpoint, RuntimeLifecycleTerminalStatusFailed, advanced.err), nil
			}
			continue

		case RuntimeLifecyclePhaseAuthorized:
			if ctx.Err() != nil {
				return RuntimeLifecycleResult{}, ctx.Err()
			}
			gate, err := c.exactAuthorityAsync(ctx, request)
			if err != nil {
				return RuntimeLifecycleResult{}, err
			}
			if gate != RuntimeLifecycleErrorCodeNone {
				return runtimeLifecycleResult(checkpoint, RuntimeLifecycleTerminalStatusFailed, gate), nil
			}
			advanced, err := c.advanceAsync(ctx, *checkpoint, RuntimeLifecyclePhaseDispatchPersisted,
				RuntimeLifecycleCallStatusDispatchPersisted, nil, 0, RuntimeLifecycleTerminalStatusNone,
				RuntimeLifecycleErrorCodeNone)
			if err != nil {
				return RuntimeLifecycleResult{}, err
			}
			if advanced.retry {
				continue
			}
			if advanced.err != RuntimeLifecycleErrorCodeNone {
				return runtimeLifecycleResult(checkpoint, RuntimeLifecycleTerminalStatusFailed, advanced.err), nil
			}
			continue

		case RuntimeLifecyclePhaseDispatchPersisted:
			// This state may be a crash boundary. A cancellation before an
			// actual call is still unsafe to retry.
			if ctx.Err() != nil {
				return c.markUncertainAsync(ctx, *checkpoint, RuntimeLifecycleErrorCodeCancelledAfterDispatch)
			}
			gate, err := c.exactAuthorityAsync(ctx, request)
			if err != nil {
				return RuntimeLifecycleResult{}, err
			}
			if gate != RuntimeLifecycleErrorCodeNone {
				return c.markUncertainAsync(ctx, *checkpoint, gate)
			}
			advanced, err := c.advanceAsync(ctx, *checkpoint, RuntimeLifecyclePhaseInFlight,
				RuntimeLifecycleCallStatusInFlight, nil, 0, RuntimeLifecycleTerminalStatusNone,
				RuntimeLifecycleErrorCodeNone)
			if err != nil {
				return RuntimeLifecycleResult{}, err
			}
			if advanced.retry {
				continue
			}
			if advanced.err != RuntimeLifecycleErrorCodeNone || advanced.checkpoint == nil {
				errCode := advanced.err
				if errCode == RuntimeLifecycleErrorCodeNone {
					errCode = RuntimeLifecycleErrorCodeInvalidCheckpoint
				}
				return runtimeLifecycleResult(checkpoint, RuntimeLifecycleTerminalStatusReconciliationRequired, errCode), nil
			}
			return c.callOnceAndRequireObservationAsync(ctx, request, *advanced.checkpoint)

		case RuntimeLifecyclePhaseInFlight, RuntimeLifecyclePhaseUncertain:
			return c.recoverByObservationAsync(ctx, request, *checkpoint)

		case RuntimeLifecyclePhaseObservedConverged:
			advanced, err := c.advanceAsync(ctx, *checkpoint, RuntimeLifecyclePhaseTerminal,
				RuntimeLifecycleCallStatusObserved, checkpoint.LastObservationFingerprint,
				checkpoint.LastObservationWatermark, RuntimeLifecycleTerminalStatusConverged,
				RuntimeLifecycleErrorCodeNone)
			if err != nil {
				return RuntimeLifecycleResult{}, err
			}
			if advanced.retry {
				continue
			}
			if advanced.err == RuntimeLifecycleErrorCodeNone {
				return runtimeLifecycleResult(advanced.checkpoint, RuntimeLifecycleTerminalStatusConverged,
					RuntimeLifecycleErrorCodeNone), nil
			}
			return runtimeLifecycleResult(checkpoint, RuntimeLifecycleTerminalStatusFailed, advanced.err), nil

		case RuntimeLifecyclePhaseObservedStopped:
			advanced, err := c.advanceAsync(ctx, *checkpoint, RuntimeLifecyclePhaseTerminal,
				RuntimeLifecycleCallStatusObserved, checkpoint.LastObservationFingerprint,
				checkpoint.LastObservationWatermark, RuntimeLifecycleTerminalStatusStopped,
				RuntimeLifecycleErrorCodeNone)
			if err != nil {
				return RuntimeLifecycleResult{}, err
			}
			if advanced.retry {
				continue
			}
			if advanced.err == RuntimeLifecycleErrorCodeNone {
				return runtimeLifecycleResult(advanced.checkpoint, RuntimeLifecycleTerminalStatusStopped,
					RuntimeLifecycleErrorCodeNone), nil
			}
			return runtimeLifecycleResult(checkpoint, RuntimeLifecycleTerminalStatusFailed, advanced.err), nil

		case RuntimeLifecyclePhaseFailed:
			advanced, err := c.advanceAsync(ctx, *checkpoint, RuntimeLifecyclePhaseTerminal, checkpoint.CallStatus,
				checkpoint.LastObservationFingerprint, checkpoint.LastObservationWatermark,
				RuntimeLifecycleTerminalStatusFailed, checkpoint.ErrorCode)
			if err != nil {
				return RuntimeLifecycleResult{}, err
			}
			if advanced.retry {
				continue
			}
			if advanced.err == RuntimeLifecycleErrorCodeNone {
				return runtimeLifecycleResult(advanced.checkpoint, RuntimeLifecycleTerminalStatusFailed,
					checkpoint.ErrorCode), nil
			}
			return runtimeLifecycleResult(checkpoint, RuntimeLifecycleTerminalStatusFailed, advanced.err), nil

		default:
			return runtimeLifecycleResult(checkpoint, RuntimeLifecycleTerminalStatusFailed,
				RuntimeLifecycleErrorCodeInvalidCheckpoint), nil
		}
	}
	return runtimeLifecycleResult(nil, RuntimeLifecycleTerminalStatusFailed, RuntimeLifecycleErrorCodeCasExhausted), nil
}

func (c *RuntimeLifecycleCoordinator) callOnceAndRequireObservationAsync(ctx context.Context,
	request RuntimeLifecycleOperationRequest, checkpoint RuntimeLifecycleCheckpoint) (RuntimeLifecycleResult, error) {
	response, err := c.executor.ExecuteAsync(ctx, RuntimeLifecycleExecutionRequest{
		OperationKey: checkpoint.OperationKey, DispatchToken: checkpoint.DispatchToken,
		Plan: request.Plan, Action: checkpoint.Action, WriterEpoch: checkpoint.WriterEpoch})
	if err != nil {
		if isContextCancellation(ctx, err) {
			return c.markUncertainAsync(ctx, checkpoint, RuntimeLifecycleErrorCodeCancelledAfterDispatch)
		}
		return c.markUncertainAsync(ctx, checkpoint, RuntimeLifecycleErrorCodeExecutorFailed)
	}

	if ctx.Err() != nil {
		return c.markUncertainAsync(ctx, checkpoint, RuntimeLifecycleErrorCodeCancelledAfterDispatch)
	}
	if response == nil || !runtimeLifecycleExecutorStatusIsDefined(response.Status) {
		return c.markUncertainAsync(ctx, checkpoint, RuntimeLifecycleErrorCodeExecutorFailed)
	}
	authority, err := c.exactAuthorityAsync(context.Background(), request)
	if err != nil {
		return RuntimeLifecycleResult{}, err
	}
	if authority != RuntimeLifecycleErrorCodeNone {
		return c.markUncertainAsync(ctx, checkpoint, authority)
	}
	switch response.Status {
	case RuntimeLifecycleExecutorStatusResponseLost:
		return c.markUncertainAsync(ctx, checkpoint, RuntimeLifecycleErrorCodeExecutorResponseLost)
	case RuntimeLifecycleExecutorStatusFailed:
		return c.markUncertainAsync(ctx, checkpoint, RuntimeLifecycleErrorCodeExecutorFailed)
	default:
		return c.markUncertainAsync(ctx, checkpoint, RuntimeLifecycleErrorCodeNone)
	}
}

func (c *RuntimeLifecycleCoordinator) recoverByObservationAsync(ctx context.Context,
	request RuntimeLifecycleOperationRequest, checkpoint RuntimeLifecycleCheckpoint) (RuntimeLifecycleResult, error) {
	observationRequest := RuntimeLifecycleObservationRequest{
		OperationKey: checkpoint.OperationKey, Plan: request.Plan, Action: checkpoint.Action,
		PlanFingerprint: checkpoint.PlanFingerprint, PreviousObservationWatermark: checkpoint.LastObservationWatermark,
		WriterEpoch: checkpoint.WriterEpoch, DispatchToken: checkpoint.DispatchToken}
	observation, err := c.executor.ObserveAsync(ctx, observationRequest)
	if err != nil {
		if isContextCancellation(ctx, err) {
			return runtimeLifecycleResult(&checkpoint, RuntimeLifecycleTerminalStatusReconciliationRequired,
				RuntimeLifecycleErrorCodeCancelledAfterDispatch), nil
		}
		return c.markUncertainAsync(ctx, checkpoint, RuntimeLifecycleErrorCodeObservationMismatch)
	}

	if observation == nil || !runtimeLifecycleValidObservation(checkpoint, observationRequest, observation) {
		return c.markUncertainAsync(ctx, checkpoint, RuntimeLifecycleErrorCodeObservationMismatch)
	}
	authority, err := c.exactAuthorityAsync(ctx, request)
	if err != nil {
		return RuntimeLifecycleResult{}, err
	}
	if authority != RuntimeLifecycleErrorCodeNone {
		return c.markUncertainAsync(ctx, checkpoint, authority)
	}
	if observation.Status == RuntimeLifecycleObservationStatusConverged && checkpoint.Action == LifecycleActionConverge {
		advanced, err := c.advanceAsync(ctx, checkpoint, RuntimeLifecyclePhaseObservedConverged,
			RuntimeLifecycleCallStatusObserved, &observation.Fingerprint, observation.Watermark,
			RuntimeLifecycleTerminalStatusNone, RuntimeLifecycleErrorCodeNone)
		if err != nil {
			return RuntimeLifecycleResult{}, err
		}
		if advanced.err == RuntimeLifecycleErrorCodeNone && !advanced.retry {
			return runtimeLifecycleResult(advanced.checkpoint, RuntimeLifecycleTerminalStatusNone,
				RuntimeLifecycleErrorCodeNone), nil
		}
		return runtimeLifecycleResult(&checkpoint, RuntimeLifecycleTerminalStatusReconciliationRequired, advanced.err), nil
	}
	if observation.Status == RuntimeLifecycleObservationStatusStopped &&
		(checkpoint.Action == LifecycleActionDrain || checkpoint.Action == LifecycleActionStop) {
		advanced, err := c.advanceAsync(ctx, checkpoint, RuntimeLifecyclePhaseObservedStopped,
			RuntimeLifecycleCallStatusObserved, &observation.Fingerprint, observation.Watermark,
			RuntimeLifecycleTerminalStatusNone, RuntimeLifecycleErrorCodeNone)
		if err != nil {
			return RuntimeLifecycleResult{}, err
		}
		if advanced.err == RuntimeLifecycleErrorCodeNone && !advanced.retry {
			return runtimeLifecycleResult(advanced.checkpoint, RuntimeLifecycleTerminalStatusNone,
				RuntimeLifecycleErrorCodeNone), nil
		}
		return runtimeLifecycleResult(&checkpoint, RuntimeLifecycleTerminalStatusReconciliationRequired, advanced.err), nil
	}
	return c.markUncertainAsync(ctx, checkpoint, RuntimeLifecycleErrorCodeObservationMismatch)
}

func (c *RuntimeLifecycleCoordinator) markUncertainAsync(ctx context.Context,
	checkpoint RuntimeLifecycleCheckpoint, errCode RuntimeLifecycleErrorCode) (RuntimeLifecycleResult, error) {
	advanced, err := c.advanceAsync(context.Background(), checkpoint, RuntimeLifecyclePhaseUncertain,
		RuntimeLifecycleCallStatusObservationRequired, checkpoint.LastObservationFingerprint,
		checkpoint.LastObservationWatermark, RuntimeLifecycleTerminalStatusReconciliationRequired, errCode)
	if err != nil {
		return RuntimeLifecycleResult{}, err
	}
	if advanced.err == RuntimeLifecycleErrorCodeNone && !advanced.retry {
		return runtimeLifecycleResult(advanced.checkpoint, RuntimeLifecycleTerminalStatusReconciliationRequired,
			errCode), nil
	}
	resultErr := errCode
	if advanced.err != RuntimeLifecycleErrorCodeNone {
		resultErr = advanced.err
	}
	return runtimeLifecycleResult(&checkpoint, RuntimeLifecycleTerminalStatusReconciliationRequired, resultErr), nil
}

func (c *RuntimeLifecycleCoordinator) exactAuthorityAsync(ctx context.Context,
	request RuntimeLifecycleOperationRequest) (RuntimeLifecycleErrorCode, error) {
	state, err := c.authority.ReadAsync(ctx, request.Cell)
	if err != nil {
		if isContextCancellation(ctx, err) {
			return RuntimeLifecycleErrorCodeNone, err
		}
		return RuntimeLifecycleErrorCodeAuthorityUnavailable, nil
	}
	if !runtimeLifecycleAuthorityStatusIsDefined(state.Status) {
		return RuntimeLifecycleErrorCodeAuthorityUnavailable, nil
	}
	if state.IsExactLeader(request.WriterEpoch) {
		return RuntimeLifecycleErrorCodeNone, nil
	}
	return RuntimeLifecycleErrorCodeAuthorityFenced, nil
}

type runtimeLifecycleLoadOutcome struct {
	checkpoint *RuntimeLifecycleCheckpoint
	err        RuntimeLifecycleErrorCode
}

func (c *RuntimeLifecycleCoordinator) loadAsync(ctx context.Context,
	key RuntimeLifecycleOperationKey) (runtimeLifecycleLoadOutcome, error) {
	read, err := c.journal.ReadAsync(ctx, key)
	if err != nil {
		if isContextCancellation(ctx, err) {
			return runtimeLifecycleLoadOutcome{}, err
		}
		return runtimeLifecycleLoadOutcome{err: RuntimeLifecycleErrorCodeJournalUnavailable}, nil
	}
	if !runtimeLifecycleJournalReadStatusIsDefined(read.Status) {
		return runtimeLifecycleLoadOutcome{err: RuntimeLifecycleErrorCodeJournalAmbiguous}, nil
	}
	switch read.Status {
	case RuntimeLifecycleJournalReadStatusFound:
		if read.Checkpoint != nil {
			return runtimeLifecycleLoadOutcome{checkpoint: read.Checkpoint}, nil
		}
		return runtimeLifecycleLoadOutcome{err: RuntimeLifecycleErrorCodeJournalUnavailable}, nil
	case RuntimeLifecycleJournalReadStatusMissing:
		if read.Checkpoint == nil {
			return runtimeLifecycleLoadOutcome{}, nil
		}
		return runtimeLifecycleLoadOutcome{err: RuntimeLifecycleErrorCodeJournalUnavailable}, nil
	case RuntimeLifecycleJournalReadStatusAmbiguous:
		return runtimeLifecycleLoadOutcome{err: RuntimeLifecycleErrorCodeJournalAmbiguous}, nil
	default:
		return runtimeLifecycleLoadOutcome{err: RuntimeLifecycleErrorCodeJournalUnavailable}, nil
	}
}

type runtimeLifecycleWriteOutcome struct {
	checkpoint *RuntimeLifecycleCheckpoint
	err        RuntimeLifecycleErrorCode
	retry      bool
}

func (c *RuntimeLifecycleCoordinator) writeAsync(ctx context.Context, expectedRevision *uint64,
	checkpoint RuntimeLifecycleCheckpoint) (runtimeLifecycleWriteOutcome, error) {
	written, err := c.journal.CompareExchangeAsync(ctx, checkpoint.OperationKey, expectedRevision, checkpoint)
	if err != nil {
		if isContextCancellation(ctx, err) {
			return runtimeLifecycleWriteOutcome{}, err
		}
		return runtimeLifecycleWriteOutcome{err: RuntimeLifecycleErrorCodeJournalUnavailable}, nil
	}
	if !runtimeLifecycleJournalWriteStatusIsDefined(written.Status) {
		return runtimeLifecycleWriteOutcome{err: RuntimeLifecycleErrorCodeJournalAmbiguous}, nil
	}
	if written.Status == RuntimeLifecycleJournalWriteStatusApplied && written.Checkpoint != nil {
		return runtimeLifecycleWriteOutcome{checkpoint: written.Checkpoint}, nil
	}
	if written.Status == RuntimeLifecycleJournalWriteStatusConflict {
		return runtimeLifecycleWriteOutcome{retry: true}, nil
	}
	if written.Status == RuntimeLifecycleJournalWriteStatusAmbiguous {
		return runtimeLifecycleWriteOutcome{err: RuntimeLifecycleErrorCodeJournalAmbiguous}, nil
	}
	return runtimeLifecycleWriteOutcome{err: RuntimeLifecycleErrorCodeJournalUnavailable}, nil
}

func (c *RuntimeLifecycleCoordinator) advanceAsync(ctx context.Context, current RuntimeLifecycleCheckpoint,
	phase RuntimeLifecyclePhase, callStatus RuntimeLifecycleCallStatus,
	observationFingerprint *RuntimeLifecycleHostObservationFingerprint, observationWatermark uint64,
	terminal RuntimeLifecycleTerminalStatus, errCode RuntimeLifecycleErrorCode) (runtimeLifecycleWriteOutcome, error) {
	if !runtimeLifecycleAllowedPhase(current.Phase, phase) {
		return runtimeLifecycleWriteOutcome{err: RuntimeLifecycleErrorCodeInvalidCheckpoint}, nil
	}
	if current.JournalRevision == ^uint64(0) {
		return runtimeLifecycleWriteOutcome{}, argumentOutOfRange("current")
	}
	next := current
	next.Phase = phase
	next.CallStatus = callStatus
	next.LastObservationFingerprint = observationFingerprint
	next.LastObservationWatermark = observationWatermark
	next.TerminalStatus = terminal
	next.ErrorCode = errCode
	next.JournalRevision = current.JournalRevision + 1
	next.PreviousEventDigest = current.EventDigest
	eventDigest, err := RuntimeLifecycleFingerprint.Event(next)
	if err != nil {
		return runtimeLifecycleWriteOutcome{}, err
	}
	next.EventDigest = eventDigest
	return c.writeAsync(ctx, &current.JournalRevision, next)
}

func runtimeLifecycleAllowedPhase(from, to RuntimeLifecyclePhase) bool {
	switch from {
	case RuntimeLifecyclePhaseProposed:
		return to == RuntimeLifecyclePhaseAuthorized
	case RuntimeLifecyclePhaseAuthorized:
		return to == RuntimeLifecyclePhaseDispatchPersisted
	case RuntimeLifecyclePhaseDispatchPersisted:
		return to == RuntimeLifecyclePhaseInFlight || to == RuntimeLifecyclePhaseUncertain
	case RuntimeLifecyclePhaseInFlight, RuntimeLifecyclePhaseUncertain:
		return to == RuntimeLifecyclePhaseObservedConverged || to == RuntimeLifecyclePhaseObservedStopped ||
			to == RuntimeLifecyclePhaseUncertain
	case RuntimeLifecyclePhaseObservedConverged, RuntimeLifecyclePhaseObservedStopped, RuntimeLifecyclePhaseFailed:
		return to == RuntimeLifecyclePhaseTerminal
	default:
		return false
	}
}

func runtimeLifecycleValid(checkpoint RuntimeLifecycleCheckpoint) bool {
	if checkpoint.SchemaVersion != RuntimeLifecycleContractSchemaVersion ||
		!(checkpoint.Driver == 0 || checkpoint.Driver == 1) ||
		!hostAdmittedRoleIsDefined(checkpoint.Role) ||
		!lifecycleActionIsDefined(checkpoint.Action) ||
		!runtimeLifecyclePhaseIsDefined(checkpoint.Phase) ||
		!runtimeLifecycleCallStatusIsDefined(checkpoint.CallStatus) ||
		!runtimeLifecycleCompensationPolicyIsDefined(checkpoint.CompensationPolicy) ||
		!runtimeLifecycleTerminalStatusIsDefined(checkpoint.TerminalStatus) ||
		!runtimeLifecycleErrorCodeIsDefined(checkpoint.ErrorCode) ||
		checkpoint.CompensationPolicy != RuntimeLifecycleCompensationPolicyNone ||
		checkpoint.JournalRevision > ^uint64(0)-1 {
		return false
	}
	eventDigest, err := RuntimeLifecycleFingerprint.Event(checkpoint)
	if err != nil {
		return false
	}
	return checkpoint.EventDigest == eventDigest
}

func runtimeLifecycleValidObservation(checkpoint RuntimeLifecycleCheckpoint,
	request RuntimeLifecycleObservationRequest, observation *RuntimeLifecycleObservation) bool {
	return observation != nil && lifecycleActionIsDefined(observation.Action) &&
		runtimeLifecycleObservationStatusIsDefined(observation.Status) &&
		observation.Watermark > checkpoint.LastObservationWatermark &&
		request.PreviousObservationWatermark == checkpoint.LastObservationWatermark &&
		observation.OperationKey == checkpoint.OperationKey &&
		observation.AllocationId == checkpoint.AllocationId &&
		observation.PlanFingerprint == checkpoint.PlanFingerprint &&
		observation.Action == checkpoint.Action
}

func runtimeLifecycleResult(checkpoint *RuntimeLifecycleCheckpoint, status RuntimeLifecycleTerminalStatus,
	errCode RuntimeLifecycleErrorCode) RuntimeLifecycleResult {
	return RuntimeLifecycleResult{Checkpoint: checkpoint, Status: status, ErrorCode: errCode}
}
