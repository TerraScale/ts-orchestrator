namespace TerraScale.Orchestrator.ControlPlane.Runtime;

/// <summary>
/// Coordinates one fenced host mutation. The journal is the source of truth: an executor is never called
/// before its dispatch is durable, and every post-dispatch path re-observes before it can report success.
/// </summary>
public sealed class RuntimeLifecycleCoordinator(
    IRuntimeLifecycleJournal journal,
    IRuntimeLifecycleAuthorityGate authority,
    IRuntimeLifecycleHostExecutor executor)
{
    private readonly IRuntimeLifecycleJournal _journal = journal ?? throw new ArgumentNullException(nameof(journal));
    private readonly IRuntimeLifecycleAuthorityGate _authority = authority ?? throw new ArgumentNullException(nameof(authority));
    private readonly IRuntimeLifecycleHostExecutor _executor = executor ?? throw new ArgumentNullException(nameof(executor));

    public async ValueTask<RuntimeLifecycleResult> ExecuteAsync(RuntimeLifecycleOperationRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        for (var step = 0; step < RuntimeLifecycleContract.MaximumCoordinatorSteps; step++)
        {
            var loaded = await LoadAsync(request.OperationKey, cancellationToken).ConfigureAwait(false);
            if (loaded.Error != RuntimeLifecycleErrorCode.None) return Result(loaded.Checkpoint, RuntimeLifecycleTerminalStatus.Failed, loaded.Error);
            var checkpoint = loaded.Checkpoint;
            if (checkpoint is null)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var proposed = RuntimeLifecycleCheckpoint.Proposed(request);
                var written = await WriteAsync(proposed, null, cancellationToken).ConfigureAwait(false);
                if (written.Retry) continue;
                if (written.Error != RuntimeLifecycleErrorCode.None) return Result(null, RuntimeLifecycleTerminalStatus.Failed, written.Error);
                continue;
            }

            if (!checkpoint.Matches(request) || !Valid(checkpoint))
                return Result(checkpoint, RuntimeLifecycleTerminalStatus.Failed, !checkpoint.Matches(request) ? RuntimeLifecycleErrorCode.IdentityMismatch : RuntimeLifecycleErrorCode.InvalidCheckpoint);

            if (checkpoint.Phase == RuntimeLifecyclePhase.Terminal)
                return Result(checkpoint, checkpoint.TerminalStatus, checkpoint.ErrorCode);

            switch (checkpoint.Phase)
            {
                case RuntimeLifecyclePhase.Proposed:
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var gate = await ExactAuthorityAsync(request, cancellationToken).ConfigureAwait(false);
                    if (gate != RuntimeLifecycleErrorCode.None) return Result(checkpoint, RuntimeLifecycleTerminalStatus.Failed, gate);
                    var advanced = await AdvanceAsync(checkpoint, RuntimeLifecyclePhase.Authorized, RuntimeLifecycleCallStatus.NotCalled, null, 0, RuntimeLifecycleTerminalStatus.None, RuntimeLifecycleErrorCode.None, cancellationToken).ConfigureAwait(false);
                    if (advanced.Retry) continue;
                    if (advanced.Error != RuntimeLifecycleErrorCode.None) return Result(checkpoint, RuntimeLifecycleTerminalStatus.Failed, advanced.Error);
                    continue;
                }
                case RuntimeLifecyclePhase.Authorized:
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var gate = await ExactAuthorityAsync(request, cancellationToken).ConfigureAwait(false);
                    if (gate != RuntimeLifecycleErrorCode.None) return Result(checkpoint, RuntimeLifecycleTerminalStatus.Failed, gate);
                    var advanced = await AdvanceAsync(checkpoint, RuntimeLifecyclePhase.DispatchPersisted, RuntimeLifecycleCallStatus.DispatchPersisted, null, 0, RuntimeLifecycleTerminalStatus.None, RuntimeLifecycleErrorCode.None, cancellationToken).ConfigureAwait(false);
                    if (advanced.Retry) continue;
                    if (advanced.Error != RuntimeLifecycleErrorCode.None) return Result(checkpoint, RuntimeLifecycleTerminalStatus.Failed, advanced.Error);
                    continue;
                }
                case RuntimeLifecyclePhase.DispatchPersisted:
                {
                    // This state may be a crash boundary. A cancellation before an actual call is still unsafe to retry.
                    if (cancellationToken.IsCancellationRequested)
                        return await MarkUncertainAsync(checkpoint, RuntimeLifecycleErrorCode.CancelledAfterDispatch).ConfigureAwait(false);
                    var gate = await ExactAuthorityAsync(request, cancellationToken).ConfigureAwait(false);
                    if (gate != RuntimeLifecycleErrorCode.None)
                        return await MarkUncertainAsync(checkpoint, gate).ConfigureAwait(false);
                    var advanced = await AdvanceAsync(checkpoint, RuntimeLifecyclePhase.InFlight, RuntimeLifecycleCallStatus.InFlight, null, 0, RuntimeLifecycleTerminalStatus.None, RuntimeLifecycleErrorCode.None, cancellationToken).ConfigureAwait(false);
                    if (advanced.Retry) continue;
                    if (advanced.Error != RuntimeLifecycleErrorCode.None) return Result(checkpoint, RuntimeLifecycleTerminalStatus.ReconciliationRequired, advanced.Error);
                    return await CallOnceAndRequireObservationAsync(request, advanced.Checkpoint!, cancellationToken).ConfigureAwait(false);
                }
                case RuntimeLifecyclePhase.InFlight:
                case RuntimeLifecyclePhase.Uncertain:
                    return await RecoverByObservationAsync(request, checkpoint, cancellationToken).ConfigureAwait(false);
                case RuntimeLifecyclePhase.ObservedConverged:
                {
                    var advanced = await AdvanceAsync(checkpoint, RuntimeLifecyclePhase.Terminal, RuntimeLifecycleCallStatus.Observed, checkpoint.LastObservationFingerprint, checkpoint.LastObservationWatermark, RuntimeLifecycleTerminalStatus.Converged, RuntimeLifecycleErrorCode.None, cancellationToken).ConfigureAwait(false);
                    if (advanced.Retry) continue;
                    return advanced.Error == RuntimeLifecycleErrorCode.None ? Result(advanced.Checkpoint, RuntimeLifecycleTerminalStatus.Converged, RuntimeLifecycleErrorCode.None) : Result(checkpoint, RuntimeLifecycleTerminalStatus.Failed, advanced.Error);
                }
                case RuntimeLifecyclePhase.ObservedStopped:
                {
                    var advanced = await AdvanceAsync(checkpoint, RuntimeLifecyclePhase.Terminal, RuntimeLifecycleCallStatus.Observed, checkpoint.LastObservationFingerprint, checkpoint.LastObservationWatermark, RuntimeLifecycleTerminalStatus.Stopped, RuntimeLifecycleErrorCode.None, cancellationToken).ConfigureAwait(false);
                    if (advanced.Retry) continue;
                    return advanced.Error == RuntimeLifecycleErrorCode.None ? Result(advanced.Checkpoint, RuntimeLifecycleTerminalStatus.Stopped, RuntimeLifecycleErrorCode.None) : Result(checkpoint, RuntimeLifecycleTerminalStatus.Failed, advanced.Error);
                }
                case RuntimeLifecyclePhase.Failed:
                {
                    var advanced = await AdvanceAsync(checkpoint, RuntimeLifecyclePhase.Terminal, checkpoint.CallStatus, checkpoint.LastObservationFingerprint, checkpoint.LastObservationWatermark, RuntimeLifecycleTerminalStatus.Failed, checkpoint.ErrorCode, cancellationToken).ConfigureAwait(false);
                    if (advanced.Retry) continue;
                    return advanced.Error == RuntimeLifecycleErrorCode.None ? Result(advanced.Checkpoint, RuntimeLifecycleTerminalStatus.Failed, checkpoint.ErrorCode) : Result(checkpoint, RuntimeLifecycleTerminalStatus.Failed, advanced.Error);
                }
                default:
                    return Result(checkpoint, RuntimeLifecycleTerminalStatus.Failed, RuntimeLifecycleErrorCode.InvalidCheckpoint);
            }
        }
        return Result(null, RuntimeLifecycleTerminalStatus.Failed, RuntimeLifecycleErrorCode.CasExhausted);
    }

    private async ValueTask<RuntimeLifecycleResult> CallOnceAndRequireObservationAsync(RuntimeLifecycleOperationRequest request, RuntimeLifecycleCheckpoint checkpoint, CancellationToken cancellationToken)
    {
        RuntimeLifecycleExecutorResponse response;
        try
        {
            response = await _executor.ExecuteAsync(new(checkpoint.OperationKey, checkpoint.DispatchToken, request.Plan, checkpoint.Action, checkpoint.WriterEpoch), cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return await MarkUncertainAsync(checkpoint, RuntimeLifecycleErrorCode.CancelledAfterDispatch).ConfigureAwait(false);
        }
        catch
        {
            return await MarkUncertainAsync(checkpoint, RuntimeLifecycleErrorCode.ExecutorFailed).ConfigureAwait(false);
        }

        if (cancellationToken.IsCancellationRequested)
            return await MarkUncertainAsync(checkpoint, RuntimeLifecycleErrorCode.CancelledAfterDispatch).ConfigureAwait(false);
        if (!Enum.IsDefined(response.Status)) return await MarkUncertainAsync(checkpoint, RuntimeLifecycleErrorCode.ExecutorFailed).ConfigureAwait(false);
        var authority = await ExactAuthorityAsync(request, CancellationToken.None).ConfigureAwait(false);
        if (authority != RuntimeLifecycleErrorCode.None)
            return await MarkUncertainAsync(checkpoint, authority).ConfigureAwait(false);
        return await MarkUncertainAsync(checkpoint, response.Status switch
        {
            RuntimeLifecycleExecutorStatus.ResponseLost => RuntimeLifecycleErrorCode.ExecutorResponseLost,
            RuntimeLifecycleExecutorStatus.Failed => RuntimeLifecycleErrorCode.ExecutorFailed,
            _ => RuntimeLifecycleErrorCode.None
        }).ConfigureAwait(false);
    }

    private async ValueTask<RuntimeLifecycleResult> RecoverByObservationAsync(RuntimeLifecycleOperationRequest request, RuntimeLifecycleCheckpoint checkpoint, CancellationToken cancellationToken)
    {
        RuntimeLifecycleObservation observation;
        try { observation = await _executor.ObserveAsync(checkpoint.OperationKey, cancellationToken).ConfigureAwait(false); }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { return Result(checkpoint, RuntimeLifecycleTerminalStatus.ReconciliationRequired, RuntimeLifecycleErrorCode.CancelledAfterDispatch); }
        catch { return await MarkUncertainAsync(checkpoint, RuntimeLifecycleErrorCode.ObservationMismatch).ConfigureAwait(false); }

        if (!ValidObservation(checkpoint, observation))
            return await MarkUncertainAsync(checkpoint, RuntimeLifecycleErrorCode.ObservationMismatch).ConfigureAwait(false);
        var authority = await ExactAuthorityAsync(request, cancellationToken).ConfigureAwait(false);
        if (authority != RuntimeLifecycleErrorCode.None)
            return await MarkUncertainAsync(checkpoint, authority).ConfigureAwait(false);
        if (observation.Status == RuntimeLifecycleObservationStatus.Converged && checkpoint.Action == LifecycleAction.Converge)
        {
            var advanced = await AdvanceAsync(checkpoint, RuntimeLifecyclePhase.ObservedConverged, RuntimeLifecycleCallStatus.Observed, observation.Fingerprint, observation.Watermark, RuntimeLifecycleTerminalStatus.None, RuntimeLifecycleErrorCode.None, cancellationToken).ConfigureAwait(false);
            return advanced.Error == RuntimeLifecycleErrorCode.None && !advanced.Retry ? Result(advanced.Checkpoint, RuntimeLifecycleTerminalStatus.None, RuntimeLifecycleErrorCode.None) : Result(checkpoint, RuntimeLifecycleTerminalStatus.ReconciliationRequired, advanced.Error);
        }
        if (observation.Status == RuntimeLifecycleObservationStatus.Stopped && checkpoint.Action is LifecycleAction.Drain or LifecycleAction.Stop)
        {
            var advanced = await AdvanceAsync(checkpoint, RuntimeLifecyclePhase.ObservedStopped, RuntimeLifecycleCallStatus.Observed, observation.Fingerprint, observation.Watermark, RuntimeLifecycleTerminalStatus.None, RuntimeLifecycleErrorCode.None, cancellationToken).ConfigureAwait(false);
            return advanced.Error == RuntimeLifecycleErrorCode.None && !advanced.Retry ? Result(advanced.Checkpoint, RuntimeLifecycleTerminalStatus.None, RuntimeLifecycleErrorCode.None) : Result(checkpoint, RuntimeLifecycleTerminalStatus.ReconciliationRequired, advanced.Error);
        }
        return await MarkUncertainAsync(checkpoint, RuntimeLifecycleErrorCode.ObservationMismatch).ConfigureAwait(false);
    }

    private async ValueTask<RuntimeLifecycleResult> MarkUncertainAsync(RuntimeLifecycleCheckpoint checkpoint, RuntimeLifecycleErrorCode error)
    {
        var advanced = await AdvanceAsync(checkpoint, RuntimeLifecyclePhase.Uncertain, RuntimeLifecycleCallStatus.ObservationRequired, checkpoint.LastObservationFingerprint, checkpoint.LastObservationWatermark, RuntimeLifecycleTerminalStatus.ReconciliationRequired, error, CancellationToken.None).ConfigureAwait(false);
        return advanced.Error == RuntimeLifecycleErrorCode.None && !advanced.Retry
            ? Result(advanced.Checkpoint, RuntimeLifecycleTerminalStatus.ReconciliationRequired, error)
            : Result(checkpoint, RuntimeLifecycleTerminalStatus.ReconciliationRequired, advanced.Error == RuntimeLifecycleErrorCode.None ? error : advanced.Error);
    }

    private async ValueTask<RuntimeLifecycleErrorCode> ExactAuthorityAsync(RuntimeLifecycleOperationRequest request, CancellationToken cancellationToken)
    {
        try
        {
            var state = await _authority.ReadAsync(request.Cell, cancellationToken).ConfigureAwait(false);
            if (!Enum.IsDefined(state.Status)) return RuntimeLifecycleErrorCode.AuthorityUnavailable;
            return state.IsExactLeader(request.WriterEpoch) ? RuntimeLifecycleErrorCode.None : RuntimeLifecycleErrorCode.AuthorityFenced;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch { return RuntimeLifecycleErrorCode.AuthorityUnavailable; }
    }

    private async ValueTask<(RuntimeLifecycleCheckpoint? Checkpoint, RuntimeLifecycleErrorCode Error)> LoadAsync(RuntimeLifecycleOperationKey key, CancellationToken cancellationToken)
    {
        try
        {
            var read = await _journal.ReadAsync(key, cancellationToken).ConfigureAwait(false);
            if (!Enum.IsDefined(read.Status)) return (null, RuntimeLifecycleErrorCode.JournalAmbiguous);
            return read.Status switch
            {
                RuntimeLifecycleJournalReadStatus.Found when read.Checkpoint is not null => (read.Checkpoint, RuntimeLifecycleErrorCode.None),
                RuntimeLifecycleJournalReadStatus.Missing when read.Checkpoint is null => (null, RuntimeLifecycleErrorCode.None),
                RuntimeLifecycleJournalReadStatus.Ambiguous => (null, RuntimeLifecycleErrorCode.JournalAmbiguous),
                _ => (null, RuntimeLifecycleErrorCode.JournalUnavailable)
            };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch { return (null, RuntimeLifecycleErrorCode.JournalUnavailable); }
    }

    private async ValueTask<(RuntimeLifecycleCheckpoint? Checkpoint, RuntimeLifecycleErrorCode Error, bool Retry)> WriteAsync(RuntimeLifecycleCheckpoint checkpoint, ulong? expectedRevision, CancellationToken cancellationToken)
    {
        try
        {
            var written = await _journal.CompareExchangeAsync(checkpoint.OperationKey, expectedRevision, checkpoint, cancellationToken).ConfigureAwait(false);
            if (!Enum.IsDefined(written.Status)) return (null, RuntimeLifecycleErrorCode.JournalAmbiguous, false);
            if (written.Status == RuntimeLifecycleJournalWriteStatus.Applied && written.Checkpoint is not null) return (written.Checkpoint, RuntimeLifecycleErrorCode.None, false);
            if (written.Status == RuntimeLifecycleJournalWriteStatus.Conflict) return (null, RuntimeLifecycleErrorCode.None, true);
            return (null, written.Status == RuntimeLifecycleJournalWriteStatus.Ambiguous ? RuntimeLifecycleErrorCode.JournalAmbiguous : RuntimeLifecycleErrorCode.JournalUnavailable, false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch { return (null, RuntimeLifecycleErrorCode.JournalUnavailable, false); }
    }

    private ValueTask<(RuntimeLifecycleCheckpoint? Checkpoint, RuntimeLifecycleErrorCode Error, bool Retry)> AdvanceAsync(RuntimeLifecycleCheckpoint current, RuntimeLifecyclePhase phase, RuntimeLifecycleCallStatus callStatus, RuntimeLifecycleHostObservationFingerprint? observationFingerprint, ulong observationWatermark, RuntimeLifecycleTerminalStatus terminal, RuntimeLifecycleErrorCode error, CancellationToken cancellationToken)
    {
        if (!Allowed(current.Phase, phase)) return ValueTask.FromResult<(RuntimeLifecycleCheckpoint?, RuntimeLifecycleErrorCode, bool)>((null, RuntimeLifecycleErrorCode.InvalidCheckpoint, false));
        var next = current with
        {
            Phase = phase,
            CallStatus = callStatus,
            LastObservationFingerprint = observationFingerprint,
            LastObservationWatermark = observationWatermark,
            TerminalStatus = terminal,
            ErrorCode = error,
            JournalRevision = checked(current.JournalRevision + 1),
            PreviousEventDigest = current.EventDigest
        };
        next = next with { EventDigest = RuntimeLifecycleFingerprint.Event(next) };
        return WriteAsync(next, current.JournalRevision, cancellationToken);
    }

    private static bool Allowed(RuntimeLifecyclePhase from, RuntimeLifecyclePhase to) => (from, to) switch
    {
        (RuntimeLifecyclePhase.Proposed, RuntimeLifecyclePhase.Authorized) => true,
        (RuntimeLifecyclePhase.Authorized, RuntimeLifecyclePhase.DispatchPersisted) => true,
        (RuntimeLifecyclePhase.DispatchPersisted, RuntimeLifecyclePhase.InFlight or RuntimeLifecyclePhase.Uncertain) => true,
        (RuntimeLifecyclePhase.InFlight, RuntimeLifecyclePhase.ObservedConverged or RuntimeLifecyclePhase.ObservedStopped or RuntimeLifecyclePhase.Uncertain) => true,
        (RuntimeLifecyclePhase.Uncertain, RuntimeLifecyclePhase.ObservedConverged or RuntimeLifecyclePhase.ObservedStopped or RuntimeLifecyclePhase.Uncertain) => true,
        (RuntimeLifecyclePhase.ObservedConverged, RuntimeLifecyclePhase.Terminal) => true,
        (RuntimeLifecyclePhase.ObservedStopped, RuntimeLifecyclePhase.Terminal) => true,
        (RuntimeLifecyclePhase.Failed, RuntimeLifecyclePhase.Terminal) => true,
        _ => false
    };

    private static bool Valid(RuntimeLifecycleCheckpoint checkpoint) =>
        checkpoint.SchemaVersion == RuntimeLifecycleContract.SchemaVersion && Enum.IsDefined(checkpoint.Driver) && Enum.IsDefined(checkpoint.Role) && Enum.IsDefined(checkpoint.Action) && Enum.IsDefined(checkpoint.Phase) && Enum.IsDefined(checkpoint.CallStatus) && Enum.IsDefined(checkpoint.CompensationPolicy) && Enum.IsDefined(checkpoint.TerminalStatus) && Enum.IsDefined(checkpoint.ErrorCode) &&
        checkpoint.CompensationPolicy == RuntimeLifecycleCompensationPolicy.None && checkpoint.JournalRevision <= ulong.MaxValue - 1 &&
        checkpoint.EventDigest == RuntimeLifecycleFingerprint.Event(checkpoint);

    private static bool ValidObservation(RuntimeLifecycleCheckpoint checkpoint, RuntimeLifecycleObservation observation) =>
        observation is not null && Enum.IsDefined(observation.Action) && Enum.IsDefined(observation.Status) && observation.Watermark > checkpoint.LastObservationWatermark &&
        observation.OperationKey == checkpoint.OperationKey && observation.AllocationId == checkpoint.AllocationId && observation.PlanFingerprint == checkpoint.PlanFingerprint;

    private static RuntimeLifecycleResult Result(RuntimeLifecycleCheckpoint? checkpoint, RuntimeLifecycleTerminalStatus status, RuntimeLifecycleErrorCode error) => new(checkpoint, status, error);
}
