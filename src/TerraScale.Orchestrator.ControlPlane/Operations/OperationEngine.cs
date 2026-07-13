namespace TerraScale.Orchestrator.ControlPlane.Operations;

public static class OperationEngine
{
    public static OperationDecision Decide(IReadOnlyList<OperationEvent> history, OperationCommand command)
    {
        ArgumentNullException.ThrowIfNull(history);
        ArgumentNullException.ThrowIfNull(command);

        var replay = Replay(history);
        if (replay.Errors.Count != 0)
        {
            return OperationDecision.Create(replay.State, errors: replay.Errors);
        }

        var state = replay.State;
        var commonError = ValidateCommand(state, command);
        if (commonError is not null)
        {
            return Reject(state, commonError);
        }

        return command switch
        {
            PrepareOperation prepare => Prepare(state, prepare),
            AuthorizeOperation authorize => Authorize(state, authorize),
            RecordDispatch dispatch => Dispatch(state, dispatch),
            RecordObservation observation => Observe(state, observation),
            RecordTerminal terminal => Terminal(state, terminal),
            _ => Reject(state, Error(OperationErrorCode.InvalidInput, "INV-005", "Unknown operation command.")),
        };
    }

    public static OperationDecision Replay(IReadOnlyList<OperationEvent> history)
    {
        ArgumentNullException.ThrowIfNull(history);
        var state = OperationState.Empty;
        var errors = new List<OperationError>();
        var normalized = new List<OperationEvent>();

        if (history.Any(static item => item is null))
        {
            errors.Add(Error(OperationErrorCode.InvalidJournal, "INV-005",
                "Journal history contains a null event."));
            return OperationDecision.Create(state, errors: errors);
        }

        foreach (var group in history.GroupBy(static item => item.Sequence).OrderBy(static group => group.Key))
        {
            var first = group.First();
            if (group.Any(item => item.EventDigest != OperationDigest.Event(item)))
            {
                errors.Add(Error(OperationErrorCode.InvalidJournal, "INV-005",
                    $"Sequence {group.Key} contains an event whose digest does not match its body."));
                return OperationDecision.Create(state, errors: errors);
            }

            if (group.Any(item => !StringComparer.Ordinal.Equals(item.EventDigest, first.EventDigest)))
            {
                errors.Add(Error(OperationErrorCode.ConflictingJournalEvent, "INV-005",
                    $"Sequence {group.Key} contains conflicting journal events."));
                return OperationDecision.Create(state, errors: errors);
            }

            normalized.Add(first);
        }

        foreach (var @event in normalized)
        {
            var validation = ValidateNextEvent(state, @event);
            if (validation is not null)
            {
                errors.Add(validation);
                return OperationDecision.Create(state, errors: errors);
            }

            state = Apply(state, @event);
        }

        return OperationDecision.Create(state);
    }

    private static OperationDecision Prepare(OperationState state, PrepareOperation command)
    {
        var inputError = ValidatePreparation(command);
        if (inputError is not null) return Reject(state, inputError);

        if (state.Checkpoint != OperationCheckpoint.None)
        {
            if (state.OperationId == command.OperationId && state.Desired == command.Desired &&
                state.ExpectedObservation == command.ExpectedObservation &&
                state.PermittedCompensations.SequenceEqual(command.PermittedCompensations, StringComparer.Ordinal))
            {
                return OperationDecision.Create(state);
            }

            var code = state.Desired?.IdempotencyKey == command.Desired.IdempotencyKey
                ? OperationErrorCode.IdempotencyConflict
                : OperationErrorCode.OperationConflict;
            return Reject(state, Error(code, "INV-004",
                "An existing operation already owns this journal and cannot be superseded."));
        }

        if (command.Now >= command.Desired.Deadline)
        {
            return Reject(state, Error(OperationErrorCode.DeadlineExpired, "INV-005",
                "Preparation deadline is not later than the explicit decision time."));
        }

        if (command.Desired.AggregateId != command.ExpectedObservation.AggregateId ||
            command.Desired.TargetIdentity != command.ExpectedObservation.TargetIdentity)
        {
            return Reject(state, Error(OperationErrorCode.OwnershipMismatch, "INV-004",
                "Expected observation does not identify the desired aggregate and target."));
        }

        if (command.Desired.Generation != command.ExpectedObservation.Generation)
        {
            return Reject(state, Error(OperationErrorCode.StaleDesiredGeneration, "INV-005",
                "Desired and expected observation generations differ."));
        }

        var @event = Stamp(state, (sequence, previous, digest) => new OperationPrepared(
            sequence, previous, digest, command.OperationId, command.WriterEpoch, command.Now,
            command.Desired, command.ExpectedObservation,
            Array.AsReadOnly(command.PermittedCompensations.ToArray())));
        return Append(state, @event);
    }

    private static OperationDecision Authorize(OperationState state, AuthorizeOperation command)
    {
        if (state.ResumableCheckpoint != OperationCheckpoint.Prepared || state.Desired is null || state.ExpectedObservation is null)
        {
            return Reject(state, Error(OperationErrorCode.InvalidTransition, "INV-004",
                "Only a prepared operation can be authorized."));
        }

        if (command.Evidence is null || command.Evidence.Observation is null ||
            string.IsNullOrWhiteSpace(command.Evidence.ApprovalDigest) ||
            string.IsNullOrWhiteSpace(command.Evidence.EvidenceDigest) ||
            !IsCompleteObservation(command.Evidence.Observation))
        {
            return Reject(state, Error(OperationErrorCode.InvalidInput, "INV-004",
                "Authorization requires observation, approval, and evidence digests."));
        }

        OperationError? hold = null;
        var observed = command.Evidence.Observation;
        if (command.Now >= state.Desired.Deadline)
            hold = Error(OperationErrorCode.DeadlineExpired, "INV-005", "Authorization deadline has expired.");
        else if (observed.AggregateId != state.Desired.AggregateId || observed.TargetIdentity != state.Desired.TargetIdentity || !observed.PositivelyOwned)
            hold = Error(OperationErrorCode.OwnershipMismatch, "INV-004", "Fresh observation does not prove exact positive ownership.");
        else if (observed.Generation != state.Desired.Generation)
            hold = Error(OperationErrorCode.StaleDesiredGeneration, "INV-005", "Fresh observation generation differs from desired generation.");
        else if (observed.ObservationId == state.ExpectedObservation.ObservationId || observed.ResourceVersion == state.ExpectedObservation.ResourceVersion)
            hold = Error(OperationErrorCode.StaleObservation, "INV-005", "Authorization requires a fresh observation identity and resource version.");
        else if (!command.Evidence.ApprovalsSatisfied || !command.Evidence.PolicySatisfied || !command.Evidence.QuorumSatisfied || !command.Evidence.BudgetSatisfied)
            hold = Error(OperationErrorCode.AuthorizationDenied, "INV-004", "One or more explicit authorization gates are not satisfied.");

        if (hold is not null) return Hold(state, command, hold);

        var sequence = state.LastSequence + 1;
        var authorizationDigest = OperationDigest.Authorization(sequence, state.JournalDigest,
            command.OperationId, command.WriterEpoch, state.Desired, command.Evidence,
            state.PermittedCompensations);
        var @event = Stamp(state, (number, previous, digest) => new OperationAuthorized(
            number, previous, digest, command.OperationId, command.WriterEpoch, command.Now,
            command.Evidence, authorizationDigest));
        return Append(state, @event);
    }

    private static OperationDecision Dispatch(OperationState state, RecordDispatch command)
    {
        if (state.Authorization is null || state.Desired is null)
        {
            return Reject(state, Error(OperationErrorCode.InvalidTransition, "INV-004",
                "Dispatch requires a committed authorization."));
        }

        if (state.Checkpoint == OperationCheckpoint.Terminal ||
            (state.Checkpoint == OperationCheckpoint.Held && state.ResumableCheckpoint != OperationCheckpoint.Authorized))
        {
            return Reject(state, Error(OperationErrorCode.InvalidTransition, "INV-004",
                "A terminal or held operation cannot dispatch."));
        }

        if (string.IsNullOrWhiteSpace(command.ExecutorId) || command.Attempt <= 0)
        {
            return Reject(state, Error(OperationErrorCode.InvalidInput, "INV-005",
                "Dispatch executor and positive attempt are required."));
        }

        if (state.Dispatch is not null)
        {
            if (state.Checkpoint == OperationCheckpoint.DispatchRecorded &&
                state.Dispatch.ExecutorId == command.ExecutorId && state.Dispatch.Attempt == command.Attempt &&
                state.Dispatch.WriterEpoch == command.WriterEpoch && state.Recovery is null)
            {
                if (command.Now >= state.Desired.Deadline)
                    return Reject(state, Error(OperationErrorCode.DeadlineExpired, "INV-005",
                        "Expired committed dispatch may only be reconciled read-only."));
                return OperationDecision.Create(state, intents: [CreateIntent(state, state.Dispatch)]);
            }

            if (state.Checkpoint == OperationCheckpoint.DispatchRecorded &&
                command.Attempt == state.Dispatch.Attempt && command.WriterEpoch > state.HighestWriterEpoch)
            {
                var recovery = Stamp(state, (sequence, previous, digest) => new OperationRecoveryRecorded(
                    sequence, previous, digest, command.OperationId, command.WriterEpoch, command.Now,
                    command.ExecutorId, state.Dispatch.Sequence));
                return Commit(state, recovery, [CreateReconcileIntent(state, null)]);
            }

            if (state.Checkpoint == OperationCheckpoint.DispatchRecorded && state.Recovery is not null &&
                command.Attempt == state.Dispatch.Attempt && command.WriterEpoch == state.Recovery.WriterEpoch &&
                command.ExecutorId == state.Recovery.ExecutorId)
            {
                return OperationDecision.Create(state, intents: [CreateReconcileIntent(state, null)]);
            }

            return Reject(state, Error(OperationErrorCode.IdempotencyConflict, "INV-005",
                "A different dispatch attempt is already persisted; reconcile it before retry."));
        }

        if (command.Now >= state.Desired.Deadline)
        {
            return Hold(state, command, Error(OperationErrorCode.DeadlineExpired, "INV-005",
                "The committed operation is preserved, but dispatch is held after its deadline."));
        }

        var @event = Stamp(state, (sequence, previous, digest) => new OperationDispatchRecorded(
            sequence, previous, digest, command.OperationId, command.WriterEpoch, command.Now,
            command.ExecutorId, command.Attempt));
        return Commit(state, @event, [CreateIntent(state, @event)]);
    }

    private static OperationDecision Observe(OperationState state, RecordObservation command)
    {
        if (state.Dispatch is null || state.Authorization is null || state.Desired is null)
        {
            return Reject(state, Error(OperationErrorCode.InvalidTransition, "INV-004",
                "Provider observation requires a persisted dispatch checkpoint."));
        }

        if (state.Checkpoint is OperationCheckpoint.Terminal or OperationCheckpoint.Held)
        {
            return Reject(state, Error(OperationErrorCode.ConflictingTerminalObservation, "INV-006",
                "A terminal or held operation cannot accept another observation."));
        }

        if (string.IsNullOrWhiteSpace(command.ObservationId) ||
            string.IsNullOrWhiteSpace(command.TargetIdentity) ||
            string.IsNullOrWhiteSpace(command.TerminalState) || command.Generation <= 0)
            return Reject(state, Error(OperationErrorCode.InvalidInput, "INV-005", "Complete provider observation identity is required."));
        if (command.ProviderWorkRequestId is not null && string.IsNullOrWhiteSpace(command.ProviderWorkRequestId))
            return Reject(state, Error(OperationErrorCode.InvalidInput, "INV-005", "Provider work-request identity cannot be blank."));

        if (state.Observation is not null)
        {
            if (ObservationMatches(state.Observation, command)) return OperationDecision.Create(state);
            if (state.Observation.Outcome is not (ProviderOutcome.Unknown or ProviderOutcome.InProgress))
                return Reject(state, Error(OperationErrorCode.ConflictingTerminalObservation, "INV-006",
                    "A contradictory final provider observation cannot replace the persisted observation."));
        }

        var outcome = command.Outcome;
        if (command.TargetIdentity != state.Desired.TargetIdentity || command.Generation != state.Desired.Generation ||
            (outcome == ProviderOutcome.Succeeded && command.TerminalState != state.Desired.DesiredTerminalState))
        {
            outcome = ProviderOutcome.Inconsistent;
        }

        var @event = Stamp(state, (sequence, previous, digest) => new OperationObservationRecorded(
            sequence, previous, digest, command.OperationId, command.WriterEpoch, command.Now,
            command.ObservationId, command.TargetIdentity, command.Generation,
            command.TerminalState, outcome, command.ProviderWorkRequestId));
        if (outcome is ProviderOutcome.Unknown or ProviderOutcome.InProgress)
        {
            return Commit(state, @event, [CreateReconcileIntent(state, command.ProviderWorkRequestId)]);
        }

        return Commit(state, @event);
    }

    private static OperationDecision Terminal(OperationState state, RecordTerminal command)
    {
        if (string.IsNullOrWhiteSpace(command.TerminalState))
            return Reject(state, Error(OperationErrorCode.InvalidInput, "INV-005", "Terminal state is required."));

        if (state.Observation is null || state.Desired is null)
        {
            return Reject(state, Error(OperationErrorCode.InvalidTransition, "INV-004",
                "Terminal recording requires an observed provider result."));
        }

        if (state.Terminal is not null)
        {
            if (state.Terminal.Outcome == command.Outcome && state.Terminal.TerminalState == command.TerminalState)
                return OperationDecision.Create(state);
            return Reject(state, Error(OperationErrorCode.ConflictingTerminalObservation, "INV-006",
                "A conflicting terminal result cannot supersede the accepted result."));
        }

        if (state.Observation.Outcome is not (ProviderOutcome.Succeeded or ProviderOutcome.Failed) ||
            command.Outcome != state.Observation.Outcome || command.TerminalState != state.Observation.TerminalState)
        {
            return Reject(state, Error(OperationErrorCode.ConflictingTerminalObservation, "INV-006",
                "Terminal result must exactly match a succeeded or failed provider observation."));
        }

        if (command.Outcome == ProviderOutcome.Succeeded && command.TerminalState != state.Desired.DesiredTerminalState)
        {
            return Reject(state, Error(OperationErrorCode.ConflictingTerminalObservation, "INV-006",
                "Successful terminal state differs from the authorized terminal state."));
        }

        var @event = Stamp(state, (sequence, previous, digest) => new OperationTerminalRecorded(
            sequence, previous, digest, command.OperationId, command.WriterEpoch, command.Now,
            command.Outcome, command.TerminalState));
        return Append(state, @event);
    }

    private static OperationError? ValidateCommand(OperationState state, OperationCommand command)
    {
        if (string.IsNullOrWhiteSpace(command.OperationId) || command.WriterEpoch <= 0 || command.Now == default)
            return Error(OperationErrorCode.InvalidInput, "INV-005", "Operation ID, positive writer epoch, and explicit time are required.");
        if (state.OperationId is not null && state.OperationId != command.OperationId)
            return Error(OperationErrorCode.OperationConflict, "INV-004", "Command operation ID differs from the journal owner.");
        if (command.WriterEpoch < state.HighestWriterEpoch)
            return Error(OperationErrorCode.StaleWriterEpoch, "INV-006", "Writer epoch is older than the journal's highest accepted epoch.");
        if (command is RecordObservation observation && !Enum.IsDefined(observation.Outcome) ||
            command is RecordTerminal terminal && !Enum.IsDefined(terminal.Outcome))
            return Error(OperationErrorCode.InvalidInput, "INV-005", "Provider outcome is outside the closed vocabulary.");
        return null;
    }

    private static OperationError? ValidatePreparation(PrepareOperation command)
    {
        var desired = command.Desired;
        var observed = command.ExpectedObservation;
        if (desired is null || observed is null || command.PermittedCompensations is null ||
            string.IsNullOrWhiteSpace(desired.AggregateId) || desired.Generation <= 0 ||
            string.IsNullOrWhiteSpace(desired.ResourceVersion) || string.IsNullOrWhiteSpace(desired.OperationKind) ||
            string.IsNullOrWhiteSpace(desired.TargetIdentity) || string.IsNullOrWhiteSpace(desired.DesiredTerminalState) ||
            string.IsNullOrWhiteSpace(desired.PayloadDigest) || string.IsNullOrWhiteSpace(desired.IdempotencyKey) ||
            desired.Deadline == default || !IsCompleteObservation(observed) ||
            command.PermittedCompensations.Any(string.IsNullOrWhiteSpace) ||
            command.PermittedCompensations.Distinct(StringComparer.Ordinal).Count() != command.PermittedCompensations.Count)
            return Error(OperationErrorCode.InvalidInput, "INV-005", "Preparation requires complete immutable desired and observed identities.");
        return null;
    }

    private static OperationError? ValidateNextEvent(OperationState state, OperationEvent @event)
    {
        if (@event.Sequence != state.LastSequence + 1 || @event.PreviousDigest != state.JournalDigest)
            return Error(OperationErrorCode.InvalidJournal, "INV-005", "Journal sequence or previous digest is not append-only.");
        if (@event.EventDigest != OperationDigest.Event(@event))
            return Error(OperationErrorCode.InvalidJournal, "INV-005", "Journal event digest does not match its content.");
        if (state.OperationId is not null && state.OperationId != @event.OperationId)
            return Error(OperationErrorCode.OperationConflict, "INV-004", "Journal contains multiple operation owners.");
        if (@event.WriterEpoch < state.HighestWriterEpoch)
            return Error(OperationErrorCode.StaleWriterEpoch, "INV-006", "Journal contains a stale writer event.");
        var semanticError = ValidateEventSemantics(state, @event);
        if (semanticError is not null) return semanticError;
        if (@event is OperationAuthorized authorized && state.Desired is not null)
        {
            var expected = OperationDigest.Authorization(authorized.Sequence, authorized.PreviousDigest,
                authorized.OperationId, authorized.WriterEpoch, state.Desired, authorized.Evidence,
                state.PermittedCompensations);
            if (authorized.AuthorizationDigest != expected)
                return Error(OperationErrorCode.InvalidJournal, "INV-005", "Authorization commit digest is invalid.");
        }

        return (@event, state.Checkpoint, state.ResumableCheckpoint) switch
        {
            (OperationPrepared, OperationCheckpoint.None, _) => null,
            (OperationAuthorized, OperationCheckpoint.Prepared, _) => null,
            (OperationAuthorized, OperationCheckpoint.Held, OperationCheckpoint.Prepared) => null,
            (OperationDispatchRecorded, OperationCheckpoint.Authorized, _) => null,
            (OperationDispatchRecorded, OperationCheckpoint.Held, OperationCheckpoint.Authorized) => null,
            (OperationRecoveryRecorded, OperationCheckpoint.DispatchRecorded, _) => null,
            (OperationObservationRecorded, OperationCheckpoint.DispatchRecorded, _) => null,
            (OperationObservationRecorded, OperationCheckpoint.Observed, _) => null,
            (OperationTerminalRecorded, OperationCheckpoint.Observed, _) => null,
            (OperationHeld, OperationCheckpoint.Prepared or OperationCheckpoint.Authorized, _) => null,
            (OperationHeld, OperationCheckpoint.Held, OperationCheckpoint.Prepared or OperationCheckpoint.Authorized) => null,
            _ => Error(OperationErrorCode.InvalidTransition, "INV-004", "Journal checkpoint transition is invalid."),
        };
    }

    private static OperationError? ValidateEventSemantics(OperationState state, OperationEvent @event)
    {
        if (string.IsNullOrWhiteSpace(@event.OperationId) || @event.WriterEpoch <= 0 || @event.RecordedAt == default)
            return Error(OperationErrorCode.InvalidJournal, "INV-005", "Journal event has an invalid operation identity, epoch, or explicit time.");

        switch (@event)
        {
            case OperationPrepared prepared:
                if (ValidatePreparation(new PrepareOperation(prepared.OperationId, prepared.WriterEpoch,
                    prepared.RecordedAt, prepared.Desired, prepared.ExpectedObservation,
                    prepared.PermittedCompensations)) is not null)
                    return Error(OperationErrorCode.InvalidJournal, "INV-005", "Prepared journal event has incomplete immutable inputs.");
                if (prepared.RecordedAt >= prepared.Desired.Deadline ||
                    prepared.Desired.AggregateId != prepared.ExpectedObservation.AggregateId ||
                    prepared.Desired.TargetIdentity != prepared.ExpectedObservation.TargetIdentity ||
                    prepared.Desired.Generation != prepared.ExpectedObservation.Generation)
                    return Error(OperationErrorCode.InvalidJournal, "INV-005", "Prepared journal event violates deadline, target, or generation invariants.");
                break;

            case OperationAuthorized authorized when state.Desired is not null && state.ExpectedObservation is not null:
                var observed = authorized.Evidence.Observation;
                if (authorized.RecordedAt >= state.Desired.Deadline ||
                    observed.AggregateId != state.Desired.AggregateId ||
                    observed.TargetIdentity != state.Desired.TargetIdentity ||
                    observed.Generation != state.Desired.Generation || !observed.PositivelyOwned ||
                    observed.ObservationId == state.ExpectedObservation.ObservationId ||
                    observed.ResourceVersion == state.ExpectedObservation.ResourceVersion ||
                    !authorized.Evidence.ApprovalsSatisfied || !authorized.Evidence.PolicySatisfied ||
                    !authorized.Evidence.QuorumSatisfied || !authorized.Evidence.BudgetSatisfied ||
                    string.IsNullOrWhiteSpace(authorized.Evidence.ApprovalDigest) ||
                    string.IsNullOrWhiteSpace(authorized.Evidence.EvidenceDigest))
                    return Error(OperationErrorCode.InvalidJournal, "INV-004", "Authorization journal event does not satisfy the irreversible commit gates.");
                break;

            case OperationDispatchRecorded dispatch when state.Desired is not null:
                if (dispatch.RecordedAt >= state.Desired.Deadline ||
                    string.IsNullOrWhiteSpace(dispatch.ExecutorId) || dispatch.Attempt <= 0)
                    return Error(OperationErrorCode.InvalidJournal, "INV-005", "Dispatch journal event violates deadline or attempt identity.");
                break;

            case OperationRecoveryRecorded recovery when state.Dispatch is not null:
                if (string.IsNullOrWhiteSpace(recovery.ExecutorId) ||
                    recovery.DispatchSequence != state.Dispatch.Sequence ||
                    recovery.WriterEpoch <= state.HighestWriterEpoch)
                    return Error(OperationErrorCode.InvalidJournal, "INV-006", "Recovery must transfer the frozen dispatch to a strictly newer epoch.");
                break;

            case OperationObservationRecorded observation when state.Desired is not null:
                if (!Enum.IsDefined(observation.Outcome) || string.IsNullOrWhiteSpace(observation.ObservationId) ||
                    string.IsNullOrWhiteSpace(observation.TargetIdentity) ||
                    string.IsNullOrWhiteSpace(observation.TerminalState) || observation.Generation <= 0 ||
                    observation.ProviderWorkRequestId is not null && string.IsNullOrWhiteSpace(observation.ProviderWorkRequestId))
                    return Error(OperationErrorCode.InvalidJournal, "INV-005", "Provider observation identity is missing.");
                var identityMatches = observation.TargetIdentity == state.Desired.TargetIdentity &&
                    observation.Generation == state.Desired.Generation;
                var successfulTerminalMatches = observation.Outcome != ProviderOutcome.Succeeded ||
                    observation.TerminalState == state.Desired.DesiredTerminalState;
                if ((!identityMatches || !successfulTerminalMatches) && observation.Outcome != ProviderOutcome.Inconsistent)
                    return Error(OperationErrorCode.InvalidJournal, "INV-006", "Mismatched provider truth must be quarantined as inconsistent.");
                if (state.Observation is not null &&
                    state.Observation.Outcome is not (ProviderOutcome.Unknown or ProviderOutcome.InProgress))
                    return Error(OperationErrorCode.ConflictingTerminalObservation, "INV-006", "A final provider observation cannot be replaced.");
                break;

            case OperationTerminalRecorded terminal when state.Desired is not null && state.Observation is not null:
                if (!Enum.IsDefined(terminal.Outcome) ||
                    state.Observation.Outcome is not (ProviderOutcome.Succeeded or ProviderOutcome.Failed) ||
                    terminal.Outcome != state.Observation.Outcome ||
                    terminal.TerminalState != state.Observation.TerminalState ||
                    (terminal.Outcome == ProviderOutcome.Succeeded && terminal.TerminalState != state.Desired.DesiredTerminalState))
                    return Error(OperationErrorCode.ConflictingTerminalObservation, "INV-006", "Terminal journal event conflicts with provider truth or authorized intent.");
                break;

            case OperationHeld held:
                if (!Enum.IsDefined(held.HeldAfter) || !Enum.IsDefined(held.Error.Code) ||
                    held.HeldAfter != state.ResumableCheckpoint || string.IsNullOrWhiteSpace(held.Error.Requirement))
                    return Error(OperationErrorCode.InvalidJournal, "INV-005", "Hold does not preserve its resumable safety checkpoint.");
                break;
        }

        return null;
    }

    private static OperationState Apply(OperationState state, OperationEvent @event) => @event switch
    {
        OperationPrepared value => state with
        {
            OperationId = value.OperationId, Checkpoint = OperationCheckpoint.Prepared,
            LastSequence = value.Sequence, JournalDigest = value.EventDigest,
            HighestWriterEpoch = value.WriterEpoch, Desired = value.Desired,
            ExpectedObservation = value.ExpectedObservation,
            PermittedCompensations = Array.AsReadOnly(value.PermittedCompensations.ToArray()),
        },
        OperationAuthorized value => state with
        {
            Checkpoint = OperationCheckpoint.Authorized, LastSequence = value.Sequence,
            JournalDigest = value.EventDigest, HighestWriterEpoch = value.WriterEpoch,
            Authorization = value, Hold = null,
        },
        OperationDispatchRecorded value => state with
        {
            Checkpoint = OperationCheckpoint.DispatchRecorded, LastSequence = value.Sequence,
            JournalDigest = value.EventDigest, HighestWriterEpoch = value.WriterEpoch,
            Dispatch = value, Hold = null,
        },
        OperationRecoveryRecorded value => state with
        {
            Checkpoint = OperationCheckpoint.DispatchRecorded, LastSequence = value.Sequence,
            JournalDigest = value.EventDigest, HighestWriterEpoch = value.WriterEpoch,
            Recovery = value,
        },
        OperationObservationRecorded value => state with
        {
            Checkpoint = OperationCheckpoint.Observed, LastSequence = value.Sequence,
            JournalDigest = value.EventDigest, HighestWriterEpoch = value.WriterEpoch,
            Observation = value,
        },
        OperationTerminalRecorded value => state with
        {
            Checkpoint = OperationCheckpoint.Terminal, LastSequence = value.Sequence,
            JournalDigest = value.EventDigest, HighestWriterEpoch = value.WriterEpoch,
            Terminal = value,
        },
        OperationHeld value => state with
        {
            Checkpoint = OperationCheckpoint.Held, LastSequence = value.Sequence,
            JournalDigest = value.EventDigest, HighestWriterEpoch = value.WriterEpoch,
            Hold = value,
        },
        _ => throw new ArgumentOutOfRangeException(nameof(@event)),
    };

    private static T Stamp<T>(OperationState state, Func<long, string, string, T> factory) where T : OperationEvent
    {
        var provisional = factory(state.LastSequence + 1, state.JournalDigest, string.Empty);
        var digest = OperationDigest.Event(provisional);
        return factory(state.LastSequence + 1, state.JournalDigest, digest);
    }

    private static OperationDecision Append(OperationState state, OperationEvent @event)
    {
        return Commit(state, @event);
    }

    private static OperationDecision Hold(OperationState state, OperationCommand command, OperationError error)
    {
        var @event = Stamp(state, (sequence, previous, digest) => new OperationHeld(
            sequence, previous, digest, command.OperationId, command.WriterEpoch, command.Now,
            state.ResumableCheckpoint, error));
        return Commit(state, @event, errors: [error]);
    }

    private static OperationDecision Reject(OperationState state, OperationError error) =>
        OperationDecision.Create(state, errors: [error]);

    private static DispatchProviderIntent CreateIntent(OperationState state, OperationDispatchRecorded dispatch)
    {
        var desired = state.Desired ?? throw new InvalidOperationException("Dispatch requires desired state.");
        var authorization = state.Authorization ?? throw new InvalidOperationException("Dispatch requires authorization.");
        return new DispatchProviderIntent(
            dispatch.OperationId, desired.OperationKind, desired.TargetIdentity,
            desired.DesiredTerminalState, desired.PayloadDigest, desired.IdempotencyKey,
            authorization.Sequence, authorization.AuthorizationDigest, authorization.WriterEpoch,
            dispatch.WriterEpoch, dispatch.ExecutorId, dispatch.Attempt, desired.Deadline);
    }

    private static ReconcileProviderIntent CreateReconcileIntent(OperationState state, string? workRequestId)
    {
        var desired = state.Desired ?? throw new InvalidOperationException("Reconciliation requires desired state.");
        var authorization = state.Authorization ?? throw new InvalidOperationException("Reconciliation requires authorization.");
        return new ReconcileProviderIntent(state.OperationId!, desired.TargetIdentity, desired.Generation,
            desired.IdempotencyKey, workRequestId, authorization.Sequence, authorization.AuthorizationDigest);
    }

    private static OperationDecision Commit(
        OperationState state,
        OperationEvent @event,
        IEnumerable<OperationIntent>? intents = null,
        IEnumerable<OperationError>? errors = null)
    {
        var validation = ValidateNextEvent(state, @event);
        if (validation is not null) return Reject(state, validation);
        return OperationDecision.Create(Apply(state, @event), [@event], intents, errors);
    }

    private static bool ObservationMatches(OperationObservationRecorded existing, RecordObservation command) =>
        existing.ObservationId == command.ObservationId && existing.TargetIdentity == command.TargetIdentity &&
        existing.Generation == command.Generation && existing.TerminalState == command.TerminalState &&
        existing.Outcome == command.Outcome && existing.ProviderWorkRequestId == command.ProviderWorkRequestId;

    private static bool IsCompleteObservation(ObservedResource observation) =>
        !string.IsNullOrWhiteSpace(observation.AggregateId) && observation.Generation > 0 &&
        !string.IsNullOrWhiteSpace(observation.ResourceVersion) &&
        !string.IsNullOrWhiteSpace(observation.ObservationId) &&
        !string.IsNullOrWhiteSpace(observation.TargetIdentity) &&
        !string.IsNullOrWhiteSpace(observation.State);

    private static OperationError Error(OperationErrorCode code, string requirement, string message) =>
        new(code, requirement, message);
}
