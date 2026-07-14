namespace TerraScale.Orchestrator.ControlPlane.Authority;

public static class AuthorityEngine
{
    public static AuthorityDecision Decide(IReadOnlyList<AuthorityEvent> history, AuthorityCommand command)
    {
        ArgumentNullException.ThrowIfNull(history);
        ArgumentNullException.ThrowIfNull(command);
        var replay = Replay(history);
        if (replay.Errors.Count != 0) return replay;
        var state = replay.State;
        var common = ValidateCommand(state, command);
        if (common is not null) return Reject(state, common);
        if (state.Status == AuthorityStatus.Fenced)
            return Reject(state, Error(AuthorityErrorCode.Fenced, "INV-004", "A fenced candidate cannot self-unfence."));

        return command switch
        {
            AcquireAuthority value => Acquire(state, value),
            RenewAuthority value => Renew(state, value),
            ReleaseAuthority value => Release(state, value),
            RequestAuthorityRead value => RequestRead(state, value),
            ObserveAuthorityCas value => ObserveSet(state, value),
            ObserveAuthorityDelete value => ObserveDelete(state, value),
            ObserveAuthorityRead value => ObserveRead(state, value),
            EvaluateMutationAuthority value => Evaluate(state, value),
            _ => Reject(state, Error(AuthorityErrorCode.InvalidInput, "INV-005", "Unknown authority command.")),
        };
    }

    public static AuthorityDecision Replay(IReadOnlyList<AuthorityEvent> history)
    {
        ArgumentNullException.ThrowIfNull(history);
        var state = AuthorityState.Empty;
        if (history.Any(static item => item is null))
            return Reject(state, Error(AuthorityErrorCode.InvalidJournal, "INV-005", "Authority journal contains a null event."));

        foreach (var group in history.GroupBy(static item => item.Sequence).OrderBy(static group => group.Key))
        {
            var first = group.First();
            try
            {
                if (group.Any(item => item.EventDigest != AuthorityDigest.Event(item)))
                    return Reject(state, Error(AuthorityErrorCode.InvalidJournal, "INV-005", "Authority event digest does not match its body."));
            }
            catch (ArgumentException)
            {
                return Reject(state, Error(AuthorityErrorCode.InvalidJournal, "INV-005", "Authority journal contains an unknown event type."));
            }

            if (group.Any(item => item.EventDigest != first.EventDigest))
                return Reject(state, Error(AuthorityErrorCode.ConflictingJournalEvent, "INV-005", "A sequence contains conflicting event bodies."));
            var error = ValidateNext(state, first);
            if (error is not null) return Reject(state, error);
            state = Apply(state, first);
        }

        return AuthorityDecision.Create(state);
    }

    private static AuthorityDecision Acquire(AuthorityState state, AcquireAuthority command)
    {
        if (state.Status is not (AuthorityStatus.Follower or AuthorityStatus.ReadOnlyHeld))
            return Reject(state, Error(AuthorityErrorCode.InvalidTransition, "INV-004", "Acquisition requires follower or held state."));
        var completed = CompletedRequestReuse(state, command.RequestId);
        if (completed is not null) return Reject(state, completed);
        var input = ValidateObservation(command.Baseline) ?? ValidateHealth(command.Health);
        if (input is not null || string.IsNullOrWhiteSpace(command.LeaseId) || command.LeaseDuration <= TimeSpan.Zero)
            return Reject(state, input ?? Error(AuthorityErrorCode.InvalidInput, "INV-005", "Lease ID and positive duration are required."));
        var health = SafetyError(command.Health);
        if (health is not null) return Hold(state, command, health);
        if (command.Baseline.AuthorityId != command.AuthorityId)
            return Reject(state, Error(AuthorityErrorCode.IdentityMismatch, "INV-004", "Acquisition observation belongs to another authority."));
        if (command.Baseline.Epoch < state.HighestEpoch)
            return Reject(state, Error(AuthorityErrorCode.EpochMismatch, "INV-004", "Acquisition baseline epoch is stale."));
        if (command.Baseline.KvRevision < state.HighestKvRevision)
            return Reject(state, Error(AuthorityErrorCode.RevisionMismatch, "INV-004", "Acquisition baseline revision is stale."));
        if (command.Baseline.Lease is not null)
        {
            var leaseError = LeaseError(command.Baseline, command.Health);
            if (leaseError?.Code is AuthorityErrorCode.ClockAnomaly or AuthorityErrorCode.ArithmeticOverflow)
                return Hold(state, command, leaseError);
            if (leaseError?.Code != AuthorityErrorCode.LeaseExpired)
                return Reject(state, leaseError ?? Error(AuthorityErrorCode.LeaseActive, "INV-004", "Observed lease is still active."));
        }

        long epoch;
        try { epoch = checked(command.Baseline.Epoch + 1); }
        catch (OverflowException) { return Hold(state, command, Error(AuthorityErrorCode.ArithmeticOverflow, "INV-004", "Fencing epoch overflowed.")); }
        if (command.Baseline.KvRevision == long.MaxValue)
            return Hold(state, command, Error(AuthorityErrorCode.ArithmeticOverflow, "INV-004", "KV revision cannot advance."));
        if (!CanAdd(command.Health.ServerTime, command.LeaseDuration))
            return Hold(state, command, Error(AuthorityErrorCode.ArithmeticOverflow, "INV-005", "Lease expiry overflows timestamp range."));

        var lease = new AuthorityLease(command.CandidateId, command.LeaseId, command.Health.ServerTime, command.LeaseDuration);
        var pending = new PendingAuthoritySet(command.RequestId, command.Baseline.KvRevision,
            command.Baseline.Epoch, epoch, lease, command.Baseline, command.Health, false);
        var @event = Stamp(state, (sequence, previous, digest) => new AuthoritySetRequested(
            sequence, previous, digest, command.AuthorityId, command.CandidateId, command.RequestId, pending));
        var intent = new CompareAndSetLeaseIntent(command.AuthorityId, command.RequestId,
            pending.ExpectedRevision, pending.ExpectedEpoch, pending.ProposedEpoch, pending.ProposedLease);
        return Commit(state, @event, [intent]);
    }

    private static AuthorityDecision Renew(AuthorityState state, RenewAuthority command)
    {
        if (state.Status != AuthorityStatus.Leader || state.Confirmed is null)
            return Reject(state, Error(AuthorityErrorCode.InvalidTransition, "INV-004", "Renewal requires confirmed leader state."));
        var completed = CompletedRequestReuse(state, command.RequestId);
        if (completed is not null) return Reject(state, completed);
        var input = ValidateObservation(command.Current) ?? ValidateHealth(command.Health);
        if (input is not null || command.LeaseDuration <= TimeSpan.Zero)
            return Reject(state, input ?? Error(AuthorityErrorCode.InvalidInput, "INV-005", "Positive renewal duration is required."));
        if (command.Current.AuthorityId != command.AuthorityId)
            return Reject(state, Error(AuthorityErrorCode.IdentityMismatch, "INV-004", "Renewal observation belongs to another authority."));
        if (command.Current.KvRevision == long.MaxValue)
            return Hold(state, command, Error(AuthorityErrorCode.ArithmeticOverflow, "INV-004", "KV revision cannot advance."));
        var exact = EnsureExactCurrent(state, command.Current, command.Health);
        if (exact is not null) return LoseAuthority(state, command, command.Current, exact);
        if (!CanAdd(command.Health.ServerTime, command.LeaseDuration))
            return Hold(state, command, Error(AuthorityErrorCode.ArithmeticOverflow, "INV-004", "Renewal expiry overflows timestamp range."));

        var lease = new AuthorityLease(command.CandidateId, state.Confirmed.Lease!.LeaseId,
            command.Health.ServerTime, command.LeaseDuration);
        var pending = new PendingAuthoritySet(command.RequestId, command.Current.KvRevision,
            command.Current.Epoch, command.Current.Epoch, lease, command.Current, command.Health, true);
        var @event = Stamp(state, (sequence, previous, digest) => new AuthoritySetRequested(
            sequence, previous, digest, command.AuthorityId, command.CandidateId, command.RequestId, pending));
        return Commit(state, @event, [new CompareAndSetLeaseIntent(command.AuthorityId,
            command.RequestId, pending.ExpectedRevision, pending.ExpectedEpoch, pending.ProposedEpoch, lease)]);
    }

    private static AuthorityDecision Release(AuthorityState state, ReleaseAuthority command)
    {
        if (state.Status != AuthorityStatus.Leader || state.Confirmed?.Lease is null)
            return Reject(state, Error(AuthorityErrorCode.InvalidTransition, "INV-004", "Release requires confirmed leader state."));
        var completed = CompletedRequestReuse(state, command.RequestId);
        if (completed is not null) return Reject(state, completed);
        var input = ValidateObservation(command.Current) ?? ValidateHealth(command.Health);
        if (input is not null) return Reject(state, input);
        if (command.Current.AuthorityId != command.AuthorityId)
            return Reject(state, Error(AuthorityErrorCode.IdentityMismatch, "INV-004", "Release observation belongs to another authority."));
        if (command.Current.KvRevision == long.MaxValue)
            return Hold(state, command, Error(AuthorityErrorCode.ArithmeticOverflow, "INV-004", "KV revision cannot advance."));
        var exact = EnsureExactCurrent(state, command.Current, command.Health);
        if (exact is not null) return LoseAuthority(state, command, command.Current, exact);
        var pending = new PendingAuthorityDelete(command.RequestId, command.Current.KvRevision,
            command.Current.Epoch, command.Current.Lease!, command.Health);
        var @event = Stamp(state, (sequence, previous, digest) => new AuthorityDeleteRequested(
            sequence, previous, digest, command.AuthorityId, command.CandidateId, command.RequestId, pending));
        return Commit(state, @event, [new CompareAndDeleteLeaseIntent(command.AuthorityId,
            command.RequestId, pending.ExpectedRevision, pending.ExpectedEpoch, pending.ExpectedLease)]);
    }

    private static AuthorityDecision RequestRead(AuthorityState state, RequestAuthorityRead command)
    {
        if (state.Status is AuthorityStatus.AcquisitionPending or AuthorityStatus.RenewalPending or AuthorityStatus.ReleasePending)
            return Reject(state, Error(AuthorityErrorCode.InvalidTransition, "INV-004", "A CAS result must resolve before a read request."));
        var completed = CompletedRequestReuse(state, command.RequestId);
        if (completed is not null) return Reject(state, completed);
        var resume = state.Status == AuthorityStatus.ReadOnlyHeld && state.ReadResumeStatus == AuthorityStatus.Leader
            ? AuthorityStatus.Leader : state.Status;
        if (resume == AuthorityStatus.Leader && state.Confirmed?.Lease?.CandidateId != command.CandidateId)
            return Reject(state, Error(AuthorityErrorCode.IdentityMismatch, "INV-004", "Only the confirmed lease candidate may re-read leader authority."));
        var @event = Stamp(state, (sequence, previous, digest) => new AuthorityReadRequested(
            sequence, previous, digest, command.AuthorityId, command.CandidateId, command.RequestId, resume));
        return Commit(state, @event, [new ReadAuthorityIntent(command.AuthorityId, command.RequestId)]);
    }

    private static AuthorityDecision ObserveSet(AuthorityState state, ObserveAuthorityCas command)
    {
        if (state.LastCompletedRequestId == command.RequestId) return AuthorityDecision.Create(state);
        var healthInput = ValidateHealth(command.Health);
        if (healthInput is not null) return Reject(state, healthInput);
        if (state.PendingSet is null || state.PendingSet.RequestId != command.RequestId ||
            state.PendingSet.ProposedLease.CandidateId != command.CandidateId ||
            state.Status is not (AuthorityStatus.AcquisitionPending or AuthorityStatus.RenewalPending))
            return Reject(state, Error(AuthorityErrorCode.StaleObservation, "INV-005", "CAS observation does not match the pending request."));
        if (!Enum.IsDefined(command.Outcome))
            return Reject(state, Error(AuthorityErrorCode.InvalidInput, "INV-005", "CAS outcome is outside the closed vocabulary."));
        if (command.Observation is not null && command.Observation.AuthorityId != command.AuthorityId)
            return Reject(state, Error(AuthorityErrorCode.IdentityMismatch, "INV-004", "CAS observation belongs to another authority."));
        if (command.Observation is not null)
        {
            var suppliedObservation = ValidateObservation(command.Observation);
            if (suppliedObservation is not null) return Reject(state, suppliedObservation);
        }
        var pending = state.PendingSet;
        if (command.Outcome == AuthorityCasOutcome.Succeeded)
        {
            var observationError = command.Observation is null ? Error(AuthorityErrorCode.InvalidInput, "INV-005", "Successful CAS requires an observation.") : ValidateObservation(command.Observation);
            if (observationError is not null) return Reject(state, observationError);
            long revision;
            try { revision = checked(pending.ExpectedRevision + 1); }
            catch (OverflowException) { return Hold(state, command, Error(AuthorityErrorCode.ArithmeticOverflow, "INV-004", "KV revision overflowed.")); }
            if (command.Observation!.KvRevision != revision || command.Observation.Epoch != pending.ProposedEpoch ||
                command.Observation.Lease != pending.ProposedLease)
                return Fence(state, command, command.Observation, Error(AuthorityErrorCode.RevisionMismatch, "INV-004", "Successful CAS observation does not exactly match the proposed lease."));
            var safety = SafetyError(command.Health) ?? LeaseError(command.Observation, command.Health);
            if (safety is not null) return LoseAuthority(state, command, command.Observation, safety);
            var confirmed = Stamp(state, (sequence, previous, digest) => new AuthoritySetConfirmed(
                sequence, previous, digest, command.AuthorityId, command.CandidateId, command.RequestId,
                command.Observation, command.Health, pending.IsRenewal));
            return Commit(state, confirmed, mutationPermit: CreatePermit(command.Observation, command.Health));
        }

        var error = command.Outcome switch
        {
            AuthorityCasOutcome.Conflict => Error(AuthorityErrorCode.CasConflict, "INV-004", "Lease CAS conflicted."),
            AuthorityCasOutcome.Failed => Error(AuthorityErrorCode.CasFailed, "INV-004", "Lease CAS failed."),
            AuthorityCasOutcome.Uncertain => Error(AuthorityErrorCode.CasUncertain, "INV-004", "Lease CAS outcome is uncertain."),
            _ => Error(AuthorityErrorCode.InvalidInput, "INV-005", "Invalid CAS outcome."),
        };
        var rejected = Stamp(state, (sequence, previous, digest) => new AuthoritySetRejected(
            sequence, previous, digest, command.AuthorityId, command.CandidateId, command.RequestId,
            command.Outcome, command.Observation, error));
        return Commit(state, rejected, errors: [error]);
    }

    private static AuthorityDecision ObserveDelete(AuthorityState state, ObserveAuthorityDelete command)
    {
        if (state.LastCompletedRequestId == command.RequestId) return AuthorityDecision.Create(state);
        var healthInput = ValidateHealth(command.Health);
        if (healthInput is not null) return Reject(state, healthInput);
        if (state.Status != AuthorityStatus.ReleasePending || state.PendingDelete is null ||
            state.PendingDelete.RequestId != command.RequestId ||
            state.PendingDelete.ExpectedLease.CandidateId != command.CandidateId)
            return Reject(state, Error(AuthorityErrorCode.StaleObservation, "INV-005", "Delete observation does not match pending release."));
        if (!Enum.IsDefined(command.Outcome)) return Reject(state, Error(AuthorityErrorCode.InvalidInput, "INV-005", "Delete outcome is invalid."));
        if (command.Observation is not null && command.Observation.AuthorityId != command.AuthorityId)
            return Reject(state, Error(AuthorityErrorCode.IdentityMismatch, "INV-004", "Delete observation belongs to another authority."));
        if (command.Observation is not null)
        {
            var suppliedObservation = ValidateObservation(command.Observation);
            if (suppliedObservation is not null) return Reject(state, suppliedObservation);
        }
        if (command.Outcome != AuthorityCasOutcome.Succeeded || command.Observation is null)
            return Fence(state, command, command.Observation, Error(command.Outcome switch
            {
                AuthorityCasOutcome.Conflict => AuthorityErrorCode.CasConflict,
                AuthorityCasOutcome.Uncertain => AuthorityErrorCode.CasUncertain,
                _ => AuthorityErrorCode.CasFailed,
            }, "INV-004", "Release was not exactly confirmed."));
        var validation = ValidateObservation(command.Observation);
        if (validation is not null) return Reject(state, validation);
        var pending = state.PendingDelete;
        long revision;
        try { revision = checked(pending.ExpectedRevision + 1); }
        catch (OverflowException) { return Hold(state, command, Error(AuthorityErrorCode.ArithmeticOverflow, "INV-004", "KV revision overflowed.")); }
        if (command.Observation.KvRevision != revision || command.Observation.Epoch != pending.ExpectedEpoch || command.Observation.Lease is not null)
            return Fence(state, command, command.Observation, Error(AuthorityErrorCode.RevisionMismatch, "INV-004", "Compare-and-delete observation does not exactly confirm absence."));
        var @event = Stamp(state, (sequence, previous, digest) => new AuthorityDeleteConfirmed(
            sequence, previous, digest, command.AuthorityId, command.CandidateId, command.RequestId, command.Observation));
        return Commit(state, @event);
    }

    private static AuthorityDecision ObserveRead(AuthorityState state, ObserveAuthorityRead command)
    {
        if (state.LastCompletedRequestId == command.RequestId) return AuthorityDecision.Create(state);
        var healthInput = ValidateHealth(command.Health);
        if (healthInput is not null) return Reject(state, healthInput);
        if (!Enum.IsDefined(command.Outcome))
            return Reject(state, Error(AuthorityErrorCode.InvalidInput, "INV-005", "Read outcome is outside the closed vocabulary."));
        if (state.PendingReadRequestId != command.RequestId || state.PendingReadCandidateId != command.CandidateId)
            return Reject(state, Error(AuthorityErrorCode.StaleObservation, "INV-005", "Read observation does not match pending read."));
        if (command.Outcome != AuthorityCasOutcome.Succeeded || command.Observation is null)
            return Hold(state, command, Error(AuthorityErrorCode.CasUncertain, "INV-004", "Authority read is not certain."));
        if (command.Observation.AuthorityId != command.AuthorityId)
            return Reject(state, Error(AuthorityErrorCode.IdentityMismatch, "INV-004", "Read observation belongs to another authority."));
        var validation = ValidateObservation(command.Observation) ?? ValidateHealth(command.Health);
        if (validation is not null) return Reject(state, validation);
        if (state.ReadResumeStatus == AuthorityStatus.Leader)
        {
            var exact = EnsureExactCurrent(state, command.Observation, command.Health);
            if (exact is not null) return LoseAuthority(state, command, command.Observation, exact);
        }
        var @event = Stamp(state, (sequence, previous, digest) => new AuthorityReadConfirmed(
            sequence, previous, digest, command.AuthorityId, command.CandidateId, command.RequestId,
            command.Observation, command.Health));
        return Commit(state, @event, mutationPermit: state.ReadResumeStatus == AuthorityStatus.Leader
            ? CreatePermit(command.Observation, command.Health) : null);
    }

    private static AuthorityDecision Evaluate(AuthorityState state, EvaluateMutationAuthority command)
    {
        if (state.Status != AuthorityStatus.Leader || state.Confirmed is null)
            return Reject(state, Error(AuthorityErrorCode.InvalidTransition, "INV-004", "Mutation authority requires confirmed leader state."));
        var input = ValidateObservation(command.Observation) ?? ValidateHealth(command.Health);
        if (input is not null) return Reject(state, input);
        if (command.Observation.AuthorityId != command.AuthorityId || state.Confirmed.Lease?.CandidateId != command.CandidateId)
            return Reject(state, Error(AuthorityErrorCode.IdentityMismatch, "INV-004", "Mutation evaluation identity differs from confirmed lease."));
        var exact = EnsureExactCurrent(state, command.Observation, command.Health);
        return exact is null ? AuthorityDecision.Create(state, mutationPermit: CreatePermit(command.Observation, command.Health)) :
            LoseAuthority(state, command, command.Observation, exact);
    }

    private static AuthorityError? EnsureExactCurrent(AuthorityState state, AuthorityObservation observation, AuthorityHealth health)
    {
        var safety = SafetyError(health);
        if (safety is not null) return safety;
        if (state.Confirmed is null || observation.AuthorityId != state.AuthorityId)
            return Error(AuthorityErrorCode.IdentityMismatch, "INV-004", "Authority observation identity differs.");
        if (observation.Epoch > state.Confirmed.Epoch)
            return Error(AuthorityErrorCode.EpochMismatch, "INV-004", "A higher fencing epoch was observed.");
        if (observation != state.Confirmed)
            return Error(observation.Epoch != state.Confirmed.Epoch ? AuthorityErrorCode.EpochMismatch : AuthorityErrorCode.RevisionMismatch,
                "INV-004", "Lease observation does not exactly match confirmed ownership.");
        return LeaseError(observation, health);
    }

    private static AuthorityError? LeaseError(AuthorityObservation observation, AuthorityHealth health)
    {
        if (observation.Lease is null) return Error(AuthorityErrorCode.LeaseExpired, "INV-004", "No active lease is observed.");
        if (health.ServerTime < observation.Lease.ServerIssuedAt || health.MonotonicElapsed < TimeSpan.Zero)
            return Error(AuthorityErrorCode.ClockAnomaly, "INV-004", "Lease time moved backwards.");
        if (!CanAdd(observation.Lease.ServerIssuedAt, observation.Lease.Duration))
            return Error(AuthorityErrorCode.ArithmeticOverflow, "INV-004", "Lease expiry overflows timestamp range.");
        var expiry = observation.Lease.ServerIssuedAt + observation.Lease.Duration;
        return health.MonotonicElapsed >= observation.Lease.Duration || health.ServerTime >= expiry
            ? Error(AuthorityErrorCode.LeaseExpired, "INV-004", "Lease is expired at the supplied time boundary.")
            : null;
    }

    private static AuthorityError? SafetyError(AuthorityHealth health)
    {
        if (!health.PartitionCertain) return Error(AuthorityErrorCode.PartitionUncertain, "INV-004", "Partition certainty is lost.");
        if (!health.ClockCertain) return Error(AuthorityErrorCode.ClockAnomaly, "INV-004", "Clock certainty is lost.");
        return null;
    }

    private static AuthorityError? ValidateCommand(AuthorityState state, AuthorityCommand command)
    {
        if (string.IsNullOrWhiteSpace(command.AuthorityId) || string.IsNullOrWhiteSpace(command.CandidateId) || string.IsNullOrWhiteSpace(command.RequestId))
            return Error(AuthorityErrorCode.InvalidInput, "INV-005", "Authority, candidate, and request identities are required.");
        if (state.AuthorityId is not null &&
            (state.AuthorityId != command.AuthorityId || state.CandidateId != command.CandidateId))
            return Error(AuthorityErrorCode.IdentityMismatch, "INV-004", "Command identity differs from journal ownership.");
        return null;
    }

    private static AuthorityError? ValidateObservation(AuthorityObservation observation)
    {
        if (observation is null || string.IsNullOrWhiteSpace(observation.AuthorityId) ||
            string.IsNullOrWhiteSpace(observation.ObservationId) || observation.KvRevision < 0 || observation.Epoch < 0 ||
            ((observation.KvRevision == 0 || observation.Epoch == 0) &&
             (observation.KvRevision != 0 || observation.Epoch != 0 || observation.Lease is not null)))
            return Error(AuthorityErrorCode.InvalidInput, "INV-005", "Observation requires stable identity and either genesis zeroes or positive revision/epoch.");
        if (observation.Lease is not null && (string.IsNullOrWhiteSpace(observation.Lease.CandidateId) ||
            string.IsNullOrWhiteSpace(observation.Lease.LeaseId) || observation.Lease.ServerIssuedAt == default || observation.Lease.Duration <= TimeSpan.Zero))
            return Error(AuthorityErrorCode.InvalidInput, "INV-005", "Observed lease is malformed.");
        return null;
    }

    private static AuthorityError? ValidateHealth(AuthorityHealth health) =>
        health is null || health.ServerTime == default || health.MonotonicElapsed < TimeSpan.Zero
            ? Error(AuthorityErrorCode.InvalidInput, "INV-005", "Explicit server time and lease duration are required.")
            : null;

    private static AuthorityDecision LoseAuthority(AuthorityState state, AuthorityCommand command, AuthorityObservation? observation, AuthorityError error) =>
        error.Code is AuthorityErrorCode.PartitionUncertain or AuthorityErrorCode.ClockAnomaly
            ? Hold(state, command, error)
            : Fence(state, command, observation, error);

    private static AuthorityDecision Hold(AuthorityState state, AuthorityCommand command, AuthorityError error)
    {
        var @event = Stamp(state, (sequence, previous, digest) => new AuthorityHeld(
            sequence, previous, digest, command.AuthorityId, command.CandidateId, command.RequestId,
            state.Status, ObservationFrom(command), error));
        return Commit(state, @event, errors: [error]);
    }

    private static AuthorityDecision Fence(AuthorityState state, AuthorityCommand command, AuthorityObservation? observation, AuthorityError error)
    {
        var @event = Stamp(state, (sequence, previous, digest) => new AuthorityFencedEvent(
            sequence, previous, digest, command.AuthorityId, command.CandidateId, command.RequestId,
            observation, error));
        return Commit(state, @event, errors: [error]);
    }

    private static AuthorityError? ValidateNext(AuthorityState state, AuthorityEvent @event)
    {
        if (@event.Sequence != state.LastSequence + 1 || @event.PreviousDigest != state.JournalDigest ||
            @event.EventDigest != AuthorityDigest.Event(@event))
            return Error(AuthorityErrorCode.InvalidJournal, "INV-005", "Authority journal chain is not append-only.");
        if (string.IsNullOrWhiteSpace(@event.AuthorityId) || string.IsNullOrWhiteSpace(@event.CandidateId) || string.IsNullOrWhiteSpace(@event.RequestId))
            return Error(AuthorityErrorCode.InvalidJournal, "INV-005", "Authority event identity is malformed.");
        if (state.AuthorityId is not null &&
            (state.AuthorityId != @event.AuthorityId || state.CandidateId != @event.CandidateId))
            return Error(AuthorityErrorCode.IdentityMismatch, "INV-004", "Authority journal mixes identities.");
        var semantic = ValidateEventSemantics(state, @event);
        if (semantic is not null) return semantic;
        return (@event, state.Status) switch
        {
            (AuthoritySetRequested { Pending.IsRenewal: false }, AuthorityStatus.Follower or AuthorityStatus.ReadOnlyHeld) => null,
            (AuthoritySetRequested { Pending.IsRenewal: true }, AuthorityStatus.Leader) => null,
            (AuthoritySetConfirmed, AuthorityStatus.AcquisitionPending or AuthorityStatus.RenewalPending) => null,
            (AuthoritySetRejected, AuthorityStatus.AcquisitionPending or AuthorityStatus.RenewalPending) => null,
            (AuthorityDeleteRequested, AuthorityStatus.Leader) => null,
            (AuthorityDeleteConfirmed, AuthorityStatus.ReleasePending) => null,
            (AuthorityReadRequested, AuthorityStatus.Follower or AuthorityStatus.Leader or AuthorityStatus.ReadOnlyHeld) => null,
            (AuthorityReadConfirmed, AuthorityStatus.ReadOnlyHeld) => null,
            (AuthorityHeld, AuthorityStatus.Follower or AuthorityStatus.Leader or AuthorityStatus.ReadOnlyHeld or AuthorityStatus.AcquisitionPending or AuthorityStatus.RenewalPending or AuthorityStatus.ReleasePending) => null,
            (AuthorityFencedEvent, _) when state.Status != AuthorityStatus.Fenced => null,
            _ => Error(AuthorityErrorCode.InvalidTransition, "INV-004", "Authority journal transition is invalid."),
        };
    }

    private static AuthorityError? ValidateEventSemantics(AuthorityState state, AuthorityEvent @event)
    {
        switch (@event)
        {
            case AuthoritySetRequested requested:
                var pending = requested.Pending;
                if (pending.RequestId != requested.RequestId || pending.ExpectedRevision < 0 ||
                    pending.ExpectedEpoch < 0 || pending.ProposedEpoch <= 0 ||
                    ValidateLease(pending.ProposedLease) is not null ||
                    ValidateObservation(pending.ExpectedObservation) is not null ||
                    ValidateHealth(pending.RequestedAtHealth) is not null ||
                    pending.ExpectedRevision != pending.ExpectedObservation.KvRevision ||
                    pending.ExpectedEpoch != pending.ExpectedObservation.Epoch ||
                    pending.ExpectedObservation.AuthorityId != requested.AuthorityId ||
                    SafetyError(pending.RequestedAtHealth) is not null)
                    return Error(AuthorityErrorCode.InvalidJournal, "INV-005", "Pending CAS set is malformed.");
                if (pending.IsRenewal)
                {
                    if (state.Confirmed is null || pending.ProposedEpoch != pending.ExpectedEpoch ||
                        pending.ExpectedRevision != state.Confirmed.KvRevision ||
                        pending.ExpectedEpoch != state.Confirmed.Epoch ||
                        pending.ExpectedObservation != state.Confirmed ||
                        pending.ProposedLease.CandidateId != state.CandidateId ||
                        pending.ProposedLease.LeaseId != state.Confirmed.Lease?.LeaseId ||
                        pending.ProposedLease.ServerIssuedAt != pending.RequestedAtHealth.ServerTime ||
                        EnsureExactCurrent(state, pending.ExpectedObservation, pending.RequestedAtHealth) is not null)
                        return Error(AuthorityErrorCode.InvalidJournal, "INV-004", "Renewal request does not preserve exact lease ownership and epoch.");
                }
                else
                {
                    if (pending.ExpectedEpoch < state.HighestEpoch ||
                        pending.ExpectedRevision < state.HighestKvRevision)
                        return Error(AuthorityErrorCode.InvalidJournal, "INV-004", "Acquisition baseline regresses persisted authority high-water.");
                    var baselineLease = pending.ExpectedObservation.Lease;
                    if (baselineLease is not null &&
                        LeaseError(pending.ExpectedObservation, pending.RequestedAtHealth)?.Code != AuthorityErrorCode.LeaseExpired)
                        return Error(AuthorityErrorCode.InvalidJournal, "INV-004", "Acquisition baseline lease was not expired.");
                    if (pending.ProposedLease.CandidateId != requested.CandidateId ||
                        pending.ProposedLease.ServerIssuedAt != pending.RequestedAtHealth.ServerTime)
                        return Error(AuthorityErrorCode.InvalidJournal, "INV-004", "Acquisition proposal identity/time differs from request evidence.");
                    try
                    {
                        if (pending.ProposedEpoch != checked(pending.ExpectedEpoch + 1))
                            return Error(AuthorityErrorCode.InvalidJournal, "INV-004", "Acquisition does not advance exactly one epoch.");
                    }
                    catch (OverflowException)
                    {
                        return Error(AuthorityErrorCode.InvalidJournal, "INV-004", "Acquisition epoch overflowed in journal.");
                    }
                }
                break;

            case AuthoritySetConfirmed confirmed:
                if (state.PendingSet is null || state.PendingSet.RequestId != confirmed.RequestId ||
                    confirmed.WasRenewal != state.PendingSet.IsRenewal ||
                    ValidateObservation(confirmed.Observation) is not null ||
                    ValidateHealth(confirmed.Health) is not null ||
                    confirmed.Observation.Epoch != state.PendingSet.ProposedEpoch ||
                    confirmed.Observation.Lease != state.PendingSet.ProposedLease ||
                    confirmed.Observation.AuthorityId != confirmed.AuthorityId ||
                    confirmed.CandidateId != state.PendingSet.ProposedLease.CandidateId)
                    return Error(AuthorityErrorCode.InvalidJournal, "INV-004", "Confirmed CAS does not exactly match pending request.");
                try
                {
                    if (confirmed.Observation.KvRevision != checked(state.PendingSet.ExpectedRevision + 1))
                        return Error(AuthorityErrorCode.InvalidJournal, "INV-004", "Confirmed CAS revision is not the exact successor.");
                }
                catch (OverflowException)
                {
                    return Error(AuthorityErrorCode.InvalidJournal, "INV-004", "Confirmed CAS revision overflowed.");
                }
                if (SafetyError(confirmed.Health) is not null || LeaseError(confirmed.Observation, confirmed.Health) is not null)
                    return Error(AuthorityErrorCode.InvalidJournal, "INV-004", "Confirmed lease was not valid at supplied result time.");
                break;

            case AuthoritySetRejected rejected:
                if (state.PendingSet is null || state.PendingSet.RequestId != rejected.RequestId ||
                    !Enum.IsDefined(rejected.Outcome) || rejected.Outcome == AuthorityCasOutcome.Succeeded ||
                    !Enum.IsDefined(rejected.Error.Code) ||
                    rejected.Observation is not null && ValidateObservation(rejected.Observation) is not null ||
                    rejected.Observation is not null && rejected.Observation.AuthorityId != rejected.AuthorityId ||
                    rejected.Error.Code != rejected.Outcome switch
                    {
                        AuthorityCasOutcome.Conflict => AuthorityErrorCode.CasConflict,
                        AuthorityCasOutcome.Failed => AuthorityErrorCode.CasFailed,
                        AuthorityCasOutcome.Uncertain => AuthorityErrorCode.CasUncertain,
                        _ => rejected.Error.Code,
                    })
                    return Error(AuthorityErrorCode.InvalidJournal, "INV-005", "Rejected CAS event does not match pending request.");
                break;

            case AuthorityDeleteRequested requested:
                if (state.Confirmed?.Lease is null || requested.Pending.RequestId != requested.RequestId ||
                    requested.CandidateId != state.Confirmed.Lease.CandidateId ||
                    requested.Pending.ExpectedRevision != state.Confirmed.KvRevision ||
                    requested.Pending.ExpectedEpoch != state.Confirmed.Epoch ||
                    requested.Pending.ExpectedLease != state.Confirmed.Lease ||
                    ValidateHealth(requested.Pending.RequestedAtHealth) is not null ||
                    EnsureExactCurrent(state, state.Confirmed, requested.Pending.RequestedAtHealth) is not null)
                    return Error(AuthorityErrorCode.InvalidJournal, "INV-004", "Delete request does not exactly match confirmed lease.");
                break;

            case AuthorityDeleteConfirmed confirmed:
                if (state.PendingDelete is null || confirmed.RequestId != state.PendingDelete.RequestId ||
                    ValidateObservation(confirmed.Observation) is not null || confirmed.Observation.Lease is not null ||
                    confirmed.Observation.Epoch != state.PendingDelete.ExpectedEpoch ||
                    confirmed.Observation.AuthorityId != confirmed.AuthorityId ||
                    confirmed.CandidateId != state.PendingDelete.ExpectedLease.CandidateId)
                    return Error(AuthorityErrorCode.InvalidJournal, "INV-004", "Delete confirmation does not prove exact absence.");
                try
                {
                    if (confirmed.Observation.KvRevision != checked(state.PendingDelete.ExpectedRevision + 1))
                        return Error(AuthorityErrorCode.InvalidJournal, "INV-004", "Delete confirmation revision is not the exact successor.");
                }
                catch (OverflowException)
                {
                    return Error(AuthorityErrorCode.InvalidJournal, "INV-004", "Delete confirmation revision overflowed.");
                }
                break;

            case AuthorityReadRequested requested:
                if (!Enum.IsDefined(requested.ResumeStatus) || requested.ResumeStatus == AuthorityStatus.Fenced)
                    return Error(AuthorityErrorCode.InvalidJournal, "INV-004", "Read request has invalid resume state.");
                break;

            case AuthorityReadConfirmed confirmed:
                if (state.PendingReadRequestId != confirmed.RequestId ||
                    state.PendingReadCandidateId != confirmed.CandidateId ||
                    ValidateObservation(confirmed.Observation) is not null || ValidateHealth(confirmed.Health) is not null ||
                    confirmed.Observation.AuthorityId != confirmed.AuthorityId)
                    return Error(AuthorityErrorCode.InvalidJournal, "INV-005", "Read confirmation does not match pending read.");
                if (state.ReadResumeStatus == AuthorityStatus.Leader && EnsureExactCurrent(state, confirmed.Observation, confirmed.Health) is not null)
                    return Error(AuthorityErrorCode.InvalidJournal, "INV-004", "Read cannot restore leader from mismatched or unsafe lease truth.");
                break;

            case AuthorityHeld held:
                if (!Enum.IsDefined(held.HeldFrom) || !Enum.IsDefined(held.Error.Code) || held.HeldFrom != state.Status ||
                    string.IsNullOrWhiteSpace(held.Error.Requirement) || string.IsNullOrWhiteSpace(held.Error.Message) ||
                    held.Observation is not null &&
                    (ValidateObservation(held.Observation) is not null || held.Observation.AuthorityId != held.AuthorityId))
                    return Error(AuthorityErrorCode.InvalidJournal, "INV-005", "Hold does not match the current state.");
                break;

            case AuthorityFencedEvent fenced when !Enum.IsDefined(fenced.Error.Code) ||
                                                   string.IsNullOrWhiteSpace(fenced.Error.Requirement) ||
                                                   string.IsNullOrWhiteSpace(fenced.Error.Message) ||
                                                   fenced.Observation is not null &&
                                                   (fenced.Observation.AuthorityId != fenced.AuthorityId ||
                                                    ValidateObservation(fenced.Observation) is not null):
                return Error(AuthorityErrorCode.InvalidJournal, "INV-005", "Fence evidence is outside the closed vocabulary or authority scope.");
        }

        return null;
    }

    private static AuthorityError? ValidateLease(AuthorityLease lease) =>
        lease is null || string.IsNullOrWhiteSpace(lease.CandidateId) || string.IsNullOrWhiteSpace(lease.LeaseId) ||
        lease.ServerIssuedAt == default || lease.Duration <= TimeSpan.Zero || !CanAdd(lease.ServerIssuedAt, lease.Duration)
            ? Error(AuthorityErrorCode.InvalidInput, "INV-005", "Lease is malformed.")
            : null;

    private static AuthorityState Apply(AuthorityState state, AuthorityEvent @event)
    {
        var common = state with
        {
            AuthorityId = @event.AuthorityId, CandidateId = @event.CandidateId,
            LastSequence = @event.Sequence, JournalDigest = @event.EventDigest,
        };
        return @event switch
        {
            AuthoritySetRequested value => common with
            {
                Status = value.Pending.IsRenewal ? AuthorityStatus.RenewalPending : AuthorityStatus.AcquisitionPending,
                HighestEpoch = Math.Max(state.HighestEpoch, value.Pending.ExpectedEpoch),
                HighestKvRevision = Math.Max(state.HighestKvRevision, value.Pending.ExpectedRevision),
                PendingSet = value.Pending, PendingDelete = null, PendingReadRequestId = null,
                PendingReadCandidateId = null, LastError = null,
            },
            AuthoritySetConfirmed value => common with
            {
                Status = AuthorityStatus.Leader, HighestEpoch = Math.Max(state.HighestEpoch, value.Observation.Epoch),
                HighestKvRevision = Math.Max(state.HighestKvRevision, value.Observation.KvRevision),
                Confirmed = value.Observation, PendingSet = null, LastCompletedRequestId = value.RequestId, LastError = null,
            },
            AuthoritySetRejected value => common with
            {
                Status = state.PendingSet?.IsRenewal == true ? AuthorityStatus.Fenced : AuthorityStatus.ReadOnlyHeld,
                HighestEpoch = Math.Max(state.HighestEpoch, value.Observation?.Epoch ?? 0), PendingSet = null,
                HighestKvRevision = Math.Max(state.HighestKvRevision, value.Observation?.KvRevision ?? 0),
                LastCompletedRequestId = value.RequestId, LastError = value.Error,
            },
            AuthorityDeleteRequested value => common with { Status = AuthorityStatus.ReleasePending, PendingDelete = value.Pending, LastError = null },
            AuthorityDeleteConfirmed value => common with
            {
                Status = AuthorityStatus.Follower, HighestEpoch = Math.Max(state.HighestEpoch, value.Observation.Epoch),
                HighestKvRevision = Math.Max(state.HighestKvRevision, value.Observation.KvRevision),
                Confirmed = value.Observation, PendingDelete = null, LastCompletedRequestId = value.RequestId, LastError = null,
            },
            AuthorityReadRequested value => common with
            {
                Status = AuthorityStatus.ReadOnlyHeld, PendingReadRequestId = value.RequestId,
                PendingReadCandidateId = value.CandidateId, ReadResumeStatus = value.ResumeStatus, LastError = null,
            },
            AuthorityReadConfirmed value => common with
            {
                Status = state.ReadResumeStatus == AuthorityStatus.Leader ? AuthorityStatus.Leader : AuthorityStatus.Follower,
                HighestEpoch = Math.Max(state.HighestEpoch, value.Observation.Epoch), Confirmed = value.Observation,
                HighestKvRevision = Math.Max(state.HighestKvRevision, value.Observation.KvRevision),
                PendingReadRequestId = null, PendingReadCandidateId = null, ReadResumeStatus = null, LastError = null,
                LastCompletedRequestId = value.RequestId,
            },
            AuthorityHeld value => common with
            {
                Status = AuthorityStatus.ReadOnlyHeld, PendingSet = null, PendingDelete = null,
                HighestEpoch = Math.Max(state.HighestEpoch, value.Observation?.Epoch ?? 0),
                HighestKvRevision = Math.Max(state.HighestKvRevision, value.Observation?.KvRevision ?? 0),
                PendingReadRequestId = null, PendingReadCandidateId = null,
                ReadResumeStatus = value.HeldFrom == AuthorityStatus.Leader ? AuthorityStatus.Leader : state.ReadResumeStatus,
                LastError = value.Error,
            },
            AuthorityFencedEvent value => common with
            {
                Status = AuthorityStatus.Fenced, HighestEpoch = Math.Max(state.HighestEpoch, value.Observation?.Epoch ?? 0),
                HighestKvRevision = Math.Max(state.HighestKvRevision, value.Observation?.KvRevision ?? 0),
                PendingSet = null, PendingDelete = null, PendingReadRequestId = null, PendingReadCandidateId = null,
                ReadResumeStatus = null, LastError = value.Error,
            },
            _ => throw new ArgumentOutOfRangeException(nameof(@event)),
        };
    }

    private static T Stamp<T>(AuthorityState state, Func<long, string, string, T> factory) where T : AuthorityEvent
    {
        var provisional = factory(state.LastSequence + 1, state.JournalDigest, string.Empty);
        return factory(provisional.Sequence, provisional.PreviousDigest, AuthorityDigest.Event(provisional));
    }

    private static AuthorityDecision Commit(
        AuthorityState state, AuthorityEvent @event,
        IEnumerable<AuthorityIntent>? intents = null,
        IEnumerable<AuthorityError>? errors = null,
        MutationAuthorityPermit? mutationPermit = null)
    {
        var validation = ValidateNext(state, @event);
        return validation is null
            ? AuthorityDecision.Create(Apply(state, @event), [@event], intents, errors, mutationPermit)
            : Reject(state, validation);
    }

    private static AuthorityDecision Reject(AuthorityState state, AuthorityError error) => AuthorityDecision.Create(state, errors: [error]);

    private static AuthorityError? CompletedRequestReuse(AuthorityState state, string requestId) =>
        state.LastCompletedRequestId == requestId
            ? Error(AuthorityErrorCode.StaleObservation, "INV-005", "A completed request identity cannot initiate another authority action.")
            : null;

    private static AuthorityError Error(AuthorityErrorCode code, string requirement, string message) => new(code, requirement, message);

    private static MutationAuthorityPermit CreatePermit(AuthorityObservation observation, AuthorityHealth health) => new(
        observation.AuthorityId, observation.Lease!.CandidateId, observation.Lease.LeaseId,
        observation.Epoch, observation.KvRevision, observation.ObservationId,
        health.ServerTime, health.MonotonicElapsed);

    private static AuthorityObservation? ObservationFrom(AuthorityCommand command) => command switch
    {
        AcquireAuthority value => value.Baseline,
        RenewAuthority value => value.Current,
        ReleaseAuthority value => value.Current,
        ObserveAuthorityCas value => value.Observation,
        ObserveAuthorityDelete value => value.Observation,
        ObserveAuthorityRead value => value.Observation,
        EvaluateMutationAuthority value => value.Observation,
        _ => null,
    };

    private static bool CanAdd(DateTimeOffset timestamp, TimeSpan duration)
    {
        try { _ = timestamp + duration; return true; }
        catch (ArgumentOutOfRangeException) { return false; }
    }
}
