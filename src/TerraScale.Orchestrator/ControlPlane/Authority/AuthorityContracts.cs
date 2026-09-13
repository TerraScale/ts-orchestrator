using System.Collections.ObjectModel;

namespace TerraScale.Orchestrator.ControlPlane.Authority;

public enum AuthorityStatus
{
    Follower,
    AcquisitionPending,
    Leader,
    RenewalPending,
    ReleasePending,
    ReadOnlyHeld,
    Fenced,
}

public enum AuthorityCasOutcome
{
    Succeeded,
    Conflict,
    Failed,
    Uncertain,
}

public enum AuthorityErrorCode
{
    InvalidInput,
    InvalidJournal,
    ConflictingJournalEvent,
    InvalidTransition,
    IdentityMismatch,
    RevisionMismatch,
    EpochMismatch,
    StaleObservation,
    LeaseActive,
    LeaseExpired,
    PartitionUncertain,
    ClockAnomaly,
    CasConflict,
    CasFailed,
    CasUncertain,
    ArithmeticOverflow,
    Fenced,
}

public sealed record AuthorityError(AuthorityErrorCode Code, string Requirement, string Message);

public sealed record AuthorityLease(
    string CandidateId,
    string LeaseId,
    DateTimeOffset ServerIssuedAt,
    TimeSpan Duration);

public sealed record AuthorityObservation(
    string AuthorityId,
    long KvRevision,
    long Epoch,
    string ObservationId,
    AuthorityLease? Lease);

public sealed record AuthorityHealth(
    DateTimeOffset ServerTime,
    TimeSpan MonotonicElapsed,
    bool PartitionCertain,
    bool ClockCertain);

public abstract record AuthorityCommand(string AuthorityId, string CandidateId, string RequestId);

public sealed record AcquireAuthority(
    string AuthorityId,
    string CandidateId,
    string RequestId,
    string LeaseId,
    AuthorityObservation Baseline,
    AuthorityHealth Health,
    TimeSpan LeaseDuration)
    : AuthorityCommand(AuthorityId, CandidateId, RequestId);

public sealed record RenewAuthority(
    string AuthorityId,
    string CandidateId,
    string RequestId,
    AuthorityObservation Current,
    AuthorityHealth Health,
    TimeSpan LeaseDuration)
    : AuthorityCommand(AuthorityId, CandidateId, RequestId);

public sealed record ReleaseAuthority(
    string AuthorityId,
    string CandidateId,
    string RequestId,
    AuthorityObservation Current,
    AuthorityHealth Health)
    : AuthorityCommand(AuthorityId, CandidateId, RequestId);

public sealed record RequestAuthorityRead(
    string AuthorityId,
    string CandidateId,
    string RequestId)
    : AuthorityCommand(AuthorityId, CandidateId, RequestId);

public sealed record ObserveAuthorityCas(
    string AuthorityId,
    string CandidateId,
    string RequestId,
    AuthorityCasOutcome Outcome,
    AuthorityObservation? Observation,
    AuthorityHealth Health)
    : AuthorityCommand(AuthorityId, CandidateId, RequestId);

public sealed record ObserveAuthorityDelete(
    string AuthorityId,
    string CandidateId,
    string RequestId,
    AuthorityCasOutcome Outcome,
    AuthorityObservation? Observation,
    AuthorityHealth Health)
    : AuthorityCommand(AuthorityId, CandidateId, RequestId);

public sealed record ObserveAuthorityRead(
    string AuthorityId,
    string CandidateId,
    string RequestId,
    AuthorityCasOutcome Outcome,
    AuthorityObservation? Observation,
    AuthorityHealth Health)
    : AuthorityCommand(AuthorityId, CandidateId, RequestId);

public sealed record EvaluateMutationAuthority(
    string AuthorityId,
    string CandidateId,
    string RequestId,
    AuthorityObservation Observation,
    AuthorityHealth Health)
    : AuthorityCommand(AuthorityId, CandidateId, RequestId);

public abstract record AuthorityIntent
{
    internal AuthorityIntent(string authorityId, string requestId) { AuthorityId = authorityId; RequestId = requestId; }
    public string AuthorityId { get; }
    public string RequestId { get; }
}

public sealed record CompareAndSetLeaseIntent : AuthorityIntent
{
    internal CompareAndSetLeaseIntent(string authorityId, string requestId, long expectedRevision, long expectedEpoch,
        long proposedEpoch, AuthorityLease proposedLease) : base(authorityId, requestId)
    { ExpectedRevision = expectedRevision; ExpectedEpoch = expectedEpoch; ProposedEpoch = proposedEpoch; ProposedLease = proposedLease; }
    public long ExpectedRevision { get; }
    public long ExpectedEpoch { get; }
    public long ProposedEpoch { get; }
    public AuthorityLease ProposedLease { get; }
}

public sealed record CompareAndDeleteLeaseIntent : AuthorityIntent
{
    internal CompareAndDeleteLeaseIntent(string authorityId, string requestId, long expectedRevision, long expectedEpoch,
        AuthorityLease expectedLease) : base(authorityId, requestId)
    { ExpectedRevision = expectedRevision; ExpectedEpoch = expectedEpoch; ExpectedLease = expectedLease; }
    public long ExpectedRevision { get; }
    public long ExpectedEpoch { get; }
    public AuthorityLease ExpectedLease { get; }
}

public sealed record ReadAuthorityIntent : AuthorityIntent
{
    internal ReadAuthorityIntent(RequestAuthorityRead request, AuthorityState state, AuthorityStatus resumeStatus)
        : base(request.AuthorityId, request.RequestId)
    {
        CandidateId = request.CandidateId;
        ResumeStatus = resumeStatus;
        ExpectedHighestEpoch = state.HighestEpoch;
        ExpectedHighestKvRevision = state.HighestKvRevision;
        ExpectedConfirmedObservation = state.Confirmed;
    }

    public string CandidateId { get; }
    public AuthorityStatus ResumeStatus { get; }
    public long ExpectedHighestEpoch { get; }
    public long ExpectedHighestKvRevision { get; }
    public AuthorityObservation? ExpectedConfirmedObservation { get; }
}

public sealed record MutationAuthorityPermit
{
    internal MutationAuthorityPermit(AuthorityCommand authorizingCommand)
    {
        (AuthorityObservation observation, AuthorityHealth health, AuthorityLease lease) = authorizingCommand switch
        {
            ObserveAuthorityCas
            {
                Outcome: AuthorityCasOutcome.Succeeded,
                Observation: { Lease: not null } acceptedObservation,
            } accepted => (acceptedObservation, accepted.Health, acceptedObservation.Lease),
            ObserveAuthorityRead
            {
                Outcome: AuthorityCasOutcome.Succeeded,
                Observation: { Lease: not null } acceptedObservation,
            } accepted => (acceptedObservation, accepted.Health, acceptedObservation.Lease),
            EvaluateMutationAuthority { Observation.Lease: not null } accepted =>
                (accepted.Observation, accepted.Health, accepted.Observation.Lease),
            _ => throw new ArgumentException(
                "A mutation permit requires an accepted CAS, read, or evaluation command with lease evidence.",
                nameof(authorizingCommand)),
        };

        AuthorizingCommand = authorizingCommand;
        AuthorityId = authorizingCommand.AuthorityId;
        CandidateId = authorizingCommand.CandidateId;
        LeaseId = lease.LeaseId;
        Epoch = observation.Epoch;
        KvRevision = observation.KvRevision;
        ObservationId = observation.ObservationId;
        EvaluatedServerTime = health.ServerTime;
        EvaluatedMonotonicElapsed = health.MonotonicElapsed;
    }

    public AuthorityCommand AuthorizingCommand { get; }
    public string RequestId => AuthorizingCommand.RequestId;
    public string AuthorityId { get; }
    public string CandidateId { get; }
    public string LeaseId { get; }
    public long Epoch { get; }
    public long KvRevision { get; }
    public string ObservationId { get; }
    public DateTimeOffset EvaluatedServerTime { get; }
    public TimeSpan EvaluatedMonotonicElapsed { get; }
}

public sealed record PendingAuthoritySet(
    string RequestId,
    long ExpectedRevision,
    long ExpectedEpoch,
    long ProposedEpoch,
    AuthorityLease ProposedLease,
    AuthorityObservation ExpectedObservation,
    AuthorityHealth RequestedAtHealth,
    bool IsRenewal);

public sealed record PendingAuthorityDelete(
    string RequestId,
    long ExpectedRevision,
    long ExpectedEpoch,
    AuthorityLease ExpectedLease,
    AuthorityHealth RequestedAtHealth);

public abstract record AuthorityEvent(
    long Sequence,
    string PreviousDigest,
    string EventDigest,
    string AuthorityId,
    string CandidateId,
    string RequestId);

public sealed record AuthoritySetRequested(
    long Sequence, string PreviousDigest, string EventDigest,
    string AuthorityId, string CandidateId, string RequestId,
    PendingAuthoritySet Pending)
    : AuthorityEvent(Sequence, PreviousDigest, EventDigest, AuthorityId, CandidateId, RequestId);

public sealed record AuthoritySetConfirmed(
    long Sequence, string PreviousDigest, string EventDigest,
    string AuthorityId, string CandidateId, string RequestId,
    AuthorityObservation Observation,
    AuthorityHealth Health,
    bool WasRenewal)
    : AuthorityEvent(Sequence, PreviousDigest, EventDigest, AuthorityId, CandidateId, RequestId);

public sealed record AuthoritySetRejected(
    long Sequence, string PreviousDigest, string EventDigest,
    string AuthorityId, string CandidateId, string RequestId,
    AuthorityCasOutcome Outcome,
    AuthorityObservation? Observation,
    AuthorityError Error)
    : AuthorityEvent(Sequence, PreviousDigest, EventDigest, AuthorityId, CandidateId, RequestId);

public sealed record AuthorityDeleteRequested(
    long Sequence, string PreviousDigest, string EventDigest,
    string AuthorityId, string CandidateId, string RequestId,
    PendingAuthorityDelete Pending)
    : AuthorityEvent(Sequence, PreviousDigest, EventDigest, AuthorityId, CandidateId, RequestId);

public sealed record AuthorityDeleteConfirmed(
    long Sequence, string PreviousDigest, string EventDigest,
    string AuthorityId, string CandidateId, string RequestId,
    AuthorityObservation Observation)
    : AuthorityEvent(Sequence, PreviousDigest, EventDigest, AuthorityId, CandidateId, RequestId);

public sealed record AuthorityReadRequested(
    long Sequence, string PreviousDigest, string EventDigest,
    string AuthorityId, string CandidateId, string RequestId,
    AuthorityStatus ResumeStatus)
    : AuthorityEvent(Sequence, PreviousDigest, EventDigest, AuthorityId, CandidateId, RequestId);

public sealed record AuthorityReadConfirmed(
    long Sequence, string PreviousDigest, string EventDigest,
    string AuthorityId, string CandidateId, string RequestId,
    AuthorityObservation Observation,
    AuthorityHealth Health)
    : AuthorityEvent(Sequence, PreviousDigest, EventDigest, AuthorityId, CandidateId, RequestId);

public sealed record AuthorityHeld(
    long Sequence, string PreviousDigest, string EventDigest,
    string AuthorityId, string CandidateId, string RequestId,
    AuthorityStatus HeldFrom,
    AuthorityObservation? Observation,
    AuthorityError Error)
    : AuthorityEvent(Sequence, PreviousDigest, EventDigest, AuthorityId, CandidateId, RequestId);

public sealed record AuthorityFencedEvent(
    long Sequence, string PreviousDigest, string EventDigest,
    string AuthorityId, string CandidateId, string RequestId,
    AuthorityObservation? Observation,
    AuthorityError Error)
    : AuthorityEvent(Sequence, PreviousDigest, EventDigest, AuthorityId, CandidateId, RequestId);

public sealed record AuthorityState(
    string? AuthorityId,
    string? CandidateId,
    AuthorityStatus Status,
    long LastSequence,
    string JournalDigest,
    long HighestEpoch,
    long HighestKvRevision,
    AuthorityObservation? Confirmed,
    PendingAuthoritySet? PendingSet,
    PendingAuthorityDelete? PendingDelete,
    string? PendingReadRequestId,
    string? PendingReadCandidateId,
    AuthorityStatus? ReadResumeStatus,
    string? LastCompletedRequestId,
    AuthorityError? LastError)
{
    public static AuthorityState Empty { get; } = new(
        null, null, AuthorityStatus.Follower, 0, AuthorityDigest.EmptyJournalDigest,
        0, 0, null, null, null, null, null, null, null, null);
}

public sealed record AuthorityDecision
{
    internal AuthorityDecision(AuthorityState state, IReadOnlyList<AuthorityEvent> eventsToAppend,
        IReadOnlyList<AuthorityIntent> intents, IReadOnlyList<AuthorityError> errors,
        MutationAuthorityPermit? mutationPermit, string decisionDigest)
    {
        State = state; EventsToAppend = eventsToAppend; Intents = intents; Errors = errors;
        MutationPermit = mutationPermit; DecisionDigest = decisionDigest;
    }

    public AuthorityState State { get; }
    public IReadOnlyList<AuthorityEvent> EventsToAppend { get; }
    public IReadOnlyList<AuthorityIntent> Intents { get; }
    public IReadOnlyList<AuthorityError> Errors { get; }
    public MutationAuthorityPermit? MutationPermit { get; }
    public string DecisionDigest { get; }

    internal static AuthorityDecision Create(
        AuthorityState state,
        IEnumerable<AuthorityEvent>? events = null,
        IEnumerable<AuthorityIntent>? intents = null,
        IEnumerable<AuthorityError>? errors = null,
        MutationAuthorityPermit? mutationPermit = null)
    {
        var eventList = new ReadOnlyCollection<AuthorityEvent>((events ?? []).ToArray());
        var intentList = new ReadOnlyCollection<AuthorityIntent>((intents ?? []).ToArray());
        var errorList = new ReadOnlyCollection<AuthorityError>((errors ?? []).ToArray());
        return new(state, eventList, intentList, errorList, mutationPermit,
            AuthorityDigest.Decision(state, eventList, intentList, errorList, mutationPermit));
    }
}

