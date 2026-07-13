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

public abstract record AuthorityIntent(string AuthorityId, string RequestId);

public sealed record CompareAndSetLeaseIntent(
    string AuthorityId,
    string RequestId,
    long ExpectedRevision,
    long ExpectedEpoch,
    long ProposedEpoch,
    AuthorityLease ProposedLease)
    : AuthorityIntent(AuthorityId, RequestId);

public sealed record CompareAndDeleteLeaseIntent(
    string AuthorityId,
    string RequestId,
    long ExpectedRevision,
    long ExpectedEpoch,
    AuthorityLease ExpectedLease)
    : AuthorityIntent(AuthorityId, RequestId);

public sealed record ReadAuthorityIntent(string AuthorityId, string RequestId)
    : AuthorityIntent(AuthorityId, RequestId);

public sealed record MutationAuthorityPermit(
    string AuthorityId,
    string CandidateId,
    string LeaseId,
    long Epoch,
    long KvRevision,
    string ObservationId,
    DateTimeOffset EvaluatedServerTime,
    TimeSpan EvaluatedMonotonicElapsed);

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

public sealed record AuthorityDecision(
    AuthorityState State,
    IReadOnlyList<AuthorityEvent> EventsToAppend,
    IReadOnlyList<AuthorityIntent> Intents,
    IReadOnlyList<AuthorityError> Errors,
    MutationAuthorityPermit? MutationPermit,
    string DecisionDigest)
{
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
