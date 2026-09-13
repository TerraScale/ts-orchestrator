using System.Collections.ObjectModel;

namespace TerraScale.Orchestrator.ControlPlane.Operations;

public enum OperationCheckpoint
{
    None,
    Prepared,
    Authorized,
    DispatchRecorded,
    Observed,
    Terminal,
    Held,
}

public enum ProviderOutcome
{
    Unknown,
    InProgress,
    Succeeded,
    Failed,
    Inconsistent,
}

public enum OperationErrorCode
{
    InvalidInput,
    InvalidJournal,
    ConflictingJournalEvent,
    InvalidTransition,
    OperationConflict,
    IdempotencyConflict,
    StaleWriterEpoch,
    StaleDesiredGeneration,
    StaleObservation,
    OwnershipMismatch,
    AuthorizationDenied,
    DeadlineExpired,
    ConflictingTerminalObservation,
}

public sealed record OperationError(OperationErrorCode Code, string Requirement, string Message);

public sealed record DesiredOperation(
    string AggregateId,
    long Generation,
    string ResourceVersion,
    string OperationKind,
    string TargetIdentity,
    string DesiredTerminalState,
    string PayloadDigest,
    string IdempotencyKey,
    DateTimeOffset Deadline);

public sealed record ObservedResource(
    string AggregateId,
    long Generation,
    string ResourceVersion,
    string ObservationId,
    string TargetIdentity,
    string State,
    bool PositivelyOwned);

public sealed record AuthorizationEvidence(
    ObservedResource Observation,
    string ApprovalDigest,
    string EvidenceDigest,
    bool ApprovalsSatisfied,
    bool PolicySatisfied,
    bool QuorumSatisfied,
    bool BudgetSatisfied)
{
    /// <summary>Authenticated tenant subject, populated by the authorization boundary for tenant-scoped operations.</summary>
    public string? TenantId { get; init; }
}

public abstract record OperationCommand(string OperationId, long WriterEpoch, DateTimeOffset Now);

public sealed record PrepareOperation(
    string OperationId,
    long WriterEpoch,
    DateTimeOffset Now,
    DesiredOperation Desired,
    ObservedResource ExpectedObservation,
    IReadOnlyList<string> PermittedCompensations)
    : OperationCommand(OperationId, WriterEpoch, Now);

public sealed record AuthorizeOperation(
    string OperationId,
    long WriterEpoch,
    DateTimeOffset Now,
    AuthorizationEvidence Evidence)
    : OperationCommand(OperationId, WriterEpoch, Now);

public sealed record RecordDispatch(
    string OperationId,
    long WriterEpoch,
    DateTimeOffset Now,
    string ExecutorId,
    long Attempt)
    : OperationCommand(OperationId, WriterEpoch, Now);

public sealed record RecordObservation(
    string OperationId,
    long WriterEpoch,
    DateTimeOffset Now,
    string ObservationId,
    string TargetIdentity,
    long Generation,
    string TerminalState,
    ProviderOutcome Outcome,
    string? ProviderWorkRequestId)
    : OperationCommand(OperationId, WriterEpoch, Now);

public sealed record RecordTerminal(
    string OperationId,
    long WriterEpoch,
    DateTimeOffset Now,
    ProviderOutcome Outcome,
    string TerminalState)
    : OperationCommand(OperationId, WriterEpoch, Now);

public abstract record OperationIntent
{
    internal OperationIntent(string operationId) => OperationId = operationId;
    public string OperationId { get; }
}

public sealed record DispatchProviderIntent : OperationIntent
{
    internal DispatchProviderIntent(string operationId, string operationKind, string aggregateId,
        long desiredGeneration, string desiredResourceVersion, string targetIdentity, string desiredTerminalState,
        string payloadDigest, string idempotencyKey, string authorizedObservationId,
        string authorizedResourceVersion, IReadOnlyList<string> permittedCompensations,
        long authorizationSequence, string authorizationDigest, long authorizingEpoch, long executorEpoch,
        string executorId, long dispatchAttempt, DateTimeOffset deadline) : base(operationId)
    {
        OperationKind = operationKind;
        AggregateId = aggregateId;
        DesiredGeneration = desiredGeneration;
        DesiredResourceVersion = desiredResourceVersion;
        TargetIdentity = targetIdentity;
        DesiredTerminalState = desiredTerminalState;
        PayloadDigest = payloadDigest;
        IdempotencyKey = idempotencyKey;
        AuthorizedObservationId = authorizedObservationId;
        AuthorizedResourceVersion = authorizedResourceVersion;
        PermittedCompensations = Array.AsReadOnly(permittedCompensations.ToArray());
        AuthorizationSequence = authorizationSequence;
        AuthorizationDigest = authorizationDigest;
        AuthorizingEpoch = authorizingEpoch;
        ExecutorEpoch = executorEpoch;
        ExecutorId = executorId;
        DispatchAttempt = dispatchAttempt;
        Deadline = deadline;
    }

    public string OperationKind { get; }
    public string AggregateId { get; }
    public long DesiredGeneration { get; }
    public string DesiredResourceVersion { get; }
    public string TargetIdentity { get; }
    public string DesiredTerminalState { get; }
    public string PayloadDigest { get; }
    public string IdempotencyKey { get; }
    public string AuthorizedObservationId { get; }
    public string AuthorizedResourceVersion { get; }
    public IReadOnlyList<string> PermittedCompensations { get; }
    public long AuthorizationSequence { get; }
    public string AuthorizationDigest { get; }
    public long AuthorizingEpoch { get; }
    public long ExecutorEpoch { get; }
    public string ExecutorId { get; }
    public long DispatchAttempt { get; }
    public DateTimeOffset Deadline { get; }
}

public sealed record ReconcileProviderIntent : OperationIntent
{
    internal ReconcileProviderIntent(string operationId, string targetIdentity, long desiredGeneration, string idempotencyKey,
        string? providerWorkRequestId, long authorizationSequence, string authorizationDigest) : base(operationId)
    {
        TargetIdentity = targetIdentity;
        DesiredGeneration = desiredGeneration;
        IdempotencyKey = idempotencyKey;
        ProviderWorkRequestId = providerWorkRequestId;
        AuthorizationSequence = authorizationSequence;
        AuthorizationDigest = authorizationDigest;
    }

    public string TargetIdentity { get; }
    public long DesiredGeneration { get; }
    public string IdempotencyKey { get; }
    public string? ProviderWorkRequestId { get; }
    public long AuthorizationSequence { get; }
    public string AuthorizationDigest { get; }
}

public abstract record OperationEvent(
    long Sequence,
    string PreviousDigest,
    string EventDigest,
    string OperationId,
    long WriterEpoch,
    DateTimeOffset RecordedAt);

public sealed record OperationPrepared(
    long Sequence,
    string PreviousDigest,
    string EventDigest,
    string OperationId,
    long WriterEpoch,
    DateTimeOffset RecordedAt,
    DesiredOperation Desired,
    ObservedResource ExpectedObservation,
    IReadOnlyList<string> PermittedCompensations)
    : OperationEvent(Sequence, PreviousDigest, EventDigest, OperationId, WriterEpoch, RecordedAt);

public sealed record OperationAuthorized(
    long Sequence,
    string PreviousDigest,
    string EventDigest,
    string OperationId,
    long WriterEpoch,
    DateTimeOffset RecordedAt,
    AuthorizationEvidence Evidence,
    string AuthorizationDigest)
    : OperationEvent(Sequence, PreviousDigest, EventDigest, OperationId, WriterEpoch, RecordedAt);

public sealed record OperationDispatchRecorded(
    long Sequence,
    string PreviousDigest,
    string EventDigest,
    string OperationId,
    long WriterEpoch,
    DateTimeOffset RecordedAt,
    string ExecutorId,
    long Attempt)
    : OperationEvent(Sequence, PreviousDigest, EventDigest, OperationId, WriterEpoch, RecordedAt);

public sealed record OperationRecoveryRecorded(
    long Sequence,
    string PreviousDigest,
    string EventDigest,
    string OperationId,
    long WriterEpoch,
    DateTimeOffset RecordedAt,
    string ExecutorId,
    long DispatchSequence)
    : OperationEvent(Sequence, PreviousDigest, EventDigest, OperationId, WriterEpoch, RecordedAt);

public sealed record OperationObservationRecorded(
    long Sequence,
    string PreviousDigest,
    string EventDigest,
    string OperationId,
    long WriterEpoch,
    DateTimeOffset RecordedAt,
    string ObservationId,
    string TargetIdentity,
    long Generation,
    string TerminalState,
    ProviderOutcome Outcome,
    string? ProviderWorkRequestId)
    : OperationEvent(Sequence, PreviousDigest, EventDigest, OperationId, WriterEpoch, RecordedAt);

public sealed record OperationTerminalRecorded(
    long Sequence,
    string PreviousDigest,
    string EventDigest,
    string OperationId,
    long WriterEpoch,
    DateTimeOffset RecordedAt,
    ProviderOutcome Outcome,
    string TerminalState)
    : OperationEvent(Sequence, PreviousDigest, EventDigest, OperationId, WriterEpoch, RecordedAt);

public sealed record OperationHeld(
    long Sequence,
    string PreviousDigest,
    string EventDigest,
    string OperationId,
    long WriterEpoch,
    DateTimeOffset RecordedAt,
    OperationCheckpoint HeldAfter,
    OperationError Error)
    : OperationEvent(Sequence, PreviousDigest, EventDigest, OperationId, WriterEpoch, RecordedAt);

public sealed record OperationState(
    string? OperationId,
    OperationCheckpoint Checkpoint,
    long LastSequence,
    string JournalDigest,
    long HighestWriterEpoch,
    DesiredOperation? Desired,
    ObservedResource? ExpectedObservation,
    IReadOnlyList<string> PermittedCompensations,
    OperationAuthorized? Authorization,
    OperationDispatchRecorded? Dispatch,
    OperationRecoveryRecorded? Recovery,
    OperationObservationRecorded? Observation,
    OperationTerminalRecorded? Terminal,
    OperationHeld? Hold)
{
    public OperationCheckpoint ResumableCheckpoint =>
        Checkpoint == OperationCheckpoint.Held && Hold is not null ? Hold.HeldAfter : Checkpoint;

    public static OperationState Empty { get; } = new(
        null, OperationCheckpoint.None, 0, OperationDigest.EmptyJournalDigest, 0,
        null, null, Array.Empty<string>(), null, null, null, null, null, null);
}

public sealed record OperationDecision
{
    internal OperationDecision(OperationState state, IReadOnlyList<OperationEvent> eventsToAppend,
        IReadOnlyList<OperationIntent> intents, IReadOnlyList<OperationError> errors, string decisionDigest)
    {
        State = state;
        EventsToAppend = eventsToAppend;
        Intents = intents;
        Errors = errors;
        DecisionDigest = decisionDigest;
    }

    public OperationState State { get; }
    public IReadOnlyList<OperationEvent> EventsToAppend { get; }
    public IReadOnlyList<OperationIntent> Intents { get; }
    public IReadOnlyList<OperationError> Errors { get; }
    public string DecisionDigest { get; }
    internal static OperationDecision Create(
        OperationState state,
        IEnumerable<OperationEvent>? events = null,
        IEnumerable<OperationIntent>? intents = null,
        IEnumerable<OperationError>? errors = null)
    {
        var eventList = new ReadOnlyCollection<OperationEvent>((events ?? []).ToArray());
        var intentList = new ReadOnlyCollection<OperationIntent>((intents ?? []).ToArray());
        var errorList = new ReadOnlyCollection<OperationError>((errors ?? []).ToArray());
        return new(state, eventList, intentList, errorList,
            OperationDigest.Decision(state, eventList, intentList, errorList));
    }
}

