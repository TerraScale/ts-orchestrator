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
    bool BudgetSatisfied);

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

public abstract record OperationIntent(string OperationId);

public sealed record DispatchProviderIntent(
    string OperationId,
    string OperationKind,
    string TargetIdentity,
    string DesiredTerminalState,
    string PayloadDigest,
    string IdempotencyKey,
    long AuthorizationSequence,
    string AuthorizationDigest,
    long AuthorizingEpoch,
    long ExecutorEpoch,
    string ExecutorId,
    long DispatchAttempt,
    DateTimeOffset Deadline)
    : OperationIntent(OperationId);

public sealed record ReconcileProviderIntent(
    string OperationId,
    string TargetIdentity,
    long DesiredGeneration,
    string IdempotencyKey,
    string? ProviderWorkRequestId,
    long AuthorizationSequence,
    string AuthorizationDigest)
    : OperationIntent(OperationId);

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

public sealed record OperationDecision(
    OperationState State,
    IReadOnlyList<OperationEvent> EventsToAppend,
    IReadOnlyList<OperationIntent> Intents,
    IReadOnlyList<OperationError> Errors,
    string DecisionDigest)
{
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
