using System.Reflection;
using TerraScale.Orchestrator.ControlPlane.Operations;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class OperationRecoveryCompletenessRegressionTests
{
    private static readonly DateTimeOffset Start = new(2026, 7, 14, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task ExpiredPersistedDispatchReplaysAsReadOnlyReconciliation()
    {
        var history = ThroughDispatch();
        var decision = OperationEngine.Decide(history,
            new RecordDispatch("op-1", 12, Desired().Deadline, "executor-12", 1));

        await Assert.That(decision.Errors).IsEmpty();
        await Assert.That(decision.EventsToAppend).IsEmpty();
        await Assert.That(decision.Intents).HasSingleItem();
        await Assert.That(decision.Intents.Single()).IsTypeOf<ReconcileProviderIntent>();
    }

    [Test]
    public async Task PersistedDeadlineHoldCannotBeBypassedByRegressingDecisionTime()
    {
        var prepared = Prepared();
        var expired = OperationEngine.Decide(prepared,
            new AuthorizeOperation("op-1", 11, Desired().Deadline, Evidence()));
        prepared.AddRange(expired.EventsToAppend);

        var rewound = OperationEngine.Decide(prepared,
            new AuthorizeOperation("op-1", 12, Desired().Deadline.AddMinutes(-1), Evidence()));

        await Assert.That(rewound.EventsToAppend).IsEmpty();
        await Assert.That(rewound.Intents).IsEmpty();
        await Assert.That(rewound.Errors.Single().Code).IsEqualTo(OperationErrorCode.DeadlineExpired);
        await Assert.That(rewound.State.Checkpoint).IsEqualTo(OperationCheckpoint.Held);
    }

    [Test]
    public async Task ReplayedNonFinalObservationReemitsReadOnlyReconciliation()
    {
        foreach (var outcome in new[] { ProviderOutcome.Unknown, ProviderOutcome.InProgress })
        {
            var history = ThroughDispatch();
            var command = new RecordObservation("op-1", 12, Start.AddMinutes(4),
                $"observation-{outcome}", "node-a", 7, "pending", outcome, "work-1");
            history.AddRange(OperationEngine.Decide(history, command).EventsToAppend);

            var replay = OperationEngine.Decide(history, command);

            await Assert.That(replay.Errors).IsEmpty();
            await Assert.That(replay.EventsToAppend).IsEmpty();
            await Assert.That(replay.Intents).HasSingleItem();
            var intent = (ReconcileProviderIntent)replay.Intents.Single();
            var state = OperationEngine.Replay(history).State;
            await Assert.That(intent.OperationId).IsEqualTo("op-1");
            await Assert.That(intent.TargetIdentity).IsEqualTo("node-a");
            await Assert.That(intent.DesiredGeneration).IsEqualTo(7);
            await Assert.That(intent.IdempotencyKey).IsEqualTo("retry-op-1");
            await Assert.That(intent.ProviderWorkRequestId).IsEqualTo("work-1");
            await Assert.That(intent.AuthorizationSequence).IsEqualTo(state.Authorization!.Sequence);
            await Assert.That(intent.AuthorizationDigest).IsEqualTo(state.Authorization.AuthorizationDigest);
        }
    }

    [Test]
    public async Task ObservationIdentityCannotBeReboundToDifferentProviderTruth()
    {
        var history = ThroughDispatch();
        var first = new RecordObservation("op-1", 12, Start.AddMinutes(4),
            "observation-1", "node-a", 7, "pending", ProviderOutcome.Unknown, "work-1");
        history.AddRange(OperationEngine.Decide(history, first).EventsToAppend);

        var conflicting = OperationEngine.Decide(history, first with
        {
            Now = Start.AddMinutes(5),
            TerminalState = "running",
            Outcome = ProviderOutcome.Succeeded,
        });

        await Assert.That(conflicting.EventsToAppend).IsEmpty();
        await Assert.That(conflicting.Intents).IsEmpty();
        await Assert.That(conflicting.Errors.Single().Code)
            .IsEqualTo(OperationErrorCode.ConflictingTerminalObservation);
    }

    [Test]
    public async Task ReplayRejectsReboundObservationIdentityAndPreservesPriorState()
    {
        var history = ThroughDispatch();
        var first = new RecordObservation("op-1", 12, Start.AddMinutes(4),
            "observation-1", "node-a", 7, "pending", ProviderOutcome.Unknown, "work-1");
        history.AddRange(OperationEngine.Decide(history, first).EventsToAppend);
        var prior = OperationEngine.Replay(history).State;
        var body = new OperationObservationRecorded(prior.LastSequence + 1, prior.JournalDigest, string.Empty,
            "op-1", 12, Start.AddMinutes(5), "observation-1", "node-a", 7,
            "running", ProviderOutcome.Succeeded, "work-1");
        var conflicting = body with { EventDigest = OperationDigest.Event(body) };

        var replay = OperationEngine.Replay(history.Append(conflicting).ToArray());

        await Assert.That(replay.Errors.Single().Code)
            .IsEqualTo(OperationErrorCode.ConflictingTerminalObservation);
        await Assert.That(OperationDigest.State(replay.State)).IsEqualTo(OperationDigest.State(prior));
    }

    [Test]
    public async Task DispatchIntentExposesFrozenGenerationObservationAndCompensationContext()
    {
        var properties = typeof(DispatchProviderIntent).GetProperties(BindingFlags.Instance | BindingFlags.Public)
            .Select(static property => property.Name)
            .ToHashSet(StringComparer.Ordinal);
        var required = new[]
        {
            "AggregateId",
            "DesiredGeneration",
            "DesiredResourceVersion",
            "AuthorizedObservationId",
            "AuthorizedResourceVersion",
            "PermittedCompensations",
        };

        await Assert.That(required.Where(name => !properties.Contains(name))).IsEmpty();

        var history = Prepared();
        history.AddRange(OperationEngine.Decide(history,
            new AuthorizeOperation("op-1", 11, Start.AddMinutes(1), Evidence())).EventsToAppend);
        var intent = (DispatchProviderIntent)OperationEngine.Decide(history,
            new RecordDispatch("op-1", 12, Start.AddMinutes(2), "executor-12", 1)).Intents.Single();
        await Assert.That(intent.AggregateId).IsEqualTo("aggregate-a");
        await Assert.That(intent.DesiredGeneration).IsEqualTo(7);
        await Assert.That(intent.DesiredResourceVersion).IsEqualTo("desired-rv-7");
        await Assert.That(intent.AuthorizedObservationId).IsEqualTo("authorized-observation");
        await Assert.That(intent.AuthorizedResourceVersion).IsEqualTo("authorized-rv-2");
        await Assert.That(intent.PermittedCompensations.SequenceEqual(
            new[] { "observe-only", "quarantine" }, StringComparer.Ordinal)).IsTrue();
        await Assert.That(() => ((IList<string>)intent.PermittedCompensations)[0] = "mutated")
            .Throws<NotSupportedException>();
    }

    [Test]
    public async Task ClosedOperationInventoriesAndIntentFieldsAreExact()
    {
        await Assert.That(Enum.GetValues<OperationCheckpoint>()).IsEquivalentTo(new[]
        {
            OperationCheckpoint.None, OperationCheckpoint.Prepared, OperationCheckpoint.Authorized,
            OperationCheckpoint.DispatchRecorded, OperationCheckpoint.Observed, OperationCheckpoint.Terminal,
            OperationCheckpoint.Held,
        });
        await Assert.That(Enum.GetValues<ProviderOutcome>()).IsEquivalentTo(new[]
        {
            ProviderOutcome.Unknown, ProviderOutcome.InProgress, ProviderOutcome.Succeeded,
            ProviderOutcome.Failed, ProviderOutcome.Inconsistent,
        });
        await Assert.That(Enum.GetValues<OperationErrorCode>()).IsEquivalentTo(new[]
        {
            OperationErrorCode.InvalidInput, OperationErrorCode.InvalidJournal,
            OperationErrorCode.ConflictingJournalEvent, OperationErrorCode.InvalidTransition,
            OperationErrorCode.OperationConflict, OperationErrorCode.IdempotencyConflict,
            OperationErrorCode.StaleWriterEpoch, OperationErrorCode.StaleDesiredGeneration,
            OperationErrorCode.StaleObservation, OperationErrorCode.OwnershipMismatch,
            OperationErrorCode.AuthorizationDenied, OperationErrorCode.DeadlineExpired,
            OperationErrorCode.ConflictingTerminalObservation,
        });
        await Assert.That(ConcreteNames<OperationCommand>()).IsEquivalentTo(new[]
        {
            nameof(PrepareOperation), nameof(AuthorizeOperation), nameof(RecordDispatch),
            nameof(RecordObservation), nameof(RecordTerminal),
        });
        await Assert.That(ConcreteNames<OperationEvent>()).IsEquivalentTo(new[]
        {
            nameof(OperationPrepared), nameof(OperationAuthorized), nameof(OperationDispatchRecorded),
            nameof(OperationRecoveryRecorded), nameof(OperationObservationRecorded),
            nameof(OperationTerminalRecorded), nameof(OperationHeld),
        });
        await Assert.That(ConcreteNames<OperationIntent>()).IsEquivalentTo(new[]
        {
            nameof(DispatchProviderIntent), nameof(ReconcileProviderIntent),
        });
        await Assert.That(PublicPropertyNames(typeof(DispatchProviderIntent))).IsEquivalentTo(new[]
        {
            "OperationId", "OperationKind", "AggregateId", "DesiredGeneration", "DesiredResourceVersion",
            "TargetIdentity", "DesiredTerminalState", "PayloadDigest", "IdempotencyKey",
            "AuthorizedObservationId", "AuthorizedResourceVersion", "PermittedCompensations",
            "AuthorizationSequence", "AuthorizationDigest", "AuthorizingEpoch", "ExecutorEpoch",
            "ExecutorId", "DispatchAttempt", "Deadline",
        });
        await Assert.That(PublicPropertyNames(typeof(ReconcileProviderIntent))).IsEquivalentTo(new[]
        {
            "OperationId", "TargetIdentity", "DesiredGeneration", "IdempotencyKey",
            "ProviderWorkRequestId", "AuthorizationSequence", "AuthorizationDigest",
        });
    }

    [Test]
    public async Task NullAuthorizationEvidenceAndObservationFailClosedWithoutChangingPriorState()
    {
        var prepared = Prepared();
        var valid = (OperationAuthorized)OperationEngine.Decide(prepared,
            new AuthorizeOperation("op-1", 11, Start.AddMinutes(1), Evidence())).EventsToAppend.Single();
        var prior = OperationEngine.Replay(prepared).State;
        foreach (var evidence in new[] { null!, Evidence() with { Observation = null! } })
        {
            var body = valid with { Evidence = evidence, EventDigest = string.Empty };
            var malformed = body with { EventDigest = OperationDigest.Event(body) };
            var replay = OperationEngine.Replay(prepared.Append(malformed).ToArray());

            await Assert.That(replay.Errors.Single().Code).IsEqualTo(OperationErrorCode.InvalidJournal);
            await Assert.That(replay.Intents).IsEmpty();
            await Assert.That(OperationDigest.State(replay.State)).IsEqualTo(OperationDigest.State(prior));
        }
    }

    [Test]
    public async Task NullHeldErrorFailsClosedWithoutChangingPriorState()
    {
        var prepared = Prepared();
        var valid = (OperationHeld)OperationEngine.Decide(prepared,
            new AuthorizeOperation("op-1", 11, Desired().Deadline, Evidence())).EventsToAppend.Single();
        var body = valid with { Error = null!, EventDigest = string.Empty };
        var malformed = body with { EventDigest = OperationDigest.Event(body) };
        var prior = OperationEngine.Replay(prepared).State;

        var replay = OperationEngine.Replay(prepared.Append(malformed).ToArray());

        await Assert.That(replay.Errors.Single().Code).IsEqualTo(OperationErrorCode.InvalidJournal);
        await Assert.That(replay.Intents).IsEmpty();
        await Assert.That(OperationDigest.State(replay.State)).IsEqualTo(OperationDigest.State(prior));
    }

    [Test]
    public async Task FatalJournalEnumerationFailureIsNotTranslated()
    {
        var history = new ThrowingHistory(new OutOfMemoryException("fatal-sentinel"));
        await Assert.That(() => OperationEngine.Replay(history)).Throws<OutOfMemoryException>();
    }

    private static string[] ConcreteNames<T>() => typeof(T).Assembly.GetExportedTypes()
        .Where(type => type != typeof(T) && typeof(T).IsAssignableFrom(type) && !type.IsAbstract)
        .Select(static type => type.Name).Order(StringComparer.Ordinal).ToArray();

    private static string[] PublicPropertyNames(Type type) => type
        .GetProperties(BindingFlags.Instance | BindingFlags.Public)
        .Select(static property => property.Name).Order(StringComparer.Ordinal).ToArray();

    private static List<OperationEvent> ThroughDispatch()
    {
        var history = Prepared();
        history.AddRange(OperationEngine.Decide(history,
            new AuthorizeOperation("op-1", 11, Start.AddMinutes(1), Evidence())).EventsToAppend);
        history.AddRange(OperationEngine.Decide(history,
            new RecordDispatch("op-1", 12, Start.AddMinutes(2), "executor-12", 1)).EventsToAppend);
        return history;
    }

    private static List<OperationEvent> Prepared() => OperationEngine.Decide([], new PrepareOperation(
        "op-1", 10, Start, Desired(), Expected(), ["observe-only", "quarantine"])).EventsToAppend.ToList();

    private static DesiredOperation Desired() => new(
        "aggregate-a", 7, "desired-rv-7", "create-node", "node-a", "running",
        "sha256:payload", "retry-op-1", Start.AddMinutes(10));

    private static ObservedResource Expected() => new(
        "aggregate-a", 7, "expected-rv-1", "expected-observation", "node-a", "absent", true);

    private static AuthorizationEvidence Evidence() => new(
        new ObservedResource("aggregate-a", 7, "authorized-rv-2", "authorized-observation",
            "node-a", "absent", true),
        "sha256:approval", "sha256:evidence", true, true, true, true);

    private sealed class ThrowingHistory(Exception exception) : IReadOnlyList<OperationEvent>
    {
        public int Count => 1;
        public OperationEvent this[int index] => throw exception;
        public IEnumerator<OperationEvent> GetEnumerator() => throw exception;
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
    }
}

