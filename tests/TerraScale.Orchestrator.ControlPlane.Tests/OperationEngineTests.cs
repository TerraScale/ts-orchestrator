using TerraScale.Orchestrator.ControlPlane.Operations;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class OperationEngineTests
{
    private static readonly DateTimeOffset Start = new(2026, 7, 13, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task CrashAndReplayAtEveryCheckpointIsDeterministic()
    {
        var history = new List<OperationEvent>();
        var commands = ScenarioCommands();

        foreach (var command in commands)
        {
            var beforeCrash = OperationEngine.Decide(history, command);
            await Assert.That(beforeCrash.Errors).IsEmpty();
            history.AddRange(beforeCrash.EventsToAppend);

            var restored = OperationEngine.Replay(history.ToArray());
            await Assert.That(restored.Errors).IsEmpty();
            await Assert.That(OperationDigest.State(restored.State)).IsEqualTo(OperationDigest.State(beforeCrash.State));
            await Assert.That(restored.State.JournalDigest).IsEqualTo(beforeCrash.State.JournalDigest);

            var replayed = OperationEngine.Replay(history.AsEnumerable().Reverse().Concat(history).ToArray());
            await Assert.That(replayed.Errors).IsEmpty();
            await Assert.That(OperationDigest.State(replayed.State)).IsEqualTo(OperationDigest.State(restored.State));
        }

        await Assert.That(OperationEngine.Replay(history).State.Checkpoint).IsEqualTo(OperationCheckpoint.Terminal);
    }

    [Test]
    public async Task IdenticalHistoryAndInputProduceIdenticalDecisionAndDigest()
    {
        var history = BuildThroughAuthorization();
        var command = new RecordDispatch("op-1", 12, Start.AddMinutes(3), "executor-new", 1);

        var first = OperationEngine.Decide(history, command);
        var second = OperationEngine.Decide(history.ToArray(), command);

        await Assert.That(first.DecisionDigest).IsEqualTo(second.DecisionDigest);
        await Assert.That(first.EventsToAppend).IsEquivalentTo(second.EventsToAppend);
        await Assert.That(first.Intents).IsEquivalentTo(second.Intents);
        await Assert.That(OperationDigest.State(first.State)).IsEqualTo(OperationDigest.State(second.State));
    }

    [Test]
    public async Task AuthorizationHoldCanBeReevaluatedWithFreshEvidenceAndHigherEpoch()
    {
        var history = BuildPrepared();
        var staleEvidence = Evidence(Observation("obs-0", "rv-1"));
        var held = OperationEngine.Decide(history,
            new AuthorizeOperation("op-1", 10, Start.AddMinutes(1), staleEvidence));
        history.AddRange(held.EventsToAppend);

        await Assert.That(held.State.Checkpoint).IsEqualTo(OperationCheckpoint.Held);
        await Assert.That(held.State.ResumableCheckpoint).IsEqualTo(OperationCheckpoint.Prepared);
        await Assert.That(held.Errors.Single().Code).IsEqualTo(OperationErrorCode.StaleObservation);
        await Assert.That(held.Intents).IsEmpty();

        var fresh = OperationEngine.Decide(history,
            new AuthorizeOperation("op-1", 11, Start.AddMinutes(2), Evidence(Observation("obs-1", "rv-2"))));
        history.AddRange(fresh.EventsToAppend);

        await Assert.That(fresh.Errors).IsEmpty();
        await Assert.That(fresh.State.Checkpoint).IsEqualTo(OperationCheckpoint.Authorized);
        await Assert.That(fresh.State.Authorization!.WriterEpoch).IsEqualTo(11);

        var dispatch = OperationEngine.Decide(history,
            new RecordDispatch("op-1", 12, Start.AddMinutes(3), "executor-12", 1));
        var intent = (DispatchProviderIntent)dispatch.Intents.Single();
        await Assert.That(intent.ExecutorEpoch).IsEqualTo(12);
        await Assert.That(intent.AuthorizingEpoch).IsEqualTo(11);
        await Assert.That(intent.TargetIdentity).IsEqualTo(Desired().TargetIdentity);
        await Assert.That(intent.PayloadDigest).IsEqualTo(Desired().PayloadDigest);
        await Assert.That(intent.IdempotencyKey).IsEqualTo(Desired().IdempotencyKey);
        await Assert.That(intent.DesiredTerminalState).IsEqualTo(Desired().DesiredTerminalState);
        await Assert.That(intent.Deadline).IsEqualTo(Desired().Deadline);
    }

    [Test]
    public async Task StaleEpochGenerationAndConflictingIdempotencyFailClosed()
    {
        var authorized = BuildThroughAuthorization();

        var stale = OperationEngine.Decide(authorized,
            new RecordDispatch("op-1", 9, Start.AddMinutes(3), "stale", 1));
        await AssertRejected(stale, OperationErrorCode.StaleWriterEpoch);

        var conflictingDesired = Desired() with { TargetIdentity = "node-b", IdempotencyKey = Desired().IdempotencyKey };
        var conflict = OperationEngine.Decide(authorized,
            new PrepareOperation("op-1", 11, Start.AddMinutes(3), conflictingDesired,
                Observation("obs-other", "rv-other") with { TargetIdentity = "node-b" }, []));
        await AssertRejected(conflict, OperationErrorCode.IdempotencyConflict);

        var staleGeneration = OperationEngine.Decide(Array.Empty<OperationEvent>(),
            new PrepareOperation("op-stale", 1, Start, Desired() with { Generation = 8 }, Observation("obs", "rv"), []));
        await AssertRejected(staleGeneration, OperationErrorCode.StaleDesiredGeneration);
    }

    [Test]
    public async Task EveryAuthorizationGateAndFreshGenerationFailClosedWithoutDispatchIntent()
    {
        var prepared = BuildPrepared();
        var fresh = Observation("obs-1", "rv-2");
        var cases = new (AuthorizationEvidence Evidence, OperationErrorCode Error)[]
        {
            (Evidence(fresh with { Generation = 8 }), OperationErrorCode.StaleDesiredGeneration),
            (Evidence(fresh with { PositivelyOwned = false }), OperationErrorCode.OwnershipMismatch),
            (Evidence(fresh) with { ApprovalsSatisfied = false }, OperationErrorCode.AuthorizationDenied),
            (Evidence(fresh) with { PolicySatisfied = false }, OperationErrorCode.AuthorizationDenied),
            (Evidence(fresh) with { QuorumSatisfied = false }, OperationErrorCode.AuthorizationDenied),
            (Evidence(fresh) with { BudgetSatisfied = false }, OperationErrorCode.AuthorizationDenied),
        };

        foreach (var (evidence, error) in cases)
        {
            var decision = OperationEngine.Decide(prepared,
                new AuthorizeOperation("op-1", 11, Start.AddMinutes(2), evidence));
            await Assert.That(decision.State.Checkpoint).IsEqualTo(OperationCheckpoint.Held);
            await Assert.That(decision.Errors.Single().Code).IsEqualTo(error);
            await Assert.That(decision.Intents).IsEmpty();
        }
    }

    [Test]
    public async Task MissingAuthorizationEvidenceAndUndefinedOutcomesAreRejectedBeforeAppend()
    {
        var prepared = BuildPrepared();
        var missingEvidence = OperationEngine.Decide(prepared,
            new AuthorizeOperation("op-1", 11, Start.AddMinutes(2), null!));
        await AssertRejected(missingEvidence, OperationErrorCode.InvalidInput);

        var blankDigests = OperationEngine.Decide(prepared,
            new AuthorizeOperation("op-1", 11, Start.AddMinutes(2),
                Evidence(Observation("obs-1", "rv-2")) with { ApprovalDigest = "", EvidenceDigest = " " }));
        await AssertRejected(blankDigests, OperationErrorCode.InvalidInput);

        var dispatched = Add(BuildThroughAuthorization(),
            new RecordDispatch("op-1", 12, Start.AddMinutes(3), "executor", 1));
        var invalidObservation = OperationEngine.Decide(dispatched,
            new RecordObservation("op-1", 12, Start.AddMinutes(4), "provider", "node-a", 7,
                "running", (ProviderOutcome)999, null));
        await AssertRejected(invalidObservation, OperationErrorCode.InvalidInput);

        var observed = Add(dispatched,
            new RecordObservation("op-1", 12, Start.AddMinutes(4), "provider", "node-a", 7,
                "running", ProviderOutcome.Succeeded, null));
        var invalidTerminal = OperationEngine.Decide(observed,
            new RecordTerminal("op-1", 12, Start.AddMinutes(5), (ProviderOutcome)999, "running"));
        await AssertRejected(invalidTerminal, OperationErrorCode.InvalidInput);
    }

    [Test]
    public async Task MalformedHistoryDeadlinesCompensationsAndWorkRequestIdsFailClosed()
    {
        var nullHistory = OperationEngine.Replay([null!]);
        await Assert.That(nullHistory.Errors.Single().Code).IsEqualTo(OperationErrorCode.InvalidJournal);

        var defaultDeadline = OperationEngine.Decide([], new PrepareOperation(
            "op-1", 1, Start, Desired() with { Deadline = default },
            Observation("obs-0", "rv-1"), []));
        await AssertRejected(defaultDeadline, OperationErrorCode.InvalidInput);

        foreach (var compensations in new IReadOnlyList<string>[]
                 {
                     new[] { "quarantine", "quarantine" },
                     new[] { "quarantine", " " },
                 })
        {
            var malformed = OperationEngine.Decide([], new PrepareOperation(
                "op-1", 1, Start, Desired(), Observation("obs-0", "rv-1"), compensations));
            await AssertRejected(malformed, OperationErrorCode.InvalidInput);
        }

        var dispatched = Add(BuildThroughAuthorization(),
            new RecordDispatch("op-1", 12, Start.AddMinutes(3), "executor", 1));
        var blankWorkRequest = OperationEngine.Decide(dispatched,
            new RecordObservation("op-1", 12, Start.AddMinutes(4), "provider", "node-a", 7,
                "running", ProviderOutcome.Succeeded, " "));
        await AssertRejected(blankWorkRequest, OperationErrorCode.InvalidInput);
    }

    [Test]
    public async Task HigherEpochAfterDispatchRecordsRecoveryAndOnlyReconcilesFrozenIntent()
    {
        var dispatched = Add(BuildThroughAuthorization(),
            new RecordDispatch("op-1", 12, Start.AddMinutes(3), "executor-old", 1));
        var before = OperationEngine.Replay(dispatched).State;
        var recovered = OperationEngine.Decide(dispatched,
            new RecordDispatch("op-1", 13, Desired().Deadline.AddMinutes(1), "executor-new", 1));

        await Assert.That(recovered.Errors).IsEmpty();
        await Assert.That(recovered.EventsToAppend.Single()).IsTypeOf<OperationRecoveryRecorded>();
        await Assert.That(recovered.Intents.Single()).IsTypeOf<ReconcileProviderIntent>();
        await Assert.That(recovered.State.HighestWriterEpoch).IsEqualTo(13);
        await Assert.That(recovered.State.Dispatch).IsEqualTo(before.Dispatch);
        await Assert.That(recovered.State.Authorization).IsEqualTo(before.Authorization);
        await Assert.That(recovered.State.Desired).IsEqualTo(before.Desired);

        var history = dispatched.Concat(recovered.EventsToAppend).ToList();
        var staleOldExecutor = OperationEngine.Decide(history,
            new RecordDispatch("op-1", 12, Start.AddMinutes(4), "executor-old", 1));
        await AssertRejected(staleOldExecutor, OperationErrorCode.StaleWriterEpoch);

        var duplicateRecovery = OperationEngine.Decide(history,
            new RecordDispatch("op-1", 13, Start.AddMinutes(5), "executor-new", 1));
        await Assert.That(duplicateRecovery.EventsToAppend).IsEmpty();
        await Assert.That(duplicateRecovery.Intents.Single()).IsTypeOf<ReconcileProviderIntent>();
    }

    [Test]
    public async Task DuplicatePreparationMustMatchObservationAndCompensationSetExactly()
    {
        var prepared = BuildPrepared();
        var changedObservation = OperationEngine.Decide(prepared,
            new PrepareOperation("op-1", 10, Start, Desired(), Observation("different", "rv-1"), ["quarantine"]));
        await AssertRejected(changedObservation, OperationErrorCode.IdempotencyConflict);

        var changedCompensation = OperationEngine.Decide(prepared,
            new PrepareOperation("op-1", 10, Start, Desired(), Observation("obs-0", "rv-1"), ["delete"]));
        await AssertRejected(changedCompensation, OperationErrorCode.IdempotencyConflict);
    }

    [Test]
    public async Task DeadlineEqualityHoldsBeforeIrreversibleCommitAndAfterItPreservesAuthorization()
    {
        var atPrepareDeadline = OperationEngine.Decide(Array.Empty<OperationEvent>(),
            new PrepareOperation("op-1", 10, Desired().Deadline, Desired(), Observation("obs-0", "rv-1"), []));
        await AssertRejected(atPrepareDeadline, OperationErrorCode.DeadlineExpired);

        var prepared = BuildPrepared();
        var atAuthorizeDeadline = OperationEngine.Decide(prepared,
            new AuthorizeOperation("op-1", 10, Desired().Deadline, Evidence(Observation("obs-1", "rv-2"))));
        await Assert.That(atAuthorizeDeadline.State.Checkpoint).IsEqualTo(OperationCheckpoint.Held);
        await Assert.That(atAuthorizeDeadline.Intents).IsEmpty();
        await Assert.That(atAuthorizeDeadline.Errors.Single().Code).IsEqualTo(OperationErrorCode.DeadlineExpired);

        var authorized = BuildThroughAuthorization();
        var authorizationDigest = OperationEngine.Replay(authorized).State.Authorization!.AuthorizationDigest;
        var atDispatchDeadline = OperationEngine.Decide(authorized,
            new RecordDispatch("op-1", 12, Desired().Deadline, "executor", 1));
        await Assert.That(atDispatchDeadline.State.Checkpoint).IsEqualTo(OperationCheckpoint.Held);
        await Assert.That(atDispatchDeadline.State.Authorization!.AuthorizationDigest).IsEqualTo(authorizationDigest);
        await Assert.That(atDispatchDeadline.Intents).IsEmpty();
    }

    [Test]
    public async Task ReorderedExactDuplicatesReplayButCorruptLinksAndConflictingBodiesFail()
    {
        var history = BuildThroughAuthorization();
        var expected = OperationEngine.Replay(history);
        var reorderedDuplicates = history.AsEnumerable().Reverse().Concat(history).ToArray();
        var replayed = OperationEngine.Replay(reorderedDuplicates);

        await Assert.That(replayed.Errors).IsEmpty();
        await Assert.That(OperationDigest.State(replayed.State)).IsEqualTo(OperationDigest.State(expected.State));

        var authorized = (OperationAuthorized)history[1];
        var brokenBase = authorized with { PreviousDigest = "broken-link", EventDigest = string.Empty };
        var broken = brokenBase with { EventDigest = OperationDigest.Event(brokenBase) };
        var brokenReplay = OperationEngine.Replay([history[0], broken]);
        await Assert.That(brokenReplay.Errors.Single().Code).IsEqualTo(OperationErrorCode.InvalidJournal);

        var conflictingBase = authorized with { RecordedAt = authorized.RecordedAt.AddTicks(1), EventDigest = string.Empty };
        var conflicting = conflictingBase with { EventDigest = OperationDigest.Event(conflictingBase) };
        var conflictingReplay = OperationEngine.Replay([history[0], authorized, conflicting]);
        await Assert.That(conflictingReplay.Errors.Single().Code).IsEqualTo(OperationErrorCode.ConflictingJournalEvent);

        var dispatched = Add(history, new RecordDispatch("op-1", 12, Start.AddMinutes(3), "executor", 1));
        var validObservation = OperationEngine.Decide(dispatched,
            new RecordObservation("op-1", 12, Start.AddMinutes(4), "provider", "node-a", 7,
                "running", ProviderOutcome.Succeeded, null)).EventsToAppend.Single();
        var invalidOutcomeBase = ((OperationObservationRecorded)validObservation) with
        {
            Outcome = (ProviderOutcome)999,
            EventDigest = string.Empty,
        };
        var invalidOutcome = invalidOutcomeBase with { EventDigest = OperationDigest.Event(invalidOutcomeBase) };
        var invalidOutcomeReplay = OperationEngine.Replay(dispatched.Append(invalidOutcome).ToArray());
        await Assert.That(invalidOutcomeReplay.Errors.Single().Code).IsEqualTo(OperationErrorCode.InvalidJournal);

        var held = OperationEngine.Decide(BuildPrepared(),
            new AuthorizeOperation("op-1", 10, Desired().Deadline, Evidence(Observation("obs-1", "rv-2"))));
        var invalidCheckpointBase = ((OperationHeld)held.EventsToAppend.Single()) with
        {
            HeldAfter = (OperationCheckpoint)999,
            EventDigest = string.Empty,
        };
        var invalidCheckpoint = invalidCheckpointBase with
        {
            EventDigest = OperationDigest.Event(invalidCheckpointBase),
        };
        var invalidCheckpointReplay = OperationEngine.Replay(BuildPrepared().Append(invalidCheckpoint).ToArray());
        await Assert.That(invalidCheckpointReplay.Errors.Single().Code).IsEqualTo(OperationErrorCode.InvalidJournal);
    }

    [Test]
    public async Task ObservationBeforeDispatchAndConflictingFinalObservationsAreRejected()
    {
        var authorized = BuildThroughAuthorization();
        var early = OperationEngine.Decide(authorized,
            new RecordObservation("op-1", 11, Start.AddMinutes(3), "provider-1", "node-a", 7,
                "running", ProviderOutcome.Succeeded, "work-1"));
        await AssertRejected(early, OperationErrorCode.InvalidTransition);

        var dispatched = Add(authorized,
            new RecordDispatch("op-1", 12, Start.AddMinutes(3), "executor", 1));
        var succeeded = Add(dispatched,
            new RecordObservation("op-1", 12, Start.AddMinutes(4), "provider-1", "node-a", 7,
                "running", ProviderOutcome.Succeeded, "work-1"));
        var contradictory = OperationEngine.Decide(succeeded,
            new RecordObservation("op-1", 12, Start.AddMinutes(5), "provider-2", "node-a", 7,
                "failed", ProviderOutcome.Failed, "work-1"));
        await AssertRejected(contradictory, OperationErrorCode.ConflictingTerminalObservation);
    }

    [Test]
    public async Task UnknownOutcomeCanOnlyProgressThroughObservationNotBlindRedispatch()
    {
        var dispatched = Add(BuildThroughAuthorization(),
            new RecordDispatch("op-1", 12, Start.AddMinutes(3), "executor", 1));
        var unknown = Add(dispatched,
            new RecordObservation("op-1", 12, Start.AddMinutes(4), "provider-1", "node-a", 7,
                "unknown", ProviderOutcome.Unknown, null));

        var unknownDecision = OperationEngine.Decide(dispatched,
            new RecordObservation("op-1", 12, Start.AddMinutes(4), "provider-1", "node-a", 7,
                "unknown", ProviderOutcome.Unknown, null));
        await Assert.That(unknownDecision.Intents.Single()).IsTypeOf<ReconcileProviderIntent>();

        var redispatch = OperationEngine.Decide(unknown,
            new RecordDispatch("op-1", 12, Start.AddMinutes(5), "executor", 1));
        await AssertRejected(redispatch, OperationErrorCode.IdempotencyConflict);
        await Assert.That(redispatch.Intents).IsEmpty();

        var reconciled = OperationEngine.Decide(unknown,
            new RecordObservation("op-1", 13, Start.AddMinutes(6), "provider-2", "node-a", 7,
                "running", ProviderOutcome.Succeeded, "work-1"));
        await Assert.That(reconciled.Errors).IsEmpty();
        await Assert.That(reconciled.State.Observation!.Outcome).IsEqualTo(ProviderOutcome.Succeeded);
    }

    [Test]
    public async Task MismatchedProviderTruthIsRecordedAsInconsistentAndCannotBecomeTerminal()
    {
        var dispatched = Add(BuildThroughAuthorization(),
            new RecordDispatch("op-1", 12, Start.AddMinutes(3), "executor", 1));
        var inconsistent = Add(dispatched,
            new RecordObservation("op-1", 12, Start.AddMinutes(4), "provider-1", "node-other", 8,
                "running", ProviderOutcome.Succeeded, "work-1"));
        var state = OperationEngine.Replay(inconsistent).State;

        await Assert.That(state.Observation!.Outcome).IsEqualTo(ProviderOutcome.Inconsistent);
        var terminal = OperationEngine.Decide(inconsistent,
            new RecordTerminal("op-1", 12, Start.AddMinutes(5), ProviderOutcome.Succeeded, "running"));
        await AssertRejected(terminal, OperationErrorCode.ConflictingTerminalObservation);
    }

    private static IReadOnlyList<OperationCommand> ScenarioCommands() =>
    [
        new PrepareOperation("op-1", 10, Start, Desired(), Observation("obs-0", "rv-1"), ["quarantine"]),
        new AuthorizeOperation("op-1", 11, Start.AddMinutes(1), Evidence(Observation("obs-1", "rv-2"))),
        new RecordDispatch("op-1", 12, Start.AddMinutes(2), "executor-12", 1),
        new RecordObservation("op-1", 12, Start.AddMinutes(3), "provider-1", "node-a", 7,
            "running", ProviderOutcome.Succeeded, "work-1"),
        new RecordTerminal("op-1", 12, Start.AddMinutes(4), ProviderOutcome.Succeeded, "running"),
    ];

    private static List<OperationEvent> BuildPrepared() => Add([], ScenarioCommands()[0]);

    private static List<OperationEvent> BuildThroughAuthorization() =>
        Add(BuildPrepared(), ScenarioCommands()[1]);

    private static List<OperationEvent> Add(IEnumerable<OperationEvent> history, OperationCommand command)
    {
        var result = history.ToList();
        var decision = OperationEngine.Decide(result, command);
        if (decision.Errors.Count != 0)
            throw new InvalidOperationException(string.Join(", ", decision.Errors.Select(static error => error.Message)));
        result.AddRange(decision.EventsToAppend);
        return result;
    }

    private static DesiredOperation Desired() => new(
        "aggregate-a", 7, "desired-rv-7", "create-node", "node-a", "running",
        "sha256:payload", "retry-op-1", Start.AddMinutes(10));

    private static ObservedResource Observation(string observationId, string resourceVersion) => new(
        "aggregate-a", 7, resourceVersion, observationId, "node-a", "absent", true);

    private static AuthorizationEvidence Evidence(ObservedResource observation) => new(
        observation, "sha256:approval", "sha256:evidence", true, true, true, true);

    private static async Task AssertRejected(OperationDecision decision, OperationErrorCode code)
    {
        await Assert.That(decision.EventsToAppend).IsEmpty();
        await Assert.That(decision.Intents).IsEmpty();
        await Assert.That(decision.Errors.Single().Code).IsEqualTo(code);
    }
}
