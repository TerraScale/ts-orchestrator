using TerraScale.Orchestrator.ControlPlane.Operations;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class OperationWorkRequestContinuityCounterexampleTests
{
    private static readonly DateTimeOffset Start = new(2026, 7, 14, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task Established_provider_work_request_rejects_different_or_missing_identity()
    {
        foreach (var candidate in new string?[] { "provider-work-2", null })
        {
            var history = ThroughObservation("provider-work-1");
            var rebound = OperationEngine.Decide(history, Observation(
                "provider-observation-2", ProviderOutcome.Succeeded, candidate, "running"));

            await Assert.That(rebound.EventsToAppend).IsEmpty();
            await Assert.That(rebound.Intents).IsEmpty();
            await Assert.That(rebound.Errors.Single().Code)
                .IsEqualTo(OperationErrorCode.ConflictingTerminalObservation);
            await Assert.That(rebound.Errors.Single().Message).Contains("work-request identity");
        }
    }

    [Test]
    public async Task Missing_provider_work_request_can_remain_missing_or_be_established_once()
    {
        foreach (var candidate in new string?[] { null, "provider-work-1" })
        {
            var history = ThroughObservation(null);
            var next = OperationEngine.Decide(history, Observation(
                "provider-observation-2", ProviderOutcome.InProgress, candidate, "creating"));

            await Assert.That(next.Errors).IsEmpty();
            await Assert.That(next.EventsToAppend).HasSingleItem();
            await Assert.That(next.Intents.Single()).IsTypeOf<ReconcileProviderIntent>();
            await Assert.That(((OperationObservationRecorded)next.EventsToAppend.Single()).ProviderWorkRequestId)
                .IsEqualTo(candidate);
        }
    }

    [Test]
    public async Task Newly_established_provider_work_request_becomes_immutable()
    {
        var history = ThroughObservation(null);
        Append(history, Observation("provider-observation-2", ProviderOutcome.InProgress,
            "provider-work-1", "creating"));

        var rebound = OperationEngine.Decide(history, Observation(
            "provider-observation-3", ProviderOutcome.Succeeded, "provider-work-2", "running"));

        await Assert.That(rebound.EventsToAppend).IsEmpty();
        await Assert.That(rebound.Errors.Single().Code)
            .IsEqualTo(OperationErrorCode.ConflictingTerminalObservation);
    }

    [Test]
    public async Task Same_provider_work_request_can_progress_from_pending_to_success()
    {
        var history = ThroughObservation("provider-work-1");
        var completed = OperationEngine.Decide(history, Observation(
            "provider-observation-2", ProviderOutcome.Succeeded, "provider-work-1", "running"));

        await Assert.That(completed.Errors).IsEmpty();
        await Assert.That(completed.EventsToAppend).HasSingleItem();
        await Assert.That(completed.Intents).IsEmpty();
        await Assert.That(((OperationObservationRecorded)completed.EventsToAppend.Single()).Outcome)
            .IsEqualTo(ProviderOutcome.Succeeded);
    }

    [Test]
    public async Task Same_observation_identity_rebound_precedes_work_request_continuity_error()
    {
        var history = ThroughObservation("provider-work-1");
        var rebound = OperationEngine.Decide(history, Observation(
            "provider-observation-1", ProviderOutcome.Succeeded, "provider-work-2", "running"));

        await Assert.That(rebound.Errors.Single().Code)
            .IsEqualTo(OperationErrorCode.ConflictingTerminalObservation);
        await Assert.That(rebound.Errors.Single().Message).Contains("observation identity");
    }

    [Test]
    public async Task Journal_replay_rejects_changed_or_removed_work_request_and_preserves_prior_state()
    {
        foreach (var candidate in new string?[] { "provider-work-2", null })
        {
            var history = ThroughObservation("provider-work-1");
            var prior = OperationEngine.Replay(history).State;
            var body = new OperationObservationRecorded(prior.LastSequence + 1, prior.JournalDigest,
                string.Empty, "op-1", 1, Start.AddMinutes(4), "provider-observation-2", "node-a", 7,
                "running", ProviderOutcome.Succeeded, candidate);
            var forged = body with { EventDigest = OperationDigest.Event(body) };

            var replay = OperationEngine.Replay(history.Append(forged).ToArray());

            await Assert.That(replay.Errors.Single().Code)
                .IsEqualTo(OperationErrorCode.ConflictingTerminalObservation);
            await Assert.That(replay.Errors.Single().Message).Contains("work-request identity");
            await Assert.That(OperationDigest.State(replay.State)).IsEqualTo(OperationDigest.State(prior));
        }
    }

    [Test]
    public async Task Observation_and_decision_digests_bind_provider_work_request_identity()
    {
        var history = ThroughDispatch();
        var first = Observation("provider-observation-1", ProviderOutcome.InProgress,
            "provider-work-1", "creating");
        var second = first with { ProviderWorkRequestId = "provider-work-2" };
        var firstDecision = OperationEngine.Decide(history, first);
        var secondDecision = OperationEngine.Decide(history, second);

        await Assert.That(((OperationObservationRecorded)firstDecision.EventsToAppend.Single()).EventDigest)
            .IsNotEqualTo(((OperationObservationRecorded)secondDecision.EventsToAppend.Single()).EventDigest);
        await Assert.That(firstDecision.DecisionDigest).IsNotEqualTo(secondDecision.DecisionDigest);
        await Assert.That(((ReconcileProviderIntent)firstDecision.Intents.Single()).ProviderWorkRequestId)
            .IsEqualTo("provider-work-1");
        await Assert.That(((ReconcileProviderIntent)secondDecision.Intents.Single()).ProviderWorkRequestId)
            .IsEqualTo("provider-work-2");
    }

    private static List<OperationEvent> ThroughObservation(string? providerWorkRequestId)
    {
        var history = ThroughDispatch();
        Append(history, Observation("provider-observation-1", ProviderOutcome.InProgress,
            providerWorkRequestId, "creating"));
        return history;
    }

    private static List<OperationEvent> ThroughDispatch()
    {
        var desired = new DesiredOperation("aggregate-a", 7, "rv-7", "create", "node-a",
            "running", "payload-7", "idem-7", Start.AddMinutes(10));
        var expected = new ObservedResource("aggregate-a", 7, "rv-7", "expected-1",
            "node-a", "absent", true);
        var evidence = new AuthorizationEvidence(
            expected with { ResourceVersion = "rv-8", ObservationId = "authorized-1" },
            "approval-1", "evidence-1", true, true, true, true);
        var history = new List<OperationEvent>();
        Append(history, new PrepareOperation("op-1", 1, Start, desired, expected, []));
        Append(history, new AuthorizeOperation("op-1", 1, Start.AddMinutes(1), evidence));
        Append(history, new RecordDispatch("op-1", 1, Start.AddMinutes(2), "executor-1", 1));
        return history;
    }

    private static RecordObservation Observation(string observationId, ProviderOutcome outcome,
        string? providerWorkRequestId, string state) => new(
        "op-1", 1, Start.AddMinutes(3), observationId, "node-a", 7,
        state, outcome, providerWorkRequestId);

    private static void Append(List<OperationEvent> history, OperationCommand command)
    {
        var decision = OperationEngine.Decide(history, command);
        if (decision.Errors.Count != 0) throw new InvalidOperationException(decision.Errors[0].Message);
        history.AddRange(decision.EventsToAppend);
    }
}
