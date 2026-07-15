using System.Globalization;

namespace TerraScale.Orchestrator.ModelTests.Simulation;

public sealed class AdversarialAudit3CounterexampleTests
{
    [Test]
    public async Task Accepted_events_with_distinct_replay_coordinates_no_longer_collapse()
    {
        var firstEvent = Event();
        var secondEvent = firstEvent with { Sequence = 9, ObservationSequence = 99 };
        var first = DeterministicSimulator.Replay([firstEvent], [], new(16, 4, 1));
        var second = DeterministicSimulator.Replay([secondEvent], [], new(16, 4, 1));

        await Assert.That(first.State.AcceptedActions.Single())
            .IsNotEqualTo(second.State.AcceptedActions.Single());
        await Assert.That(first.State.Canonical()).IsNotEqualTo(second.State.Canonical());
        await Assert.That(first.Digest).IsNotEqualTo(second.Digest);
    }

    [Test]
    public async Task Accepted_action_retains_the_exact_event_that_authorized_it()
    {
        var acceptedEvent = Event();
        var result = DeterministicSimulator.Replay([acceptedEvent], [], new(16, 4, 1));

        await Assert.That(result.Code).IsEqualTo(SimulationFailureCode.Completed);
        await Assert.That(result.State.AcceptedActions).HasSingleItem();
        await Assert.That(result.State.AcceptedActions[0].AcceptedEvent).IsSameReferenceAs(acceptedEvent);
    }

    [Test]
    public async Task Every_event_field_is_bound_to_accepted_evidence_and_the_state_digest()
    {
        var baselineResult = DeterministicSimulator.Replay([Event()], [], new(16, 4, 1));
        var baseline = baselineResult.State.AcceptedActions.Single();
        var variants = new[]
        {
            baseline.AcceptedEvent with { Sequence = 2 },
            baseline.AcceptedEvent with { DueTick = 2 },
            baseline.AcceptedEvent with { EventId = "other-event" },
            baseline.AcceptedEvent with { Kind = ModelEventKind.RequestCreate },
            baseline.AcceptedEvent with { Node = "n2" },
            baseline.AcceptedEvent with { Operation = "other-operation" },
            baseline.AcceptedEvent with { Generation = 3 },
            baseline.AcceptedEvent with { Epoch = 2 },
            baseline.AcceptedEvent with { IdempotencyKey = "other-key" },
            baseline.AcceptedEvent with { Resource = "other-resource" },
            baseline.AcceptedEvent with { ObservationSequence = 2 },
        };

        foreach (var variant in variants)
        {
            var evidence = baseline with { AcceptedEvent = variant };
            var state = WithAcceptedAction(baselineResult.State, evidence);
            await Assert.That(evidence).IsNotEqualTo(baseline);
            await Assert.That(state.Canonical()).IsNotEqualTo(baselineResult.State.Canonical());
            await Assert.That(state.Digest()).IsNotEqualTo(baselineResult.Digest);
            await Assert.That(state.Canonical()).Contains(ModelState.EventCanonical(variant));
        }
    }

    [Test]
    public async Task Semantic_replay_is_value_equal_and_culture_stable_without_losing_reference_provenance()
    {
        var originalCulture = CultureInfo.CurrentCulture;
        try
        {
            var firstEvent = Event();
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("tr-TR");
            var first = DeterministicSimulator.Replay([firstEvent], [], new(16, 4, 1));
            var replayEvent = Event();
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("ar-SA");
            var replay = DeterministicSimulator.Replay([replayEvent], [], new(16, 4, 1));

            await Assert.That(first.State.AcceptedActions[0]).IsEqualTo(replay.State.AcceptedActions[0]);
            await Assert.That(first.Digest).IsEqualTo(replay.Digest);
            await Assert.That(first.State.AcceptedActions[0].AcceptedEvent).IsSameReferenceAs(firstEvent);
            await Assert.That(replay.State.AcceptedActions[0].AcceptedEvent).IsSameReferenceAs(replayEvent);
        }
        finally
        {
            CultureInfo.CurrentCulture = originalCulture;
        }
    }

    [Test]
    public async Task Every_reachable_accepted_action_kind_uses_the_exact_event_helper()
    {
        var authorization = Event(sequence: 1, kind: ModelEventKind.AuthorizeOperation);
        var create = Event(sequence: 2, kind: ModelEventKind.RequestCreate);
        var mutation = Event(sequence: 3, kind: ModelEventKind.MutationSucceeded);
        var result = DeterministicSimulator.Replay([authorization, create, mutation], [], new(16, 4, 1));

        await Assert.That(result.Code).IsEqualTo(SimulationFailureCode.Completed);
        await Assert.That(result.State.AcceptedActions.Select(static action => action.Kind))
            .IsEquivalentTo(new[] { AcceptedActionKind.Authorization, AcceptedActionKind.Create, AcceptedActionKind.Mutation });
        await Assert.That(result.State.AcceptedActions[0].AcceptedEvent).IsSameReferenceAs(authorization);
        await Assert.That(result.State.AcceptedActions[1].AcceptedEvent).IsSameReferenceAs(create);
        await Assert.That(result.State.AcceptedActions[2].AcceptedEvent).IsSameReferenceAs(mutation);
        foreach (var action in result.State.AcceptedActions)
        {
            await Assert.That(result.State.Canonical()).Contains(ModelState.EventCanonical(action.AcceptedEvent));
        }
    }

    [Test]
    public async Task Missing_or_unsupported_accepted_event_is_rejected_at_the_state_boundary()
    {
        var state = ModelState.Create([]);
        var missing = new AcceptedActionEvidence(null!, 1, "n1", 1, false, false, true,
            ModelNodeRole.Critical, 1, 3);
        var unsupported = new AcceptedActionEvidence(Event(kind: ModelEventKind.Delivery), 1, "n1", 1,
            false, false, true, ModelNodeRole.Critical, 1, 3);

        await Assert.That(unsupported.Kind).IsEqualTo(AcceptedActionKind.Unspecified);
        await Assert.That(Capture(() => WithAcceptedAction(state, missing))).IsTypeOf<ArgumentException>();
        await Assert.That(Capture(() => WithAcceptedAction(state, unsupported))).IsTypeOf<ArgumentException>();
    }

    private static ModelState WithAcceptedAction(ModelState state, AcceptedActionEvidence evidence) => new(
        state.Clock, state.Identities, state.CurrentEpoch, state.Leader, state.Nodes, state.Operations,
        state.Queue, state.DeliveredEventIds, state.AcceptedMutations, state.RejectedMutations,
        state.Terminations, state.CompletedMutationOperations, [evidence]);

    private static ModelEvent Event(long sequence = 1, ModelEventKind kind = ModelEventKind.AuthorizeOperation) => new(
        sequence, sequence, $"event-{sequence.ToString(CultureInfo.InvariantCulture)}", kind, "n1",
        "operation-1", 2, 1, "create-key", "resource-1", sequence);

    private static Exception? Capture(Action action)
    {
        try
        {
            action();
            return null;
        }
        catch (Exception exception)
        {
            return exception;
        }
    }
}
