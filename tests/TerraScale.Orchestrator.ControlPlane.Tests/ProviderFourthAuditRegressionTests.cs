using TerraScale.Orchestrator.ControlPlane.Providers;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class ProviderFourthAuditRegressionTests
{
    [Test]
    public async Task Create_absence_evidence_cannot_replay_across_regional_scope()
    {
        var observationCell = new ProviderCellId("gru");
        var observationCompartment = new ProviderCompartmentId("gru-compartment");
        var observation = new ProviderCreateObservation(new("shared-create"), observationCell,
            observationCompartment, new(7), ProviderObservedState.Absent, null);
        var gru = Context(new("gru"), new("gru-compartment"), "gru-operation");
        var sfo = Context(new("sfo"), new("sfo-compartment"), "sfo-operation");
        var wrongCompartment = Context(new("gru"), new("other-compartment"), "other-operation");

        var original = ProviderOwnershipEngine.Authorize(Request(gru, observation));
        var crossCell = ProviderOwnershipEngine.Authorize(Request(sfo, observation));
        var crossCompartment = ProviderOwnershipEngine.Authorize(Request(wrongCompartment, observation));

        await Assert.That(original.Authorized).IsTrue();
        await Assert.That(ReferenceEquals(observation.CellId, observationCell)).IsTrue();
        await Assert.That(ReferenceEquals(observation.CompartmentId, observationCompartment)).IsTrue();
        var intent = (CreateNodeProviderIntent)original.Intents.Single();
        await Assert.That(intent.Context.CellId.Value).IsEqualTo(observationCell.Value);
        await Assert.That(intent.Context.CompartmentId.Value).IsEqualTo(observationCompartment.Value);
        foreach (var replayed in new[] { crossCell, crossCompartment })
        {
            await Assert.That(replayed.Authorized).IsFalse();
            await Assert.That(replayed.Trace.Single(reason => reason.Code == ProviderDecisionCode.GenerationMatches).Outcome)
                .IsEqualTo(ProviderDecisionOutcome.Rejected);
            await Assert.That(replayed.Intents).IsEmpty();
            await Assert.That(Capture(() => { _ = replayed.CaptureDurableAuthorization(); })).IsTypeOf<InvalidOperationException>();
        }
    }

    [Test]
    public async Task Resolved_create_intent_retains_exact_observation_scope_and_rejects_scope_replay()
    {
        var cell = new ProviderCellId("gru");
        var compartment = new ProviderCompartmentId("gru-compartment");
        var observation = new ProviderCreateObservation(new("shared-create"), cell, compartment,
            new(7), ProviderObservedState.Present, new("node:resolved"));
        var exactContext = Context(new("gru"), new("gru-compartment"), "gru-operation", ProviderObservedState.Present);
        var replayContext = Context(new("sfo"), new("sfo-compartment"), "sfo-operation", ProviderObservedState.Present);

        var exact = ProviderOwnershipEngine.Authorize(Request(exactContext, observation));
        var replayed = ProviderOwnershipEngine.Authorize(Request(replayContext, observation));
        var intent = (ObserveResolvedProviderCreateIntent)exact.Intents.Single();

        await Assert.That(exact.Authorized).IsTrue();
        await Assert.That(ReferenceEquals(intent.CellId, cell)).IsTrue();
        await Assert.That(ReferenceEquals(intent.CompartmentId, compartment)).IsTrue();
        await Assert.That(intent.CellId.Value).IsEqualTo("gru");
        await Assert.That(intent.CompartmentId.Value).IsEqualTo("gru-compartment");
        await Assert.That(replayed.Authorized).IsFalse();
        await Assert.That(replayed.Intents).IsEmpty();
    }

    [Test]
    public async Task Create_observation_scope_is_required_defensively_copied_and_conflicts_fail_closed()
    {
        var context = Context(new("gru"), new("gru-compartment"), "gru-operation");
        var exact = new ProviderCreateObservation(new("shared-create"), context.CellId, context.CompartmentId,
            new(7), ProviderObservedState.Absent, null);
        await Assert.That(Capture(() => new ProviderCreateObservation(new("shared-create"), null!, context.CompartmentId,
            new(7), ProviderObservedState.Absent, null))).IsTypeOf<ArgumentNullException>();
        await Assert.That(Capture(() => new ProviderCreateObservation(new("shared-create"), context.CellId, null!,
            new(7), ProviderObservedState.Absent, null))).IsTypeOf<ArgumentNullException>();

        var source = new List<ProviderCreateObservation> { exact };
        var request = Request(context, source);
        source.Clear();
        await Assert.That(ProviderOwnershipEngine.Authorize(request).Authorized).IsTrue();

        var conflicting = new ProviderCreateObservation(new("shared-create"), new("sfo"), new("sfo-compartment"),
            new(7), ProviderObservedState.Absent, null);
        var ambiguous = ProviderOwnershipEngine.Authorize(Request(context, [exact, conflicting]));
        await Assert.That(ambiguous.Authorized).IsFalse();
        await Assert.That(ambiguous.Trace.Single(reason => reason.Code == ProviderDecisionCode.EvidenceUnique).Outcome)
            .IsEqualTo(ProviderDecisionOutcome.Held);
        await Assert.That(ambiguous.Trace.Single(reason => reason.Code == ProviderDecisionCode.EvidenceConsistent).Outcome)
            .IsEqualTo(ProviderDecisionOutcome.Held);
        await Assert.That(ambiguous.Intents).IsEmpty();
    }

    private static ProviderOperationContext Context(
        ProviderCellId cell, ProviderCompartmentId compartment, string operation,
        ProviderObservedState observedState = ProviderObservedState.Absent) => new(
        new(operation), cell, compartment, new(5), ProviderResourceKind.Node, ProviderAction.CreateNode,
        new IdempotentProviderCreate(new("shared-create")), new(7), observedState,
        ProviderTerminalState.Present, [ProviderApproval.RegionalAuthority],
        new(DeadlineEvidenceStatus.Valid, new(1)), new($"{cell.Value}-idempotency"),
        [ProviderCompensation.ObserveOnly], new CreateNodeProviderParameters(
            new("template"), new("placement"), new(new string('a', 64))));

    private static ProviderAuthorizationRequest Request(
        ProviderOperationContext context, ProviderCreateObservation observation) => Request(context, [observation]);

    private static ProviderAuthorizationRequest Request(
        ProviderOperationContext context, IEnumerable<ProviderCreateObservation> observations) => new(
        context, new(context.CellId, context.CompartmentId, context.ControllerEpoch), [], [],
        ProviderObservationCompleteness.Complete, [], observations, [ProviderApproval.RegionalAuthority],
        null, new(context, ProviderCallStatus.NotCalled, null));

    private static Exception? Capture(Action action)
    {
        try { action(); return null; }
        catch (Exception exception) { return exception; }
    }
}
