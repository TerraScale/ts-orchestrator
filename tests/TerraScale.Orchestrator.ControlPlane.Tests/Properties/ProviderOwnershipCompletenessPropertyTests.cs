using TerraScale.Orchestrator.ControlPlane.Providers;

namespace TerraScale.Orchestrator.ControlPlane.Tests.Properties;

public sealed class ProviderOwnershipCompletenessPropertyTests
{
    private const int Cases = 1_000;

    [Test]
    public async Task Call_evidence_replay_rejects_every_fingerprint_dimension_for_1000_cases()
    {
        var original = Context();
        var expectedTraceOrder = new[]
        {
            ProviderDecisionCode.EvidenceComplete,
            ProviderDecisionCode.EvidenceUnique,
            ProviderDecisionCode.EvidenceConsistent,
            ProviderDecisionCode.AuthorityPresent,
            ProviderDecisionCode.ScopeMatches,
            ProviderDecisionCode.EpochCurrentOrDurablyResumable,
            ProviderDecisionCode.OwnershipMatches,
            ProviderDecisionCode.GenerationMatches,
            ProviderDecisionCode.DeadlineValid,
            ProviderDecisionCode.ApprovalsComplete,
            ProviderDecisionCode.CallEvidenceMatches,
            ProviderDecisionCode.PriorAuthorizationCompatible,
            ProviderDecisionCode.ActionResourceCompatible,
            ProviderDecisionCode.TagsConsistent,
            ProviderDecisionCode.TagsNotAuthority,
        };

        for (var seed = 0; seed < Cases; seed++)
        {
            var acceptedLikeStatus = (seed % 3) switch
            {
                0 => ProviderCallStatus.Accepted,
                1 => ProviderCallStatus.ResponseLost,
                _ => ProviderCallStatus.Completed,
            };
            var acceptedForOriginal = new ProviderCallEvidence(original, acceptedLikeStatus, new("work-a"));
            var replayed = MutateContext(seed % 16);
            var decision = ProviderOwnershipEngine.Authorize(Request(replayed, acceptedForOriginal));

            await Assert.That(decision.Authorized).IsFalse();
            await Assert.That(decision.Intents).IsEmpty();
            await Assert.That(string.Join(',', decision.Trace.Select(reason => reason.Code)))
                .IsEqualTo(string.Join(',', expectedTraceOrder));
            await Assert.That(Reason(decision, ProviderDecisionCode.CallEvidenceMatches).Outcome)
                .IsEqualTo(ProviderDecisionOutcome.Rejected);
            await Assert.That(Capture(() => { _ = decision.CaptureDurableAuthorization(); })).IsTypeOf<InvalidOperationException>();
        }
    }

    [Test]
    public async Task Call_lifecycle_and_durable_resume_are_exact_for_1000_cases()
    {
        for (var seed = 0; seed < Cases; seed++)
        {
            var context = Context(operation: $"operation-{seed}", idempotency: $"idempotency-{seed}");
            var mode = seed % 6;
            var status = mode switch
            {
                0 => ProviderCallStatus.NotCalled,
                1 or 2 => ProviderCallStatus.Accepted,
                3 or 4 => ProviderCallStatus.ResponseLost,
                _ => ProviderCallStatus.Completed,
            };
            var work = mode is 2 or 4 or 5 ? new ProviderWorkRequestId($"work-{seed}") : null;
            var decision = ProviderOwnershipEngine.Authorize(Request(context, new(context, status, work)));

            await Assert.That(decision.Authorized).IsTrue();
            await Assert.That(Reason(decision, ProviderDecisionCode.CallEvidenceMatches).Outcome)
                .IsEqualTo(ProviderDecisionOutcome.Passed);
            var intent = decision.Intents.Single();
            var expectedType = mode switch
            {
                0 => typeof(TerminateNodeProviderIntent),
                2 or 4 => typeof(ReadProviderWorkRequestIntent),
                _ => typeof(ObserveProviderResourceIntent),
            };
            await Assert.That(intent.GetType()).IsEqualTo(expectedType);
            await Assert.That(intent.Context).IsSameReferenceAs(context);
            if (intent is ReadProviderWorkRequestIntent read)
                await Assert.That(read.WorkRequestId).IsEqualTo(work);

            if (status == ProviderCallStatus.NotCalled)
            {
                await Assert.That(Capture(() => { _ = decision.CaptureDurableAuthorization(); })).IsTypeOf<InvalidOperationException>();
                continue;
            }

            var durable = decision.CaptureDurableAuthorization();
            var resumed = ProviderOwnershipEngine.Authorize(Request(
                context, new(context, ProviderCallStatus.NotCalled, null), authorityEpoch: context.ControllerEpoch.Value + 1, prior: durable));
            await Assert.That(resumed.Authorized).IsTrue();
            await Assert.That(resumed.Intents.Single()).IsTypeOf<TerminateNodeProviderIntent>();
            await Assert.That(Reason(resumed, ProviderDecisionCode.CallEvidenceMatches).Outcome)
                .IsEqualTo(ProviderDecisionOutcome.Passed);
        }
    }

    [Test]
    public async Task Handoff_every_inventory_and_proof_dimension_is_fail_closed_for_1000_cases()
    {
        var traceOrder = new[]
        {
            ProviderDecisionCode.HandoffInventoryUnique,
            ProviderDecisionCode.HandoffInventoryExact,
            ProviderDecisionCode.HandoffScopeMatches,
            ProviderDecisionCode.HandoffGenerationNotRollback,
            ProviderDecisionCode.HandoffRetainUnmanage,
            ProviderDecisionCode.HandoffJournalReceipt,
            ProviderDecisionCode.HandoffProviderReady,
            ProviderDecisionCode.HandoffTrustReady,
            ProviderDecisionCode.HandoffBackupReady,
            ProviderDecisionCode.HandoffFenceActivated,
        };
        for (var seed = 0; seed < Cases; seed++)
        {
            var mode = seed % 18;
            var first = new HandoffInventoryItem(new($"node-{seed}"), ProviderResourceKind.Node, new(7));
            var second = new HandoffInventoryItem(new($"volume-{seed}"), ProviderResourceKind.Volume, new(7));
            HandoffInventoryItem[] expected = [first, second];
            IEnumerable<HandoffInventoryItem> pulumi = expected.Reverse();
            IEnumerable<HandoffInventoryItem> regional = expected;
            if (mode == 13) expected = [first, first];
            if (mode == 14) pulumi = [first];
            if (mode == 15) regional = [first, new(second.ResourceId, second.Kind, new(8))];
            if (mode == 16) pulumi = [first, new(second.ResourceId, ProviderResourceKind.Backend, second.Generation)];
            var inventory = new FreshBootstrapInventory(expected, pulumi, regional);
            var scope = HandoffScope.ForFreshBootstrap(new("gru"), new("compartment"), new(7), new("handoff"), inventory);
            var wrongScope = mode == 17
                ? HandoffScope.ForFreshBootstrap(new("sfo"), new("compartment"), new(7), new("handoff"), inventory)
                : HandoffScope.ForFreshBootstrap(new("gru"), new("compartment"), new(8), new("other-handoff"), inventory);
            var evidence = HandoffEvidenceFor(scope, wrongScope, mode);
            var decision = ProviderOwnershipEngine.EvaluateHandoff(
                new(inventory, scope, scope.BootstrapGeneration, evidence));

            await Assert.That(decision.Ready).IsEqualTo(mode == 0);
            await Assert.That(decision.Intent is not null).IsEqualTo(mode == 0);
            await Assert.That(decision.Trace.Select(reason => reason.Code).SequenceEqual(traceOrder)).IsTrue();
            if (mode is >= 1 and <= 6)
                await Assert.That(decision.Trace[mode + 3].Outcome).IsEqualTo(ProviderDecisionOutcome.Held);
            if (mode is >= 7 and <= 12)
                await Assert.That(decision.Trace[mode - 3].Outcome).IsEqualTo(ProviderDecisionOutcome.Rejected);
        }
    }

    [Test]
    public async Task Handoff_generation_high_water_is_anti_rollback_and_output_closed_for_1000_cases()
    {
        for (var seed = 0; seed < Cases; seed++)
        {
            var candidateValue = checked((ulong)seed + 3UL);
            var relation = seed % 3;
            var currentValue = relation switch
            {
                0 => candidateValue + 1UL,
                1 => candidateValue,
                _ => candidateValue - 1UL,
            };
            var item = new HandoffInventoryItem(new($"node-{seed}"), ProviderResourceKind.Node, new(candidateValue));
            var inventory = new FreshBootstrapInventory([item], [item], [item]);
            var scope = HandoffScope.ForFreshBootstrap(
                new("gru"), new("compartment"), new(candidateValue), new($"handoff-{seed}"), inventory);
            var evidence = HandoffEvidenceFor(scope, scope, 0);
            var decision = ProviderOwnershipEngine.EvaluateHandoff(
                new(inventory, scope, new(currentValue), evidence));
            var generationReason = decision.Trace[3];

            await Assert.That(decision.Trace.Count).IsEqualTo(10);
            await Assert.That(generationReason.Code).IsEqualTo(ProviderDecisionCode.HandoffGenerationNotRollback);
            await Assert.That(generationReason.Observed).IsEqualTo(candidateValue);
            await Assert.That(generationReason.Required).IsEqualTo(currentValue);
            await Assert.That(decision.Ready).IsEqualTo(relation != 0);
            await Assert.That(decision.Intent is not null).IsEqualTo(relation != 0);
            if (decision.Intent is not null)
            {
                await Assert.That(decision.Intent.Scope).IsSameReferenceAs(scope);
                await Assert.That(decision.Intent.CurrentAcceptedBootstrapGeneration.Value).IsEqualTo(currentValue);
            }
        }
    }

    [Test]
    public async Task Every_closed_provider_action_emits_only_its_exact_typed_intent_for_1000_cases()
    {
        var actions = Enum.GetValues<ProviderAction>();
        var expectedTypes = new Dictionary<ProviderAction, Type>
        {
            [ProviderAction.CreateNode] = typeof(CreateNodeProviderIntent),
            [ProviderAction.Observe] = typeof(ObserveProviderResourceIntent),
            [ProviderAction.StartNode] = typeof(StartNodeProviderIntent),
            [ProviderAction.StopNode] = typeof(StopNodeProviderIntent),
            [ProviderAction.TerminateNode] = typeof(TerminateNodeProviderIntent),
            [ProviderAction.CreateVolume] = typeof(CreateVolumeProviderIntent),
            [ProviderAction.ExpandVolume] = typeof(ExpandVolumeProviderIntent),
            [ProviderAction.ChangeVolumePerformance] = typeof(ChangeVolumePerformanceProviderIntent),
            [ProviderAction.AttachVolume] = typeof(AttachVolumeProviderIntent),
            [ProviderAction.DetachVolume] = typeof(DetachVolumeProviderIntent),
            [ProviderAction.RegisterBackend] = typeof(RegisterBackendProviderIntent),
            [ProviderAction.DeregisterBackend] = typeof(DeregisterBackendProviderIntent),
        };
        await Assert.That(expectedTypes.Count).IsEqualTo(actions.Length);
        for (var seed = 0; seed < Cases; seed++)
        {
            var action = actions[seed % actions.Length];
            var context = ActionContext(action, seed);
            var decision = ProviderOwnershipEngine.Authorize(ActionRequest(context));
            await Assert.That(decision.Authorized).IsTrue();
            await Assert.That(decision.Intents.Single().GetType()).IsEqualTo(expectedTypes[action]);
            await Assert.That(decision.Intents.Single().Context).IsSameReferenceAs(context);
            await Assert.That(decision.Trace.Count).IsEqualTo(15);
        }
    }

    private static ProviderOperationContext ActionContext(ProviderAction action, int seed)
    {
        var existing = new ExistingProviderResource(new($"resource:{seed}"));
        var create = new IdempotentProviderCreate(new($"create-{seed}"));
        var digest = new ProviderBootstrapEnvelopeDigest(new string((char)('a' + seed % 6), 64));
        var tuple = action switch
        {
            ProviderAction.CreateNode => (ProviderResourceKind.Node, (ProviderTarget)create, ProviderObservedState.Absent, ProviderTerminalState.Present, (ProviderActionParameters)new CreateNodeProviderParameters(new("template"), new("placement"), digest)),
            ProviderAction.Observe => (ProviderResourceKind.Node, (ProviderTarget)existing, ProviderObservedState.Running, ProviderTerminalState.Running, (ProviderActionParameters)new ObserveProviderParameters()),
            ProviderAction.StartNode => (ProviderResourceKind.Node, (ProviderTarget)existing, ProviderObservedState.Stopped, ProviderTerminalState.Running, (ProviderActionParameters)new StartNodeProviderParameters()),
            ProviderAction.StopNode => (ProviderResourceKind.Node, (ProviderTarget)existing, ProviderObservedState.Running, ProviderTerminalState.Stopped, (ProviderActionParameters)new StopNodeProviderParameters()),
            ProviderAction.TerminateNode => (ProviderResourceKind.Node, (ProviderTarget)existing, ProviderObservedState.Running, ProviderTerminalState.Terminated, (ProviderActionParameters)new TerminateNodeProviderParameters()),
            ProviderAction.CreateVolume => (ProviderResourceKind.Volume, (ProviderTarget)create, ProviderObservedState.Absent, ProviderTerminalState.Present, (ProviderActionParameters)new CreateVolumeProviderParameters(new(1_000), ProviderVolumePerformance.Balanced)),
            ProviderAction.ExpandVolume => (ProviderResourceKind.Volume, (ProviderTarget)existing, ProviderObservedState.Present, ProviderTerminalState.Expanded, (ProviderActionParameters)new ExpandVolumeProviderParameters(new(2_000))),
            ProviderAction.ChangeVolumePerformance => (ProviderResourceKind.Volume, (ProviderTarget)existing, ProviderObservedState.Present, ProviderTerminalState.PerformanceChanged, (ProviderActionParameters)new ChangeVolumePerformanceProviderParameters(ProviderVolumePerformance.Iops)),
            ProviderAction.AttachVolume => (ProviderResourceKind.Attachment, (ProviderTarget)existing, ProviderObservedState.Absent, ProviderTerminalState.Attached, (ProviderActionParameters)new AttachVolumeProviderParameters(new("volume:one"), new("node:one"))),
            ProviderAction.DetachVolume => (ProviderResourceKind.Attachment, (ProviderTarget)existing, ProviderObservedState.Present, ProviderTerminalState.Detached, (ProviderActionParameters)new DetachVolumeProviderParameters()),
            ProviderAction.RegisterBackend => (ProviderResourceKind.Backend, (ProviderTarget)existing, ProviderObservedState.Absent, ProviderTerminalState.Registered, (ProviderActionParameters)new RegisterBackendProviderParameters(new("backend:one"))),
            ProviderAction.DeregisterBackend => (ProviderResourceKind.Backend, (ProviderTarget)existing, ProviderObservedState.Present, ProviderTerminalState.Deregistered, (ProviderActionParameters)new DeregisterBackendProviderParameters(new("backend:one"))),
            _ => throw new ArgumentOutOfRangeException(nameof(action)),
        };
        return new(new($"operation-{seed}"), new("gru"), new("compartment"), new(5), tuple.Item1, action,
            tuple.Item2, new(7), tuple.Item3, tuple.Item4, [ProviderApproval.RegionalAuthority],
            new(DeadlineEvidenceStatus.Valid, new(1)), new($"idempotency-{seed}"),
            [ProviderCompensation.ObserveOnly], tuple.Item5);
    }

    private static ProviderAuthorizationRequest ActionRequest(ProviderOperationContext context)
    {
        var call = new ProviderCallEvidence(context, ProviderCallStatus.NotCalled, null);
        if (context.Target is IdempotentProviderCreate create)
            return new(context, new(context.CellId, context.CompartmentId, context.ControllerEpoch), [], [],
                ProviderObservationCompleteness.Complete, [],
                [new ProviderCreateObservation(create.Key, context.ExpectedGeneration, context.ExpectedObservedState, null)],
                context.Approvals, null, call);
        var resource = ((ExistingProviderResource)context.Target).Id;
        return new(context, new(context.CellId, context.CompartmentId, context.ControllerEpoch),
            [new ProviderOwnershipRecord(resource, context.CellId, context.CompartmentId, context.ExpectedGeneration)], [],
            ProviderObservationCompleteness.Complete,
            [new ProviderResourceObservation(resource, context.ExpectedGeneration, context.ExpectedObservedState)], [],
            context.Approvals, null, call);
    }

    private static HandoffEvidence HandoffEvidenceFor(HandoffScope scope, HandoffScope wrongScope, int mode)
    {
        HandoffProofValue Select(int proof) => new(
            mode == proof + 6 || mode == 17 ? wrongScope : scope,
            mode == proof ? HandoffEvidenceStatus.Missing : HandoffEvidenceStatus.Verified);
        var retain = Select(1); var journal = Select(2); var provider = Select(3);
        var trust = Select(4); var backup = Select(5); var fence = Select(6);
        return new(
            new RetainUnmanageHandoffProof(retain.Scope, retain.Status),
            new RegionalJournalHandoffProof(journal.Scope, journal.Status),
            new ProviderReadyHandoffProof(provider.Scope, provider.Status),
            new TrustReadyHandoffProof(trust.Scope, trust.Status),
            new BackupReadyHandoffProof(backup.Scope, backup.Status),
            new RegionalFenceHandoffProof(fence.Scope, fence.Status));
    }

    private sealed record HandoffProofValue(HandoffScope Scope, HandoffEvidenceStatus Status);

    private static ProviderOperationContext MutateContext(int dimension) => dimension switch
    {
        0 => Context(operation: "operation-b"),
        1 => Context(cell: new("sfo")),
        2 => Context(compartment: new("other-compartment")),
        3 => Context(epoch: 6),
        4 => Context(kind: ProviderResourceKind.Volume),
        5 => Context(action: ProviderAction.StopNode),
        6 => Context(target: new ExistingProviderResource(new("node-2"))),
        7 => Context(generation: new(8)),
        8 => Context(observed: ProviderObservedState.Stopped),
        9 => Context(terminal: ProviderTerminalState.Stopped),
        10 => Context(approvals: [ProviderApproval.RegionalAuthority, ProviderApproval.DestructiveMutation]),
        11 => Context(deadline: new(DeadlineEvidenceStatus.Expired, new(1))),
        12 => Context(deadline: new(DeadlineEvidenceStatus.Valid, new(2))),
        13 => Context(idempotency: "idempotency-b"),
        14 => Context(compensations: [ProviderCompensation.ObserveOnly, ProviderCompensation.StopCreatedNode]),
        15 => Context(parameters: new StopNodeProviderParameters()),
        _ => throw new ArgumentOutOfRangeException(nameof(dimension)),
    };

    private static ProviderOperationContext Context(
        string operation = "operation-a", ProviderCellId? cell = null, ProviderCompartmentId? compartment = null,
        ulong epoch = 5, ProviderResourceKind kind = ProviderResourceKind.Node,
        ProviderAction action = ProviderAction.TerminateNode, ProviderTarget? target = null,
        ProviderGeneration? generation = null, ProviderObservedState observed = ProviderObservedState.Running,
        ProviderTerminalState terminal = ProviderTerminalState.Terminated,
        IEnumerable<ProviderApproval>? approvals = null, DeadlineEvidence? deadline = null,
        string idempotency = "idempotency-a", IEnumerable<ProviderCompensation>? compensations = null,
        ProviderActionParameters? parameters = null) => new(
        new(operation), cell ?? new("gru"), compartment ?? new("compartment"), new(epoch), kind, action,
        target ?? new ExistingProviderResource(new("node-1")), generation ?? new(7), observed, terminal,
        approvals ?? [ProviderApproval.RegionalAuthority], deadline ?? new(DeadlineEvidenceStatus.Valid, new(1)),
        new(idempotency), compensations ?? [ProviderCompensation.ObserveOnly], parameters ?? new TerminateNodeProviderParameters());

    private static ProviderAuthorizationRequest Request(
        ProviderOperationContext context, ProviderCallEvidence call, ulong? authorityEpoch = null,
        DurableProviderAuthorization? prior = null)
    {
        var target = (ExistingProviderResource)context.Target;
        return new(
            context, new(context.CellId, context.CompartmentId, new(authorityEpoch ?? context.ControllerEpoch.Value)),
            [new ProviderOwnershipRecord(target.Id, context.CellId, context.CompartmentId, context.ExpectedGeneration)],
            [], ProviderObservationCompleteness.Complete,
            [new ProviderResourceObservation(target.Id, context.ExpectedGeneration, context.ExpectedObservedState)],
            [], context.Approvals, prior, call);
    }

    private static ProviderDecisionReason Reason(ProviderAuthorizationDecision decision, ProviderDecisionCode code) =>
        decision.Trace.Single(reason => reason.Code == code);

    private static Exception? Capture(Action action)
    {
        try { action(); return null; }
        catch (Exception exception) { return exception; }
    }
}
