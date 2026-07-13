using System.Globalization;
using TerraScale.Orchestrator.ControlPlane.Providers;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class ProviderOwnershipTests
{
    [Test]
    public async Task ExactOwnedCurrentMutationEmitsOnlyTypedIntent()
    {
        var decision = ProviderOwnershipEngine.Authorize(Request());
        await Assert.That(decision.Authorized).IsTrue();
        await Assert.That(decision.Intents.Single() is TerminateNodeProviderIntent).IsTrue();
        await Assert.That(decision.Trace.All(x => x.Outcome is ProviderDecisionOutcome.Passed or ProviderDecisionOutcome.NotApplicable)).IsTrue();
    }

    [Test]
    public async Task TagsAloneNeverAuthorizeMutation()
    {
        var context = Context();
        var tag = new ProviderInventoryTagEvidence(Resource, Cell, Compartment, context.OperationId, Generation);
        var decision = ProviderOwnershipEngine.Authorize(Request(includeAuthority: false, ownership: [], tags: [tag]));
        await Assert.That(decision.Authorized).IsFalse();
        await Assert.That(Reason(decision, ProviderDecisionCode.AuthorityPresent).Outcome).IsEqualTo(ProviderDecisionOutcome.Held);
        await Assert.That(decision.Intents).IsEmpty();
    }

    [Test]
    public async Task MismatchedOrDuplicateTagsFailClosedEvenWithAuthoritativeOwnership()
    {
        var context = Context();
        var mismatched = new ProviderInventoryTagEvidence(
            Resource, Cell, Compartment, new("different-operation"), Generation);
        var exact = new ProviderInventoryTagEvidence(
            Resource, Cell, Compartment, context.OperationId, Generation);
        var mismatchDecision = ProviderOwnershipEngine.Authorize(Request(context: context, tags: [mismatched]));
        var duplicateDecision = ProviderOwnershipEngine.Authorize(Request(context: context, tags: [exact, exact]));
        await Assert.That(Reason(mismatchDecision, ProviderDecisionCode.TagsConsistent).Outcome).IsEqualTo(ProviderDecisionOutcome.Rejected);
        await Assert.That(Reason(duplicateDecision, ProviderDecisionCode.EvidenceUnique).Outcome).IsEqualTo(ProviderDecisionOutcome.Held);
        await Assert.That(mismatchDecision.Intents).IsEmpty();
        await Assert.That(duplicateDecision.Intents).IsEmpty();
    }

    [Test]
    public async Task StaleAndFutureEpochRejectWithoutDurableAuthorization()
    {
        var stale = ProviderOwnershipEngine.Authorize(Request(context: Context(epoch: 4), authority: Authority(5)));
        var future = ProviderOwnershipEngine.Authorize(Request(context: Context(epoch: 6), authority: Authority(5)));
        await Assert.That(Reason(stale, ProviderDecisionCode.EpochCurrentOrDurablyResumable).Outcome).IsEqualTo(ProviderDecisionOutcome.Rejected);
        await Assert.That(Reason(future, ProviderDecisionCode.EpochCurrentOrDurablyResumable).Outcome).IsEqualTo(ProviderDecisionOutcome.Rejected);
    }

    [Test]
    public async Task HigherEpochLeaderCanResumeExactDurableIrreversibleOperation()
    {
        var context = Context(epoch: 5);
        var prior = DurableProviderAuthorization.Capture(context, irreversible: true);
        var decision = ProviderOwnershipEngine.Authorize(Request(context: context, authority: Authority(6), prior: prior));
        await Assert.That(decision.Authorized).IsTrue();
        await Assert.That(decision.Intents.Single() is TerminateNodeProviderIntent).IsTrue();
    }

    [Test]
    public async Task DurableAuthorizationCannotSupersedeTerminalTarget()
    {
        var original = Context(action: ProviderAction.TerminateNode, terminal: ProviderTerminalState.Terminated);
        var conflicting = Context(action: ProviderAction.StopNode, terminal: ProviderTerminalState.Stopped);
        var prior = DurableProviderAuthorization.Capture(original, irreversible: true);
        var decision = ProviderOwnershipEngine.Authorize(Request(context: conflicting, prior: prior));
        await Assert.That(decision.Authorized).IsFalse();
        await Assert.That(Reason(decision, ProviderDecisionCode.PriorAuthorizationCompatible).Outcome).IsEqualTo(ProviderDecisionOutcome.Rejected);
    }

    [Test]
    public async Task LostResponseUsesSameIdempotencyAndReadsWorkRequestOrObserves()
    {
        var work = new ProviderWorkRequestId("work-1");
        var read = ProviderOwnershipEngine.Authorize(Request(call: new(ProviderCallStatus.ResponseLost, work)));
        var observe = ProviderOwnershipEngine.Authorize(Request(call: new(ProviderCallStatus.ResponseLost, null)));
        await Assert.That(((ReadProviderWorkRequestIntent)read.Intents.Single()).WorkRequestId).IsEqualTo(work);
        await Assert.That(read.Intents.Single().Context.IdempotencyKey).IsEqualTo(Context().IdempotencyKey);
        await Assert.That(observe.Intents.Single() is ObserveProviderResourceIntent).IsTrue();
    }

    [Test]
    public async Task AcceptedCallWithoutWorkRequestIsObservedAndNeverRepeated()
    {
        var decision = ProviderOwnershipEngine.Authorize(Request(call: new(ProviderCallStatus.Accepted, null)));
        await Assert.That(decision.Authorized).IsTrue();
        await Assert.That(decision.Intents.Single() is ObserveProviderResourceIntent).IsTrue();
    }

    [Test]
    public async Task LateAcceptedCallAfterLeadershipLossCanOnlyResumeExactDurableOperation()
    {
        var context = Context(epoch: 5);
        var prior = DurableProviderAuthorization.Capture(context, irreversible: true);
        var decision = ProviderOwnershipEngine.Authorize(Request(
            context: context, authority: Authority(6), prior: prior,
            call: new(ProviderCallStatus.Accepted, null)));
        await Assert.That(decision.Authorized).IsTrue();
        await Assert.That(decision.Intents.Single() is ObserveProviderResourceIntent).IsTrue();
        await Assert.That(decision.Intents.Single().Context).IsSameReferenceAs(context);
    }

    [Test]
    public async Task CreateVolumeUsesCreateKeyAndClosedTypedIntent()
    {
        var context = new ProviderOperationContext(
            new("operation-1"), Cell, Compartment, Epoch, ProviderResourceKind.Volume,
            ProviderAction.CreateVolume, new IdempotentProviderCreate(new("volume-create-1")), Generation,
            ProviderObservedState.Absent, ProviderTerminalState.Present, [ProviderApproval.RegionalAuthority],
            new(DeadlineEvidenceStatus.Valid, new(1)), new("idempotency-1"),
            [ProviderCompensation.ObserveOnly], new CreateVolumeProviderParameters(new(1_000), ProviderVolumePerformance.Balanced));
        var decision = ProviderOwnershipEngine.Authorize(Request(
            context: context, ownership: [], required: [ProviderApproval.RegionalAuthority]));
        await Assert.That(decision.Authorized).IsTrue();
        var intent = (CreateVolumeProviderIntent)decision.Intents.Single();
        await Assert.That(intent.Parameters.Size.Value).IsEqualTo(1_000UL);
    }

    [Test]
    public async Task ActionCriticalParametersAreCompatibleTypedAndDurablyFingerprintBound()
    {
        var original = VolumeContext(new ExpandVolumeProviderParameters(new(2_000)));
        var changed = VolumeContext(new ExpandVolumeProviderParameters(new(3_000)));
        var intentDecision = ProviderOwnershipEngine.Authorize(Request(
            context: original, observedState: ProviderObservedState.Present));
        var prior = DurableProviderAuthorization.Capture(original, irreversible: true);
        var changedDecision = ProviderOwnershipEngine.Authorize(Request(
            context: changed, observedState: ProviderObservedState.Present, prior: prior));
        var wrongParameters = VolumeContext(new ChangeVolumePerformanceProviderParameters(ProviderVolumePerformance.Iops));
        var incompatible = ProviderOwnershipEngine.Authorize(Request(
            context: wrongParameters, observedState: ProviderObservedState.Present));

        await Assert.That(((ExpandVolumeProviderIntent)intentDecision.Intents.Single()).Parameters.NewSize.Value).IsEqualTo(2_000UL);
        await Assert.That(Reason(changedDecision, ProviderDecisionCode.PriorAuthorizationCompatible).Outcome).IsEqualTo(ProviderDecisionOutcome.Rejected);
        await Assert.That(Reason(incompatible, ProviderDecisionCode.ActionResourceCompatible).Outcome).IsEqualTo(ProviderDecisionOutcome.Rejected);
    }

    [Test]
    public async Task ArgumentBearingIntentsExposeTheirExactClosedParameters()
    {
        var performance = ExistingContext(
            ProviderResourceKind.Volume, ProviderAction.ChangeVolumePerformance,
            ProviderTerminalState.PerformanceChanged,
            new ChangeVolumePerformanceProviderParameters(ProviderVolumePerformance.Iops));
        var attach = ExistingContext(
            ProviderResourceKind.Attachment, ProviderAction.AttachVolume, ProviderTerminalState.Attached,
            new AttachVolumeProviderParameters(new("volume:one"), new("node:one")));
        var backend = ExistingContext(
            ProviderResourceKind.Backend, ProviderAction.RegisterBackend, ProviderTerminalState.Registered,
            new RegisterBackendProviderParameters(new("backend:one")));

        var performanceIntent = (ChangeVolumePerformanceProviderIntent)ProviderOwnershipEngine
            .Authorize(Request(context: performance)).Intents.Single();
        var attachIntent = (AttachVolumeProviderIntent)ProviderOwnershipEngine
            .Authorize(Request(context: attach)).Intents.Single();
        var backendIntent = (RegisterBackendProviderIntent)ProviderOwnershipEngine
            .Authorize(Request(context: backend)).Intents.Single();

        await Assert.That(performanceIntent.Parameters.Performance).IsEqualTo(ProviderVolumePerformance.Iops);
        await Assert.That(attachIntent.Parameters.VolumeId).IsEqualTo(new ProviderResourceId("volume:one"));
        await Assert.That(attachIntent.Parameters.NodeId).IsEqualTo(new ProviderResourceId("node:one"));
        await Assert.That(backendIntent.Parameters.BackendId).IsEqualTo(new ProviderBackendId("backend:one"));
    }

    [Test]
    public async Task CreateAuthorizationRequiresAbsenceEvidenceForTheExactCreateKey()
    {
        var context = CreateNodeContext();
        var exact = new ProviderCreateObservation(new("node-create-1"), Generation, ProviderObservedState.Absent, null);
        var unrelated = new ProviderCreateObservation(new("other-create"), Generation, ProviderObservedState.Absent, null);
        var resolved = new ProviderCreateObservation(new("node-create-1"), Generation, ProviderObservedState.Present, Resource);
        var resolvedContext = CreateNodeContext(ProviderObservedState.Present);

        var authorized = ProviderOwnershipEngine.Authorize(Request(context: context, ownership: [], createObservations: [exact]));
        var unrelatedDecision = ProviderOwnershipEngine.Authorize(Request(context: context, ownership: [], createObservations: [unrelated]));
        var resolvedDecision = ProviderOwnershipEngine.Authorize(Request(context: context, ownership: [], createObservations: [resolved]));
        var resolvedObservation = ProviderOwnershipEngine.Authorize(Request(context: resolvedContext, ownership: [], createObservations: [resolved]));

        await Assert.That(authorized.Authorized).IsTrue();
        await Assert.That(((CreateNodeProviderIntent)authorized.Intents.Single()).Parameters.PlacementId).IsEqualTo(new ProviderPlacementId("placement-a"));
        await Assert.That(unrelatedDecision.Authorized).IsFalse();
        await Assert.That(resolvedDecision.Authorized).IsFalse();
        await Assert.That(((ObserveResolvedProviderCreateIntent)resolvedObservation.Intents.Single()).ResolvedResourceId).IsEqualTo(Resource);
        await Assert.That(Reason(unrelatedDecision, ProviderDecisionCode.GenerationMatches).Outcome).IsEqualTo(ProviderDecisionOutcome.Rejected);
        await Assert.That(Reason(resolvedDecision, ProviderDecisionCode.GenerationMatches).Outcome).IsEqualTo(ProviderDecisionOutcome.Rejected);
    }

    [Test]
    public async Task GenerationScopeDeadlineApprovalAndActionMismatchFailClosed()
    {
        var wrongGeneration = ProviderOwnershipEngine.Authorize(Request(observationGeneration: 8));
        var wrongScope = ProviderOwnershipEngine.Authorize(Request(authority: new(Cell, new("other-compartment"), Epoch)));
        var unknownDeadline = ProviderOwnershipEngine.Authorize(Request(context: Context(deadline: DeadlineEvidenceStatus.Unknown)));
        var missingApproval = ProviderOwnershipEngine.Authorize(Request(required: [ProviderApproval.SecurityReview]));
        var incompatible = ProviderOwnershipEngine.Authorize(Request(context: Context(kind: ProviderResourceKind.Volume)));
        var wrongObservation = ProviderOwnershipEngine.Authorize(Request(observedState: ProviderObservedState.Stopped));
        var incomplete = ProviderOwnershipEngine.Authorize(new(
            Context(), Authority(), [Ownership()], [], ProviderObservationCompleteness.Incomplete,
            [Observation()], [], [ProviderApproval.RegionalAuthority], null,
            new(ProviderCallStatus.NotCalled, null)));
        await Assert.That(Reason(wrongGeneration, ProviderDecisionCode.GenerationMatches).Outcome).IsEqualTo(ProviderDecisionOutcome.Rejected);
        await Assert.That(Reason(wrongScope, ProviderDecisionCode.ScopeMatches).Outcome).IsEqualTo(ProviderDecisionOutcome.Rejected);
        await Assert.That(Reason(unknownDeadline, ProviderDecisionCode.DeadlineValid).Outcome).IsEqualTo(ProviderDecisionOutcome.Held);
        await Assert.That(Reason(missingApproval, ProviderDecisionCode.ApprovalsComplete).Outcome).IsEqualTo(ProviderDecisionOutcome.Rejected);
        await Assert.That(Reason(incompatible, ProviderDecisionCode.ActionResourceCompatible).Outcome).IsEqualTo(ProviderDecisionOutcome.Rejected);
        await Assert.That(Reason(wrongObservation, ProviderDecisionCode.GenerationMatches).Outcome).IsEqualTo(ProviderDecisionOutcome.Rejected);
        await Assert.That(Reason(incomplete, ProviderDecisionCode.EvidenceComplete).Outcome).IsEqualTo(ProviderDecisionOutcome.Held);
    }

    [Test]
    public async Task DuplicateAndConflictingEvidenceHoldBeforeIntent()
    {
        var exact = Ownership();
        var duplicate = ProviderOwnershipEngine.Authorize(Request(ownership: [exact, exact]));
        var conflict = ProviderOwnershipEngine.Authorize(Request(ownership:
            [exact, new(Resource, Cell, Compartment, new(8))]));
        await Assert.That(Reason(duplicate, ProviderDecisionCode.EvidenceUnique).Outcome).IsEqualTo(ProviderDecisionOutcome.Held);
        await Assert.That(Reason(conflict, ProviderDecisionCode.EvidenceConsistent).Outcome).IsEqualTo(ProviderDecisionOutcome.Held);
        await Assert.That(duplicate.Intents).IsEmpty();
        await Assert.That(conflict.Intents).IsEmpty();
    }

    [Test]
    public async Task EvidencePermutationAndCultureProduceIdenticalDecision()
    {
        var ownership = new[] { Ownership(), new ProviderOwnershipRecord(new("other-resource"), Cell, Compartment, Generation) };
        string? baseline = null;
        foreach (var items in new[] { ownership, ownership.Reverse().ToArray() })
        foreach (var culture in new[] { "en-US", "tr-TR", "ar-SA" })
        {
            var original = CultureInfo.CurrentCulture;
            try
            {
                CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(culture);
                var serialized = Serialize(ProviderOwnershipEngine.Authorize(Request(ownership: items)));
                baseline ??= serialized;
                await Assert.That(serialized).IsEqualTo(baseline);
            }
            finally { CultureInfo.CurrentCulture = original; }
        }
    }

    [Test]
    public async Task ExactHandoffInventoryAndEveryProofEnableSelfManagement()
    {
        var items = Inventory();
        var inventory = new FreshBootstrapInventory(items, items.Reverse(), items);
        var scope = Scope(inventory);
        var decision = ProviderOwnershipEngine.EvaluateHandoff(new(inventory, scope, Evidence(scope)));
        await Assert.That(decision.Ready).IsTrue();
        await Assert.That(decision.Intent).IsNotNull();
        await Assert.That(decision.Intent!.Scope).IsEqualTo(scope);
    }

    [Test]
    public async Task HandoffMissingProofMismatchAndDuplicateNeverEnable()
    {
        var items = Inventory();
        var exactInventory = new FreshBootstrapInventory(items, items, items);
        var exactScope = Scope(exactInventory);
        var mismatchInventory = new FreshBootstrapInventory(items, items.Take(1), items);
        var duplicateInventory = new FreshBootstrapInventory(items.Append(items[0]), items, items);
        var missing = ProviderOwnershipEngine.EvaluateHandoff(new(exactInventory, exactScope, Evidence(exactScope, backup: HandoffEvidenceStatus.Missing)));
        var mismatch = ProviderOwnershipEngine.EvaluateHandoff(new(mismatchInventory, Scope(mismatchInventory), Evidence(Scope(mismatchInventory))));
        var duplicate = ProviderOwnershipEngine.EvaluateHandoff(new(duplicateInventory, Scope(duplicateInventory), Evidence(Scope(duplicateInventory))));
        await Assert.That(missing.Ready).IsFalse();
        await Assert.That(mismatch.Ready).IsFalse();
        await Assert.That(duplicate.Ready).IsFalse();
        await Assert.That(duplicate.Trace.Single(x => x.Code == ProviderDecisionCode.HandoffInventoryUnique).Outcome).IsEqualTo(ProviderDecisionOutcome.Held);
    }

    [Test]
    public async Task HandoffProofsCannotReplayAcrossCellGenerationOrInventory()
    {
        var items = Inventory();
        var inventory = new FreshBootstrapInventory(items, items, items);
        var expected = Scope(inventory);
        var otherCell = Scope(inventory, cell: new("sfo"));
        var staleGeneration = Scope(inventory, generation: new(6));
        var alteredItems = items.Append(new HandoffInventoryItem(new("extra-node"), ProviderResourceKind.Node, new(1))).ToArray();
        var alteredInventory = new FreshBootstrapInventory(alteredItems, alteredItems, alteredItems);

        var crossCell = ProviderOwnershipEngine.EvaluateHandoff(new(inventory, expected, Evidence(otherCell)));
        var stale = ProviderOwnershipEngine.EvaluateHandoff(new(inventory, expected, Evidence(staleGeneration)));
        var mismatchedInventory = ProviderOwnershipEngine.EvaluateHandoff(new(alteredInventory, expected, Evidence(expected)));

        await Assert.That(crossCell.Ready).IsFalse();
        await Assert.That(stale.Ready).IsFalse();
        await Assert.That(mismatchedInventory.Ready).IsFalse();
        await Assert.That(Reason(crossCell, ProviderDecisionCode.HandoffRetainUnmanage).Outcome).IsEqualTo(ProviderDecisionOutcome.Rejected);
        await Assert.That(Reason(stale, ProviderDecisionCode.HandoffJournalReceipt).Outcome).IsEqualTo(ProviderDecisionOutcome.Rejected);
        await Assert.That(Reason(mismatchedInventory, ProviderDecisionCode.HandoffScopeMatches).Outcome).IsEqualTo(ProviderDecisionOutcome.Rejected);
    }

    [Test]
    public async Task HandoffCopiesInventoryAndHistoricalAdoptionIsUnrepresentable()
    {
        var mutable = Inventory().ToList();
        var input = new FreshBootstrapInventory(mutable, mutable, mutable);
        mutable.Clear();
        await Assert.That(input.Expected.Count).IsEqualTo(2);
        await Assert.That(typeof(FreshBootstrapInventory).GetProperties().Any(p => p.Name.Contains("Historical", StringComparison.OrdinalIgnoreCase) || p.Name.Contains("Adopt", StringComparison.OrdinalIgnoreCase))).IsFalse();
        await Assert.That(typeof(FreshBootstrapInventory).GetConstructors().SelectMany(c => c.GetParameters()).Any(p => p.Name?.Contains("Historical", StringComparison.OrdinalIgnoreCase) == true || p.Name?.Contains("Adopt", StringComparison.OrdinalIgnoreCase) == true)).IsFalse();
    }

    [Test]
    public async Task IntentsAndTraceHaveNoFreeTextPayloadOrIoSurface()
    {
        var forbidden = new[] { typeof(string), typeof(byte[]), typeof(Delegate), typeof(Type), typeof(System.Diagnostics.Process) };
        await Assert.That(typeof(ProviderDecisionReason).GetProperties().Any(p => forbidden.Contains(p.PropertyType))).IsFalse();
        await Assert.That(typeof(ProviderIntent).Assembly.GetTypes().Where(t => typeof(ProviderIntent).IsAssignableFrom(t))
            .SelectMany(t => t.GetProperties()).Any(p => forbidden.Contains(p.PropertyType))).IsFalse();
        await Assert.That(Serialize(ProviderOwnershipEngine.Authorize(Request()))).DoesNotContain("secret");
    }

    [Test]
    public async Task UnknownDefaultAndDuplicateInputsFailClosed()
    {
        await Assert.That(Throws<ArgumentException>(() => new ProviderOperationId("bad/secret"))).IsTrue();
        await Assert.That(new ProviderResourceId("arn:aws:ec2:us-east-1:123456789012:instance/i-123").Value).StartsWith("arn:");
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => new ProviderGeneration(0))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => Context(action: (ProviderAction)0))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => Context(approvals: [ProviderApproval.RegionalAuthority, ProviderApproval.RegionalAuthority]))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => new ProviderResourceObservation(Resource, Generation, (ProviderObservedState)0))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => new HandoffInventoryItem(Resource, (ProviderResourceKind)0, Generation))).IsTrue();
        var inventory = new FreshBootstrapInventory(Inventory(), Inventory(), Inventory());
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => Evidence(Scope(inventory), (HandoffEvidenceStatus)0))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => new ProviderCallEvidence(ProviderCallStatus.NotCalled, new("impossible-work")))).IsTrue();
    }

    private static ProviderCellId Cell { get; } = new("gru");
    private static ProviderCompartmentId Compartment { get; } = new("gru-compartment");
    private static ProviderResourceId Resource { get; } = new("node-1");
    private static ProviderGeneration Generation { get; } = new(7);
    private static ProviderEpoch Epoch { get; } = new(5);

    private static ProviderOperationContext Context(
        ulong epoch = 5, ProviderResourceKind kind = ProviderResourceKind.Node,
        ProviderAction action = ProviderAction.TerminateNode,
        ProviderTerminalState terminal = ProviderTerminalState.Terminated,
        DeadlineEvidenceStatus deadline = DeadlineEvidenceStatus.Valid,
        IEnumerable<ProviderApproval>? approvals = null) => new(
        new("operation-1"), Cell, Compartment, new(epoch), kind, action, new ExistingProviderResource(Resource),
        Generation, ProviderObservedState.Running, terminal, approvals ?? [ProviderApproval.RegionalAuthority, ProviderApproval.DestructiveMutation],
        new(deadline, new(1)), new("idempotency-1"), [ProviderCompensation.ObserveOnly], Parameters(action));

    private static ProviderActionParameters Parameters(ProviderAction action) => action switch
    {
        ProviderAction.Observe => new ObserveProviderParameters(),
        ProviderAction.StartNode => new StartNodeProviderParameters(),
        ProviderAction.StopNode => new StopNodeProviderParameters(),
        ProviderAction.TerminateNode => new TerminateNodeProviderParameters(),
        ProviderAction.DetachVolume => new DetachVolumeProviderParameters(),
        ProviderAction.CreateNode => new CreateNodeProviderParameters(new("node-template"), new("placement-a"), Digest()),
        ProviderAction.CreateVolume => new CreateVolumeProviderParameters(new(1_000), ProviderVolumePerformance.Balanced),
        ProviderAction.ExpandVolume => new ExpandVolumeProviderParameters(new(2_000)),
        ProviderAction.ChangeVolumePerformance => new ChangeVolumePerformanceProviderParameters(ProviderVolumePerformance.Iops),
        ProviderAction.AttachVolume => new AttachVolumeProviderParameters(new("volume-1"), new("node-1")),
        ProviderAction.RegisterBackend => new RegisterBackendProviderParameters(new("backend-1")),
        ProviderAction.DeregisterBackend => new DeregisterBackendProviderParameters(new("backend-1")),
        _ => throw new ArgumentOutOfRangeException(nameof(action)),
    };

    private static ProviderBootstrapEnvelopeDigest Digest() => new(new string('a', 64));

    private static ProviderOperationContext VolumeContext(ProviderActionParameters parameters) => new(
        new("operation-1"), Cell, Compartment, Epoch, ProviderResourceKind.Volume, ProviderAction.ExpandVolume,
        new ExistingProviderResource(Resource), Generation, ProviderObservedState.Present, ProviderTerminalState.Expanded,
        [ProviderApproval.RegionalAuthority, ProviderApproval.DestructiveMutation], new(DeadlineEvidenceStatus.Valid, new(1)),
        new("idempotency-1"), [ProviderCompensation.ObserveOnly], parameters);

    private static ProviderOperationContext ExistingContext(
        ProviderResourceKind kind, ProviderAction action, ProviderTerminalState terminal,
        ProviderActionParameters parameters) => new(
        new("operation-1"), Cell, Compartment, Epoch, kind, action, new ExistingProviderResource(Resource),
        Generation, ProviderObservedState.Running, terminal,
        [ProviderApproval.RegionalAuthority, ProviderApproval.DestructiveMutation],
        new(DeadlineEvidenceStatus.Valid, new(1)), new("idempotency-1"),
        [ProviderCompensation.ObserveOnly], parameters);

    private static ProviderOperationContext CreateNodeContext(ProviderObservedState expectedState = ProviderObservedState.Absent) => new(
        new("operation-1"), Cell, Compartment, Epoch, ProviderResourceKind.Node, ProviderAction.CreateNode,
        new IdempotentProviderCreate(new("node-create-1")), Generation, expectedState,
        ProviderTerminalState.Present, [ProviderApproval.RegionalAuthority, ProviderApproval.DestructiveMutation],
        new(DeadlineEvidenceStatus.Valid, new(1)), new("idempotency-1"), [ProviderCompensation.ObserveOnly],
        new CreateNodeProviderParameters(new("node-template"), new("placement-a"), Digest()));

    private static RegionalProviderAuthority Authority(ulong epoch = 5) => new(Cell, Compartment, new(epoch));
    private static ProviderOwnershipRecord Ownership() => new(Resource, Cell, Compartment, Generation);
    private static ProviderResourceObservation Observation(ulong generation = 7, ProviderObservedState state = ProviderObservedState.Running) => new(Resource, new(generation), state);

    private static ProviderAuthorizationRequest Request(
        ProviderOperationContext? context = null, RegionalProviderAuthority? authority = null,
        IEnumerable<ProviderOwnershipRecord>? ownership = null, IEnumerable<ProviderInventoryTagEvidence>? tags = null,
        ulong observationGeneration = 7, ProviderObservedState observedState = ProviderObservedState.Running,
        IEnumerable<ProviderCreateObservation>? createObservations = null,
        IEnumerable<ProviderApproval>? required = null,
        DurableProviderAuthorization? prior = null, ProviderCallEvidence? call = null,
        bool includeAuthority = true)
    {
        var actualContext = context ?? Context();
        var create = actualContext.Target as IdempotentProviderCreate;
        var isCreate = create is not null;
        return new(
            actualContext, includeAuthority ? authority ?? Authority() : null,
            ownership ?? (isCreate ? [] : [Ownership()]), tags ?? [], ProviderObservationCompleteness.Complete,
            isCreate ? [] : [Observation(observationGeneration, observedState)],
            createObservations ?? (isCreate ? [new ProviderCreateObservation(create!.Key, Generation, ProviderObservedState.Absent, null)] : []),
            required ?? [ProviderApproval.RegionalAuthority, ProviderApproval.DestructiveMutation], prior,
            call ?? new(ProviderCallStatus.NotCalled, null));
    }

    private static HandoffInventoryItem[] Inventory() =>
    [new(new("seed-node"), ProviderResourceKind.Node, new(1)), new(new("control-volume"), ProviderResourceKind.Volume, new(1))];
    private static HandoffScope Scope(
        FreshBootstrapInventory inventory, ProviderCellId? cell = null,
        ProviderGeneration? generation = null) => HandoffScope.ForFreshBootstrap(
        cell ?? Cell, Compartment, generation ?? Generation, new("handoff-operation"), inventory);
    private static HandoffEvidence Evidence(
        HandoffScope scope, HandoffEvidenceStatus backup = HandoffEvidenceStatus.Verified) => new(
        new RetainUnmanageHandoffProof(scope, HandoffEvidenceStatus.Verified),
        new RegionalJournalHandoffProof(scope, HandoffEvidenceStatus.Verified),
        new ProviderReadyHandoffProof(scope, HandoffEvidenceStatus.Verified),
        new TrustReadyHandoffProof(scope, HandoffEvidenceStatus.Verified),
        new BackupReadyHandoffProof(scope, backup),
        new RegionalFenceHandoffProof(scope, HandoffEvidenceStatus.Verified));
    private static ProviderDecisionReason Reason(ProviderAuthorizationDecision d, ProviderDecisionCode c) => d.Trace.Single(x => x.Code == c);
    private static ProviderDecisionReason Reason(HandoffDecision d, ProviderDecisionCode c) => d.Trace.Single(x => x.Code == c);
    private static string Serialize(ProviderAuthorizationDecision d) => $"{d.Authorized}|{string.Join(';', d.Trace.Select(x => $"{x.Code}:{x.Outcome}:{x.Observed}:{x.Required}"))}|{string.Join(',', d.Intents.Select(x => x.GetType().Name))}";
    private static bool Throws<T>(Action action) where T : Exception { try { action(); return false; } catch (T) { return true; } }
}
