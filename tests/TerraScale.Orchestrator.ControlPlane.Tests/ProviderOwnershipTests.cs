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
            [ProviderCompensation.ObserveOnly], null);
        var decision = ProviderOwnershipEngine.Authorize(Request(
            context: context, ownership: [], required: [ProviderApproval.RegionalAuthority]));
        await Assert.That(decision.Authorized).IsTrue();
        await Assert.That(decision.Intents.Single() is CreateVolumeProviderIntent).IsTrue();
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
            [Observation()], [ProviderApproval.RegionalAuthority], null,
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
        var decision = ProviderOwnershipEngine.EvaluateHandoff(new(items, items.Reverse(), items), Evidence());
        await Assert.That(decision.Ready).IsTrue();
        await Assert.That(decision.Intent).IsNotNull();
    }

    [Test]
    public async Task HandoffMissingProofMismatchAndDuplicateNeverEnable()
    {
        var items = Inventory();
        var missing = ProviderOwnershipEngine.EvaluateHandoff(new(items, items, items), Evidence(backup: HandoffEvidenceStatus.Missing));
        var mismatch = ProviderOwnershipEngine.EvaluateHandoff(new(items, items.Take(1), items), Evidence());
        var duplicate = ProviderOwnershipEngine.EvaluateHandoff(new(items.Append(items[0]), items, items), Evidence());
        await Assert.That(missing.Ready).IsFalse();
        await Assert.That(mismatch.Ready).IsFalse();
        await Assert.That(duplicate.Ready).IsFalse();
        await Assert.That(duplicate.Trace.Single(x => x.Code == ProviderDecisionCode.HandoffInventoryUnique).Outcome).IsEqualTo(ProviderDecisionOutcome.Held);
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
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => Evidence((HandoffEvidenceStatus)0))).IsTrue();
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
        new(deadline, new(1)), new("idempotency-1"), [ProviderCompensation.ObserveOnly], null);

    private static RegionalProviderAuthority Authority(ulong epoch = 5) => new(Cell, Compartment, new(epoch));
    private static ProviderOwnershipRecord Ownership() => new(Resource, Cell, Compartment, Generation);
    private static ProviderResourceObservation Observation(ulong generation = 7, ProviderObservedState state = ProviderObservedState.Running) => new(Resource, new(generation), state);

    private static ProviderAuthorizationRequest Request(
        ProviderOperationContext? context = null, RegionalProviderAuthority? authority = null,
        IEnumerable<ProviderOwnershipRecord>? ownership = null, IEnumerable<ProviderInventoryTagEvidence>? tags = null,
        ulong observationGeneration = 7, ProviderObservedState observedState = ProviderObservedState.Running,
        IEnumerable<ProviderApproval>? required = null,
        DurableProviderAuthorization? prior = null, ProviderCallEvidence? call = null,
        bool includeAuthority = true) => new(
        context ?? Context(), includeAuthority ? authority ?? Authority() : null, ownership ?? [Ownership()], tags ?? [],
        ProviderObservationCompleteness.Complete, [Observation(observationGeneration, observedState)],
        required ?? [ProviderApproval.RegionalAuthority, ProviderApproval.DestructiveMutation], prior,
        call ?? new(ProviderCallStatus.NotCalled, null));

    private static HandoffInventoryItem[] Inventory() =>
    [new(new("seed-node"), ProviderResourceKind.Node, new(1)), new(new("control-volume"), ProviderResourceKind.Volume, new(1))];
    private static HandoffEvidence Evidence(HandoffEvidenceStatus backup = HandoffEvidenceStatus.Verified) => new(
        HandoffEvidenceStatus.Verified, HandoffEvidenceStatus.Verified, HandoffEvidenceStatus.Verified,
        HandoffEvidenceStatus.Verified, backup, HandoffEvidenceStatus.Verified);
    private static ProviderDecisionReason Reason(ProviderAuthorizationDecision d, ProviderDecisionCode c) => d.Trace.Single(x => x.Code == c);
    private static string Serialize(ProviderAuthorizationDecision d) => $"{d.Authorized}|{string.Join(';', d.Trace.Select(x => $"{x.Code}:{x.Outcome}:{x.Observed}:{x.Required}"))}|{string.Join(',', d.Intents.Select(x => x.GetType().Name))}";
    private static bool Throws<T>(Action action) where T : Exception { try { action(); return false; } catch (T) { return true; } }
}
