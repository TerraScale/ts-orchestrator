using System.Collections;
using TerraScale.Orchestrator.ControlPlane.Budgets;
using TerraScale.Orchestrator.ControlPlane.Providers;

namespace TerraScale.Orchestrator.ControlPlane.Tests.Properties;

public sealed class BudgetProviderEnumerableBoundaryTests
{
    [Test]
    public async Task Budget_decisions_bound_before_extra_current_and_classify_ordinary_iterator_failures()
    {
        var exact = ManyUsage(BudgetTechnicalInputLimits.MaximumEvidenceCount);
        var exactDecision = BudgetTestData.Evaluate(policy: BudgetTestData.Policy(maximumEvidence: BudgetTechnicalInputLimits.MaximumEvidenceCount),
            usage: exact, nodes: [], prices: []);
        await Assert.That(exactDecision.Reason).IsNotEqualTo(BudgetDecisionReason.EvidenceLimitExceeded);

        var oversized = new BoundaryEnumerable<BudgetUsageObservation?>(BudgetTechnicalInputLimits.MaximumEvidenceCount + 1,
            _ => BudgetTestData.CellUsage());
        var oversizedDecision = BudgetTestData.Evaluate(policy: BudgetTestData.Policy(maximumEvidence: int.MaxValue), usage: oversized, nodes: [], prices: []);
        await Assert.That(oversizedDecision.Reason).IsEqualTo(BudgetDecisionReason.EvidenceLimitExceeded);
        await Assert.That(oversized.ExtraCurrentRead).IsFalse();

        foreach (var phase in Enum.GetValues<IteratorFailurePhase>().Where(x => x != IteratorFailurePhase.None))
        {
            var hostile = new BoundaryEnumerable<BudgetUsageObservation?>(1, _ => BudgetTestData.CellUsage(), phase, new InvalidOperationException("secret-payload"));
            var decision = BudgetTestData.Evaluate(usage: hostile);
            await Assert.That(decision.Reason).IsEqualTo(BudgetDecisionReason.EvidenceLimitExceeded);
        }
        var fatal = new BoundaryEnumerable<BudgetUsageObservation?>(1, _ => BudgetTestData.CellUsage(), IteratorFailurePhase.Current, new OutOfMemoryException("fatal"));
        await Assert.That(Capture(() => BudgetTestData.Evaluate(usage: fatal))).IsTypeOf<OutOfMemoryException>();
    }

    [Test]
    public async Task Budget_policy_and_anomaly_snapshots_are_bounded_defensive_and_fail_closed()
    {
        var mutable = new List<NodeClassCapacityPolicy?> { new(BudgetTestData.NodeClass(), 0, 2, 0) };
        var disposing = new BoundaryEnumerable<NodeClassCapacityPolicy?>(1, index => mutable[index], onDispose: mutable.Clear);
        var created = BudgetPolicy.TryCreate(BudgetTestData.Cell(), BudgetTestData.CostCenter(), BudgetTestData.Approval(), BudgetEmergencyPosture.Normal,
            BudgetTestData.Q(10), 16, disposing, BudgetTestData.Vector(10), BudgetTestData.Vector(10), BudgetTestData.Vector(10),
            BudgetTestData.Vector(10), new(BudgetTestData.Vector(5), BudgetTestData.Vector(5), BudgetTestData.Vector(7), BudgetTestData.Vector(7)), out var policy, out _);
        await Assert.That(created).IsTrue();
        await Assert.That(policy!.NodeClasses.Count).IsEqualTo(1);

        var policyOversized = new BoundaryEnumerable<NodeClassCapacityPolicy?>(BudgetTechnicalInputLimits.MaximumNodeClassPolicyCount + 1,
            index => new(BudgetTestData.NodeClass($"node-{index}"), 0, 2, 0));
        var rejected = BudgetPolicy.TryCreate(BudgetTestData.Cell(), BudgetTestData.CostCenter(), BudgetTestData.Approval(), BudgetEmergencyPosture.Normal,
            BudgetTestData.Q(10), int.MaxValue, policyOversized, BudgetTestData.Vector(10), BudgetTestData.Vector(10), BudgetTestData.Vector(10),
            BudgetTestData.Vector(10), new(BudgetTestData.Vector(5), BudgetTestData.Vector(5), BudgetTestData.Vector(7), BudgetTestData.Vector(7)), out _, out var error);
        await Assert.That(rejected).IsFalse(); await Assert.That(error).IsEqualTo(BudgetPolicyError.InvalidEvidenceLimit);
        await Assert.That(policyOversized.ExtraCurrentRead).IsFalse();

        var anomalyHostile = new BoundaryEnumerable<BudgetResourceObservation?>(1, _ => null, IteratorFailurePhase.Dispose, new InvalidOperationException("secret"));
        var anomaly = BudgetAnomalyDetector.Detect(BudgetTestData.Cell(), BudgetTestData.CostCenter(), 16, BudgetTestData.Q(10), true, anomalyHostile);
        await Assert.That(anomaly.Error).IsEqualTo(BudgetAnomalyError.InvalidEvidenceLimit);
    }

    [Test]
    public async Task Provider_snapshots_cover_exact_max_max_plus_one_all_iterator_phases_and_fatals()
    {
        var exact = Enumerable.Range(0, ProviderTechnicalInputLimits.MaximumOperationEvidenceCount)
            .Select(index => new ProviderOwnershipRecord(new($"node-{index}"), Cell, Compartment, new ProviderGeneration(7))).ToArray();
        var exactRequest = Request(exact);
        await Assert.That(exactRequest.OwnershipRecords.Count).IsEqualTo(ProviderTechnicalInputLimits.MaximumOperationEvidenceCount);

        var oversized = new BoundaryEnumerable<ProviderOwnershipRecord>(ProviderTechnicalInputLimits.MaximumOperationEvidenceCount + 1,
            index => new(new($"node-{index}"), Cell, Compartment, new(7)));
        await Assert.That(Capture(() => Request(oversized))).IsTypeOf<ArgumentException>();
        await Assert.That(oversized.ExtraCurrentRead).IsFalse();

        foreach (var phase in Enum.GetValues<IteratorFailurePhase>().Where(x => x != IteratorFailurePhase.None))
        {
            var hostile = new BoundaryEnumerable<ProviderOwnershipRecord>(1, _ => Ownership(), phase, new InvalidOperationException("secret-payload"));
            var failure = Capture(() => Request(hostile));
            await Assert.That(failure).IsTypeOf<ArgumentException>();
            await Assert.That(failure!.Message).DoesNotContain("secret-payload");
        }
        var fatal = new BoundaryEnumerable<ProviderOwnershipRecord>(1, _ => Ownership(), IteratorFailurePhase.Current, new OutOfMemoryException("fatal"));
        await Assert.That(Capture(() => Request(fatal))).IsTypeOf<OutOfMemoryException>();
    }

    [Test]
    public async Task Provider_handoff_snapshot_is_defensive_and_bounded_before_current()
    {
        var mutable = new List<HandoffInventoryItem> { new(new("node"), ProviderResourceKind.Node, new(1)) };
        var source = new BoundaryEnumerable<HandoffInventoryItem>(1, index => mutable[index], onDispose: mutable.Clear);
        var inventory = new FreshBootstrapInventory(source, [new(new("node"), ProviderResourceKind.Node, new(1))], [new(new("node"), ProviderResourceKind.Node, new(1))]);
        await Assert.That(inventory.Expected.Count).IsEqualTo(1);
        var oversized = new BoundaryEnumerable<HandoffInventoryItem>(ProviderTechnicalInputLimits.MaximumHandoffInventoryCount + 1,
            index => new(new($"node-{index}"), ProviderResourceKind.Node, new(1)));
        await Assert.That(Capture(() => new FreshBootstrapInventory(oversized, [], []))).IsTypeOf<ArgumentException>();
        await Assert.That(oversized.ExtraCurrentRead).IsFalse();
    }

    private static BudgetUsageObservation?[] ManyUsage(int count) => Enumerable.Range(0, count)
        .Select(index => index == 0 ? BudgetTestData.CellUsage() : index == 1 ? BudgetTestData.GlobalUsage() :
            new BudgetUsageObservation(BudgetUsageScope.Cell, BudgetTestData.Cell(), BudgetTestData.CostCenter(), BudgetTestData.Evidence($"e-{index}"), BudgetEvidenceStatus.Current, BudgetTestData.Q(1), BudgetTestData.Vector(index)))
        .Cast<BudgetUsageObservation?>().ToArray();
    private static ProviderCellId Cell { get; } = new("gru");
    private static ProviderCompartmentId Compartment { get; } = new("compartment");
    private static ProviderResourceId Resource { get; } = new("node");
    private static ProviderOwnershipRecord Ownership() => new(Resource, Cell, Compartment, new(7));
    private static ProviderAuthorizationRequest Request(IEnumerable<ProviderOwnershipRecord> ownership)
    {
        var context = new ProviderOperationContext(new("operation"), Cell, Compartment, new(5), ProviderResourceKind.Node,
            ProviderAction.TerminateNode, new ExistingProviderResource(Resource), new(7), ProviderObservedState.Running, ProviderTerminalState.Terminated,
            [ProviderApproval.RegionalAuthority], new(DeadlineEvidenceStatus.Valid, new(1)), new("idempotency"), [ProviderCompensation.ObserveOnly], new TerminateNodeProviderParameters());
        return new(context, new(Cell, Compartment, new(5)), ownership, [], ProviderObservationCompleteness.Complete,
            [new(Resource, new(7), ProviderObservedState.Running)], [], [ProviderApproval.RegionalAuthority], null, new(context, ProviderCallStatus.NotCalled, null));
    }
    private static Exception? Capture(Action action) { try { action(); return null; } catch (Exception exception) { return exception; } }
}

internal enum IteratorFailurePhase { None, GetEnumerator, MoveNext, Current, Dispose }

internal sealed class BoundaryEnumerable<T> : IEnumerable<T>
{
    private readonly int _count; private readonly Func<int, T> _factory; private readonly IteratorFailurePhase _phase;
    private readonly Exception? _failure; private readonly Action? _onDispose;
    internal BoundaryEnumerable(int count, Func<int, T> factory, IteratorFailurePhase phase = IteratorFailurePhase.None,
        Exception? failure = null, Action? onDispose = null) { _count = count; _factory = factory; _phase = phase; _failure = failure; _onDispose = onDispose; }
    internal bool ExtraCurrentRead { get; private set; }
    public IEnumerator<T> GetEnumerator()
    {
        if (_phase == IteratorFailurePhase.GetEnumerator) throw _failure!;
        return new Enumerator(this);
    }
    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    private sealed class Enumerator(BoundaryEnumerable<T> owner) : IEnumerator<T>
    {
        private int _index = -1;
        public T Current
        {
            get
            {
                if (_index == owner._count - 1 && owner._count is BudgetTechnicalInputLimits.MaximumEvidenceCount + 1 or ProviderTechnicalInputLimits.MaximumOperationEvidenceCount + 1 or ProviderTechnicalInputLimits.MaximumHandoffInventoryCount + 1)
                    owner.ExtraCurrentRead = true;
                if (owner._phase == IteratorFailurePhase.Current) throw owner._failure!;
                return owner._factory(_index);
            }
        }
        object? IEnumerator.Current => Current;
        public bool MoveNext() { if (owner._phase == IteratorFailurePhase.MoveNext) throw owner._failure!; return ++_index < owner._count; }
        public void Reset() => throw new NotSupportedException();
        public void Dispose() { owner._onDispose?.Invoke(); if (owner._phase == IteratorFailurePhase.Dispose) throw owner._failure!; }
    }
}
