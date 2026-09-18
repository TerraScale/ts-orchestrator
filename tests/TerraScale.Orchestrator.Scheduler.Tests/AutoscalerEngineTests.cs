using TerraScale.Orchestrator.Scheduler.Autoscaling;

namespace TerraScale.Orchestrator.Scheduler.Tests;

public sealed class AutoscalerEngineTests
{
    private static readonly ResourceVector NodeCapacity = new(
        cpu: 200, memory: 8_000_000_000, blockIo: 0, ephemeralDisk: 0, bandwidth: 0, pids: 512, fileDescriptors: 0, hugePages: 0);

    private static AutoscalerConfig Config(int minNodes = 1, int maxNodes = 3, int flapSuppressionTicks = 0) =>
        new(minNodes, maxNodes, scaleUpHeadroomPercent: 30, scaleDownHeadroomPercent: 40,
            scaleUpConfirmTicks: 2, scaleDownConfirmTicks: 3, maxConcurrentProvisions: 2,
            flapSuppressionTicks: flapSuppressionTicks);

    private static NodeObservation Node(
        string id,
        AutoscalingNodeState state = AutoscalingNodeState.Ready,
        ResourceVector? usage = null,
        int pending = 0,
        IEnumerable<StatefulReplicaHealth>? replicas = null) =>
        new(id, state, NodeCapacity, usage ?? ResourceVector.Zero, pending, replicas);

    private static AllocationDemand Demand(string roleId, long memory, long pids) =>
        new(roleId, "terrabase-member", true, new ResourceVector(
            cpu: 100, memory: memory, blockIo: 0, ephemeralDisk: 0, bandwidth: 0, pids: pids, fileDescriptors: 0, hugePages: 0));

    [Test]
    public async Task ScaleUpRequiresConfirmationTicksAndSizesToUnschedulableDemand()
    {
        var engine = new AutoscalerEngine(Config(), AllowAllDrains());
        var snapshot = new AutoscalerSnapshot(
            [Node("node-a", usage: NodeCapacity)],
            [Demand("member-x", 4_000_000_000, 256)]);

        var first = engine.Tick(snapshot);
        var second = engine.Tick(snapshot);

        await Assert.That(first).IsEmpty();
        var provision = second.OfType<AutoscalerAction.ProvisionNode>().Single();
        await Assert.That(provision.Request.NodeId).IsEqualTo("as-node-1");
        await Assert.That(provision.Request.Resources).IsEqualTo(Demand("member-x", 4_000_000_000, 256).Resources);
    }

    [Test]
    public async Task InFlightReservePreventsDoubleProvisioningUntilSnapshotReflectsOrRefuted()
    {
        var engine = new AutoscalerEngine(Config(), AllowAllDrains());
        var snapshot = new AutoscalerSnapshot(
            [Node("node-a", usage: NodeCapacity)],
            [Demand("member-x", 4_000_000_000, 256)]);
        var stillSaturated = new AutoscalerSnapshot(
            [Node("node-a", usage: NodeCapacity)],
            [Demand("member-x", 12_000_000_000, 256)]);

        var stream = new List<string>();
        for (var t = 1; t <= 4; t++)
        {
            stream.Add(string.Join(',', engine.Tick(snapshot).Select(Describe)));
        }

        // Confirmation at tick 2 provisions exactly one node; the remembered
        // in-flight reserve means the unchanged snapshot never provisions again.
        await Assert.That(string.Join(';', stream)).IsEqualTo(";provision:as-node-1;;");

        // The widened deficit adds exactly one node; the reserve for the first
        // shortfall is never re-provisioned.
        var widened = string.Join(',', engine.Tick(stillSaturated).Select(Describe));
        await Assert.That(widened).IsEqualTo("provision:as-node-2");

        // Refuting the provisioner-reported failure of the node whose reserve
        // covers the deficit releases exactly that reserve: the breach counter
        // restarts after an emitted batch, and the next confirmed breach
        // provisions the replacement.
        engine.RefuteProvision("as-node-2");
        var afterRefute = new List<string>();
        for (var t = 6; t <= 7; t++)
        {
            afterRefute.Add(string.Join(',', engine.Tick(stillSaturated).Select(Describe)));
        }

        await Assert.That(string.Join(';', afterRefute)).IsEqualTo(";provision:as-node-3");
    }

    [Test]
    public async Task ScaleDownCordonsAndDrainsLowestUtilizationReadyNodeOnceConfirmed()
    {
        var engine = new AutoscalerEngine(Config(minNodes: 1, maxNodes: 3), AllowAllDrains());
        var idle = new AutoscalerSnapshot(
            [Node("node-a", usage: ResourceVector.Zero), Node("node-b", usage: new ResourceVector(
                cpu: 10, memory: 1_000_000_000, blockIo: 0, ephemeralDisk: 0, bandwidth: 0, pids: 10, fileDescriptors: 0, hugePages: 0))],
            []);

        engine.Tick(idle);
        engine.Tick(idle);
        var actions = engine.Tick(idle);

        var cordon = actions.OfType<AutoscalerAction.CordonNode>().Single();
        var drain = actions.OfType<AutoscalerAction.DrainNode>().Single();
        await Assert.That(cordon.NodeId).IsEqualTo("node-a");
        await Assert.That(drain.NodeId).IsEqualTo("node-a");
    }

    [Test]
    public async Task ScaleDownDefersWhileReplicaIsUnderReplicatedElsewhere()
    {
        var blocking = new StatefulReplicaHealth("terrabase-member", "member-x", up: true, peerAckCount: 0, minReplicas: 2, lagBytes: 0);
        var peerReplica = new StatefulReplicaHealth("terrabase-member", "member-x", up: false, peerAckCount: 0, minReplicas: 2, lagBytes: 0);
        var evaluator = new ReplicaDrainSafetyEvaluator(new DrainPolicy(1_048_576));
        var engine = new AutoscalerEngine(Config(minNodes: 1), evaluator);
        var snapshot = new AutoscalerSnapshot(
            [Node("node-a", replicas: [blocking]), Node("node-b", replicas: [peerReplica])],
            []);

        for (var i = 0; i < 5; i++)
        {
            engine.Tick(snapshot);
        }

        // The under-replicated peer blocks every drain: never cordon, never drain.
        var actions = engine.Tick(snapshot);
        await Assert.That(actions.OfType<AutoscalerAction.CordonNode>()).IsEmpty();
        await Assert.That(actions.OfType<AutoscalerAction.DrainNode>()).IsEmpty();
    }

    [Test]
    public async Task DrainedNodeWithZeroAllocationsRetiresButBusyNodeDoesNot()
    {
        var engine = new AutoscalerEngine(Config(), AllowAllDrains());
        var busyUsage = new ResourceVector(
            cpu: 10, memory: 0, blockIo: 0, ephemeralDisk: 0, bandwidth: 0, pids: 3, fileDescriptors: 0, hugePages: 0);
        var snapshot = new AutoscalerSnapshot(
            [Node("node-a", AutoscalingNodeState.Draining), Node("node-b", AutoscalingNodeState.Draining, usage: busyUsage)],
            []);

        var actions = engine.Tick(snapshot);

        var retire = actions.OfType<AutoscalerAction.RetireNode>().Single();
        await Assert.That(retire.NodeId).IsEqualTo("node-a");
    }

    [Test]
    public async Task FlapSuppressionBlocksProvisioningWhileRetirementIsRemembered()
    {
        var engine = new AutoscalerEngine(Config(flapSuppressionTicks: 3), AllowAllDrains());
        var draining = new AutoscalerSnapshot([Node("node-a", AutoscalingNodeState.Draining)], []);
        var retired = engine.Tick(draining);
        await Assert.That(retired.OfType<AutoscalerAction.RetireNode>()).HasSingleItem();

        var saturated = new AutoscalerSnapshot(
            [Node("node-b", usage: NodeCapacity)],
            [Demand("member-x", 4_000_000_000, 256)]);

        var stream = new List<string>();
        for (var t = 2; t <= 6; t++)
        {
            stream.Add(string.Join(',', engine.Tick(saturated).Select(Describe)));
        }

        // Ticks 2-3 confirm the breach, but the retirement remembered at tick 1
        // suppresses provisioning through the 3-tick window (expired at tick 5);
        // the first tick past the window provisions.
        await Assert.That(string.Join(';', stream)).IsEqualTo(";;;provision:as-node-1;");
    }

    [Test]
    public async Task MinNodesFloorBlocksScaleDownBelowTheFloor()
    {
        var engine = new AutoscalerEngine(Config(minNodes: 2, maxNodes: 3), AllowAllDrains());
        var idle = new AutoscalerSnapshot([Node("node-a")], []);

        for (var i = 0; i < 5; i++)
        {
            engine.Tick(idle);
        }

        var actions = engine.Tick(idle);
        await Assert.That(actions.OfType<AutoscalerAction.CordonNode>()).IsEmpty();
    }

    [Test]
    public async Task ZeroCapacityDimensionWithDemandBreachesImmediately()
    {
        var engine = new AutoscalerEngine(Config(), AllowAllDrains());
        var noCapacity = new NodeObservation("node-a", AutoscalingNodeState.Ready, ResourceVector.Zero, ResourceVector.Zero, 0, null);
        var snapshot = new AutoscalerSnapshot([noCapacity], [Demand("member-x", 4_000_000_000, 256)]);

        engine.Tick(snapshot);
        var actions = engine.Tick(snapshot);
        await Assert.That(actions.OfType<AutoscalerAction.ProvisionNode>()).HasSingleItem();
    }

    [Test]
    public async Task IdenticalSnapshotsProduceIdenticalActionsRegardlessOfInputOrder()
    {
        var evaluator = new ReplicaDrainSafetyEvaluator(new DrainPolicy(1_048_576));
        var left = new AutoscalerEngine(Config(), evaluator);
        var right = new AutoscalerEngine(Config(), evaluator);
        var nodes = new[]
        {
            Node("node-a", usage: NodeCapacity),
            Node("node-b", usage: ResourceVector.Zero),
            Node("node-c", usage: ResourceVector.Zero),
        };
        var demand = new[] { Demand("member-x", 4_000_000_000, 256), Demand("member-y", 6_000_000_000, 128) };

        var ordered = new AutoscalerSnapshot(nodes, demand);
        var reversed = new AutoscalerSnapshot(nodes.Reverse(), demand.Reverse());

        for (var i = 0; i < 3; i++)
        {
            var leftActions = left.Tick(ordered);
            var rightActions = right.Tick(reversed);
            await Assert.That(string.Join(';', rightActions.Select(Describe))).IsEqualTo(string.Join(';', leftActions.Select(Describe)));
        }
    }

    [Test]
    public async Task DemandAgainstZeroCpuCapacityServesAsBreachSignal()
    {
        var engine = new AutoscalerEngine(Config(), AllowAllDrains());
        var capacityWithoutCpu = new ResourceVector(
            cpu: 0, memory: 8_000_000_000, blockIo: 0, ephemeralDisk: 0, bandwidth: 0, pids: 512, fileDescriptors: 0, hugePages: 0);
        var node = new NodeObservation("node-a", AutoscalingNodeState.Ready, capacityWithoutCpu, ResourceVector.Zero, 0, null);
        var snapshot = new AutoscalerSnapshot([node], [Demand("member-x", 0, 1)]);

        engine.Tick(snapshot);
        var actions = engine.Tick(snapshot);
        await Assert.That(actions.OfType<AutoscalerAction.ProvisionNode>()).HasSingleItem();
    }

    private static IDrainSafetyEvaluator AllowAllDrains() => new AllowAllDrainSafetyEvaluator();

    private sealed class AllowAllDrainSafetyEvaluator : IDrainSafetyEvaluator
    {
        public DrainDecision Evaluate(NodeDrainCandidate candidate, IReadOnlyList<NodeDrainCandidate> peers) =>
            DrainDecision.Allow("test evaluator allows every drain");
    }

    private static string Describe(AutoscalerAction action) =>
        action switch
        {
            AutoscalerAction.ProvisionNode provision => $"provision:{provision.Request.NodeId}",
            AutoscalerAction.CordonNode cordon => $"cordon:{cordon.NodeId}",
            AutoscalerAction.DrainNode drain => $"drain:{drain.NodeId}",
            AutoscalerAction.RetireNode retire => $"retire:{retire.NodeId}",
            _ => "unknown",
        };

}
