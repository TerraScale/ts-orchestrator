using System.Numerics;

namespace TerraScale.Orchestrator.Scheduler.Autoscaling;

/// <summary>
/// Deterministic fleet autoscaler: a pure decision function over validated
/// cluster snapshots. Between ticks it carries only hysteresis state —
/// confirmation counters, remembered in-flight provisions and cordons a
/// snapshot has not reflected yet, drains this autoscaler started and has not
/// observed finished, and the recently retired node ids of the flap
/// suppression window. Identical snapshots fed to identically constructed
/// engines produce identical actions.
/// </summary>
public sealed class AutoscalerEngine
{
    /// <summary>The node class every provisioned node carries.</summary>
    public const string ProvisionedNodeClass = "greenfield";

    /// <summary>
    /// How long a remembered cordon survives without being reflected by a
    /// snapshot: once the bridge expires, the snapshot is authoritative again.
    /// In-flight provisions have no TTL — see <see cref="RefuteProvision"/>.
    /// </summary>
    private const int InFlightCordonTickTtl = 2;

    private const int DimensionCount = 8;

    private readonly AutoscalerConfig config;
    private readonly IDrainSafetyEvaluator drainSafety;

    private long tick;
    private int scaleUpBreachTicks;
    private int scaleDownIdleTicks;
    private int provisionSequence;
    private readonly Dictionary<string, ResourceVector> inFlightProvisions = new(StringComparer.Ordinal);
    private readonly Dictionary<string, long> cordonedInFlight = new(StringComparer.Ordinal);
    private readonly HashSet<string> drainingInFlight = new(StringComparer.Ordinal);
    private readonly HashSet<string> retirementInFlight = new(StringComparer.Ordinal);
    private readonly Dictionary<string, long> recentlyRetired = new(StringComparer.Ordinal);

    public AutoscalerEngine(AutoscalerConfig config, IDrainSafetyEvaluator drainSafety)
    {
        this.config = config ?? throw new ArgumentNullException(nameof(config));
        this.drainSafety = drainSafety ?? throw new ArgumentNullException(nameof(drainSafety), "A drain safety evaluator is required.");
    }

    /// <summary>
    /// Applies the scaling policy to one snapshot and returns this tick's
    /// actions in canonical order: retire actions for drained nodes first (by
    /// node id), then the cordon and drain pair of at most one scale-down
    /// victim, then the provision actions (by node id).
    /// </summary>
    public IReadOnlyList<AutoscalerAction> Tick(AutoscalerSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        tick++;
        var actions = new List<AutoscalerAction>();
        ReconcileInFlight(snapshot);
        actions.AddRange(PlanRetireActions(snapshot));

        var pressure = ComputeClusterPressure(snapshot);
        scaleUpBreachTicks = pressure.ScaleUpBreach ? scaleUpBreachTicks + 1 : 0;
        var idle = !pressure.ScaleUpBreach && pressure.MinimumHeadroomExceeds(config.ScaleDownHeadroomPercent);
        scaleDownIdleTicks = idle ? scaleDownIdleTicks + 1 : 0;

        actions.AddRange(PlanScaleDown(snapshot, pressure));
        actions.AddRange(PlanScaleUp(snapshot, pressure));
        return actions;
    }

    /// <summary>
    /// Releases the remembered in-flight provision of one node because its
    /// provisioner explicitly reported the provision failed. Provision
    /// feedback is the only way an unreflected provision stops counting
    /// against the reserve: the engine never guesses a provision failed from
    /// elapsed ticks alone, so a slow-booting node cannot trigger a
    /// replacement storm.
    /// </summary>
    public void RefuteProvision(string nodeId)
    {
        var validated = AutoscalingTokens.Require(nodeId, nameof(nodeId));
        if (!inFlightProvisions.Remove(validated))
        {
            throw new InvalidOperationException($"Node {validated} has no in-flight provision to refute.");
        }
    }

    /// <summary>
    /// Drops remembered in-flight state once a snapshot reflects it, so
    /// snapshot state always wins once it is visible. An engine-initiated
    /// drain stays in flight until the snapshot observes the node Retired: a
    /// draining node that falls out of the heartbeat window is exactly the
    /// node whose containers are least certainly stopped, so a second
    /// concurrent drain must stay blocked.
    /// </summary>
    private void ReconcileInFlight(AutoscalerSnapshot snapshot)
    {
        var states = snapshot.Nodes.ToDictionary(node => node.NodeId, node => node.State, StringComparer.Ordinal);
        foreach (var nodeId in inFlightProvisions.Keys.Where(states.ContainsKey).ToArray())
        {
            inFlightProvisions.Remove(nodeId);
        }

        foreach (var (nodeId, cordonedTick) in cordonedInFlight.ToArray())
        {
            var applied = states.TryGetValue(nodeId, out var state) &&
                state is AutoscalingNodeState.Cordoned or AutoscalingNodeState.Draining or AutoscalingNodeState.Retired;
            if (applied || tick - cordonedTick > InFlightCordonTickTtl)
            {
                cordonedInFlight.Remove(nodeId);
            }
        }

        foreach (var nodeId in drainingInFlight.ToArray())
        {
            if (states.TryGetValue(nodeId, out var state) && state == AutoscalingNodeState.Retired)
            {
                drainingInFlight.Remove(nodeId);
            }
        }

        // A retirement remains in flight until the snapshot observes that the
        // draining node is no longer draining. Unlike flap suppression there
        // is no TTL: a delayed observation must never cause a second retire.
        foreach (var nodeId in retirementInFlight.ToArray())
        {
            if (!states.TryGetValue(nodeId, out var state) || state != AutoscalingNodeState.Draining)
            {
                retirementInFlight.Remove(nodeId);
            }
        }

        foreach (var (nodeId, retiredTick) in recentlyRetired.ToArray())
        {
            if (tick - retiredTick > config.FlapSuppressionTicks)
            {
                recentlyRetired.Remove(nodeId);
            }
        }
    }

    /// <summary>
    /// Retires every Draining node that reports zero running allocations:
    /// usage is the running-allocation gauge and pending allocations the
    /// queued count, so both must be zero before the drain is complete. A
    /// node that was never drained never reaches this path.
    /// </summary>
    private IEnumerable<AutoscalerAction> PlanRetireActions(AutoscalerSnapshot snapshot)
    {
        foreach (var node in snapshot.Nodes)
        {
            if (node.State != AutoscalingNodeState.Draining ||
                retirementInFlight.Contains(node.NodeId) ||
                recentlyRetired.ContainsKey(node.NodeId) ||
                node.Usage.Pids > 0 ||
                node.PendingAllocations > 0)
            {
                continue;
            }

            recentlyRetired[node.NodeId] = tick;
            retirementInFlight.Add(node.NodeId);
            // The retire gate observed a quiet, drained node, so this
            // engine's drain of it is finished; retirement now owns the node.
            drainingInFlight.Remove(node.NodeId);
            yield return new AutoscalerAction.RetireNode(node.NodeId);
        }
    }

    /// <summary>
    /// Cordons and drains at most one node per tick: the lowest-utilization
    /// Ready node the drain safety evaluator allows, once the sustained
    /// headroom counter is confirmed, while no other drain is in flight and
    /// the fleet stays at or above MinNodes. When every candidate is blocked
    /// the engine defers and re-evaluates next tick.
    /// </summary>
    private IEnumerable<AutoscalerAction> PlanScaleDown(AutoscalerSnapshot snapshot, ClusterPressure pressure)
    {
        if (scaleDownIdleTicks < config.ScaleDownConfirmTicks ||
            DrainInFlight(snapshot) ||
            cordonedInFlight.Count > 0 ||
            ActiveFleetSize(snapshot) + inFlightProvisions.Count - 1 < config.MinNodes)
        {
            yield break;
        }

        foreach (var node in snapshot.Nodes.Where(node => node.State == AutoscalingNodeState.Ready).OrderBy(UtilizationRatio))
        {
            var decision = drainSafety.Evaluate(node.ToDrainCandidate(), PeerCandidates(snapshot, node.NodeId));
            if (!decision.Allowed)
            {
                continue;
            }

            cordonedInFlight[node.NodeId] = tick;
            drainingInFlight.Add(node.NodeId);
            scaleDownIdleTicks = 0;
            yield return new AutoscalerAction.CordonNode(node.NodeId);
            yield return new AutoscalerAction.DrainNode(node.NodeId);
            yield break;
        }
    }

    /// <summary>
    /// Provisions nodes once the sustained-pressure counter is confirmed, no
    /// retirement is inside the flap suppression window, and demand exists to
    /// size the nodes: the sizing is the largest unschedulable demand
    /// (falling back to the largest demand overall), each new node carries
    /// that exact envelope, and the provision count is the per-dimension
    /// deficit after the capacity of already-provisioning nodes is counted
    /// against it, capped by MaxNodes and MaxConcurrentProvisions.
    /// </summary>
    private IEnumerable<AutoscalerAction> PlanScaleUp(AutoscalerSnapshot snapshot, ClusterPressure pressure)
    {
        if (scaleUpBreachTicks < config.ScaleUpConfirmTicks || recentlyRetired.Count > 0)
        {
            yield break;
        }

        var sizing = LargestProvisionSizing(snapshot);
        if (sizing is null)
        {
            // Pressure without demand cannot size a node; the breach counter
            // keeps running and the next demand-bearing snapshot decides.
            yield break;
        }

        var provisioningCount = snapshot.Nodes.Count(node => node.State == AutoscalingNodeState.Provisioning) + inFlightProvisions.Count;
        var fleetSize = ActiveFleetSize(snapshot) + inFlightProvisions.Count;
        var needed = RequiredProvisionCount(pressure, sizing, provisioningCount);
        var allowed = (int)Math.Min(Math.Min(needed, config.MaxNodes - fleetSize), config.MaxConcurrentProvisions - provisioningCount);
        if (allowed <= 0)
        {
            yield break;
        }

        var reserved = snapshot.Nodes.Select(node => node.NodeId)
            .Concat(inFlightProvisions.Keys)
            .ToHashSet(StringComparer.Ordinal);
        var reason = $"cluster pressure breached the scale-up headroom for {config.ScaleUpConfirmTicks} consecutive ticks.";
        for (var count = 0; count < allowed; count++)
        {
            var nodeId = NextProvisionNodeId(reserved);
            var request = new NodeProvisionRequest(nodeId, ProvisionedNodeClass, sizing, reason);
            reserved.Add(nodeId);
            inFlightProvisions[nodeId] = sizing;
            yield return new AutoscalerAction.ProvisionNode(request);
        }

        scaleUpBreachTicks = 0;
    }

    private string NextProvisionNodeId(HashSet<string> reserved)
    {
        while (true)
        {
            provisionSequence++;
            var nodeId = $"as-node-{provisionSequence}";
            if (!reserved.Contains(nodeId))
            {
                return nodeId;
            }
        }
    }

    /// <summary>
    /// Whether any drain is still in flight: a drain this engine started and
    /// has not observed finished, or any node the snapshot reports Cordoned
    /// or Draining. Draining one node at a time keeps the fleet from draining
    /// in waves; remembering the engine's own drains keeps the gate closed
    /// exactly when a draining victim disappears from the snapshot because
    /// its agent went silent.
    /// </summary>
    private bool DrainInFlight(AutoscalerSnapshot snapshot) =>
        drainingInFlight.Count > 0 ||
        snapshot.Nodes.Any(node =>
            !recentlyRetired.ContainsKey(node.NodeId) &&
            node.State is AutoscalingNodeState.Cordoned or AutoscalingNodeState.Draining);

    private IEnumerable<NodeDrainCandidate> PeerCandidates(AutoscalerSnapshot snapshot, string candidateNodeId) =>
        snapshot.Nodes.Where(node => node.NodeId != candidateNodeId).Select(node => node.ToDrainCandidate()).ToArray();

    private static int ActiveFleetSize(AutoscalerSnapshot snapshot) =>
        snapshot.Nodes.Count(node => node.State != AutoscalingNodeState.Retired);

    /// <summary>
    /// The derived cluster pressure of one snapshot. Projected demand is the
    /// usage of every node still serving work plus the demand set; capacity
    /// is summed over the same nodes; Provisioning nodes and remembered
    /// in-flight provisions contribute their reserved capacity to the
    /// in-flight reserve counted against the scale-up deficit. All ratio
    /// arithmetic is exact, so derived values are deterministic.
    /// </summary>
    private ClusterPressure ComputeClusterPressure(AutoscalerSnapshot snapshot)
    {
        var projected = new BigInteger[DimensionCount];
        var activeCapacity = new BigInteger[DimensionCount];
        var provisioningCapacity = new BigInteger[DimensionCount];
        foreach (var node in snapshot.Nodes)
        {
            switch (node.State)
            {
                case AutoscalingNodeState.Ready or AutoscalingNodeState.Cordoned or AutoscalingNodeState.Draining:
                    Accumulate(activeCapacity, node.Capacity);
                    Accumulate(projected, node.Usage);
                    break;
                case AutoscalingNodeState.Provisioning:
                    Accumulate(provisioningCapacity, node.Capacity);
                    break;
            }
        }

        foreach (var entry in snapshot.Demand)
        {
            Accumulate(projected, entry.Resources);
        }

        foreach (var provision in inFlightProvisions.Values)
        {
            Accumulate(provisioningCapacity, provision);
        }

        var breach = false;
        BigInteger? headroomNumerator = null;
        BigInteger headroomDenominator = 1;
        for (var dimension = 0; dimension < DimensionCount; dimension++)
        {
            var dimensionCapacity = activeCapacity[dimension];
            var dimensionProjected = projected[dimension];
            if (dimensionCapacity <= 0)
            {
                if (dimensionProjected > 0)
                {
                    // Demand against zero capacity can never be served.
                    breach = true;
                }

                continue;
            }

            // Breach: projected > capacity * (1 - scaleUpHeadroom/100).
            if (dimensionProjected * 100 > dimensionCapacity * (100 - config.ScaleUpHeadroomPercent))
            {
                breach = true;
            }

            var numerator = dimensionCapacity - dimensionProjected;
            if (numerator < 0)
            {
                numerator = BigInteger.Zero;
            }

            // Minimum headroom across dimensions, kept as an exact fraction.
            if (headroomNumerator is null || numerator * headroomDenominator < headroomNumerator.Value * dimensionCapacity)
            {
                headroomNumerator = numerator;
                headroomDenominator = dimensionCapacity;
            }
        }

        return new ClusterPressure(projected, activeCapacity, provisioningCapacity, breach, headroomNumerator, headroomDenominator);
    }

    private static void Accumulate(BigInteger[] sums, ResourceVector resources)
    {
        foreach (var (dimension, value) in resources.OrderedValues())
        {
            sums[(int)dimension] += value;
        }
    }

    /// <summary>
    /// Sizes provisioned nodes: the largest demand no Ready node has the free
    /// capacity to host, with the largest demand overall as the fallback.
    /// Envelopes compare by dimension in declared order, so the choice is
    /// deterministic. Returns null when the snapshot carries no demand.
    /// </summary>
    private static ResourceVector? LargestProvisionSizing(AutoscalerSnapshot snapshot)
    {
        if (snapshot.Demand.Count == 0)
        {
            return null;
        }

        var pool = snapshot.Demand.Where(entry => !DemandFitsAnyReadyNode(entry, snapshot)).ToArray();
        if (pool.Length == 0)
        {
            pool = [.. snapshot.Demand];
        }

        return pool.Select(entry => entry.Resources).Aggregate((largest, next) => EnvelopeLarger(next, largest) ? next : largest);
    }

    private static bool DemandFitsAnyReadyNode(AllocationDemand entry, AutoscalerSnapshot snapshot) =>
        snapshot.Nodes.Any(node =>
            node.State == AutoscalingNodeState.Ready &&
            NodeObservation.Fits(entry.Resources, node.Capacity.SubtractChecked(node.Usage)));

    /// <summary>
    /// Orders two resource envelopes lexicographically by dimension in
    /// declared order, so the choice is deterministic.
    /// </summary>
    private static bool EnvelopeLarger(ResourceVector left, ResourceVector right)
    {
        foreach (var (l, r) in left.OrderedValues().Select(d => d.Value)
            .Zip(right.OrderedValues().Select(d => d.Value), (l, r) => (l, r)))
        {
            if (l != r)
            {
                return l > r;
            }
        }

        return false;
    }

    /// <summary>
    /// How many nodes of the given sizing close the scale-up deficit: per
    /// dimension, the hard shortfall of projected demand against active
    /// capacity plus the in-flight reserve, divided by the sizing and
    /// rounded up. When no dimension reports a shortfall but nothing is in
    /// flight, one node still relieves the breached headroom; when the
    /// in-flight reserve already covers the deficit, zero nodes are needed,
    /// so the same shortfall is never provisioned twice.
    /// </summary>
    private static long RequiredProvisionCount(ClusterPressure pressure, ResourceVector sizing, int provisioningCount)
    {
        BigInteger needed = 0;
        foreach (var (dimension, sizingValue) in sizing.OrderedValues())
        {
            var index = (int)dimension;
            var served = pressure.ActiveCapacity[index] + pressure.ProvisioningCapacity[index];
            if (pressure.Projected[index] <= served || sizingValue <= 0)
            {
                continue;
            }

            var deficit = pressure.Projected[index] - served;
            var count = (deficit + sizingValue - 1) / sizingValue;
            if (count > needed)
            {
                needed = count;
            }
        }

        if (needed == 0 && provisioningCount == 0)
        {
            return 1;
        }

        return (long)Math.Min(needed, int.MaxValue);
    }

    /// <summary>
    /// The exact utilization of one node: the maximum usage-to-capacity ratio
    /// over the dimensions with positive capacity, and zero when every
    /// dimension is degenerate. Ordering by this ratio (then node id, which
    /// the canonical snapshot order supplies) is total.
    /// </summary>
    private static Utilization UtilizationRatio(NodeObservation node) => new(node);

    private readonly record struct Utilization(NodeObservation Node) : IComparable<Utilization>
    {
        public int CompareTo(Utilization other)
        {
            var (numerator, denominator) = MaxRatio(Node);
            var (otherNumerator, otherDenominator) = MaxRatio(other.Node);
            var comparison = (numerator * otherDenominator).CompareTo(otherNumerator * denominator);
            return comparison;
        }

        private static (BigInteger Numerator, BigInteger Denominator) MaxRatio(NodeObservation node)
        {
            BigInteger bestNumerator = 0, bestDenominator = 1;
            foreach (var (dimension, capacity) in node.Capacity.OrderedValues())
            {
                if (capacity <= 0)
                {
                    continue;
                }

                var usage = ValueOf(node.Usage, dimension);
                if (usage * bestDenominator > bestNumerator * capacity)
                {
                    bestNumerator = usage;
                    bestDenominator = capacity;
                }
            }

            return (bestNumerator, bestDenominator);

            static long ValueOf(ResourceVector vector, ResourceDimension dimension) =>
                vector.OrderedValues().Single(pair => pair.Dimension == dimension).Value;
        }
    }

    private sealed record ClusterPressure(
        BigInteger[] Projected,
        BigInteger[] ActiveCapacity,
        BigInteger[] ProvisioningCapacity,
        bool ScaleUpBreach,
        BigInteger? MinimumHeadroomNumerator,
        BigInteger MinimumHeadroomDenominator)
    {
        public bool MinimumHeadroomExceeds(int scaleDownHeadroomPercent) =>
            MinimumHeadroomNumerator is { } numerator &&
            numerator * 100 > MinimumHeadroomDenominator * scaleDownHeadroomPercent;
    }
}
