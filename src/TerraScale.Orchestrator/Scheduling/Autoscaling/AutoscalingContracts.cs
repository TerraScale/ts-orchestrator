using System.Collections.ObjectModel;
using System.Text.RegularExpressions;

namespace TerraScale.Orchestrator.Scheduler.Autoscaling;

/// <summary>
/// Closed node lifecycle vocabulary of the autoscaler.
/// </summary>
public enum AutoscalingNodeState
{
    Ready,
    Provisioning,
    Cordoned,
    Draining,
    Retired,
}

public sealed partial class AutoscalingTokens
{
    public const int MaximumLength = 63;
    public const int MaximumReasonLength = 256;
    public const int MaximumReplicaCount = 1024;
    public const int MaximumNodeCount = 1024;
    public const int MaximumDemandCount = 4096;
    public const int MaximumConcurrentProvisions = 64;

    [GeneratedRegex("^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")]
    private static partial Regex TokenPattern();

    public static string Require(string value, string parameterName) =>
        TokenPattern().IsMatch(value) && value.Length <= MaximumLength
            ? value
            : throw new ArgumentException("Value must be a lowercase DNS-style token of at most 63 characters.", parameterName);
}

/// <summary>
/// Bounded fleet scaling policy. Headroom percentages are exclusive bounds on
/// (0, 100); confirm ticks give every decision hysteresis; the flap
/// suppression window blocks provisioning while a retirement is remembered.
/// </summary>
public sealed record AutoscalerConfig
{
    public AutoscalerConfig(
        int minNodes,
        int maxNodes,
        int scaleUpHeadroomPercent,
        int scaleDownHeadroomPercent,
        int scaleUpConfirmTicks,
        int scaleDownConfirmTicks,
        int maxConcurrentProvisions,
        int flapSuppressionTicks)
    {
        if (minNodes < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(minNodes), minNodes, "MinNodes must be at least one.");
        }
        if (maxNodes < minNodes)
        {
            throw new ArgumentOutOfRangeException(nameof(maxNodes), maxNodes, "MaxNodes must be at least MinNodes.");
        }
        if (scaleUpHeadroomPercent is <= 0 or >= 100)
        {
            throw new ArgumentOutOfRangeException(nameof(scaleUpHeadroomPercent), scaleUpHeadroomPercent, "Scale-up headroom must be between 0 and 100 exclusive.");
        }
        if (scaleDownHeadroomPercent is <= 0 or >= 100)
        {
            throw new ArgumentOutOfRangeException(nameof(scaleDownHeadroomPercent), scaleDownHeadroomPercent, "Scale-down headroom must be between 0 and 100 exclusive.");
        }
        if (scaleUpConfirmTicks < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(scaleUpConfirmTicks), scaleUpConfirmTicks, "Scale-up confirmation ticks must be at least one.");
        }
        if (scaleDownConfirmTicks < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(scaleDownConfirmTicks), scaleDownConfirmTicks, "Scale-down confirmation ticks must be at least one.");
        }
        if (maxConcurrentProvisions is < 1 or > AutoscalingTokens.MaximumConcurrentProvisions)
        {
            throw new ArgumentOutOfRangeException(nameof(maxConcurrentProvisions), maxConcurrentProvisions, $"Provision concurrency must be between 1 and {AutoscalingTokens.MaximumConcurrentProvisions}.");
        }
        if (flapSuppressionTicks < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(flapSuppressionTicks), flapSuppressionTicks, "Flap suppression ticks must be non-negative.");
        }

        MinNodes = minNodes;
        MaxNodes = maxNodes;
        ScaleUpHeadroomPercent = scaleUpHeadroomPercent;
        ScaleDownHeadroomPercent = scaleDownHeadroomPercent;
        ScaleUpConfirmTicks = scaleUpConfirmTicks;
        ScaleDownConfirmTicks = scaleDownConfirmTicks;
        MaxConcurrentProvisions = maxConcurrentProvisions;
        FlapSuppressionTicks = flapSuppressionTicks;
    }

    public int MinNodes { get; }

    public int MaxNodes { get; }

    public int ScaleUpHeadroomPercent { get; }

    public int ScaleDownHeadroomPercent { get; }

    public int ScaleUpConfirmTicks { get; }

    public int ScaleDownConfirmTicks { get; }

    public int MaxConcurrentProvisions { get; }

    public int FlapSuppressionTicks { get; }
}

/// <summary>
/// Replica health of one stateful allocation as observed on a node.
/// </summary>
public sealed record StatefulReplicaHealth
{
    public StatefulReplicaHealth(string roleKind, string allocationId, bool up, int peerAckCount, int minReplicas, long lagBytes)
    {
        RoleKind = AutoscalingTokens.Require(roleKind, nameof(roleKind));
        AllocationId = AutoscalingTokens.Require(allocationId, nameof(allocationId));
        if (peerAckCount < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(peerAckCount), peerAckCount, "Peer acknowledgements must be non-negative.");
        }
        if (minReplicas < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(minReplicas), minReplicas, "The minimum replica count must be at least one.");
        }
        if (lagBytes < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(lagBytes), lagBytes, "Replication lag must be non-negative.");
        }

        Up = up;
        PeerAckCount = peerAckCount;
        MinReplicas = minReplicas;
        LagBytes = lagBytes;
    }

    public string RoleKind { get; }

    public string AllocationId { get; }

    public bool Up { get; }

    public int PeerAckCount { get; }

    public int MinReplicas { get; }

    public long LagBytes { get; }
}

/// <summary>
/// One node's stateful replica observations, canonicalized and deduplicated.
/// </summary>
public sealed record NodeDrainCandidate
{
    public NodeDrainCandidate(string nodeId, IEnumerable<StatefulReplicaHealth>? replicas)
    {
        NodeId = AutoscalingTokens.Require(nodeId, nameof(nodeId));
        var snapshot = (replicas ?? []).Take(AutoscalingTokens.MaximumReplicaCount + 1).ToArray();
        if (snapshot.Length > AutoscalingTokens.MaximumReplicaCount)
        {
            throw new ArgumentException($"Replica input exceeds the bound of {AutoscalingTokens.MaximumReplicaCount} entries.", nameof(replicas));
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var replica in snapshot)
        {
            ArgumentNullException.ThrowIfNull(replica);
            if (!seen.Add(replica.RoleKind + "/" + replica.AllocationId))
            {
                throw new ArgumentException("A role allocation may appear only once per node.", nameof(replicas));
            }
        }

        Replicas = new ReadOnlyCollection<StatefulReplicaHealth>(snapshot);
    }

    public string NodeId { get; }

    public ReadOnlyCollection<StatefulReplicaHealth> Replicas { get; }
}

/// <summary>
/// Drain verdict with the sorted allocation ids that block a deferred drain.
/// </summary>
public sealed record DrainDecision(bool Allowed, string Reason, ReadOnlyCollection<string> BlockingAllocationIds)
{
    public static DrainDecision Allow(string reason) =>
        new(true, reason, new ReadOnlyCollection<string>(Array.Empty<string>()));

    public static DrainDecision Defer(string reason, IEnumerable<string> blockingAllocationIds) =>
        new(false, reason, new ReadOnlyCollection<string>(blockingAllocationIds.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray()));
}

/// <summary>
/// Drain safety policy: the maximum replication lag a drained replica may
/// carry. The bound is exclusive; a caught-up replica (zero lag) always passes.
/// </summary>
public sealed record DrainPolicy
{
    public DrainPolicy(long maxLagBytes)
    {
        if (maxLagBytes < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(maxLagBytes), maxLagBytes, "The drain lag bound must be positive.");
        }

        MaxLagBytes = maxLagBytes;
    }

    public long MaxLagBytes { get; }
}

/// <summary>
/// Seam every drain path must consult before a stateful node is disturbed.
/// Implementations are fail-closed: an error verdict blocks the drain.
/// </summary>
public interface IDrainSafetyEvaluator
{
    DrainDecision Evaluate(NodeDrainCandidate candidate, IReadOnlyList<NodeDrainCandidate> peers);
}

/// <summary>
/// Stateful drain gate. A node may drain iff every hosted replica is up,
/// caught up within the lag bound, and keeps at least <c>MinReplicas</c>
/// acknowledgements plus up replicas of the same role kind on other nodes.
/// </summary>
public sealed class ReplicaDrainSafetyEvaluator(DrainPolicy policy) : IDrainSafetyEvaluator
{
    public DrainDecision Evaluate(NodeDrainCandidate candidate, IReadOnlyList<NodeDrainCandidate> peers)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        ArgumentNullException.ThrowIfNull(peers);
        if (peers.Count > AutoscalingTokens.MaximumReplicaCount)
        {
            throw new ArgumentException($"Peer input exceeds the bound of {AutoscalingTokens.MaximumReplicaCount} entries.", nameof(peers));
        }

        var own = candidate.Replicas.Select(r => r.RoleKind + "/" + r.AllocationId).ToHashSet(StringComparer.Ordinal);
        var upElsewhereByRole = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
        var seenPeers = new HashSet<string>(StringComparer.Ordinal);
        foreach (var peer in peers)
        {
            ArgumentNullException.ThrowIfNull(peer);
            if (peer.NodeId == candidate.NodeId)
            {
                throw new ArgumentException("The candidate node may not appear among its drain peers.", nameof(peers));
            }
            if (!seenPeers.Add(peer.NodeId))
            {
                throw new ArgumentException("Peer nodes must be unique.", nameof(peers));
            }

            foreach (var replica in peer.Replicas)
            {
                if (!replica.Up || own.Contains(replica.RoleKind + "/" + replica.AllocationId))
                {
                    continue;
                }

                if (!upElsewhereByRole.TryGetValue(replica.RoleKind, out var upSet))
                {
                    upSet = [];
                    upElsewhereByRole[replica.RoleKind] = upSet;
                }

                upSet.Add(replica.AllocationId);
            }
        }

        var blocking = new List<string>();
        foreach (var replica in candidate.Replicas)
        {
            var survivors = replica.PeerAckCount + (upElsewhereByRole.TryGetValue(replica.RoleKind, out var upSet) ? upSet.Count : 0);
            if (!replica.Up || replica.LagBytes >= policy.MaxLagBytes || survivors < replica.MinReplicas)
            {
                blocking.Add(replica.AllocationId);
            }
        }

        return blocking.Count == 0
            ? DrainDecision.Allow("Every replica is up, caught up, and sufficiently replicated on other nodes.")
            : DrainDecision.Defer("Replicas are down, lagging, or under-replicated on other nodes.", blocking);
    }
}

/// <summary>
/// One autoscaler view of a node: lifecycle state, capacity, usage, queued
/// allocations, and stateful replica health. Usage must fit inside capacity
/// on every dimension.
/// </summary>
public sealed record NodeObservation
{
    public NodeObservation(
        string nodeId,
        AutoscalingNodeState state,
        ResourceVector capacity,
        ResourceVector usage,
        int pendingAllocations,
        IEnumerable<StatefulReplicaHealth>? statefulReplicas)
    {
        NodeId = AutoscalingTokens.Require(nodeId, nameof(nodeId));
        if (!Enum.IsDefined(state))
        {
            throw new ArgumentOutOfRangeException(nameof(state), state, "Unknown node state.");
        }

        ArgumentNullException.ThrowIfNull(capacity);
        ArgumentNullException.ThrowIfNull(usage);
        if (!Fits(usage, capacity))
        {
            throw new ArgumentException("Usage cannot exceed capacity.", nameof(usage));
        }

        if (pendingAllocations < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(pendingAllocations), pendingAllocations, "Pending allocation count must be non-negative.");
        }

        var replicaList = (statefulReplicas ?? []).Take(AutoscalingTokens.MaximumReplicaCount + 1).ToArray();
        if (replicaList.Length > AutoscalingTokens.MaximumReplicaCount)
        {
            throw new ArgumentException($"Replica input exceeds the bound of {AutoscalingTokens.MaximumReplicaCount} entries.", nameof(statefulReplicas));
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var replica in replicaList)
        {
            ArgumentNullException.ThrowIfNull(replica);
            if (!seen.Add(replica.RoleKind + "/" + replica.AllocationId))
            {
                throw new ArgumentException("A role allocation may appear only once per node.", nameof(statefulReplicas));
            }
        }

        State = state;
        Capacity = capacity;
        Usage = usage;
        PendingAllocations = pendingAllocations;
        StatefulReplicas = new ReadOnlyCollection<StatefulReplicaHealth>(replicaList);
    }

    public string NodeId { get; }

    public AutoscalingNodeState State { get; }

    public ResourceVector Capacity { get; }

    public ResourceVector Usage { get; }

    public int PendingAllocations { get; }

    public ReadOnlyCollection<StatefulReplicaHealth> StatefulReplicas { get; }

    internal NodeDrainCandidate ToDrainCandidate() => new(NodeId, StatefulReplicas);

    internal static bool Fits(ResourceVector candidate, ResourceVector within) =>
        candidate.SubtractChecked(within).OrderedValues().All(dimension => dimension.Value <= 0);
}

/// <summary>
/// One unit of unsatisfied or projected workload demand.
/// </summary>
public sealed record AllocationDemand
{
    public AllocationDemand(string roleId, string roleKind, bool stateful, ResourceVector resources)
    {
        RoleId = AutoscalingTokens.Require(roleId, nameof(roleId));
        RoleKind = AutoscalingTokens.Require(roleKind, nameof(roleKind));
        Resources = resources ?? throw new ArgumentNullException(nameof(resources));
        Stateful = stateful;
    }

    public string RoleId { get; }

    public string RoleKind { get; }

    public bool Stateful { get; }

    public ResourceVector Resources { get; }
}

/// <summary>
/// One validated cluster observation, stored in canonical order (nodes by
/// node id, demand by role id) so identical clusters produce identical
/// decisions regardless of input order.
/// </summary>
public sealed record AutoscalerSnapshot
{
    public AutoscalerSnapshot(IEnumerable<NodeObservation>? nodes, IEnumerable<AllocationDemand>? demand)
    {
        var nodeList = (nodes ?? []).Take(AutoscalingTokens.MaximumNodeCount + 1).ToArray();
        var demandList = (demand ?? []).Take(AutoscalingTokens.MaximumDemandCount + 1).ToArray();
        if (nodeList.Length > AutoscalingTokens.MaximumNodeCount)
        {
            throw new ArgumentException($"Node input exceeds the bound of {AutoscalingTokens.MaximumNodeCount} entries.", nameof(nodes));
        }

        if (demandList.Length > AutoscalingTokens.MaximumDemandCount)
        {
            throw new ArgumentException($"Demand input exceeds the bound of {AutoscalingTokens.MaximumDemandCount} entries.", nameof(demand));
        }

        if (nodeList.Any(node => node is null) || demandList.Any(entry => entry is null))
        {
            throw new ArgumentException("Snapshot collections cannot contain null.");
        }

        if (nodeList.Select(node => node.NodeId).GroupBy(id => id, StringComparer.Ordinal).Any(group => group.Count() > 1))
        {
            throw new ArgumentException("A node may appear only once per snapshot.", nameof(nodes));
        }

        if (demandList.Select(entry => entry.RoleId).GroupBy(id => id, StringComparer.Ordinal).Any(group => group.Count() > 1))
        {
            throw new ArgumentException("A role may appear only once per snapshot.", nameof(demand));
        }

        Nodes = new ReadOnlyCollection<NodeObservation>(nodeList.OrderBy(node => node.NodeId, StringComparer.Ordinal).ToArray());
        Demand = new ReadOnlyCollection<AllocationDemand>(demandList.OrderBy(entry => entry.RoleId, StringComparer.Ordinal).ToArray());
    }

    public ReadOnlyCollection<NodeObservation> Nodes { get; }

    public ReadOnlyCollection<AllocationDemand> Demand { get; }
}

/// <summary>
/// One node creation request handed to a node provisioner.
/// </summary>
public sealed record NodeProvisionRequest
{
    public NodeProvisionRequest(string nodeId, string nodeClass, ResourceVector resources, string reason)
    {
        NodeId = AutoscalingTokens.Require(nodeId, nameof(nodeId));
        NodeClass = AutoscalingTokens.Require(nodeClass, nameof(nodeClass));
        Resources = resources ?? throw new ArgumentNullException(nameof(resources));
        if (string.IsNullOrEmpty(reason) || reason.Length > AutoscalingTokens.MaximumReasonLength)
        {
            throw new ArgumentException("A nonempty bounded reason is required.", nameof(reason));
        }

        if (Resources.OrderedValues().All(dimension => dimension.Value == 0))
        {
            throw new ArgumentException("A provision request must reserve at least one resource.", nameof(resources));
        }

        Reason = reason;
    }

    public string NodeId { get; }

    public string NodeClass { get; }

    public ResourceVector Resources { get; }

    public string Reason { get; }
}

/// <summary>
/// Closed autoscaler action union.
/// </summary>
public abstract record AutoscalerAction
{
    private AutoscalerAction() { }

    public sealed record ProvisionNode(NodeProvisionRequest Request) : AutoscalerAction;

    public sealed record CordonNode(string NodeId) : AutoscalerAction;

    public sealed record DrainNode(string NodeId) : AutoscalerAction;

    public sealed record RetireNode(string NodeId) : AutoscalerAction;
}
