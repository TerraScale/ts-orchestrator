using TerraScale.Orchestrator.Scheduler;
using TerraScale.Orchestrator.Scheduler.Autoscaling;

namespace TerraScale.Orchestrator.Nodes;

/// <summary>
/// The complete launch description for one TerraBase member process: the
/// executable pieces plus every TERRABASE_* variable except the listener URLs,
/// which the member process host derives from the reserved ports.
/// </summary>
public sealed record MemberLaunchDescription(
    string NodeId,
    string DotNetPath,
    string HostAssemblyPath,
    string WorkingDirectory,
    int PeerPort,
    int ObservabilityPort,
    IReadOnlyDictionary<string, string> Environment);

/// <summary>
/// A local-development node fleet: every node is one process hosting one
/// TerraBase member. The fleet materializes nodes for the autoscaler, reports
/// heartbeats as autoscaler snapshots, applies cordon/drain/retire actions,
/// and surfaces member process loss immediately. It exists to drive scale-up,
/// scale-down, and auto-heal against real members on one host (and, through
/// the Firecracker lane, inside VMs); it is not a production provisioner.
/// </summary>
public sealed class LocalNodeFleet : IAsyncDisposable
{
    private readonly Func<NodeProvisionRequest, MemberLaunchDescription> memberFactory;
    private readonly ResourceVector nodeCapacity;
    private readonly TimeSpan readinessTimeout;
    private readonly Dictionary<string, FleetNode> nodes = new(StringComparer.Ordinal);
    private readonly Lock gate = new();

    /// <summary>
    /// Creates one fleet whose nodes have the given capacity envelope and
    /// whose members are built by the supplied factory.
    /// </summary>
    public LocalNodeFleet(
        Func<NodeProvisionRequest, MemberLaunchDescription> memberFactory,
        ResourceVector? nodeCapacity = null,
        TimeSpan? readinessTimeout = null)
    {
        this.memberFactory = memberFactory ?? throw new ArgumentNullException(nameof(memberFactory));
        this.nodeCapacity = nodeCapacity ?? DefaultNodeCapacity;
        this.readinessTimeout = readinessTimeout ?? TimeSpan.FromSeconds(60);
    }

    /// <summary>The capacity every provisioned node reports.</summary>
    public static ResourceVector DefaultNodeCapacity { get; } = new(
        cpu: 200, memory: 4_000_000_000, blockIo: 0, ephemeralDisk: 0, bandwidth: 0, pids: 64, fileDescriptors: 0, hugePages: 0);

    /// <summary>Provisions one node: starts its member and reports it Ready.</summary>
    public async Task ProvisionAsync(NodeProvisionRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var description = memberFactory(request);
        var member = await MemberProcessHost.StartAsync(description, readinessTimeout);
        lock (gate)
        {
            nodes[request.NodeId] = new FleetNode(
                AutoscalingNodeState.Ready,
                member,
                request.Resources,
                Cordoned: false);
        }
    }

    /// <summary>Cordons one node: it stops counting as drain-safe capacity.</summary>
    public Task CordonAsync(string nodeId)
    {
        lock (gate)
        {
            var node = RequireNode(nodeId);
            nodes[nodeId] = node with { State = AutoscalingNodeState.Cordoned, Cordoned = true };
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Drains one node: stops its member gracefully once, and reports the
    /// node Draining with zero running allocations after the member exits.
    /// </summary>
    public async Task DrainAsync(string nodeId)
    {
        MemberProcessHost? member;
        lock (gate)
        {
            var node = RequireNode(nodeId);
            nodes[nodeId] = node with { State = AutoscalingNodeState.Draining };
            member = node.Member;
        }

        if (member is not null)
        {
            await member.StopAsync(TimeSpan.FromSeconds(15));
        }
    }

    /// <summary>Retires one drained node and releases its member and data.</summary>
    public async Task RetireAsync(string nodeId)
    {
        FleetNode? node;
        lock (gate)
        {
            node = RequireNode(nodeId);
            nodes.Remove(nodeId);
        }

        if (node.Member is not null)
        {
            await node.Member.DisposeAsync();
        }
    }

    /// <summary>Kills one node's member abruptly, simulating host loss.</summary>
    public void KillMember(string nodeId)
    {
        lock (gate)
        {
            var node = RequireNode(nodeId);
            node.Member?.Kill();
            nodes[nodeId] = node with { State = AutoscalingNodeState.Retired };
        }
    }

    /// <summary>
    /// Builds the autoscaler snapshot from live member observations. A node
    /// whose member died is reported with its replica down so the drain
    /// safety gate defers; a node removed after member loss disappears from
    /// the snapshot entirely, exactly as a heartbeat-silent node does.
    /// </summary>
    public async Task<AutoscalerSnapshot> ObserveAsync(IReadOnlyList<AllocationDemand>? demand = null)
    {
        var observations = new List<(string NodeId, FleetNode Node, MemberObservation Member)>();
        lock (gate)
        {
            foreach (var (nodeId, node) in nodes)
            {
                observations.Add((nodeId, node, new MemberObservation(false, 0)));
            }
        }

        for (var index = 0; index < observations.Count; index++)
        {
            var (nodeId, node, _) = observations[index];
            var observation = node.Member is null
                ? new MemberObservation(false, 0)
                : await node.Member.ObserveAsync();
            observations[index] = (nodeId, node, observation);
        }

        var nodeViews = observations.Select(entry => new NodeObservation(
            entry.NodeId,
            entry.Node.State,
            entry.Node.Capacity,
            UsageOf(entry),
            0,
            [ReplicaOf(entry)])).ToArray();
        return new AutoscalerSnapshot(nodeViews, demand ?? []);

        static ResourceVector UsageOf((string NodeId, FleetNode Node, MemberObservation Member) entry) =>
            entry.Member.Up
                ? new ResourceVector(
                    cpu: 10, memory: 500_000_000, blockIo: 0, ephemeralDisk: 0, bandwidth: 0, pids: 1, fileDescriptors: 0, hugePages: 0)
                : ResourceVector.Zero;

        static StatefulReplicaHealth ReplicaOf((string NodeId, FleetNode Node, MemberObservation Member) entry) =>
            new("terrabase-member", entry.NodeId, entry.Member.Up, peerAckCount: 1, minReplicas: 2, lagBytes: entry.Member.ReplicationLagSequences);
    }

    /// <summary>Whether one node's member process is alive right now.</summary>
    public bool IsMemberAlive(string nodeId)
    {
        lock (gate)
        {
            return nodes.TryGetValue(nodeId, out var node) && node.Member is { IsAlive: true };
        }
    }

    public async ValueTask DisposeAsync()
    {
        FleetNode[] remaining;
        lock (gate)
        {
            remaining = [.. nodes.Values];
            nodes.Clear();
        }

        foreach (var node in remaining)
        {
            if (node.Member is not null)
            {
                await node.Member.DisposeAsync();
            }
        }
    }

    private FleetNode RequireNode(string nodeId) =>
        nodes.TryGetValue(nodeId, out var node)
            ? node
            : throw new InvalidOperationException($"Node {nodeId} is not part of this fleet.");

    private sealed record FleetNode(
        AutoscalingNodeState State,
        MemberProcessHost? Member,
        ResourceVector Capacity,
        bool Cordoned);
}
