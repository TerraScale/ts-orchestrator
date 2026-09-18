using TerraScale.Orchestrator.Scheduler.Autoscaling;

namespace TerraScale.Orchestrator.Nodes;

/// <summary>
/// A node fleet the autoscaler runtime drives: it materializes nodes, reports
/// fleet observations as autoscaler snapshots, and applies lifecycle actions.
/// Implementations range from single-host member processes to Firecracker
/// microVMs.
/// </summary>
public interface INodeFleet : IAsyncDisposable
{
    /// <summary>Provisions one node with the given request.</summary>
    Task ProvisionAsync(NodeProvisionRequest request);

    /// <summary>Cordons one node.</summary>
    Task CordonAsync(string nodeId);

    /// <summary>Drains one node, stopping its member gracefully.</summary>
    Task DrainAsync(string nodeId);

    /// <summary>Retires one drained node, releasing its resources.</summary>
    Task RetireAsync(string nodeId);

    /// <summary>Kills one node's member abruptly, simulating host loss.</summary>
    void KillMember(string nodeId);

    /// <summary>Builds the autoscaler snapshot from live member observations.</summary>
    Task<AutoscalerSnapshot> ObserveAsync(IReadOnlyList<AllocationDemand>? demand = null);

    /// <summary>Whether one node's member is alive right now.</summary>
    bool IsMemberAlive(string nodeId);
}
