using TerraScale.Orchestrator.Scheduler.Autoscaling;

namespace TerraScale.Orchestrator.Nodes;

/// <summary>
/// One autoscaler step against the local node fleet: observe the fleet, tick
/// the deterministic engine, and apply the emitted actions in order. Apply
/// is fail-closed — the first failed provision, cordon, drain, or retire
/// stops the step instead of retrying blindly, mirroring the production
/// role's contract.
/// </summary>
public sealed class AutoscalerRuntime
{
    private readonly AutoscalerEngine engine;
    private readonly INodeFleet fleet;

    public AutoscalerRuntime(AutoscalerEngine engine, INodeFleet fleet)
    {
        this.engine = engine ?? throw new ArgumentNullException(nameof(engine));
        this.fleet = fleet ?? throw new ArgumentNullException(nameof(fleet));
    }

    /// <summary>The fleet this runtime drives.</summary>
    public INodeFleet Fleet => fleet;

    /// <summary>
    /// Observes the fleet with the supplied demand, ticks the engine, applies
    /// every emitted action, and returns the actions for inspection.
    /// </summary>
    public async Task<IReadOnlyList<AutoscalerAction>> StepAsync(IReadOnlyList<AllocationDemand>? demand = null)
    {
        var snapshot = await fleet.ObserveAsync(demand);
        var actions = engine.Tick(snapshot);
        foreach (var action in actions)
        {
            switch (action)
            {
                case AutoscalerAction.ProvisionNode provision:
                    await fleet.ProvisionAsync(provision.Request);
                    break;
                case AutoscalerAction.CordonNode cordon:
                    await fleet.CordonAsync(cordon.NodeId);
                    break;
                case AutoscalerAction.DrainNode drain:
                    await fleet.DrainAsync(drain.NodeId);
                    break;
                case AutoscalerAction.RetireNode retire:
                    await fleet.RetireAsync(retire.NodeId);
                    break;
                default:
                    throw new InvalidOperationException($"Unknown autoscaler action {action}.");
            }
        }

        return actions;
    }
}
