namespace TerraScale.Orchestrator.Protocol.Messaging;

/// <summary>
/// Connectivity classes for regional autonomy. They align one-to-one with the executable
/// decision core <c>TerraScale.Orchestrator.ControlPlane.Messaging.ConnectivityState</c>
/// consumed by <c>MessagingPolicyEngine.DecidePartition</c>.
/// </summary>
public enum MessagingConnectivity
{
    Unspecified = 0,
    Connected,
    /// <summary>The cell is isolated from the global plane but its regional quorum is healthy.</summary>
    GlobalIsolated,
    /// <summary>The cell lost its own regional NATS quorum.</summary>
    RegionalQuorumLost,
}

/// <summary>The mutation classes the autonomy rules freeze or permit.</summary>
public enum RegionalAutonomyOperationClass
{
    Unspecified = 0,
    /// <summary>Regional work already authorized before isolation: keep running and reconciling it.</summary>
    PreAuthorizedRegionalOperation,
    /// <summary>Starting a new global desired-state generation.</summary>
    NewGlobalGeneration,
    /// <summary>Changing global policy or trust.</summary>
    NewGlobalPolicy,
    /// <summary>Publishing or activating a new global release.</summary>
    NewGlobalRelease,
    /// <summary>Claiming or renewing the global authority lease from an isolated cell.</summary>
    GlobalAuthorityClaim,
    /// <summary>Read-only observation and reporting: always permitted.</summary>
    RegionalObservation,
}

public enum RegionalAutonomyDecision
{
    Unspecified = 0,
    Permitted,
    /// <summary>Frozen: hold the mutation; it requires reconnection and a current global epoch.</summary>
    FrozenGlobalMutation,
    /// <summary>Held: regional mutations stop until the regional quorum returns; read-only work continues.</summary>
    HeldUntilRegionalQuorum,
    /// <summary>Frozen: an isolated cell may never claim global authority.</summary>
    FrozenGlobalAuthorityClaim,
}

/// <summary>
/// Regional autonomy rules: an isolated cell keeps its pre-authorized regional work and
/// freezes new global generations, policy, and releases. When the regional quorum itself is
/// lost, running workloads continue on their last committed allocation but new mutations are
/// held. The epoch/generation comparison logic lives in
/// <c>MessagingPolicyEngine.DecidePartition</c>; these rules freeze the operation classes.
/// </summary>
public static class RegionalAutonomyRules
{
    public static RegionalAutonomyDecision Decide(
        MessagingConnectivity connectivity,
        RegionalAutonomyOperationClass operationClass)
    {
        if (connectivity == MessagingConnectivity.Unspecified ||
            operationClass == RegionalAutonomyOperationClass.Unspecified)
        {
            return RegionalAutonomyDecision.Unspecified;
        }

        return (connectivity, operationClass) switch
        {
            (_, RegionalAutonomyOperationClass.RegionalObservation) => RegionalAutonomyDecision.Permitted,
            (MessagingConnectivity.Connected, _) => RegionalAutonomyDecision.Permitted,
            (MessagingConnectivity.GlobalIsolated, RegionalAutonomyOperationClass.PreAuthorizedRegionalOperation) =>
                RegionalAutonomyDecision.Permitted,
            (MessagingConnectivity.GlobalIsolated, RegionalAutonomyOperationClass.GlobalAuthorityClaim) =>
                RegionalAutonomyDecision.FrozenGlobalAuthorityClaim,
            (MessagingConnectivity.GlobalIsolated,
                RegionalAutonomyOperationClass.NewGlobalGeneration or
                RegionalAutonomyOperationClass.NewGlobalPolicy or
                RegionalAutonomyOperationClass.NewGlobalRelease) =>
                RegionalAutonomyDecision.FrozenGlobalMutation,
            (MessagingConnectivity.RegionalQuorumLost, RegionalAutonomyOperationClass.GlobalAuthorityClaim) =>
                RegionalAutonomyDecision.FrozenGlobalAuthorityClaim,
            (MessagingConnectivity.RegionalQuorumLost, _) => RegionalAutonomyDecision.HeldUntilRegionalQuorum,
            _ => RegionalAutonomyDecision.Unspecified,
        };
    }
}
