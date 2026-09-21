namespace TerraScale.Orchestrator.Runtime;

/// <summary>Reconstructs a detached, closed-catalog plan before persisting or dispatching it.</summary>
internal static class HostRuntimePlanSnapshot
{
    internal static HostRuntimePlan Copy(HostRuntimePlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        if (plan.SchemaVersion != 2 || !Enum.IsDefined(plan.Role) || !Enum.IsDefined(plan.Driver) ||
            !Enum.IsDefined(plan.Architecture) || plan.AllocationId is null || plan.ArtifactDigest is null || plan.Resources is null)
            throw new InvalidDataException("The host workload inventory requires a complete canonical plan.");
        return plan.Driver switch
        {
            RuntimeDriver.NativeSystemd => NativeSystemdRuntimeAdmission.RequireCanonicalNativePlan(plan),
            RuntimeDriver.OciContainer => ContainerdHostRuntimeAdapter.RequireCanonicalPlan(plan),
            _ => throw new InvalidDataException("The host runtime driver is invalid.")
        };
    }
}
