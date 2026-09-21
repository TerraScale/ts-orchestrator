using TerraScale.Orchestrator.ControlPlane.Delivery;

namespace TerraScale.Orchestrator.Runtime;

internal sealed record HostNativeAllocation(RuntimeDriver Driver, string AllocationId, string Fingerprint,
    SystemdAllocationState State, int? MainProcessId, string? ImageReference = null, string? Platform = null)
{
    internal bool Matches(HostRuntimePlan plan) => Driver == plan.Driver && AllocationId == plan.AllocationId.Value &&
        Fingerprint == CanonicalPlanFingerprint.Compute(plan) &&
        (Driver == RuntimeDriver.NativeSystemd || ImageReference == plan.Oci!.ImageReference && Platform == plan.Oci.Platform);
}

internal sealed record HostNativeInventorySnapshot(IReadOnlyList<RuntimeDriver> Drivers, IReadOnlyList<HostNativeAllocation> Allocations);

/// <summary>Read-only discovery of every closed-catalog allocation for this exact regional node.</summary>
internal interface IHostNativeInventoryProbe
{
    Task<HostNativeInventorySnapshot> ReadAsync(HostWorkloadIdentity identity, CancellationToken cancellationToken);
}

internal sealed class HostNativeInventoryProbe(IContainerdClient containerd, IHostCommandRunner? commands = null,
    ISystemdHostProbe? hostProbe = null) : IHostNativeInventoryProbe
{
    private readonly IContainerdClient containerd = containerd ?? throw new ArgumentNullException(nameof(containerd));
    private readonly IHostCommandRunner commands = commands ?? new ProcessHostCommandRunner();
    private readonly ISystemdHostProbe hostProbe = hostProbe ?? new LinuxSystemdHostProbe();

    public async Task<HostNativeInventorySnapshot> ReadAsync(HostWorkloadIdentity identity, CancellationToken cancellationToken)
    {
        if (!hostProbe.Probe().IsAdmitted) throw new InvalidOperationException("Native inventory needs an admitted systemd/cgroup-v2 host.");
        var observed = new List<HostNativeAllocation>();
        var addresses = AdmittedRoleCatalog.All.SelectMany(role => role.AllowedDrivers.Select(driver =>
            (Driver: driver, Id: HostConvergenceRuntime.AllocationIdFor(identity.Cell, identity.NodeId, role.ArtifactKey).Value))).Distinct();
        foreach (var (driver, id) in addresses)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (driver == RuntimeDriver.NativeSystemd)
            {
                var result = await commands.RunAsync(LinuxSystemdHostProbe.SystemctlPath,
                    ["show", $"terrascale-{id}.service", "--property=LoadState", "--property=ActiveState", "--property=MainPID", "--property=Description"],
                    cancellationToken).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
                if (result.StandardOutput.Length > 16_384) throw new InvalidDataException("The native inventory response exceeds its bounds.");
                var values = result.StandardOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(line => line.Split('=', 2))
                    .ToDictionary(parts => parts[0], parts => parts.Length == 2 ? parts[1] : throw new InvalidDataException("Invalid systemd inventory."), StringComparer.Ordinal);
                if (values.GetValueOrDefault("LoadState") == "not-found")
                {
                    SystemdHostRuntimeAdapter.RequireAbsentObservation(values);
                    continue;
                }
                var prefix = $"TerraScale allocation {id} plan ";
                var description = values.GetValueOrDefault("Description");
                if (result.ExitCode != 0 || values.GetValueOrDefault("LoadState") != "loaded" ||
                    description?.StartsWith(prefix, StringComparison.Ordinal) != true || !Fingerprint(description[prefix.Length..]))
                    throw new InvalidDataException("A native allocation cannot be attributed to a canonical host plan.");
                var state = values.GetValueOrDefault("ActiveState") switch
                {
                    "active" => SystemdAllocationState.Running,
                    "activating" or "reloading" => SystemdAllocationState.Starting,
                    "deactivating" => SystemdAllocationState.Stopping,
                    "inactive" => SystemdAllocationState.Stopped,
                    "failed" => SystemdAllocationState.Failed,
                    _ => throw new InvalidDataException("A native allocation has an unknown state.")
                };
                if (!int.TryParse(values.GetValueOrDefault("MainPID"), System.Globalization.NumberStyles.None,
                        System.Globalization.CultureInfo.InvariantCulture, out var pid) || pid < 0)
                    throw new InvalidDataException("A native allocation has an invalid process observation.");
                observed.Add(new(driver, id, description[prefix.Length..], state, pid == 0 ? null : pid));
            }
            else
            {
                var containerId = "terrascale-" + id;
                var allocation = await containerd.ObserveAsync(ContainerdHostRuntimeAdapter.Namespace, containerId, cancellationToken).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
                if (allocation.ContainerId != containerId || !Enum.IsDefined(allocation.State))
                    throw new InvalidDataException("Container inventory returned a different allocation or unknown state.");
                if (allocation.State == ContainerdAllocationState.Absent)
                {
                    if (allocation.ProcessId is not null) throw new InvalidDataException("Absent container reports a process.");
                    continue;
                }
                if (!Fingerprint(allocation.PlanFingerprint) || allocation.ProcessId is <= 0)
                    throw new InvalidDataException("Container inventory is missing its canonical identity or process observation.");
                observed.Add(new(driver, id, allocation.PlanFingerprint!, allocation.State switch
                {
                    ContainerdAllocationState.Running => SystemdAllocationState.Running,
                    ContainerdAllocationState.Created => SystemdAllocationState.Starting,
                    ContainerdAllocationState.Stopped => SystemdAllocationState.Stopped,
                    _ => SystemdAllocationState.Failed
                }, allocation.ProcessId, allocation.ImageReference, allocation.Platform));
            }
        }
        return new([RuntimeDriver.NativeSystemd, RuntimeDriver.OciContainer], observed);
    }

    internal static bool Fingerprint(string? value) => value is { Length: 64 } && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
}
