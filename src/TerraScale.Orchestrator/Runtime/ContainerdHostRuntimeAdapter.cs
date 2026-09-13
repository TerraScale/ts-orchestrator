using System.Security.Cryptography;
using System.Text;

namespace TerraScale.Orchestrator.Runtime;

internal enum ContainerdAllocationState
{
    Absent,
    Created,
    Running,
    Stopped,
    Failed
}

internal sealed record ContainerdAllocationObservation(
    string ContainerId,
    ContainerdAllocationState State,
    string? ImageReference,
    string? Platform,
    string? PlanFingerprint,
    int? ProcessId,
    string Detail);

internal sealed record ContainerdCreateRequest(
    string Namespace,
    string ContainerId,
    string ImageReference,
    string Platform,
    OciSecurityPlan Security,
    RuntimeResourceLimits Resources,
    string PlanFingerprint);

internal interface IContainerdClient
{
    Task<ContainerdAllocationObservation> ObserveAsync(
        string @namespace,
        string containerId,
        CancellationToken cancellationToken);

    Task<string> PullAsync(
        string @namespace,
        string imageReference,
        string platform,
        CancellationToken cancellationToken);

    Task CreateAsync(ContainerdCreateRequest request, CancellationToken cancellationToken);
    Task StartAsync(string @namespace, string containerId, CancellationToken cancellationToken);
    Task StopAsync(string @namespace, string containerId, CancellationToken cancellationToken);
    Task DeleteAsync(string @namespace, string containerId, CancellationToken cancellationToken);
}

internal sealed class ContainerdHostRuntimeAdapter(IContainerdClient client)
{
    private readonly IContainerdClient client =
        client ?? throw new ArgumentNullException(nameof(client));

    internal const string Namespace = "terrascale";

    public async Task ConvergeAsync(HostRuntimePlan plan, CancellationToken cancellationToken)
    {
        var oci = RequireCanonicalOciPlan(plan);
        var fingerprint = CanonicalPlanFingerprint.Compute(plan);
        var observation = await client.ObserveAsync(Namespace, oci.ContainerId, cancellationToken);
        if (observation.State != ContainerdAllocationState.Absent)
        {
            RequireMatchingAllocation(observation, oci, fingerprint);
            if (observation.State == ContainerdAllocationState.Running)
            {
                return;
            }
            if (observation.State is ContainerdAllocationState.Created or ContainerdAllocationState.Stopped)
            {
                await client.StartAsync(Namespace, oci.ContainerId, cancellationToken);
                return;
            }
            throw new InvalidOperationException(
                $"containerd allocation {plan.AllocationId} is failed and requires an observed recovery decision.");
        }

        var pulledDigest = await client.PullAsync(
            Namespace,
            oci.ImageReference,
            oci.Platform,
            cancellationToken);
        if (!string.Equals(pulledDigest, plan.ArtifactDigest.Value, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"containerd returned an unexpected digest for allocation {plan.AllocationId}.");
        }
        await client.CreateAsync(
            new(
                Namespace,
                oci.ContainerId,
                oci.ImageReference,
                oci.Platform,
                oci.Security,
                oci.Resources,
                fingerprint),
            cancellationToken);
        await client.StartAsync(Namespace, oci.ContainerId, cancellationToken);
    }

    public async Task<ContainerdAllocationObservation> ObserveAsync(
        HostRuntimePlan plan,
        CancellationToken cancellationToken)
    {
        var oci = RequireCanonicalOciPlan(plan);
        var observation = await client.ObserveAsync(
            Namespace,
            oci.ContainerId,
            cancellationToken);
        if (observation.State != ContainerdAllocationState.Absent)
        {
            RequireMatchingAllocation(
                observation,
                oci,
                CanonicalPlanFingerprint.Compute(plan));
        }
        return observation;
    }

    public async Task StopAsync(HostRuntimePlan plan, CancellationToken cancellationToken)
    {
        var oci = RequireCanonicalOciPlan(plan);
        var observation = await ObserveAsync(plan, cancellationToken);
        if (observation.State is ContainerdAllocationState.Running)
        {
            await client.StopAsync(Namespace, oci.ContainerId, cancellationToken);
        }
    }

    public async Task DeleteAsync(HostRuntimePlan plan, CancellationToken cancellationToken)
    {
        var oci = RequireCanonicalOciPlan(plan);
        var observation = await ObserveAsync(plan, cancellationToken);
        if (observation.State == ContainerdAllocationState.Absent)
        {
            return;
        }
        if (observation.State == ContainerdAllocationState.Running)
        {
            await client.StopAsync(Namespace, oci.ContainerId, cancellationToken);
        }
        await client.DeleteAsync(Namespace, oci.ContainerId, cancellationToken);
    }

    private static void RequireMatchingAllocation(
        ContainerdAllocationObservation observation,
        OciExecutionPlan expected,
        string fingerprint)
    {
        if (!string.Equals(observation.ImageReference, expected.ImageReference, StringComparison.Ordinal) ||
            !string.Equals(observation.Platform, expected.Platform, StringComparison.Ordinal) ||
            !string.Equals(observation.PlanFingerprint, fingerprint, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"Existing containerd allocation '{expected.ContainerId}' is not owned by the canonical plan.");
        }
    }

    private static OciExecutionPlan RequireCanonicalOciPlan(HostRuntimePlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        if (plan.Driver != RuntimeDriver.OciContainer || plan.Oci is null || plan.Systemd is not null)
        {
            throw new ArgumentException("The containerd adapter requires an OCI plan.", nameof(plan));
        }
        var expected = HostRuntimePlan.Create(
            plan.Role,
            plan.Driver,
            plan.AllocationId,
            plan.ArtifactDigest,
            plan.Architecture,
            plan.Resources);
        var actualOci = plan.Oci;
        if (expected.Oci is not { } expectedOci)
        {
            throw new InvalidOperationException("The OCI execution plan could not be reconstructed from the admitted role.");
        }
        if (plan.SchemaVersion != expected.SchemaVersion ||
            actualOci.ContainerId != expectedOci.ContainerId ||
            actualOci.ImageReference != expectedOci.ImageReference ||
            actualOci.Platform != expectedOci.Platform ||
            actualOci.Resources != expectedOci.Resources ||
            actualOci.Security.RunAsUser != expectedOci.Security.RunAsUser ||
            actualOci.Security.RunAsGroup != expectedOci.Security.RunAsGroup ||
            actualOci.Security.NoNewPrivileges != expectedOci.Security.NoNewPrivileges ||
            actualOci.Security.ReadOnlyRootFileSystem != expectedOci.Security.ReadOnlyRootFileSystem ||
            !actualOci.Security.DroppedCapabilities.SequenceEqual(expectedOci.Security.DroppedCapabilities) ||
            actualOci.Security.SeccompProfile != expectedOci.Security.SeccompProfile ||
            actualOci.Security.CgroupParent != expectedOci.Security.CgroupParent ||
            plan.Resources != expected.Resources)
        {
            throw new InvalidOperationException("The OCI execution plan is not canonical for the admitted role.");
        }
        return actualOci;
    }
}

internal static class CanonicalPlanFingerprint
{
    public static string Compute(HostRuntimePlan plan)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Add(hash, plan.SchemaVersion.ToString(System.Globalization.CultureInfo.InvariantCulture));
        Add(hash, plan.Role.ToString());
        Add(hash, plan.Driver.ToString());
        Add(hash, plan.AllocationId.Value);
        Add(hash, plan.ArtifactDigest.Value);
        Add(hash, plan.Architecture.ToString());
        Add(hash, plan.Resources.MemoryMaxBytes.ToString(System.Globalization.CultureInfo.InvariantCulture));
        Add(hash, plan.Resources.MemoryHighBytes.ToString(System.Globalization.CultureInfo.InvariantCulture));
        Add(hash, plan.Resources.MemorySwapMaxBytes.ToString(System.Globalization.CultureInfo.InvariantCulture));
        Add(hash, plan.Resources.TasksMax.ToString(System.Globalization.CultureInfo.InvariantCulture));
        Add(hash, plan.Resources.CpuQuotaPercent.ToString(System.Globalization.CultureInfo.InvariantCulture));
        Add(hash, plan.Resources.CpuWeight.ToString(System.Globalization.CultureInfo.InvariantCulture));
        Add(hash, plan.Resources.IoWeight.ToString(System.Globalization.CultureInfo.InvariantCulture));
        Add(hash, plan.Resources.Nice.ToString(System.Globalization.CultureInfo.InvariantCulture));
        if (plan.Oci is { } oci)
        {
            Add(hash, oci.ContainerId);
            Add(hash, oci.ImageReference);
            Add(hash, oci.Platform);
            Add(hash, oci.Security.RunAsUser.ToString(System.Globalization.CultureInfo.InvariantCulture));
            Add(hash, oci.Security.RunAsGroup.ToString(System.Globalization.CultureInfo.InvariantCulture));
            Add(hash, oci.Security.NoNewPrivileges.ToString());
            Add(hash, oci.Security.ReadOnlyRootFileSystem.ToString());
            foreach (var capability in oci.Security.DroppedCapabilities)
            {
                Add(hash, capability);
            }
            Add(hash, oci.Security.SeccompProfile);
            Add(hash, oci.Security.CgroupParent);
        }
        return Convert.ToHexStringLower(hash.GetHashAndReset());
    }

    private static void Add(IncrementalHash hash, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        Span<byte> length = stackalloc byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(length, bytes.Length);
        hash.AppendData(length);
        hash.AppendData(bytes);
    }
}
