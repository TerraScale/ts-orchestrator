using System.Security.Cryptography;
using System.Text;
using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using TerraScale.Orchestrator.ControlPlane.Delivery;

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
        // Host convergence supplies the previous admitted plan for replacement.
        // A plausible fingerprint alone does not establish ownership.
        var observation = await ObserveAsync(plan, cancellationToken);
        if (observation.State == ContainerdAllocationState.Absent)
            return;
        if (observation.State == ContainerdAllocationState.Running)
        {
            await client.StopAsync(Namespace, oci.ContainerId, cancellationToken);
        }
        await client.DeleteAsync(Namespace, oci.ContainerId, cancellationToken);
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

    private static OciExecutionPlan RequireCanonicalOciPlan(HostRuntimePlan plan) => RequireCanonicalPlan(plan).Oci!;

    internal static HostRuntimePlan RequireCanonicalPlan(HostRuntimePlan plan)
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
        return expected;
    }
}

/// <summary>Maps the containerd lifecycle to the host convergence observation contract.</summary>
internal sealed class ContainerdHostRuntimeConverger(IContainerdClient client) : IHostRuntimeConverger
{
    private readonly ContainerdHostRuntimeAdapter adapter = new(client);

    public Task ConvergeAsync(HostRuntimePlan plan, CancellationToken cancellationToken) =>
        adapter.ConvergeAsync(plan, cancellationToken);

    public Task StopAsync(HostRuntimePlan plan, CancellationToken cancellationToken) =>
        adapter.StopAsync(plan, cancellationToken);

    public async Task<SystemdAllocationObservation> ObserveAsync(
        HostRuntimePlan plan,
        CancellationToken cancellationToken)
    {
        var observation = await adapter.ObserveAsync(plan, cancellationToken).ConfigureAwait(false);
        return new(
            plan.Oci?.ContainerId ?? plan.AllocationId.Value,
            observation.State switch
            {
                ContainerdAllocationState.Absent => SystemdAllocationState.Absent,
                ContainerdAllocationState.Running => SystemdAllocationState.Running,
                ContainerdAllocationState.Created => SystemdAllocationState.Starting,
                ContainerdAllocationState.Stopped => SystemdAllocationState.Stopped,
                _ => SystemdAllocationState.Failed
            },
            observation.ProcessId,
            observation.Detail);
    }
}

/// <summary>Routes each admitted role to its declared native or OCI runtime driver.</summary>
internal sealed class CompositeHostRuntimeConverger(
    IHostRuntimeConverger systemd,
    IHostRuntimeConverger? containerd) : IHostRuntimeConverger
{
    private readonly IHostRuntimeConverger systemd = systemd ?? throw new ArgumentNullException(nameof(systemd));
    private readonly IHostRuntimeConverger? containerd = containerd;

    private IHostRuntimeConverger For(HostRuntimePlan plan) => plan.Driver switch
    {
        RuntimeDriver.NativeSystemd => systemd,
        RuntimeDriver.OciContainer => containerd ?? throw new InvalidOperationException(
            "An OCI workload was admitted but no production containerd client was configured."),
        _ => throw new ArgumentOutOfRangeException(nameof(plan.Driver))
    };

    public Task ConvergeAsync(HostRuntimePlan plan, CancellationToken cancellationToken) =>
        For(plan).ConvergeAsync(plan, cancellationToken);

    public Task StopAsync(HostRuntimePlan plan, CancellationToken cancellationToken) =>
        For(plan).StopAsync(plan, cancellationToken);

    public Task<SystemdAllocationObservation> ObserveAsync(HostRuntimePlan plan, CancellationToken cancellationToken) =>
        For(plan).ObserveAsync(plan, cancellationToken);
}

/// <summary>
/// Production containerd bridge using the installed nerdctl client. The command path is
/// explicit configuration, arguments are passed without a shell, and every observation is
/// checked against the canonical plan fingerprint before host convergence can claim readiness.
/// </summary>
internal sealed class NerdctlContainerdClient : IContainerdClient
{
    private readonly string executable;

    internal NerdctlContainerdClient(string executable = "nerdctl") =>
        this.executable = string.IsNullOrWhiteSpace(executable)
            ? throw new ArgumentException("The containerd command path is required.", nameof(executable))
            : executable;

    public async Task<ContainerdAllocationObservation> ObserveAsync(
        string @namespace,
        string containerId,
        CancellationToken cancellationToken)
    {
        var result = await RunAsync(["--namespace", @namespace, "inspect", containerId], cancellationToken);
        if (result.ExitCode != 0)
        {
            // nerdctl's inspect errors are human-readable aggregate messages,
            // not a stable not-found code. Confirm absence with a successful
            // daemon listing; never interpret a socket or permissions failure
            // containing "not found" as permission to create a container.
            var listing = await RunAsync(["--namespace", @namespace, "ps", "--all", "--format", "{{.Names}}"], cancellationToken);
            EnsureSuccess(listing, "list containerd allocations");
            if (!listing.Output.Split(['\r', '\n', ','], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                    .Contains(containerId, StringComparer.Ordinal))
                return new(containerId, ContainerdAllocationState.Absent, null, null, null, null, "absent");
        }
        EnsureSuccess(result, "inspect containerd allocation");
        using var document = JsonDocument.Parse(result.Output);
        var root = document.RootElement.ValueKind == JsonValueKind.Array
            ? document.RootElement.EnumerateArray().FirstOrDefault()
            : document.RootElement;
        if (root.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null)
            return new(containerId, ContainerdAllocationState.Absent, null, null, null, null, "absent");
        var status = root.TryGetProperty("State", out var state) && state.TryGetProperty("Status", out var stateValue)
            ? stateValue.GetString()
            : root.TryGetProperty("Status", out var statusValue) ? statusValue.GetString() : null;
        var labels = root.TryGetProperty("Labels", out var rootLabels)
            ? rootLabels
            : root.TryGetProperty("Config", out var config) && config.TryGetProperty("Labels", out var labelValue)
                ? labelValue
                : default;
        var image = root.TryGetProperty("Config", out config) && config.TryGetProperty("Image", out var actualImage)
            ? actualImage.GetString()
            : root.TryGetProperty("ImageName", out var imageName) ? imageName.GetString() : null;
        var platform = labels.ValueKind == JsonValueKind.Object && labels.TryGetProperty("terrascale.platform", out var platformLabel)
            ? platformLabel.GetString()
            : root.TryGetProperty("Platform", out var platformValue) && platformValue.ValueKind == JsonValueKind.String
                ? platformValue.GetString()
                : null;
        var fingerprint = labels.ValueKind == JsonValueKind.Object && labels.TryGetProperty("terrascale.plan", out var fingerprintValue)
            ? fingerprintValue.GetString() : null;
        int? pid = root.TryGetProperty("State", out state) && state.TryGetProperty("Pid", out var pidValue) && pidValue.TryGetInt32(out var parsedPid)
            ? parsedPid : null;
        return new(containerId, ParseState(status), image, platform, fingerprint, pid, status ?? "unknown");
    }

    public async Task<string> PullAsync(string @namespace, string imageReference, string platform, CancellationToken cancellationToken)
    {
        var result = await RunAsync(["--namespace", @namespace, "pull", "--platform", platform, imageReference], cancellationToken);
        EnsureSuccess(result, "pull containerd image");
        // The requested image is digest-addressed. Returning its digest is safe only after the
        // pull command has succeeded; the adapter separately rejects any non-matching digest.
        var marker = imageReference.LastIndexOf("@sha256:", StringComparison.Ordinal);
        if (marker < 0)
            throw new InvalidOperationException("Containerd image references must be digest-addressed.");
        return imageReference[(marker + "@sha256:".Length)..];
    }

    public async Task CreateAsync(ContainerdCreateRequest request, CancellationToken cancellationToken)
    {
        var security = request.Security;
        var arguments = new List<string>
        {
            "--namespace", request.Namespace, "--cgroup-manager", "systemd", "create", "--name", request.ContainerId,
            "--platform", request.Platform, "--user", $"{security.RunAsUser}:{security.RunAsGroup}",
            "--label", $"terrascale.plan={request.PlanFingerprint}",
            "--label", $"terrascale.image={request.ImageReference}",
            "--label", $"terrascale.platform={request.Platform}",
            "--read-only", "--cap-drop", string.Join(',', security.DroppedCapabilities),
            "--security-opt", "no-new-privileges=true", "--security-opt", $"seccomp={security.SeccompProfile}",
            "--cgroup-parent", security.CgroupParent, "--memory", request.Resources.MemoryMaxBytes.ToString(CultureInfo.InvariantCulture),
            "--memory-swap", request.Resources.MemoryMaxBytes.ToString(CultureInfo.InvariantCulture),
            "--pids-limit", request.Resources.TasksMax.ToString(CultureInfo.InvariantCulture),
            "--cpus", (request.Resources.CpuQuotaPercent / 100d).ToString("F2", CultureInfo.InvariantCulture),
            request.ImageReference
        };
        var result = await RunAsync(arguments, cancellationToken);
        EnsureSuccess(result, "create containerd allocation");
    }

    public Task StartAsync(string @namespace, string containerId, CancellationToken cancellationToken) =>
        RunCheckedAsync(["--namespace", @namespace, "start", containerId], "start containerd allocation", cancellationToken);

    public Task StopAsync(string @namespace, string containerId, CancellationToken cancellationToken) =>
        RunCheckedAsync(["--namespace", @namespace, "stop", "--time", "10", containerId], "stop containerd allocation", cancellationToken);

    public Task DeleteAsync(string @namespace, string containerId, CancellationToken cancellationToken) =>
        RunCheckedAsync(["--namespace", @namespace, "rm", containerId], "delete containerd allocation", cancellationToken);

    private async Task RunCheckedAsync(IReadOnlyList<string> arguments, string operation, CancellationToken cancellationToken)
    {
        var result = await RunAsync(arguments, cancellationToken);
        EnsureSuccess(result, operation);
    }

    private async Task<CommandResult> RunAsync(IReadOnlyList<string> arguments, CancellationToken cancellationToken)
    {
        var startInfo = new ProcessStartInfo(executable)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        foreach (var argument in arguments) startInfo.ArgumentList.Add(argument);
        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("The containerd command could not be started.");
        var output = ReadBoundedAsync(process.StandardOutput, cancellationToken);
        var error = ReadBoundedAsync(process.StandardError, cancellationToken);
        try
        {
            await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            try
            {
                if (!process.HasExited) process.Kill(entireProcessTree: true);
            }
            catch (InvalidOperationException) { }
            await process.WaitForExitAsync().ConfigureAwait(false);
            throw;
        }
        return new(process.ExitCode, await output.ConfigureAwait(false), await error.ConfigureAwait(false));
    }

    private static async Task<string> ReadBoundedAsync(StreamReader reader, CancellationToken cancellationToken)
    {
        const int maximumCharacters = 64 * 1024;
        var buffer = new char[4096];
        var builder = new StringBuilder();
        while (true)
        {
            var count = await reader.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false);
            if (count == 0) return builder.ToString();
            if (builder.Length + count > maximumCharacters)
                throw new InvalidOperationException("The containerd command produced too much output.");
            builder.Append(buffer, 0, count);
        }
    }

    private static ContainerdAllocationState ParseState(string? value) => value?.ToLowerInvariant() switch
    {
        "running" => ContainerdAllocationState.Running,
        "created" => ContainerdAllocationState.Created,
        "stopped" or "exited" => ContainerdAllocationState.Stopped,
        "dead" or "failed" => ContainerdAllocationState.Failed,
        _ => ContainerdAllocationState.Failed
    };

    private static void EnsureSuccess(CommandResult result, string operation)
    {
        if (result.ExitCode != 0)
            throw new InvalidOperationException($"The containerd client could not {operation}; exit code {result.ExitCode}.");
    }

    private sealed record CommandResult(int ExitCode, string Output, string Error);
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
        if (plan.Systemd is { } systemd)
        {
            Add(hash, "systemd");
            Add(hash, systemd.UnitName);
            Add(hash, systemd.Executable);
            Add(hash, systemd.Arguments.Count.ToString(System.Globalization.CultureInfo.InvariantCulture));
            foreach (var argument in systemd.Arguments) Add(hash, argument);
            Add(hash, systemd.Properties.Count.ToString(System.Globalization.CultureInfo.InvariantCulture));
            foreach (var property in systemd.Properties) Add(hash, property);
        }
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
