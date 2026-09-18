using System.Runtime.Versioning;

namespace TerraScale.Orchestrator.Runtime;

/// <summary>
/// Read-only evidence collected from the host before a native systemd executor is
/// constructed.  A host is admitted only when every value is true.
/// </summary>
internal sealed record SystemdHostProbeResult(
    bool IsLinux,
    bool IsSystemdPid1,
    bool HasCgroupV2,
    bool HasSystemctl,
    bool HasSystemdRun)
{
    public bool IsAdmitted => IsLinux && IsSystemdPid1 && HasCgroupV2 && HasSystemctl && HasSystemdRun;
}

/// <summary>Read-only host capability probe used by production systemd admission.</summary>
internal interface ISystemdHostProbe
{
    SystemdHostProbeResult Probe();
}

/// <summary>
/// Production host probe.  It reads kernel/proc filesystem state and fixed binary
/// paths only; it never invokes a shell, systemctl, systemd-run, or another process.
/// </summary>
internal sealed class LinuxSystemdHostProbe : ISystemdHostProbe
{
    internal const string SystemdPid1CommPath = "/proc/1/comm";
    internal const string CgroupV2ControllersPath = "/sys/fs/cgroup/cgroup.controllers";
    internal const string SystemctlPath = "/usr/bin/systemctl";
    internal const string SystemdRunPath = "/usr/bin/systemd-run";

    public SystemdHostProbeResult Probe()
    {
        var isLinux = OperatingSystem.IsLinux();
        if (!isLinux)
        {
            return new(false, false, false, false, false);
        }

        return new(
            IsLinux: true,
            IsSystemdPid1: ReadSystemdPid1(),
            HasCgroupV2: IsReadableRegularFile(CgroupV2ControllersPath),
            HasSystemctl: IsExecutableRegularFile(SystemctlPath),
            HasSystemdRun: IsExecutableRegularFile(SystemdRunPath));
    }

    private static bool ReadSystemdPid1()
    {
        try
        {
            return string.Equals(
                File.ReadAllText(SystemdPid1CommPath).Trim(),
                "systemd",
                StringComparison.Ordinal);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static bool IsReadableRegularFile(string path)
    {
        try
        {
            var info = new FileInfo(path);
            return info.Exists && !info.Attributes.HasFlag(FileAttributes.Directory);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    [SupportedOSPlatform("linux")]
    private static bool IsExecutableRegularFile(string path)
    {
        if (!IsReadableRegularFile(path))
        {
            return false;
        }

        try
        {
            var mode = File.GetUnixFileMode(path);
            const UnixFileMode executeBits = UnixFileMode.UserExecute |
                UnixFileMode.GroupExecute |
                UnixFileMode.OtherExecute;
            return (mode & executeBits) != 0;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }
}

/// <summary>
/// Fail-closed native-systemd admission and adapter-composition primitive.
///
/// This primitive is intentionally not wired to <c>Program</c> or to a production
/// lifecycle coordinator. A future coordinator must supply a plan that has already
/// passed the persisted RuntimeDecisionEngine and operation-authorization workflow.
/// This boundary performs only host/runtime admission and canonical-plan fencing;
/// it does not authorize operations, provide operation-journal/idempotency/recovery
/// semantics, parse CLI input, or expose a production mutation route on its own.
/// </summary>
internal sealed class NativeSystemdRuntimeAdmission
{
    private readonly HostRuntimePlan plan;
    private readonly SystemdHostRuntimeAdapter adapter;

    private NativeSystemdRuntimeAdmission(
        HostRuntimePlan plan,
        SystemdHostRuntimeAdapter adapter)
    {
        this.plan = plan;
        this.adapter = adapter;
    }

    /// <summary>
    /// Admits a canonical native-systemd plan and composes the normal process
    /// runner with the system manager (not the per-user manager). No current
    /// production lifecycle path calls this method.
    /// </summary>
    public static NativeSystemdRuntimeAdmission Create(HostRuntimePlan plan) =>
        Create(plan, new LinuxSystemdHostProbe(), commandRunner: null);

    /// <summary>
    /// Injectable admission/composition seam for deterministic and zero-execution
    /// tests. A future persisted-authorized coordinator may use the production
    /// overload after its operation boundary is implemented.
    /// </summary>
    internal static NativeSystemdRuntimeAdmission Create(
        HostRuntimePlan plan,
        ISystemdHostProbe hostProbe,
        IHostCommandRunner? commandRunner = null)
    {
        var canonicalPlan = RequireCanonicalNativePlan(plan);
        ArgumentNullException.ThrowIfNull(hostProbe);

        SystemdHostProbeResult hostEvidence;
        try
        {
            hostEvidence = hostProbe.Probe();
        }
        catch (Exception exception)
        {
            throw new InvalidOperationException(
                "Native systemd host admission could not be established.",
                exception);
        }

        if (hostEvidence is null || !hostEvidence.IsAdmitted)
        {
            throw new InvalidOperationException(
                "Native systemd host admission requires Linux, systemd as PID 1, cgroup v2, " +
                "and executable /usr/bin/systemctl and /usr/bin/systemd-run.");
        }

        // Keep executor construction after both read-only host admission and the
        // complete plan fence. This adapter remains unwired until a persisted
        // authorized runtime coordinator owns the operation boundary.
        var runtimeAdapter = new SystemdHostRuntimeAdapter(
            commandRunner ?? new ProcessHostCommandRunner(),
            userManager: false);
        return new(canonicalPlan, runtimeAdapter);
    }

    /// <summary>Returns the immutable canonical snapshot admitted at composition time.</summary>
    internal HostRuntimePlan Plan => plan;

    public Task ConvergeAsync(CancellationToken cancellationToken) =>
        adapter.ConvergeAsync(plan, cancellationToken);

    public Task<SystemdAllocationObservation> ObserveAsync(CancellationToken cancellationToken) =>
        adapter.ObserveAsync(plan, cancellationToken);

    public Task StopAsync(CancellationToken cancellationToken) =>
        adapter.StopAsync(plan, cancellationToken);

    private static HostRuntimePlan RequireCanonicalNativePlan(HostRuntimePlan candidate)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        if (candidate.SchemaVersion != 2)
        {
            throw new InvalidOperationException("The host runtime plan schema is not supported.");
        }
        if (!Enum.IsDefined(candidate.Role))
        {
            throw new InvalidOperationException("The host runtime plan role is not admitted.");
        }
        if (!Enum.IsDefined(candidate.Driver) || candidate.Driver != RuntimeDriver.NativeSystemd)
        {
            throw new InvalidOperationException("Native systemd admission requires a native systemd plan.");
        }
        if (!Enum.IsDefined(candidate.Architecture))
        {
            throw new InvalidOperationException("The host runtime plan architecture is not admitted.");
        }
        if (candidate.AllocationId is null || candidate.ArtifactDigest is null || candidate.Resources is null ||
            candidate.Systemd is null || candidate.Oci is not null)
        {
            throw new InvalidOperationException("The host runtime plan is incomplete.");
        }

        // This closes the role boundary before any executor exists.  In
        // particular, OCI-only roles cannot be converted to a native plan by a
        // caller changing only the driver or nested execution object.
        AdmittedRoleCatalog.Admit(candidate.Role, RuntimeDriver.NativeSystemd);

        HostRuntimePlan expected;
        try
        {
            expected = HostRuntimePlan.Create(
                candidate.Role,
                RuntimeDriver.NativeSystemd,
                candidate.AllocationId,
                candidate.ArtifactDigest,
                candidate.Architecture,
                candidate.Resources,
                // The immutable digest layout root is a deployment parameter: reconstruct the
                // canonical plan under the candidate's own root so admission compares like for
                // like instead of pinning every host to the /opt default. The credential flag
                // travels in the plan itself (the LoadCredentialEncrypted property), so the
                // reconstruction reproduces whatever the candidate carries.
                InstallRootOf(candidate.Systemd),
                HasEncryptedCredentials(candidate.Systemd),
                StateRootOf(candidate.Systemd));
        }
        catch (Exception exception)
        {
            throw new InvalidOperationException(
                "The host runtime plan could not be reconstructed from the closed catalog.",
                exception);
        }

        if (candidate.Systemd is not { } actualSystemd || expected.Systemd is not { } expectedSystemd)
        {
            throw new InvalidOperationException("The systemd execution plan is incomplete.");
        }
        if (candidate.SchemaVersion != expected.SchemaVersion ||
            candidate.Role != expected.Role ||
            candidate.Driver != expected.Driver ||
            candidate.AllocationId.Value != expected.AllocationId.Value ||
            candidate.ArtifactDigest.Value != expected.ArtifactDigest.Value ||
            candidate.Architecture != expected.Architecture ||
            candidate.Resources != expected.Resources ||
            !string.Equals(actualSystemd.UnitName, expectedSystemd.UnitName, StringComparison.Ordinal) ||
            !string.Equals(actualSystemd.Executable, expectedSystemd.Executable, StringComparison.Ordinal) ||
            !actualSystemd.Arguments.SequenceEqual(expectedSystemd.Arguments, StringComparer.Ordinal) ||
            !actualSystemd.Properties.SequenceEqual(expectedSystemd.Properties, StringComparer.Ordinal))
        {
            throw new InvalidOperationException(
                "The systemd execution plan is not canonical for the admitted role, allocation, or digest.");
        }

        return expected;
    }

    private static bool HasEncryptedCredentials(SystemdExecutionPlan? systemd) =>
        systemd?.Properties.Any(static value =>
            value.StartsWith("LoadCredentialEncrypted=", StringComparison.Ordinal)) ?? false;

    /// <summary>The state layout root the plan's absolute EnvironmentFile/Environment paths live under.</summary>
    private static string? StateRootOf(SystemdExecutionPlan? systemd)
    {
        if (systemd?.Properties.FirstOrDefault(static value =>
                value.StartsWith("EnvironmentFile=-", StringComparison.Ordinal)) is not { } environmentFile)
            return null;
        // EnvironmentFile=-{root}/terrascale-{allocation}/environment
        var path = environmentFile["EnvironmentFile=-".Length..];
        var allocationDirectory = Path.GetDirectoryName(path);
        return allocationDirectory is null ? null : Path.GetDirectoryName(allocationDirectory);
    }

    /// <summary>
    /// The digest layout root of one executable path <c>{root}/{artifactKey}/sha256-{digest}/{artifactKey}</c>.
    /// </summary>
    private static string? InstallRootOf(SystemdExecutionPlan? systemd)
    {
        if (systemd?.Executable is not { } executable)
            return null;
        var digestDirectory = Path.GetDirectoryName(executable);
        var keyDirectory = digestDirectory is null ? null : Path.GetDirectoryName(digestDirectory);
        return keyDirectory is null ? null : Path.GetDirectoryName(keyDirectory);
    }
}

