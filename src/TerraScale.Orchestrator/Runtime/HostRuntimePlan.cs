using System.Text.RegularExpressions;

namespace TerraScale.Orchestrator.Runtime;

public enum HostArchitecture
{
    Arm64,
    X64
}

public sealed partial record RuntimeAllocationId
{
    public RuntimeAllocationId(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Length is < 1 or > 63 || !TokenPattern().IsMatch(value))
        {
            throw new ArgumentException("Allocation ID must be a lowercase DNS-style token.", nameof(value));
        }
        Value = value;
    }

    public string Value { get; }
    public override string ToString() => Value;

    [GeneratedRegex("^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$", RegexOptions.CultureInvariant)]
    private static partial Regex TokenPattern();
}

public sealed record ArtifactDigest
{
    public ArtifactDigest(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Length != 64 || value.Any(character =>
                character is not (>= '0' and <= '9') and not (>= 'a' and <= 'f')))
        {
            throw new ArgumentException("Artifact digest must be lowercase SHA-256 hex.", nameof(value));
        }
        Value = value;
    }

    public string Value { get; }
    public override string ToString() => Value;
}

public sealed record RuntimeResourceLimits(
    long MemoryMaxBytes,
    int TasksMax,
    int CpuQuotaPercent);

public sealed record SystemdExecutionPlan(
    string UnitName,
    string Executable,
    IReadOnlyList<string> Arguments,
    IReadOnlyList<string> Properties);

public sealed record OciSecurityPlan(
    uint RunAsUser,
    uint RunAsGroup,
    bool NoNewPrivileges,
    bool ReadOnlyRootFileSystem,
    IReadOnlyList<string> DroppedCapabilities,
    string SeccompProfile,
    string CgroupParent);

public sealed record OciExecutionPlan(
    string ContainerId,
    string ImageReference,
    string Platform,
    OciSecurityPlan Security,
    RuntimeResourceLimits Resources);

public sealed record HostRuntimePlan(
    int SchemaVersion,
    AdmittedRole Role,
    RuntimeDriver Driver,
    RuntimeAllocationId AllocationId,
    ArtifactDigest ArtifactDigest,
    HostArchitecture Architecture,
    RuntimeResourceLimits Resources,
    SystemdExecutionPlan? Systemd,
    OciExecutionPlan? Oci)
{
    public static HostRuntimePlan Create(
        AdmittedRole role,
        RuntimeDriver driver,
        RuntimeAllocationId allocationId,
        ArtifactDigest digest,
        HostArchitecture architecture)
    {
        var descriptor = AdmittedRoleCatalog.Admit(role, driver);
        var resources = RuntimeResourceLimitPolicy.For(role);
        return driver switch
        {
            RuntimeDriver.NativeSystemd => new(
                1,
                role,
                driver,
                allocationId,
                digest,
                architecture,
                resources,
                CreateSystemd(descriptor, allocationId, digest, resources),
                null),
            RuntimeDriver.OciContainer => new(
                1,
                role,
                driver,
                allocationId,
                digest,
                architecture,
                resources,
                null,
                CreateOci(descriptor, allocationId, digest, architecture, resources)),
            _ => throw new ArgumentOutOfRangeException(nameof(driver))
        };
    }

    private static SystemdExecutionPlan CreateSystemd(
        AdmittedRoleDescriptor descriptor,
        RuntimeAllocationId allocation,
        ArtifactDigest digest,
        RuntimeResourceLimits resources)
    {
        var unit = $"terrascale-{allocation}.service";
        var executable = $"/opt/terrascale/artifacts/{descriptor.ArtifactKey}/sha256-{digest}/{descriptor.ArtifactKey}";
        return new(
            unit,
            executable,
            [$"--config=/var/lib/terrascale-{allocation}/config.json"],
            [
                "Type=exec",
                "Restart=always",
                "RestartSec=5s",
                "NoNewPrivileges=yes",
                "PrivateTmp=yes",
                "ProtectSystem=strict",
                "ProtectHome=yes",
                "ProtectKernelTunables=yes",
                "ProtectKernelModules=yes",
                "ProtectControlGroups=yes",
                "RestrictSUIDSGID=yes",
                "LockPersonality=yes",
                $"StateDirectory=terrascale-{allocation}",
                $"MemoryMax={resources.MemoryMaxBytes}",
                $"TasksMax={resources.TasksMax}",
                $"CPUQuota={resources.CpuQuotaPercent}%"
            ]);
    }

    private static OciExecutionPlan CreateOci(
        AdmittedRoleDescriptor descriptor,
        RuntimeAllocationId allocation,
        ArtifactDigest digest,
        HostArchitecture architecture,
        RuntimeResourceLimits resources) =>
        new(
            $"terrascale-{allocation}",
            $"registry.terrascale.internal/terrascale/{descriptor.ArtifactKey}@sha256:{digest}",
            architecture == HostArchitecture.Arm64 ? "linux/arm64" : "linux/amd64",
            new(
                65532,
                65532,
                true,
                true,
                ["ALL"],
                "terrascale-default-v1",
                $"terrascale/{allocation}"),
            resources);
}

internal static class RuntimeResourceLimitPolicy
{
    public static RuntimeResourceLimits For(AdmittedRole role) => role switch
    {
        AdmittedRole.TerraBaseMember => new(8L * 1024 * 1024 * 1024, 2048, 400),
        AdmittedRole.ControlNatsServer or AdmittedRole.ProductNatsServer => new(2L * 1024 * 1024 * 1024, 512, 200),
        AdmittedRole.MetricsStore or AdmittedRole.Loki or AdmittedRole.Tempo => new(4L * 1024 * 1024 * 1024, 1024, 300),
        AdmittedRole.CiRunner => new(8L * 1024 * 1024 * 1024, 4096, 800),
        _ => new(1L * 1024 * 1024 * 1024, 512, 200)
    };
}
