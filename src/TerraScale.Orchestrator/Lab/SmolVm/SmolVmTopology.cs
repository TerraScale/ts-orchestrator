using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.Lab.SmolVm;

internal sealed record SmolVmResourceProfile(
    byte CpuCount,
    uint MemoryMiB,
    ulong StorageGiB,
    ulong OverlayGiB)
{
    public SmolVmResourceProfile Validate()
    {
        if (CpuCount is < 1 or > 32)
        {
            throw new ArgumentOutOfRangeException(nameof(CpuCount));
        }
        if (MemoryMiB is < 512 or > 131_072)
        {
            throw new ArgumentOutOfRangeException(nameof(MemoryMiB));
        }
        if (StorageGiB is < 4 or > 4_096 || OverlayGiB is < 1 or > 1_024)
        {
            throw new ArgumentOutOfRangeException(nameof(StorageGiB));
        }
        return this;
    }
}

internal enum SmolVmPortPurpose
{
    ControlNats,
    ProductNats,
    TerraBaseHttp,
    TerraBaseNative,
    Authentication,
    Api,
    Dashboard,
    Controller,
    OtlpGrpc,
    OtlpHttp
}

internal sealed record SmolVmPortBinding(
    SmolVmPortPurpose Purpose,
    ushort HostPort,
    ushort GuestPort);

internal sealed record SmolVmMachinePlan(
    string Name,
    string Cell,
    int SeedIndex,
    string BaseArtifactPath,
    ArtifactDigest BaseArtifactDigest,
    SmolVmResourceProfile Resources,
    IReadOnlyList<string> AllowedEgressCidrs,
    IReadOnlyList<SmolVmPortBinding> Ports);

internal sealed record SmolVmRegionsTopology(
    int SchemaVersion,
    string RunId,
    string NamespacePrefix,
    IReadOnlyList<SmolVmMachinePlan> Machines)
{
    private static readonly (SmolVmPortPurpose Purpose, ushort GuestPort)[] GuestPorts =
    [
        (SmolVmPortPurpose.ControlNats, 4222),
        (SmolVmPortPurpose.ProductNats, 5222),
        (SmolVmPortPurpose.TerraBaseHttp, 8080),
        (SmolVmPortPurpose.TerraBaseNative, 8081),
        (SmolVmPortPurpose.Authentication, 8082),
        (SmolVmPortPurpose.Api, 8083),
        (SmolVmPortPurpose.Dashboard, 8084),
        (SmolVmPortPurpose.Controller, 8085),
        (SmolVmPortPurpose.OtlpGrpc, 4317),
        (SmolVmPortPurpose.OtlpHttp, 4318)
    ];

    public static SmolVmRegionsTopology Create(
        string runId,
        string baseArtifactPath,
        ArtifactDigest baseArtifactDigest,
        SmolVmResourceProfile resources,
        IReadOnlyList<string> allowedEgressCidrs,
        ushort firstHostPort = 24_000)
    {
        ValidateRunId(runId);
        ArgumentException.ThrowIfNullOrWhiteSpace(baseArtifactPath);
        if (!Path.IsPathFullyQualified(baseArtifactPath))
        {
            throw new ArgumentException("The SmolVM base artifact path must be absolute.", nameof(baseArtifactPath));
        }
        ArgumentNullException.ThrowIfNull(allowedEgressCidrs);
        resources.Validate();
        var prefix = $"ts-{runId}";
        var machines = new List<SmolVmMachinePlan>(9);
        var ordinal = 0;
        foreach (var cell in new[] { "gru", "sfo", "fra" })
        {
            for (var seedIndex = 1; seedIndex <= 3; seedIndex++)
            {
                var portBase = firstHostPort + ordinal * 20;
                if (portBase + GuestPorts.Length - 1 > ushort.MaxValue)
                {
                    throw new ArgumentOutOfRangeException(nameof(firstHostPort));
                }
                var ports = GuestPorts.Select((port, slot) => new SmolVmPortBinding(
                        port.Purpose,
                        checked((ushort)(portBase + slot)),
                        port.GuestPort))
                    .ToArray();
                machines.Add(new(
                    $"{prefix}-{cell}-seed-{seedIndex}",
                    cell,
                    seedIndex,
                    baseArtifactPath,
                    baseArtifactDigest,
                    resources,
                    allowedEgressCidrs.ToArray(),
                    ports));
                ordinal++;
            }
        }
        var topology = new SmolVmRegionsTopology(1, runId, prefix, machines);
        topology.Validate();
        return topology;
    }

    public void Validate()
    {
        ValidateRunId(RunId);
        if (SchemaVersion != 1 || NamespacePrefix != $"ts-{RunId}" || Machines.Count != 9)
        {
            throw new InvalidOperationException("A regions-smol topology must contain exactly nine namespaced seed VMs.");
        }
        var expected = new HashSet<string>(StringComparer.Ordinal);
        foreach (var cell in new[] { "gru", "sfo", "fra" })
        {
            for (var seedIndex = 1; seedIndex <= 3; seedIndex++)
            {
                expected.Add($"{NamespacePrefix}-{cell}-seed-{seedIndex}");
            }
        }
        if (!expected.SetEquals(Machines.Select(machine => machine.Name)) ||
            Machines.Select(machine => machine.Name).Distinct(StringComparer.Ordinal).Count() != 9)
        {
            throw new InvalidOperationException("The nine seed VM identities do not match GRU/SFO/FRA R3.");
        }
        if (Machines.Any(machine =>
                machine.Cell is not ("gru" or "sfo" or "fra") ||
                machine.SeedIndex is < 1 or > 3 ||
                !machine.Name.StartsWith(NamespacePrefix + "-", StringComparison.Ordinal) ||
                machine.Ports.Count != GuestPorts.Length))
        {
            throw new InvalidOperationException("A seed VM is outside the closed regions-smol topology.");
        }
        var hostPorts = Machines.SelectMany(machine => machine.Ports).Select(port => port.HostPort).ToArray();
        if (hostPorts.Distinct().Count() != hostPorts.Length)
        {
            throw new InvalidOperationException("SmolVM host port mappings must be globally unique per run.");
        }
    }

    public bool OwnsMachineName(string name) =>
        name.StartsWith(NamespacePrefix + "-", StringComparison.Ordinal);

    public static bool IsElasticMachineName(string namespacePrefix, string name) =>
        name.StartsWith(namespacePrefix + "-", StringComparison.Ordinal) &&
        name.Contains("-elastic-", StringComparison.Ordinal);

    private static void ValidateRunId(string runId)
    {
        _ = new RuntimeAllocationId(runId);
        if (runId.Length > 24)
        {
            throw new ArgumentException("SmolVM run IDs cannot exceed 24 characters.", nameof(runId));
        }
    }
}
