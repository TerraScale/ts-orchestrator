using System.Reflection;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Options;

namespace TsOrch.Agent;

public sealed class NodeReportComposer(
    HostMetricsCollector metrics,
    PlacementTracker tracker,
    DockerEngineClient docker,
    IOptions<AgentOptions> options,
    TimeProvider timeProvider)
{
    public static string AgentVersion { get; } =
        typeof(NodeReportComposer).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
        ?? throw new InvalidOperationException("TsOrch.Agent has no informational version.");

    private readonly AgentOptions _options = options.Value;

    public async Task<Hello> ComposeHelloAsync(NodeSession session, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);
        var capacity = await metrics.ReadCapacityAsync(cancellationToken);
        var identity = session.Identity;
        return new Hello(
            session.NodeId,
            identity.Region,
            identity.PoolKind,
            identity.VcnIp,
            CurrentArch(),
            identity.Shape,
            identity.FaultDomain,
            capacity.CpuTotalMilli,
            capacity.MemTotalMiB,
            capacity.DiskTotalGiB,
            identity.Labels,
            capacity.Volumes,
            AgentVersion);
    }

    public async Task<Heartbeat> ComposeHeartbeatAsync(CancellationToken cancellationToken)
    {
        var host = await metrics.CollectHostAsync(cancellationToken);
        var listed = await docker.ListManagedContainersAsync(_options.LabelPrefix, cancellationToken);
        IReadOnlyList<ContainerMetrics> containerMetrics = listed.TryGetValue(out var containers, out _)
            ? await metrics.CollectContainersAsync(containers, cancellationToken)
            : [];
        return new Heartbeat(
            timeProvider.GetUtcNow().ToUnixTimeMilliseconds(),
            tracker.Snapshot(),
            host,
            containerMetrics,
            await metrics.ReadEdgeMetricsAsync(cancellationToken));
    }

    private static CpuArch CurrentArch() => RuntimeInformation.OSArchitecture switch
    {
        Architecture.Arm64 => CpuArch.Arm64,
        Architecture.X64 => CpuArch.X64,
        var other => throw new PlatformNotSupportedException($"ts-orch agent does not support {other}."),
    };
}
