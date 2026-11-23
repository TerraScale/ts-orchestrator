using System.Reflection;
using System.Runtime.InteropServices;

namespace TsOrch.Agent;

public sealed class NodeReportComposer(
    HostMetricsCollector metrics,
    PlacementTracker tracker,
    DockerEngineClient docker,
    AgentOptions options,
    TimeProvider timeProvider)
{
    public static string AgentVersion { get; } =
        typeof(NodeReportComposer).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
        ?? throw new InvalidOperationException("TsOrch.Agent has no informational version.");

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
        var containerMetrics = await docker.ListManagedContainersAsync(options.LabelPrefix, cancellationToken) switch
        {
            IReadOnlyList<ManagedContainer> containers => await metrics.CollectContainersAsync(containers, cancellationToken),
            Unavailable => [],
            InternalFailure => [],
        };
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
