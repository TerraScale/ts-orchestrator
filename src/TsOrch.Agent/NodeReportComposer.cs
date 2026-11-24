using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;

namespace TsOrch.Agent;

public sealed class NodeReportComposer(
    HostMetricsCollector metrics,
    PlacementTracker tracker,
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
            AgentVersion,
            FindNetBirdIpv4());
    }

    public async Task<Heartbeat> ComposeHeartbeatAsync(CancellationToken cancellationToken)
    {
        var host = await metrics.CollectHostAsync(cancellationToken);
        var volumes = await metrics.ReadVolumesAsync(cancellationToken);
        return new Heartbeat(
            timeProvider.GetUtcNow().ToUnixTimeMilliseconds(),
            tracker.Snapshot(),
            host,
            metrics.ContainerSnapshot(),
            await metrics.ReadEdgeMetricsAsync(cancellationToken),
            FindNetBirdIpv4(),
            volumes);
    }

    public static string? FindNetBirdIpv4()
    {
        try
        {
            foreach (var iface in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (!string.Equals(iface.Name, "wt0", StringComparison.Ordinal))
                {
                    continue;
                }

                foreach (var unicast in iface.GetIPProperties().UnicastAddresses)
                {
                    if (unicast.Address.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(unicast.Address))
                    {
                        return unicast.Address.ToString();
                    }
                }
            }
        }
        catch (NetworkInformationException)
        {
        }

        return null;
    }

    private static CpuArch CurrentArch() => RuntimeInformation.OSArchitecture switch
    {
        Architecture.Arm64 => CpuArch.Arm64,
        Architecture.X64 => CpuArch.X64,
        var other => throw new PlatformNotSupportedException($"ts-orch agent does not support {other}."),
    };
}
