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

    private static readonly IReadOnlyList<string> Capabilities = [AgentCapabilities.GrowVolumeId];

    public async Task<Hello> ComposeHelloAsync(NodeSession session, long volumeSeq, CancellationToken cancellationToken)
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
            AgentVersion,
            volumeSeq,
            capacity.Volumes,
            FindNetBirdIpv4(),
            Capabilities);
    }

    public async Task<Heartbeat> ComposeHeartbeatAsync(long volumeSeq, string? volumeChallenge, CancellationToken cancellationToken)
    {
        var snapshot = await metrics.CollectHostSnapshotAsync(cancellationToken);
        return new Heartbeat(
            timeProvider.GetUtcNow().ToUnixTimeMilliseconds(),
            tracker.Snapshot(),
            snapshot.Metrics,
            metrics.ContainerSnapshot(),
            volumeSeq,
            await metrics.ReadEdgeMetricsAsync(cancellationToken),
            FindNetBirdIpv4(),
            snapshot.Volumes,
            volumeChallenge);
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

public sealed class SessionVolumeReports(
    NodeReportComposer reports,
    NodeSession session,
    Func<AgentMessage, CancellationToken, Task> send) : IDisposable
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private long _volumeSeq;

    public Task SendHelloAsync(CancellationToken cancellationToken) =>
        SendAsync((volumeSeq, token) => reports.ComposeHelloAsync(session, volumeSeq, token), cancellationToken);

    public Task SendHeartbeatAsync(CancellationToken cancellationToken) =>
        SendAsync((volumeSeq, token) => reports.ComposeHeartbeatAsync(volumeSeq, null, token), cancellationToken);

    public Task SendVolumeProbeAsync(ProbeVolumes probe, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(probe);
        ArgumentException.ThrowIfNullOrWhiteSpace(probe.Challenge);
        return SendAsync((volumeSeq, token) => reports.ComposeHeartbeatAsync(volumeSeq, probe.Challenge, token), cancellationToken);
    }

    public void Dispose() => _gate.Dispose();

    private async Task SendAsync<TMessage>(Func<long, CancellationToken, Task<TMessage>> compose, CancellationToken cancellationToken)
        where TMessage : AgentMessage
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var volumeSeq = ++_volumeSeq;
            var message = await compose(volumeSeq, cancellationToken);
            await send(message, cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }
}
