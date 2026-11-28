using System.Collections.Concurrent;
using System.Globalization;
using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Win32.SafeHandles;

namespace TsOrch.Agent;

public sealed record class NodeCapacity(int CpuTotalMilli, int MemTotalMiB, int DiskTotalGiB, IReadOnlyList<VolumeInfo>? Volumes);

public sealed record class HostMetricsSnapshot(HostMetrics Metrics, IReadOnlyList<VolumeInfo>? Volumes);

public readonly record struct VolumeReading(IReadOnlyList<VolumeInfo>? Volumes, double? MeasuredDataUsedPct, int? MeasuredDataTotalGiB);

public sealed class HostMetricsCollector(
    DockerEngineClient docker,
    AgentOptions options,
    TimeProvider timeProvider,
    ILogger<HostMetricsCollector> logger) : BackgroundService
{
    private static readonly TimeSpan OomReconnectDelay = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan StatsPollInterval = TimeSpan.FromSeconds(5);
    private const double BytesPerMiB = 1024d * 1024d;
    private const double BytesPerGiB = BytesPerMiB * 1024d;
    private const int MaxParallelStats = 4;

    private readonly Lock _gate = new();
    private readonly ConcurrentDictionary<string, ContainerSample> _containerSamples = [with(StringComparer.Ordinal)];
    private readonly ConcurrentDictionary<string, (string Service, int Count)> _oomKills = new(StringComparer.Ordinal);
    private IReadOnlyList<ContainerMetrics> _latestContainers = [];
    private CpuSample? _lastCpu;
    private NetSample? _lastNet;

    protected override Task ExecuteAsync(CancellationToken stoppingToken) =>
        Task.WhenAll(WatchOomsAsync(stoppingToken), SampleContainersAsync(stoppingToken));

    public void ForgetPlacement(string placementId) => _oomKills.TryRemove(placementId, out _);

    public IReadOnlyList<ContainerMetrics> ContainerSnapshot()
    {
        var samples = Volatile.Read(ref _latestContainers)
            .ToDictionary(static sample => sample.PlacementId, StringComparer.Ordinal);
        foreach (var (placementId, oom) in _oomKills)
        {
            samples[placementId] = samples.TryGetValue(placementId, out var sample)
                ? sample with { OomKills = oom.Count }
                : new ContainerMetrics(placementId, oom.Service, 0, 0, 0, 0, 0, 0, 0, oom.Count);
        }

        return [.. samples.Values.OrderBy(static sample => sample.PlacementId, StringComparer.Ordinal)];
    }

    private async Task WatchOomsAsync(CancellationToken cancellationToken)
    {
        const long nanosecondsPerSecond = 1_000_000_000;
        var cursor = timeProvider.GetUtcNow().ToUnixTimeSeconds() * nanosecondsPerSecond;
        HashSet<string> seenAtCursor = [with(StringComparer.Ordinal)];
        while (!cancellationToken.IsCancellationRequested)
        {
            var interrupted = await docker.WatchOomEventsAsync(cursor / nanosecondsPerSecond, oom =>
            {
                if (oom.TimeNano < cursor || oom.Actor?.Attributes is not { } labels
                    || labels.GetValueOrDefault(ContainerLabels.Managed(options.LabelPrefix)) != "true"
                    || !labels.TryGetValue(ContainerLabels.PlacementId(options.LabelPrefix), out var placementId)
                    || !labels.TryGetValue(ContainerLabels.Service(options.LabelPrefix), out var service))
                {
                    return;
                }

                if (oom.TimeNano > cursor)
                {
                    cursor = oom.TimeNano;
                    seenAtCursor.Clear();
                }

                if (seenAtCursor.Add(oom.Actor.ID))
                {
                    _oomKills.AddOrUpdate(placementId, static (_, name) => (name, 1),
                        static (_, current, _) => (current.Service, current.Count + 1), service);
                }
            }, cancellationToken);
            if (interrupted is not null)
            {
                AgentLog.OomSubscriptionInterrupted(logger, interrupted);
                await Task.Delay(OomReconnectDelay, timeProvider, cancellationToken);
            }
        }
    }

    private async Task SampleContainersAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(StatsPollInterval, timeProvider);
        do
        {
            var listed = await docker.ListManagedContainersAsync(options.LabelPrefix, cancellationToken);
            var samples = listed switch
            {
                IReadOnlyList<ManagedContainer> containers => await CollectContainersAsync(containers, cancellationToken),
                DockerDaemonUnavailable failure => ReportListFailure(failure.Message),
                DockerResponseInvalid failure => ReportListFailure(failure.Message),
            };
            Volatile.Write(ref _latestContainers, samples);
        }
        while (await timer.WaitForNextTickAsync(cancellationToken));
    }

    private IReadOnlyList<ContainerMetrics> ReportListFailure(string reason)
    {
        AgentLog.ReconcileListFailed(logger, reason);
        return [];
    }

    public async Task<HostMetricsSnapshot> CollectHostSnapshotAsync(CancellationToken cancellationToken)
    {
        var now = timeProvider.GetUtcNow();
        var cpu = await ReadCpuSampleAsync(cancellationToken);
        var memory = await ReadMemInfoAsync(cancellationToken);
        var net = await ReadNetSampleAsync(now, cancellationToken);
        double cpuPct;
        long rxBps;
        long txBps;
        lock (_gate)
        {
            cpuPct = cpu is not null && _lastCpu is { } previousCpu && cpu.Total > previousCpu.Total
                ? Math.Clamp(100d * (1d - ((double)(cpu.Idle - previousCpu.Idle) / (cpu.Total - previousCpu.Total))), 0d, 100d)
                : 0d;
            _lastCpu = cpu ?? _lastCpu;
            (rxBps, txBps) = net is not null && _lastNet is { } previousNet && net.At > previousNet.At
                ? (PerSecond(net.Rx - previousNet.Rx, net.At - previousNet.At), PerSecond(net.Tx - previousNet.Tx, net.At - previousNet.At))
                : (0L, 0L);
            _lastNet = net ?? _lastNet;
        }

        var reading = ReadVolumes();
        var rootPct = DiskUsedPct("/");
        var diskPct = reading.MeasuredDataUsedPct is { } dataPct ? Math.Max(rootPct, dataPct) : rootPct;
        var host = new HostMetrics(
            now.ToUnixTimeMilliseconds(),
            Math.Round(cpuPct, 2),
            await ReadPressureAsync("/proc/pressure/cpu", cancellationToken),
            (int)(memory.TotalKiB / 1024),
            (int)((memory.TotalKiB - memory.AvailableKiB) / 1024),
            await ReadPressureAsync("/proc/pressure/memory", cancellationToken),
            await ReadPressureAsync("/proc/pressure/io", cancellationToken),
            Math.Round(diskPct, 2),
            rxBps,
            txBps,
            await ReadLoad1Async(cancellationToken));
        return new HostMetricsSnapshot(host, reading.Volumes);
    }

    private async Task<IReadOnlyList<ContainerMetrics>> CollectContainersAsync(IReadOnlyList<ManagedContainer> containers, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(containers);
        var placements = containers.Select(static container => container.PlacementId).ToHashSet(StringComparer.Ordinal);
        foreach (var stale in _oomKills.Keys.Where(id => !placements.Contains(id)))
        {
            _oomKills.TryRemove(stale, out _);
        }

        var running = containers.Where(static container => container.Running).ToList();
        ConcurrentBag<ContainerMetrics> collected = [];
        await Parallel.ForEachAsync(
            running,
            new ParallelOptions { MaxDegreeOfParallelism = MaxParallelStats, CancellationToken = cancellationToken },
            async (container, token) =>
            {
                if (await CollectContainerAsync(container, token) is { } metrics)
                {
                    collected.Add(metrics);
                }
            });

        var live = running.Select(static container => container.Id).ToHashSet(StringComparer.Ordinal);
        foreach (var stale in _containerSamples.Keys.Where(id => !live.Contains(id)))
        {
            _containerSamples.TryRemove(stale, out _);
        }

        return [.. collected.GroupBy(static metrics => metrics.PlacementId, StringComparer.Ordinal).Select(static group => group.First())];
    }

    public async Task<EdgeMetricsSnapshot?> ReadEdgeMetricsAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(options.EdgeMetricsFile))
        {
            return null;
        }

        try
        {
            await using var stream = File.OpenRead(options.EdgeMetricsFile);
            return await JsonSerializer.DeserializeAsync(stream, EdgeJsonContext.Default.EdgeMetricsSnapshot, cancellationToken);
        }
        catch (Exception exception) when (exception is JsonException or IOException)
        {
            AgentLog.EdgeMetricsUnreadable(logger, options.EdgeMetricsFile, exception.Message);
            return null;
        }
    }

    public VolumeReading ReadVolumes()
    {
        if (string.IsNullOrWhiteSpace(options.DataVolumePath))
        {
            return new VolumeReading([], null, null);
        }

        var normalizedDataPath = Path.GetFullPath(options.DataVolumePath).TrimEnd('/');
        var statPath = normalizedDataPath.Length == 0 ? "/" : normalizedDataPath;
        if (!OperatingSystem.IsLinux())
        {
            if (!Directory.Exists(statPath) || string.Equals(normalizedDataPath, NodePaths.DataVolume, StringComparison.Ordinal))
            {
                return new VolumeReading([], null, null);
            }

            var drive = new DriveInfo(statPath);
            var usedPct = drive.TotalSize <= 0
                ? 0d
                : 100d * (drive.TotalSize - drive.AvailableFreeSpace) / drive.TotalSize;
            return new VolumeReading(
                [
                    new VolumeInfo(
                        statPath,
                        "unknown",
                        (int)Math.Round(drive.TotalSize / BytesPerGiB),
                        Math.Round(usedPct, 2)),
                ],
                usedPct,
                (int)Math.Round(drive.TotalSize / BytesPerGiB));
        }

        var opened = MountTable.OpenDirectoryReadOnly(statPath);
        return opened switch
        {
            SafeFileHandle directoryHandle => ReadLinuxVolumes(directoryHandle, normalizedDataPath, statPath),
            DirectoryMissing => new VolumeReading([], null, null),
            DirectoryOpenFailed failed => new VolumeReading(ReportVolumeProbeFailed(statPath, failed.Message), null, null),
        };
    }

    private VolumeReading ReadLinuxVolumes(SafeFileHandle directoryHandle, string normalizedDataPath, string statPath)
    {
        using (directoryHandle)
        {
            if (MountTable.TryReadDirectoryMountSnapshot(directoryHandle) is not { } snapshot)
            {
                return new VolumeReading(
                    ReportVolumeProbeFailed(statPath, $"Inspecting mount metadata and filesystem usage for {statPath} failed."),
                    null,
                    null);
            }

            var read = MountTable.TryRead();
            var volumes = read switch
            {
                IReadOnlyList<MountEntry> mounts => ResolveVolumes(mounts, normalizedDataPath, statPath, snapshot),
                MountTableReadFailed failed => ReportMountTableReadFailed(failed.Message),
            };
            return new VolumeReading(volumes, snapshot.UsedPct, (int)Math.Round(snapshot.TotalBytes / BytesPerGiB));
        }
    }

    private IReadOnlyList<VolumeInfo>? ResolveVolumes(
        IReadOnlyList<MountEntry> mounts,
        string normalizedDataPath,
        string statPath,
        DirectoryMountSnapshot snapshot)
    {
        return MountTable.ResolveDedicatedBlockMount(mounts, statPath, snapshot.Identity) switch
        {
            DedicatedBlockMount dedicatedMount => ResolveDedicatedVolumes(dedicatedMount, statPath, snapshot),
            DedicatedBlockMountInconsistent inconsistent => ReportVolumeProbeFailed(statPath, inconsistent.Message),
            DedicatedBlockMountMissing => ResolveNonDedicatedVolumes(mounts, normalizedDataPath, statPath, snapshot),
        };
    }

    private IReadOnlyList<VolumeInfo>? ResolveDedicatedVolumes(
        DedicatedBlockMount dedicatedMount,
        string statPath,
        DirectoryMountSnapshot snapshot)
    {
        return MountTable.ResolveVerifiedBlockNodes(dedicatedMount) switch
        {
            VerifiedBlockNodes verifiedNodes => ResolveVerifiedVolume(dedicatedMount, verifiedNodes, statPath, snapshot),
            BlockNodeValidationRejected rejected => ReportVolumeProbeFailed(statPath, rejected.Message),
            BlockNodeValidationFailed failed => ReportVolumeProbeFailed(statPath, failed.Message),
        };
    }

    private IReadOnlyList<VolumeInfo>? ResolveVerifiedVolume(
        DedicatedBlockMount dedicatedMount,
        VerifiedBlockNodes verifiedNodes,
        string statPath,
        DirectoryMountSnapshot snapshot)
    {
        if (!MountTable.IsGrowableFilesystem(dedicatedMount.Mount.FileSystem) || dedicatedMount.Mount.IsReadOnly)
        {
            return ResolveOciVolume(dedicatedMount, verifiedNodes, statPath, snapshot, identity: null, DirectorySnapshots.Empty);
        }

        var outcome = MountTable.ReadUsableVolumeIdentity(verifiedNodes);
        return outcome switch
        {
            UsableVolumeIdentity usable => ResolveOciVolume(dedicatedMount, verifiedNodes, statPath, snapshot, usable.Identity, usable.Snapshots),
            NoUsableVolumeIdentity none => ResolveOciVolume(dedicatedMount, verifiedNodes, statPath, snapshot, identity: null, none.Snapshots),
            DirectoryScanFailed failed => ReportVolumeProbeFailed(statPath, failed.Message),
        };
    }

    private IReadOnlyList<VolumeInfo>? ResolveOciVolume(
        DedicatedBlockMount dedicatedMount,
        VerifiedBlockNodes verifiedNodes,
        string statPath,
        DirectoryMountSnapshot snapshot,
        string? identity,
        DirectorySnapshots directories)
    {
        return MountTable.FindOciDevice(verifiedNodes) switch
        {
            OciDeviceFound found =>
                BuildVerifiedVolume(dedicatedMount, verifiedNodes, statPath, snapshot, found.Path, identity, directories.Concat(found.Snapshots)),
            OciDeviceAbsent absent =>
                BuildVerifiedVolume(dedicatedMount, verifiedNodes, statPath, snapshot, verifiedNodes.DiskPath, identity, directories.Concat(absent.Snapshots)),
            DirectoryScanFailed failed => ReportVolumeProbeFailed(statPath, failed.Message),
        };
    }

    private IReadOnlyList<VolumeInfo>? BuildVerifiedVolume(
        DedicatedBlockMount dedicatedMount,
        VerifiedBlockNodes verifiedNodes,
        string statPath,
        DirectoryMountSnapshot snapshot,
        string device,
        string? identity,
        DirectorySnapshots directories)
    {
        if (MountTable.FindChangedVolumeBinding(dedicatedMount, verifiedNodes, statPath, directories) is { } changed)
        {
            return ReportVolumeProbeFailed(statPath, changed);
        }

        return
        [
            new VolumeInfo(
                statPath,
                device,
                (int)Math.Round(snapshot.TotalBytes / BytesPerGiB),
                Math.Round(snapshot.UsedPct, 2),
                identity),
        ];
    }

    private static IReadOnlyList<VolumeInfo> ResolveNonDedicatedVolumes(
        IReadOnlyList<MountEntry> mounts,
        string normalizedDataPath,
        string statPath,
        DirectoryMountSnapshot snapshot)
    {
        if (string.Equals(normalizedDataPath, NodePaths.DataVolume, StringComparison.Ordinal))
        {
            return [];
        }

        var pathIdentity = snapshot.Identity;
        var mount = pathIdentity.MountId is { } mountId ? MountTable.FindContaining(mounts, mountId) : null;
        var mountedBlockDevice = mount is { MajorMinor: { } majorMinor }
            && string.Equals(pathIdentity.MajorMinor, majorMinor, StringComparison.Ordinal)
            ? MountTable.TryResolveBlockDevice(majorMinor)
            : null;
        var device = mountedBlockDevice
            ?? (mount is null || mount.Device.StartsWith("/dev/", StringComparison.Ordinal) ? "unknown" : mount.Device);
        return
        [
            new VolumeInfo(
                statPath,
                device,
                (int)Math.Round(snapshot.TotalBytes / BytesPerGiB),
                Math.Round(snapshot.UsedPct, 2)),
        ];
    }

    private IReadOnlyList<VolumeInfo>? ReportVolumeProbeFailed(string path, string reason)
    {
        AgentLog.VolumeProbeFailed(logger, path, reason);
        return null;
    }

    private IReadOnlyList<VolumeInfo>? ReportMountTableReadFailed(string reason)
    {
        AgentLog.MountTableReadFailed(logger, reason);
        return null;
    }

    public async Task<NodeCapacity> ReadCapacityAsync(CancellationToken cancellationToken)
    {
        var memory = await ReadMemInfoAsync(cancellationToken);
        var reading = ReadVolumes();
        var volumes = reading.Volumes;
        var diskTotalGiB = volumes is { Count: > 0 }
            ? volumes[0].SizeGiB
            : reading.MeasuredDataTotalGiB ?? (int)Math.Round(new DriveInfo("/").TotalSize / BytesPerGiB);
        return new NodeCapacity(
            Environment.ProcessorCount * 1000,
            (int)(memory.TotalKiB / 1024),
            diskTotalGiB,
            volumes);
    }

    private async Task<ContainerMetrics?> CollectContainerAsync(ManagedContainer container, CancellationToken cancellationToken)
    {
        var read = await docker.GetContainerStatsAsync(container.Id, cancellationToken);
        return read switch
        {
            ContainerStatsSample stats => await MeasureAsync(container, stats, cancellationToken),
            DockerResourceMissing failure => StatsUnavailable(container, failure.Message),
            DockerDaemonUnavailable failure => StatsUnavailable(container, failure.Message),
            DockerResponseInvalid failure => StatsUnavailable(container, failure.Message),
        };
    }

    private async Task<ContainerMetrics> MeasureAsync(ManagedContainer container, ContainerStatsSample stats, CancellationToken cancellationToken)
    {
        var inspected = await docker.InspectContainerAsync(container.Id, cancellationToken);
        var restarts = inspected switch
        {
            ContainerState state => state.RestartCount,
            DockerResourceMissing or DockerDaemonUnavailable or DockerResponseInvalid => 0,
        };
        return Measure(container, stats, restarts);
    }

    private ContainerMetrics? StatsUnavailable(ManagedContainer container, string reason)
    {
        AgentLog.ContainerStatsUnavailable(logger, container.Id, reason);
        return null;
    }

    private ContainerMetrics Measure(ManagedContainer container, ContainerStatsSample stats, int restarts)
    {
        var now = timeProvider.GetUtcNow();
        var sample = new ContainerSample(now, stats);
        double cpuPct = 0;
        long rxBps = 0;
        long txBps = 0;
        if (_containerSamples.TryGetValue(container.Id, out var previous) && now > previous.At)
        {
            var cpuDelta = stats.CpuTotalNanos - previous.Stats.CpuTotalNanos;
            var systemDelta = stats.SystemCpuNanos - previous.Stats.SystemCpuNanos;
            cpuPct = cpuDelta > 0 && systemDelta > 0 ? 100d * cpuDelta / systemDelta * Math.Max(1, stats.OnlineCpus) : 0d;
            rxBps = PerSecond(stats.RxBytes - previous.Stats.RxBytes, now - previous.At);
            txBps = PerSecond(stats.TxBytes - previous.Stats.TxBytes, now - previous.At);
        }

        _containerSamples[container.Id] = sample;
        return new ContainerMetrics(
            container.PlacementId,
            container.ServiceName,
            Math.Round(cpuPct, 2),
            (int)(stats.MemUsageBytes / BytesPerMiB),
            (int)(stats.MemLimitBytes / BytesPerMiB),
            (int)stats.Pids,
            rxBps,
            txBps,
            restarts,
            OomKills: 0);
    }

    private static long PerSecond(long delta, TimeSpan elapsed) =>
        delta <= 0 || elapsed <= TimeSpan.Zero ? 0 : (long)(delta / elapsed.TotalSeconds);

    private static double DiskUsedPct(string path)
    {
        if (!Directory.Exists(path))
        {
            return 0;
        }

        var drive = new DriveInfo(path);
        return drive.TotalSize <= 0 ? 0 : 100d * (drive.TotalSize - drive.AvailableFreeSpace) / drive.TotalSize;
    }

    private static async Task<string?> ReadProcFileAsync(string path, CancellationToken cancellationToken)
    {
        try
        {
            return await File.ReadAllTextAsync(path, cancellationToken);
        }
        catch (Exception exception) when (exception is FileNotFoundException or DirectoryNotFoundException or UnauthorizedAccessException or IOException)
        {
            return null;
        }
    }

    private static async Task<CpuSample?> ReadCpuSampleAsync(CancellationToken cancellationToken)
    {
        if (await ReadProcFileAsync("/proc/stat", cancellationToken) is not { } text)
        {
            return null;
        }

        var line = text.AsSpan()[..Math.Max(0, text.IndexOf('\n', StringComparison.Ordinal))];
        if (!line.StartsWith("cpu "))
        {
            return null;
        }

        long total = 0;
        long idle = 0;
        var index = 0;
        foreach (var range in line[4..].Split(' '))
        {
            var field = line[4..][range];
            if (field.IsEmpty)
            {
                continue;
            }

            if (index < 8 && long.TryParse(field, NumberStyles.None, CultureInfo.InvariantCulture, out var value))
            {
                total += value;
                if (index is 3 or 4)
                {
                    idle += value;
                }
            }

            index++;
        }

        return new CpuSample(total, idle);
    }

    private static async Task<MemorySample> ReadMemInfoAsync(CancellationToken cancellationToken)
    {
        if (await ReadProcFileAsync("/proc/meminfo", cancellationToken) is not { } text)
        {
            return new MemorySample(0, 0);
        }

        long total = 0;
        long available = 0;
        foreach (var line in text.Split('\n'))
        {
            if (line.StartsWith("MemTotal:", StringComparison.Ordinal))
            {
                total = ParseKiB(line);
            }
            else if (line.StartsWith("MemAvailable:", StringComparison.Ordinal))
            {
                available = ParseKiB(line);
            }
        }

        return new MemorySample(total, available);
    }

    private static long ParseKiB(string line)
    {
        var fields = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        return fields.Length >= 2 && long.TryParse(fields[1], NumberStyles.None, CultureInfo.InvariantCulture, out var value) ? value : 0;
    }

    private static async Task<double> ReadPressureAsync(string path, CancellationToken cancellationToken)
    {
        if (await ReadProcFileAsync(path, cancellationToken) is not { } text)
        {
            return 0;
        }

        foreach (var line in text.Split('\n'))
        {
            if (!line.StartsWith("some ", StringComparison.Ordinal))
            {
                continue;
            }

            foreach (var field in line.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                if (field.StartsWith("avg10=", StringComparison.Ordinal)
                    && double.TryParse(field.AsSpan(6), NumberStyles.Float, CultureInfo.InvariantCulture, out var value))
                {
                    return value;
                }
            }
        }

        return 0;
    }

    private static async Task<double> ReadLoad1Async(CancellationToken cancellationToken)
    {
        if (await ReadProcFileAsync("/proc/loadavg", cancellationToken) is not { } text)
        {
            return 0;
        }

        var space = text.IndexOf(' ', StringComparison.Ordinal);
        return space > 0 && double.TryParse(text.AsSpan(0, space), NumberStyles.Float, CultureInfo.InvariantCulture, out var load) ? load : 0;
    }

    private static async Task<NetSample?> ReadNetSampleAsync(DateTimeOffset now, CancellationToken cancellationToken)
    {
        if (await ReadProcFileAsync("/proc/net/dev", cancellationToken) is not { } text)
        {
            return null;
        }

        long rx = 0;
        long tx = 0;
        foreach (var line in text.Split('\n'))
        {
            var colon = line.IndexOf(':', StringComparison.Ordinal);
            if (colon < 0)
            {
                continue;
            }

            var name = line[..colon].Trim();
            if (name is "lo" or "docker0" || name.StartsWith("veth", StringComparison.Ordinal) || name.StartsWith("br-", StringComparison.Ordinal))
            {
                continue;
            }

            var fields = line[(colon + 1)..].Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length >= 9
                && long.TryParse(fields[0], NumberStyles.None, CultureInfo.InvariantCulture, out var received)
                && long.TryParse(fields[8], NumberStyles.None, CultureInfo.InvariantCulture, out var transmitted))
            {
                rx += received;
                tx += transmitted;
            }
        }

        return new NetSample(now, rx, tx);
    }

    private sealed record class CpuSample(long Total, long Idle);

    private sealed record class NetSample(DateTimeOffset At, long Rx, long Tx);

    private readonly record struct MemorySample(long TotalKiB, long AvailableKiB);

    private sealed record class ContainerSample(DateTimeOffset At, ContainerStatsSample Stats);
}
