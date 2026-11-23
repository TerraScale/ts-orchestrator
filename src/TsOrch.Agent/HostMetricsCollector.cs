using System.Collections.Concurrent;
using System.Globalization;
using System.Text.Json;

namespace TsOrch.Agent;

public sealed record class NodeCapacity(int CpuTotalMilli, int MemTotalMiB, int DiskTotalGiB, IReadOnlyList<VolumeInfo> Volumes);

public sealed record class MountEntry(string Device, string MountPoint, string FileSystem);

public static class MountTable
{
    public const string MountsFile = "/proc/self/mounts";

    public static async Task<IReadOnlyList<MountEntry>> ReadAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(MountsFile))
        {
            return [];
        }

        List<MountEntry> entries = [];
        foreach (var line in await File.ReadAllLinesAsync(MountsFile, cancellationToken))
        {
            var fields = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length >= 3)
            {
                entries.Add(new MountEntry(Unescape(fields[0]), Unescape(fields[1]), fields[2]));
            }
        }

        return entries;
    }

    public static MountEntry? FindContaining(IReadOnlyList<MountEntry> entries, string path)
    {
        ArgumentNullException.ThrowIfNull(entries);
        var full = Path.GetFullPath(path).TrimEnd('/');
        MountEntry? best = null;
        foreach (var entry in entries)
        {
            var mountPoint = entry.MountPoint.TrimEnd('/');
            var contains = mountPoint.Length == 0
                || full == mountPoint
                || full.StartsWith(mountPoint + "/", StringComparison.Ordinal);
            if (contains && (best is null || entry.MountPoint.Length >= best.MountPoint.Length))
            {
                best = entry;
            }
        }

        return best;
    }

    private static string Unescape(string value) =>
        value.Replace("\\040", " ", StringComparison.Ordinal).Replace("\\011", "\t", StringComparison.Ordinal).Replace("\\134", "\\", StringComparison.Ordinal);
}

public sealed class HostMetricsCollector(
    DockerEngineClient docker,
    AgentOptions options,
    TimeProvider timeProvider,
    ILogger<HostMetricsCollector> logger)
{
    private const double BytesPerMiB = 1024d * 1024d;
    private const double BytesPerGiB = BytesPerMiB * 1024d;
    private const int MaxParallelStats = 4;

    private readonly Lock _gate = new();
    private readonly ConcurrentDictionary<string, ContainerSample> _containerSamples = [with(StringComparer.Ordinal)];
    private CpuSample? _lastCpu;
    private NetSample? _lastNet;

    public async Task<HostMetrics> CollectHostAsync(CancellationToken cancellationToken)
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

        return new HostMetrics(
            now.ToUnixTimeMilliseconds(),
            Math.Round(cpuPct, 2),
            await ReadPressureAsync("/proc/pressure/cpu", cancellationToken),
            (int)(memory.TotalKiB / 1024),
            (int)((memory.TotalKiB - memory.AvailableKiB) / 1024),
            await ReadPressureAsync("/proc/pressure/memory", cancellationToken),
            await ReadPressureAsync("/proc/pressure/io", cancellationToken),
            Math.Round(Math.Max(DiskUsedPct("/"), DiskUsedPct(options.DataVolumePath)), 2),
            rxBps,
            txBps,
            await ReadLoad1Async(cancellationToken));
    }

    public async Task<IReadOnlyList<ContainerMetrics>> CollectContainersAsync(IReadOnlyList<ManagedContainer> containers, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(containers);
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

        return [.. collected.OrderBy(static metrics => metrics.PlacementId, StringComparer.Ordinal)];
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

    public async Task<NodeCapacity> ReadCapacityAsync(CancellationToken cancellationToken)
    {
        var memory = await ReadMemInfoAsync(cancellationToken);
        var dataPath = Directory.Exists(options.DataVolumePath) ? options.DataVolumePath : "/";
        var drive = new DriveInfo(dataPath);
        List<VolumeInfo> volumes = [];
        if (Directory.Exists(options.DataVolumePath))
        {
            var mount = MountTable.FindContaining(await MountTable.ReadAsync(cancellationToken), options.DataVolumePath);
            volumes.Add(new VolumeInfo(
                options.DataVolumePath,
                mount?.Device ?? "unknown",
                (int)Math.Round(drive.TotalSize / BytesPerGiB),
                Math.Round(DiskUsedPct(options.DataVolumePath), 2)));
        }

        return new NodeCapacity(
            Environment.ProcessorCount * 1000,
            (int)(memory.TotalKiB / 1024),
            (int)Math.Round(drive.TotalSize / BytesPerGiB),
            volumes);
    }

    private async Task<ContainerMetrics?> CollectContainerAsync(ManagedContainer container, CancellationToken cancellationToken) =>
        await docker.GetContainerStatsAsync(container.Id, cancellationToken) switch
        {
            ContainerStatsSample stats => await docker.InspectContainerAsync(container.Id, cancellationToken) switch
            {
                ContainerState state => Measure(container, stats, state.RestartCount, state.OomKilled ? 1 : 0),
                NotFound => Measure(container, stats, 0, 0),
                Unavailable => Measure(container, stats, 0, 0),
                InternalFailure => Measure(container, stats, 0, 0),
            },
            NotFound failure => StatsUnavailable(container, failure.Message),
            Unavailable failure => StatsUnavailable(container, failure.Message),
            InternalFailure failure => StatsUnavailable(container, failure.Message),
        };

    private ContainerMetrics? StatsUnavailable(ManagedContainer container, string reason)
    {
        AgentLog.ContainerStatsUnavailable(logger, container.Id, reason);
        return null;
    }

    private ContainerMetrics Measure(ManagedContainer container, ContainerStatsSample stats, int restarts, int oomKills)
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
            oomKills);
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
