using System.Text.Json;
using TsOrch.Protocol;

namespace TsOrch.Edge;

public sealed partial class EdgeMetricsCollector(
    EdgeServerOptions options,
    TimeProvider timeProvider,
    ILogger<EdgeMetricsCollector> logger) : BackgroundService
{
    public static readonly TimeSpan FlushInterval = TimeSpan.FromSeconds(10);

    private const int ReservoirCapacity = 2048;

    private readonly Lock _gate = new();
    private readonly Dictionary<string, ServiceWindow> _services = [with(StringComparer.Ordinal)];
    private long _windowStartedAt = timeProvider.GetTimestamp();
    private int _postgresConnections;

    public void RequestStarted(string serviceName)
    {
        ArgumentException.ThrowIfNullOrEmpty(serviceName);
        lock (_gate)
        {
            Window(serviceName).ActiveConnections++;
        }
    }

    public void RequestCompleted(string serviceName, int statusCode, TimeSpan elapsed, bool recordLatency)
    {
        ArgumentException.ThrowIfNullOrEmpty(serviceName);
        lock (_gate)
        {
            var window = Window(serviceName);
            window.ActiveConnections--;
            window.Requests++;
            if (statusCode >= StatusCodes.Status500InternalServerError)
            {
                window.Responses5xx++;
            }

            if (recordLatency)
            {
                window.RecordLatency(elapsed.TotalMilliseconds);
            }
        }
    }

    public void PostgresConnectionOpened() => Interlocked.Increment(ref _postgresConnections);

    public void PostgresConnectionClosed() => Interlocked.Decrement(ref _postgresConnections);

    public EdgeMetricsSnapshot Flush()
    {
        var now = timeProvider.GetTimestamp();
        List<EdgeServiceMetrics> services;
        double windowSeconds;
        lock (_gate)
        {
            windowSeconds = Math.Max(timeProvider.GetElapsedTime(_windowStartedAt, now).TotalSeconds, 0.001);
            _windowStartedAt = now;
            services = [with(capacity: _services.Count)];
            List<string>? idle = null;
            foreach (var (serviceName, window) in _services)
            {
                if (window.Requests == 0 && window.ActiveConnections == 0)
                {
                    (idle ??= []).Add(serviceName);
                    continue;
                }

                services.Add(window.Drain(serviceName, windowSeconds));
            }

            foreach (var serviceName in idle ?? [])
            {
                _services.Remove(serviceName);
            }
        }

        return new EdgeMetricsSnapshot(
            timeProvider.GetUtcNow().ToUnixTimeMilliseconds(),
            (int)Math.Round(windowSeconds),
            services,
            Volatile.Read(ref _postgresConnections));
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(FlushInterval, timeProvider);
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            await WriteAsync(Flush(), stoppingToken);
        }
    }

    private async Task WriteAsync(EdgeMetricsSnapshot snapshot, CancellationToken cancellationToken)
    {
        var temporary = options.MetricsFile + ".tmp";
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(options.MetricsFile)
                ?? throw new InvalidOperationException($"Metrics file '{options.MetricsFile}' has no parent directory."));
            await using (var stream = new FileStream(temporary, FileMode.Create, FileAccess.Write, FileShare.None, bufferSize: 4096, FileOptions.Asynchronous))
            {
                await JsonSerializer.SerializeAsync(stream, snapshot, EdgeJsonContext.Default.EdgeMetricsSnapshot, cancellationToken);
            }

            File.Move(temporary, options.MetricsFile, overwrite: true);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            LogMetricsWriteFailed(logger, options.MetricsFile, exception);
        }
    }

    private ServiceWindow Window(string serviceName)
    {
        if (!_services.TryGetValue(serviceName, out var window))
        {
            window = new ServiceWindow();
            _services.Add(serviceName, window);
        }

        return window;
    }

    [LoggerMessage(Level = LogLevel.Error, Message = "Failed to write edge metrics to {Path}")]
    private static partial void LogMetricsWriteFailed(ILogger logger, string path, Exception exception);

    private sealed class ServiceWindow
    {
        private readonly double[] _reservoir = new double[ReservoirCapacity];
        private long _latencySamples;

        public long Requests { get; set; }

        public long Responses5xx { get; set; }

        public int ActiveConnections { get; set; }

        public void RecordLatency(double milliseconds)
        {
            var seen = _latencySamples++;
            if (seen < ReservoirCapacity)
            {
                _reservoir[seen] = milliseconds;
                return;
            }

            var slot = Random.Shared.NextInt64(seen + 1);
            if (slot < ReservoirCapacity)
            {
                _reservoir[slot] = milliseconds;
            }
        }

        public EdgeServiceMetrics Drain(string serviceName, double windowSeconds)
        {
            var samples = _reservoir.AsSpan(0, (int)Math.Min(_latencySamples, ReservoirCapacity));
            samples.Sort();
            var metrics = new EdgeServiceMetrics(
                serviceName,
                Requests / windowSeconds,
                Requests == 0 ? 0 : Responses5xx * 100.0 / Requests,
                Percentile(samples, 0.50),
                Percentile(samples, 0.95),
                Percentile(samples, 0.99),
                Requests,
                Responses5xx,
                ActiveConnections);
            Requests = 0;
            Responses5xx = 0;
            _latencySamples = 0;
            return metrics;
        }

        private static double Percentile(ReadOnlySpan<double> sorted, double quantile) =>
            sorted.IsEmpty ? 0 : sorted[Math.Clamp((int)Math.Ceiling(quantile * sorted.Length) - 1, 0, sorted.Length - 1)];
    }
}
