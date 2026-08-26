using System.Text.Json.Serialization;

namespace TerraScale.Orchestrator.Messaging;

/// <summary>
/// The closed endpoint-name domain of the regional control service. Service request
/// statistics are labeled only by this enumeration (plus result) so the cardinality
/// of the service instrumentation is fixed by the code, not by traffic.
/// </summary>
internal enum NatsServiceEndpointName
{
    Health = 1,
    InstanceHealth = 2,
    Status = 3,
    Members = 4,
    Stats = 5,
    DirectDelivery = 6
}

internal enum NatsServiceRequestResult
{
    Ok = 1,
    Error = 2
}

/// <summary>
/// Bounded latency statistics for one service endpoint: request and error counts
/// plus p50/p95/p99 latency over a fixed-size reservoir of recent durations. The
/// sample window is bounded by construction so a busy endpoint can grow neither
/// memory nor cardinality.
/// </summary>
internal sealed record NatsServiceEndpointMeasurement(
    NatsServiceEndpointName Endpoint,
    long Requests,
    long Errors,
    long MinimumMilliseconds,
    long P50Milliseconds,
    long P95Milliseconds,
    long P99Milliseconds,
    long MaximumMilliseconds)
{
    internal static NatsServiceEndpointMeasurement Empty(NatsServiceEndpointName endpoint) =>
        new(endpoint, 0, 0, 0, 0, 0, 0, 0);

    internal void Validate()
    {
        if (!Enum.IsDefined(Endpoint) || Requests < 0 || Errors < 0 || Errors > Requests ||
            MinimumMilliseconds < 0 || P50Milliseconds < 0 || P95Milliseconds < 0 || P99Milliseconds < 0 ||
            MaximumMilliseconds < 0 ||
            P50Milliseconds > P95Milliseconds || P95Milliseconds > P99Milliseconds ||
            MinimumMilliseconds > MaximumMilliseconds ||
            (Requests > 0 && (P50Milliseconds < MinimumMilliseconds || P99Milliseconds < MaximumMilliseconds)))
            throw new InvalidOperationException("The NATS service endpoint measurement is invalid.");
    }
}

/// <summary>
/// Thread-safe recorder for service endpoint statistics: one bounded reservoir per
/// endpoint in the closed endpoint enumeration. Endpoints, latencies, and counts are
/// the only state — no subject, payload, or requester identity is retained.
/// </summary>
internal sealed class NatsServiceEndpointStats
{
    private const int SampleLimit = 256;
    private readonly Dictionary<NatsServiceEndpointName, Recorder> recorders = new();

    internal void Record(NatsServiceEndpointName endpoint, NatsServiceRequestResult result, TimeSpan duration)
    {
        if (!Enum.IsDefined(endpoint)) throw new ArgumentOutOfRangeException(nameof(endpoint));
        if (!Enum.IsDefined(result)) throw new ArgumentOutOfRangeException(nameof(result));
        Recorder recorder;
        lock (recorders)
        {
            if (!recorders.TryGetValue(endpoint, out var existing))
            {
                existing = new Recorder();
                recorders.Add(endpoint, existing);
            }
            recorder = existing;
        }
        recorder.Record(result, duration);
    }

    internal IReadOnlyList<NatsServiceEndpointMeasurement> Snapshot()
    {
        lock (recorders)
        {
            return recorders
                .Select(pair => pair.Value.Measurement(pair.Key))
                .OrderBy(static measurement => measurement.Endpoint)
                .ToArray();
        }
    }

    private sealed class Recorder
    {
        private readonly long[] samples = new long[SampleLimit];
        private readonly object gate = new();
        private long requests;
        private long errors;
        private int sampleCount;
        private int sampleHead;

        internal void Record(NatsServiceRequestResult result, TimeSpan duration)
        {
            var milliseconds = Math.Max(0,
                (long)Math.Round(duration.TotalMilliseconds, MidpointRounding.ToPositiveInfinity));
            lock (gate)
            {
                requests++;
                if (result == NatsServiceRequestResult.Error) errors++;
                samples[sampleHead] = milliseconds;
                sampleHead = (sampleHead + 1) % SampleLimit;
                if (sampleCount < SampleLimit) sampleCount++;
            }
        }

        internal NatsServiceEndpointMeasurement Measurement(NatsServiceEndpointName endpoint)
        {
            lock (gate)
            {
                if (requests == 0) return NatsServiceEndpointMeasurement.Empty(endpoint);
                var window = samples.AsSpan(0, sampleCount).ToArray();
                Array.Sort(window);
                long Percentile(double fraction)
                {
                    var index = Math.Clamp((int)Math.Ceiling(fraction * window.Length) - 1, 0, window.Length - 1);
                    return window[index];
                }
                var measurement = new NatsServiceEndpointMeasurement(
                    endpoint,
                    requests,
                    errors,
                    window[0],
                    Percentile(0.50),
                    Percentile(0.95),
                    Percentile(0.99),
                    window[^1]);
                measurement.Validate();
                return measurement;
            }
        }
    }
}

/// <summary>
/// The document served by the read-only <c>stats</c> service endpoint: service
/// version, schema metadata, health, and per-endpoint request/error/latency
/// statistics. It exposes no identity, no payloads, and no addresses.
/// </summary>
internal sealed record NatsServiceStatsDocument(
    int SchemaVersion,
    string Cell,
    string Service,
    string Version,
    int SchemaGeneration,
    bool Healthy,
    DateTimeOffset ObservedAt,
    IReadOnlyList<NatsServiceEndpointMeasurement> Endpoints)
{
    internal static readonly int CurrentSchemaVersion = 1;

    internal static NatsServiceStatsDocument Create(
        string cell,
        string version,
        int schemaGeneration,
        bool healthy,
        DateTimeOffset observedAt,
        IEnumerable<NatsServiceEndpointMeasurement> endpoints)
    {
        if (!CellTokenRule.IsValid(cell)) throw new ArgumentException("The cell is not a bounded token.", nameof(cell));
        ArgumentNullException.ThrowIfNull(version);
        var document = new NatsServiceStatsDocument(
            CurrentSchemaVersion,
            cell,
            $"terrascale_orchestrator_{cell}",
            version,
            schemaGeneration,
            healthy,
            observedAt,
            endpoints.OrderBy(static measurement => measurement.Endpoint).ToArray());
        document.Validate();
        return document;
    }

    internal void Validate()
    {
        if (SchemaVersion != CurrentSchemaVersion || !CellTokenRule.IsValid(Cell) ||
            Service != $"terrascale_orchestrator_{Cell}" ||
            string.IsNullOrWhiteSpace(Version) || SchemaGeneration <= 0 || ObservedAt == default ||
            Endpoints.Select(static measurement => measurement.Endpoint).Distinct().Count() != Endpoints.Count)
            throw new InvalidOperationException("The NATS service stats document is invalid.");
        foreach (var endpoint in Endpoints) endpoint.Validate();
    }
}

[JsonSerializable(typeof(NatsServiceStatsDocument))]
[JsonSerializable(typeof(NatsServiceEndpointMeasurement))]
internal sealed partial class NatsServiceEndpointStatsJsonContext : JsonSerializerContext;
