using System.Diagnostics.Metrics;
using System.Net;
using System.Net.Sockets;
using OpenTelemetry.Exporter;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Observability;

namespace TerraScale.Orchestrator.Tests;

public sealed class OrchestratorTelemetryTests
{
    [Test]
    public async Task OtlpConfigurationAllowsOnlySupportedSecureOrLoopbackEndpoints()
    {
        await Assert.That(OtlpExporterConfiguration.Resolve(_ => null)).IsNull();

        var local = OtlpExporterConfiguration.Resolve(Environment([
            new("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318"),
            new("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf")
        ]));

        await Assert.That(local).IsNotNull();
        await Assert.That(local!.Endpoint).IsEqualTo(new Uri("http://127.0.0.1:4318/"));
        await Assert.That(local.Protocol).IsEqualTo(OtlpExportProtocol.HttpProtobuf);
        await Assert.That(() => OtlpExporterConfiguration.Resolve(Environment([
                new("OTEL_EXPORTER_OTLP_ENDPOINT", "http://192.0.2.1:4318")
            ])))
            .Throws<ArgumentException>();
        await Assert.That(() => OtlpExporterConfiguration.Resolve(Environment([
                new("OTEL_EXPORTER_OTLP_ENDPOINT", "https://user:secret@collector.example:4318")
            ])))
            .Throws<ArgumentException>();
    }

    [Test]
    public async Task StartupExportsBoundedTraceMetricAndLogSignalsOverOtlpHttp()
    {
        var port = FreePort();
        using var listener = new HttpListener();
        listener.Prefixes.Add($"http://127.0.0.1:{port}/");
        listener.Start();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var requestsTask = ReceiveAsync(listener, 3, timeout.Token);
        var options = new OrchestratorOptions(
            OrchestratorCommand.Check,
            "gru",
            "nats://127.0.0.1:4222",
            3,
            Instance: "controller-1");

        using (var telemetry = OrchestratorTelemetry.Start(options, Environment([
                   new("OTEL_EXPORTER_OTLP_ENDPOINT", $"http://127.0.0.1:{port}"),
                   new("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf")
               ])))
        {
            using var activity = telemetry.StartRuntime();
            await Assert.That(activity).IsNotNull();
            telemetry.RecordReady(TimeSpan.FromMilliseconds(125));
        }

        var requests = await requestsTask;
        await Assert.That(requests.Select(request => request.Path).Order())
            .IsEquivalentTo(["/v1/logs", "/v1/metrics", "/v1/traces"]);
        await Assert.That(requests.All(request => request.ContentType == "application/x-protobuf"))
            .IsTrue();
        await Assert.That(requests.All(request => request.Bytes > 0)).IsTrue();
    }

    [Test]
    public async Task MembershipMetricsExposeOnlyBoundedAggregateHealth()
    {
        var measurements = new List<MetricMeasurement>();
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, meterListener) =>
        {
            if (instrument.Meter.Name == OrchestratorTelemetry.InstrumentationName &&
                instrument.Name.Contains("membership", StringComparison.Ordinal))
                meterListener.EnableMeasurementEvents(instrument);
        };
        listener.SetMeasurementEventCallback<long>((instrument, value, tags, _) =>
        {
            var copiedTags = new Dictionary<string, object?>(StringComparer.Ordinal);
            foreach (var tag in tags) copiedTags.Add(tag.Key, tag.Value);
            measurements.Add(new(instrument.Name, value, copiedTags));
        });
        listener.Start();
        var options = new OrchestratorOptions(
            OrchestratorCommand.Check,
            "gru",
            "nats://127.0.0.1:4222",
            3,
            Instance: "controller-1");
        using var telemetry = OrchestratorTelemetry.Start(options, _ => null);
        var health = new RegionalRuntimeMembershipHealth(
            3, 2, 1, 1, 0, 1, 4, 1, true, 250,
            RegionalRuntimeMembershipCondition.Degraded, DateTimeOffset.UtcNow);
        telemetry.ObserveMembership(() => health);

        listener.RecordObservableInstruments();

        await Assert.That(measurements.Single(measurement => measurement.Name.EndsWith("quorum.available", StringComparison.Ordinal)).Value)
            .IsEqualTo(1);
        await Assert.That(measurements.Single(measurement => measurement.Name.EndsWith("authority.leaders", StringComparison.Ordinal)).Value)
            .IsEqualTo(1);
        await Assert.That(measurements.Single(measurement => measurement.Name.EndsWith("heartbeat.max_age", StringComparison.Ordinal)).Value)
            .IsEqualTo(250);
        await Assert.That(measurements.Single(measurement => measurement.Name.EndsWith("records.rejected", StringComparison.Ordinal)).Value)
            .IsEqualTo(4);
        await Assert.That(measurements.Where(measurement => measurement.Name.EndsWith("membership.controllers", StringComparison.Ordinal))
            .ToDictionary(measurement => (string)measurement.Tags["state"]!, measurement => measurement.Value))
            .IsEquivalentTo(new Dictionary<string, long>
            {
                ["active"] = 2,
                ["stale"] = 1,
                ["missing"] = 1,
                ["unexpected"] = 0,
                ["conflicting"] = 1
            });
        await Assert.That(measurements.SelectMany(static measurement => measurement.Tags.Keys)
            .Any(tag => tag.Contains("instance", StringComparison.OrdinalIgnoreCase) ||
                        tag.Contains("peer", StringComparison.OrdinalIgnoreCase))).IsFalse();
        await Assert.That(() => telemetry.ObserveMembership(() => health))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task GlobalDirectoryMetricsExposeOnlyBoundedAggregateHealth()
    {
        var measurements = new List<MetricMeasurement>();
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, meterListener) =>
        {
            if (instrument.Meter.Name == OrchestratorTelemetry.InstrumentationName &&
                instrument.Name.Contains("cell_directory", StringComparison.Ordinal))
                meterListener.EnableMeasurementEvents(instrument);
        };
        listener.SetMeasurementEventCallback<long>((instrument, value, tags, _) =>
        {
            var copiedTags = new Dictionary<string, object?>(StringComparer.Ordinal);
            foreach (var tag in tags) copiedTags.Add(tag.Key, tag.Value);
            measurements.Add(new(instrument.Name, value, copiedTags));
        });
        listener.Start();
        using var telemetry = OrchestratorTelemetry.Start(new(
            OrchestratorCommand.Check,
            "gru",
            "nats://127.0.0.1:4222",
            3,
            Instance: "controller-1"), _ => null);
        var snapshot = new GlobalCellDirectorySnapshot(
            1,
            DateTimeOffset.UtcNow,
            2,
            1,
            4,
            GlobalCellDirectoryCondition.Degraded,
            []);
        telemetry.ObserveCellDirectory(() => snapshot);

        listener.RecordObservableInstruments();

        await Assert.That(measurements.Where(measurement =>
                measurement.Name.EndsWith("cell_directory.cells", StringComparison.Ordinal))
            .ToDictionary(measurement => (string)measurement.Tags["state"]!, measurement => measurement.Value))
            .IsEquivalentTo(new Dictionary<string, long> { ["active"] = 2, ["stale"] = 1 });
        await Assert.That(measurements.Single(measurement =>
                measurement.Name.EndsWith("advertisements.rejected", StringComparison.Ordinal)).Value)
            .IsEqualTo(4);
        await Assert.That(measurements.SelectMany(static measurement => measurement.Tags.Keys)
            .Any(tag => tag.Contains("instance", StringComparison.OrdinalIgnoreCase) ||
                        tag.Contains("peer", StringComparison.OrdinalIgnoreCase) ||
                        tag.Contains("remote_cell", StringComparison.OrdinalIgnoreCase))).IsFalse();
    }

    private static Func<string, string?> Environment(IEnumerable<KeyValuePair<string, string>> values)
    {
        var environment = values.ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);
        return key => environment.GetValueOrDefault(key);
    }

    private static int FreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    private static async Task<IReadOnlyList<OtlpRequest>> ReceiveAsync(
        HttpListener listener,
        int count,
        CancellationToken cancellationToken)
    {
        var requests = new List<OtlpRequest>(count);
        while (requests.Count < count)
        {
            var context = await listener.GetContextAsync().WaitAsync(cancellationToken);
            await using var body = new MemoryStream();
            await context.Request.InputStream.CopyToAsync(body, cancellationToken);
            requests.Add(new(
                context.Request.Url!.AbsolutePath,
                context.Request.ContentType,
                body.Length));
            context.Response.StatusCode = (int)HttpStatusCode.OK;
            context.Response.ContentType = "application/x-protobuf";
            context.Response.ContentLength64 = 0;
            context.Response.Close();
        }
        return requests;
    }

    private sealed record OtlpRequest(string Path, string? ContentType, long Bytes);
    private sealed record MetricMeasurement(
        string Name,
        long Value,
        IReadOnlyDictionary<string, object?> Tags);
}

