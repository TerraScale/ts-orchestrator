using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Net;
using Microsoft.Extensions.Logging;
using OpenTelemetry;
using OpenTelemetry.Exporter;
using OpenTelemetry.Logs;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;

namespace TerraScale.Orchestrator.Observability;

internal sealed record OtlpExporterConfiguration(Uri Endpoint, OtlpExportProtocol Protocol)
{
    public static OtlpExporterConfiguration? Resolve(Func<string, string?> environment)
    {
        ArgumentNullException.ThrowIfNull(environment);
        var endpointText = environment("OTEL_EXPORTER_OTLP_ENDPOINT");
        if (string.IsNullOrWhiteSpace(endpointText))
        {
            return null;
        }
        if (!Uri.TryCreate(endpointText, UriKind.Absolute, out var endpoint) ||
            endpoint.Scheme is not "http" and not "https" ||
            string.IsNullOrEmpty(endpoint.Host) ||
            !string.IsNullOrEmpty(endpoint.UserInfo) ||
            !string.IsNullOrEmpty(endpoint.Query) ||
            !string.IsNullOrEmpty(endpoint.Fragment))
        {
            throw new ArgumentException("OTEL_EXPORTER_OTLP_ENDPOINT must be an absolute HTTP(S) base URL without credentials, query, or fragment.");
        }
        if (endpoint.Scheme == "http" && !IsLoopback(endpoint.Host))
        {
            throw new ArgumentException("Plaintext OTLP export is permitted only to a loopback collector.");
        }
        var protocol = environment("OTEL_EXPORTER_OTLP_PROTOCOL") switch
        {
            null or "" or "grpc" => OtlpExportProtocol.Grpc,
            "http/protobuf" => OtlpExportProtocol.HttpProtobuf,
            _ => throw new ArgumentException("OTEL_EXPORTER_OTLP_PROTOCOL must be 'grpc' or 'http/protobuf'.")
        };
        return new(EnsureBasePath(endpoint), protocol);
    }

    private static bool IsLoopback(string host) =>
        string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase) ||
        IPAddress.TryParse(host, out var address) && IPAddress.IsLoopback(address);

    private static Uri EnsureBasePath(Uri endpoint)
    {
        var builder = new UriBuilder(endpoint);
        if (!builder.Path.EndsWith('/'))
        {
            builder.Path += '/';
        }
        return builder.Uri;
    }
}

/// <summary>Bounded, low-cardinality OTLP signals for the Orchestrator process.</summary>
internal sealed class OrchestratorTelemetry : IDisposable
{
    internal const string InstrumentationName = "TerraScale.Orchestrator";

    private readonly ActivitySource activitySource;
    private readonly Meter meter;
    private readonly Counter<long> startupCounter;
    private readonly Histogram<double> startupDuration;
    private readonly OpenTelemetrySdk sdk;
    private readonly ILogger logger;
    private readonly string cell;
    private readonly string instance;

    private OrchestratorTelemetry(
        OrchestratorOptions options,
        OtlpExporterConfiguration? exporter)
    {
        cell = options.Cell;
        instance = options.Instance;
        sdk = OpenTelemetrySdk.Create(builder =>
        {
            builder.ConfigureResource(resource => resource
                    .AddService(
                        InstrumentationName,
                        serviceNamespace: "TerraScale",
                        serviceVersion: BuildVersion.Current.Contract,
                        serviceInstanceId: options.Instance)
                    .AddAttributes([
                        new KeyValuePair<string, object>("terrascale.cell", options.Cell)
                    ]))
                .WithTracing(tracing => tracing.AddSource(InstrumentationName))
                .WithMetrics(metrics => metrics.AddMeter(InstrumentationName))
                .WithLogging(
                    _ => { },
                    logging =>
                    {
                        logging.IncludeFormattedMessage = false;
                        logging.IncludeScopes = true;
                        logging.ParseStateValues = true;
                    });
            if (exporter is not null)
            {
                builder.UseOtlpExporter(exporter.Protocol, exporter.Endpoint);
            }
        });
        activitySource = new(InstrumentationName, BuildVersion.Current.Contract);
        meter = new(InstrumentationName, BuildVersion.Current.Contract);
        startupCounter = meter.CreateCounter<long>("terrascale.orchestrator.startups", unit: "{startup}");
        startupDuration = meter.CreateHistogram<double>("terrascale.orchestrator.startup.duration", unit: "ms");
        logger = sdk.GetLoggerFactory().CreateLogger(InstrumentationName);
    }

    public static OrchestratorTelemetry Start(
        OrchestratorOptions options,
        Func<string, string?> environment)
    {
        ArgumentNullException.ThrowIfNull(options);
        return new(options, OtlpExporterConfiguration.Resolve(environment));
    }

    public Activity? StartRuntime()
    {
        var activity = activitySource.StartActivity("orchestrator.start", ActivityKind.Internal);
        activity?.SetTag("terrascale.cell", cell);
        activity?.SetTag("service.instance.id", instance);
        return activity;
    }

    public void RecordReady(TimeSpan elapsed)
    {
        var tags = Tags("ready");
        startupCounter.Add(1, tags);
        startupDuration.Record(elapsed.TotalMilliseconds, tags);
        logger.LogInformation(
            "Orchestrator startup completed for cell {Cell} and instance {Instance}",
            cell,
            instance);
    }

    public void RecordFailure(TimeSpan elapsed, Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
        var tags = Tags("failed");
        startupCounter.Add(1, tags);
        startupDuration.Record(elapsed.TotalMilliseconds, tags);
        logger.LogError(
            "Orchestrator startup failed for cell {Cell}, instance {Instance}, failure type {FailureType}",
            cell,
            instance,
            exception.GetType().Name);
    }

    public void Dispose()
    {
        sdk.Dispose();
        meter.Dispose();
        activitySource.Dispose();
    }

    private TagList Tags(string outcome) => new()
    {
        { "terrascale.cell", cell },
        { "service.instance.id", instance },
        { "outcome", outcome }
    };
}
