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
using TerraScale.Orchestrator.Messaging;

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
    private readonly ObservableGauge<long> membershipControllers;
    private readonly ObservableGauge<long> membershipQuorum;
    private readonly ObservableGauge<long> membershipLeaders;
    private readonly ObservableGauge<long> membershipHeartbeatAge;
    private readonly ObservableCounter<long> rejectedMembershipRecords;
    private readonly ObservableGauge<long> globalDirectoryCells;
    private readonly ObservableCounter<long> rejectedGlobalAdvertisements;
    private readonly OpenTelemetrySdk sdk;
    private readonly ILogger logger;
    private readonly string cell;
    private readonly string instance;
    private Func<RegionalRuntimeMembershipHealth>? membershipHealth;
    private Func<GlobalCellDirectorySnapshot>? globalCellDirectory;

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
        membershipControllers = meter.CreateObservableGauge(
            "terrascale.orchestrator.membership.controllers",
            ObserveMembershipControllers,
            unit: "{controller}");
        membershipQuorum = meter.CreateObservableGauge(
            "terrascale.orchestrator.membership.quorum.available",
            ObserveMembershipQuorum,
            unit: "{boolean}");
        membershipLeaders = meter.CreateObservableGauge(
            "terrascale.orchestrator.membership.authority.leaders",
            ObserveMembershipLeaders,
            unit: "{controller}");
        membershipHeartbeatAge = meter.CreateObservableGauge(
            "terrascale.orchestrator.membership.heartbeat.max_age",
            ObserveMembershipHeartbeatAge,
            unit: "ms");
        rejectedMembershipRecords = meter.CreateObservableCounter(
            "terrascale.orchestrator.membership.records.rejected",
            ObserveRejectedMembershipRecords,
            unit: "{record}");
        globalDirectoryCells = meter.CreateObservableGauge(
            "terrascale.orchestrator.cell_directory.cells",
            ObserveGlobalDirectoryCells,
            unit: "{cell}");
        rejectedGlobalAdvertisements = meter.CreateObservableCounter(
            "terrascale.orchestrator.cell_directory.advertisements.rejected",
            ObserveRejectedGlobalAdvertisements,
            unit: "{advertisement}");
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

    internal void ObserveMembership(Func<RegionalRuntimeMembershipHealth> observe)
    {
        ArgumentNullException.ThrowIfNull(observe);
        if (Interlocked.CompareExchange(ref membershipHealth, observe, null) is not null)
            throw new InvalidOperationException("Regional membership telemetry is already attached.");
    }

    internal void ObserveCellDirectory(Func<GlobalCellDirectorySnapshot> observe)
    {
        ArgumentNullException.ThrowIfNull(observe);
        if (Interlocked.CompareExchange(ref globalCellDirectory, observe, null) is not null)
            throw new InvalidOperationException("Global cell directory telemetry is already attached.");
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
        GC.KeepAlive(membershipControllers);
        GC.KeepAlive(membershipQuorum);
        GC.KeepAlive(membershipLeaders);
        GC.KeepAlive(membershipHeartbeatAge);
        GC.KeepAlive(rejectedMembershipRecords);
        GC.KeepAlive(globalDirectoryCells);
        GC.KeepAlive(rejectedGlobalAdvertisements);
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

    private IEnumerable<Measurement<long>> ObserveMembershipControllers()
    {
        var health = Volatile.Read(ref membershipHealth)?.Invoke();
        if (health is null) yield break;
        yield return new(health.ActiveControllers, MembershipTags("active", health.Condition));
        yield return new(health.StaleControllers, MembershipTags("stale", health.Condition));
        yield return new(health.MissingControllers, MembershipTags("missing", health.Condition));
        yield return new(health.UnexpectedControllers, MembershipTags("unexpected", health.Condition));
        yield return new(health.ConflictingControllers, MembershipTags("conflicting", health.Condition));
    }

    private IEnumerable<Measurement<long>> ObserveMembershipQuorum()
    {
        var health = Volatile.Read(ref membershipHealth)?.Invoke();
        if (health is null) yield break;
        yield return new(health.QuorumAvailable ? 1 : 0, MembershipTags(null, health.Condition));
    }

    private IEnumerable<Measurement<long>> ObserveMembershipLeaders()
    {
        var health = Volatile.Read(ref membershipHealth)?.Invoke();
        if (health is null) yield break;
        yield return new(health.AuthorityLeaders, MembershipTags(null, health.Condition));
    }

    private IEnumerable<Measurement<long>> ObserveMembershipHeartbeatAge()
    {
        var health = Volatile.Read(ref membershipHealth)?.Invoke();
        if (health is null) yield break;
        yield return new(health.MaximumHeartbeatAgeMilliseconds, MembershipTags(null, health.Condition));
    }

    private IEnumerable<Measurement<long>> ObserveRejectedMembershipRecords()
    {
        var health = Volatile.Read(ref membershipHealth)?.Invoke();
        if (health is null) yield break;
        yield return new(health.RejectedRecords, MembershipTags(null, health.Condition));
    }

    private IEnumerable<Measurement<long>> ObserveGlobalDirectoryCells()
    {
        var snapshot = Volatile.Read(ref globalCellDirectory)?.Invoke();
        if (snapshot is null) yield break;
        yield return new(snapshot.ActiveCells, GlobalDirectoryTags("active", snapshot.Condition));
        yield return new(snapshot.StaleCells, GlobalDirectoryTags("stale", snapshot.Condition));
    }

    private IEnumerable<Measurement<long>> ObserveRejectedGlobalAdvertisements()
    {
        var snapshot = Volatile.Read(ref globalCellDirectory)?.Invoke();
        if (snapshot is null) yield break;
        yield return new(snapshot.RejectedAdvertisements, GlobalDirectoryTags(null, snapshot.Condition));
    }

    private TagList MembershipTags(string? state, RegionalRuntimeMembershipCondition condition)
    {
        var tags = new TagList
        {
            { "terrascale.cell", cell },
            { "condition", condition.ToString().ToLowerInvariant() }
        };
        if (state is not null) tags.Add("state", state);
        return tags;
    }

    private TagList GlobalDirectoryTags(string? state, GlobalCellDirectoryCondition condition)
    {
        var tags = new TagList
        {
            { "terrascale.cell", cell },
            { "condition", condition.ToString().ToLowerInvariant() }
        };
        if (state is not null) tags.Add("state", state);
        return tags;
    }
}
