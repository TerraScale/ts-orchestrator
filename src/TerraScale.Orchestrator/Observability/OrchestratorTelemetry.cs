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
using TerraScale.Orchestrator.Runtime;

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
    private readonly Counter<long> natsServiceRequests;
    private readonly Counter<long> natsServiceErrors;
    private readonly Histogram<double> natsServiceRequestDuration;
    private readonly Counter<long> natsMessages;
    private readonly Counter<long> natsAdvisories;
    private readonly ObservableGauge<long> natsClientReconnects;
    private readonly ObservableGauge<long> natsConnections;
    private readonly ObservableGauge<long> natsRoutes;
    private readonly ObservableGauge<long> natsAccounts;
    private readonly ObservableGauge<long> natsGateways;
    private readonly ObservableGauge<long> natsJetStreamDomains;
    private readonly ObservableGauge<long> natsStreams;
    private readonly ObservableGauge<long> natsConsumers;
    private readonly ObservableGauge<long> natsConsumerLag;
    private readonly ObservableGauge<long> natsConsumerRedelivered;
    private readonly ObservableGauge<long> natsConsumerAckPending;
    private readonly ObservableGauge<long> natsFlowControlWaiting;
    private readonly ObservableGauge<long> natsStreamBytes;
    private readonly ObservableGauge<long> natsStreamDuplicates;
    private readonly ObservableGauge<long> natsKvWatches;
    private readonly ObservableGauge<long> natsObjectStoreObjects;
    private readonly ObservableGauge<long> natsObjectStoreBytes;
    private readonly ObservableGauge<long> natsServerMemory;
    private readonly ObservableGauge<long> natsStorageBytes;
    private readonly ObservableGauge<long> natsPartitionDuration;
    private readonly ObservableGauge<long> natsRecoveryDuration;
    private readonly ObservableGauge<long> natsCertificateExpiryDays;
    private readonly ObservableGauge<long> natsMonitoringAvailability;
    private readonly ObservableGauge<long> natsMeshCells;
    private readonly ObservableGauge<long> operatorDesiredReplicas;
    private readonly ObservableGauge<long> operatorObservedReplicas;
    private readonly ObservableGauge<long> operatorReadyReplicas;
    private readonly ObservableGauge<long> operatorProgressPercent;
    private readonly ObservableGauge<long> operatorMinReplicas;
    private readonly ObservableGauge<long> operatorMaxReplicas;
    private readonly ObservableGauge<long> operatorNeeds;
    private readonly ObservableGauge<long> operatorHealthy;
    private readonly OpenTelemetrySdk sdk;
    private readonly ILogger logger;
    private readonly string cell;
    private readonly string instance;
    private Func<RegionalRuntimeMembershipHealth>? membershipHealth;
    private Func<GlobalCellDirectorySnapshot>? globalCellDirectory;
    private Func<NatsMonitoringAggregate>? natsMonitoring;
    private Func<Operations.OperatorStatusDocument?>? operatorStatusObserver;
    // The most recent aggregate observed by the pull gauges; it supplies the bounded
    // scope labels for the push counters without holding any listener lock.
    private NatsMonitoringAggregate? natsScope;

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
        // NATS monitoring instruments (issue #23): every instrument is cataloged in
        // NatsMonitoringInstrumentCatalog, carries only bounded labels, and reads
        // the bounded aggregate — never a connection, stream, consumer, session,
        // NKey, message, or operation identity.
        natsServiceRequests = meter.CreateCounter<long>(
            "terrascale.orchestrator.nats.service.requests",
            unit: "{request}");
        natsServiceErrors = meter.CreateCounter<long>(
            "terrascale.orchestrator.nats.service.errors",
            unit: "{error}");
        natsServiceRequestDuration = meter.CreateHistogram<double>(
            "terrascale.orchestrator.nats.service.request.duration",
            unit: "ms");
        natsMessages = meter.CreateCounter<long>(
            "terrascale.orchestrator.nats.messages",
            unit: "{message}");
        natsAdvisories = meter.CreateCounter<long>(
            "terrascale.orchestrator.nats.advisories",
            unit: "{advisory}");
        natsClientReconnects = meter.CreateObservableGauge(
            "terrascale.orchestrator.nats.client.reconnects",
            () => ObserveNatsAggregate(aggregate => aggregate.Reconnects, null),
            unit: "{reconnect}");
        natsConnections = meter.CreateObservableGauge(
            "terrascale.orchestrator.nats.connections",
            () => ObserveNatsAggregate(aggregate => aggregate.Connections, null),
            unit: "{connection}");
        natsRoutes = meter.CreateObservableGauge(
            "terrascale.orchestrator.nats.routes",
            () => ObserveNatsAggregate(aggregate => aggregate.Routes, null),
            unit: "{route}");
        natsAccounts = meter.CreateObservableGauge(
            "terrascale.orchestrator.nats.accounts",
            () => ObserveNatsAggregate(aggregate => aggregate.Accounts, null),
            unit: "{account}");
        natsGateways = meter.CreateObservableGauge(
            "terrascale.orchestrator.nats.gateways",
            ObserveNatsGateways,
            unit: "{gateway}");
        natsJetStreamDomains = meter.CreateObservableGauge(
            "terrascale.orchestrator.nats.jetstream.domains",
            () => ObserveNatsAggregate(aggregate => aggregate.JetStreamDomains, null),
            unit: "{domain}");
        natsStreams = meter.CreateObservableGauge(
            "terrascale.orchestrator.nats.streams",
            ObserveNatsStreams,
            unit: "{stream}");
        natsConsumers = meter.CreateObservableGauge(
            "terrascale.orchestrator.nats.consumers",
            ObserveNatsConsumers,
            unit: "{consumer}");
        natsConsumerLag = meter.CreateObservableGauge(
            "terrascale.orchestrator.nats.consumer.lag",
            () => ObserveNatsConsumerMetric(static consumer => consumer.Lag),
            unit: "{message}");
        natsConsumerRedelivered = meter.CreateObservableGauge(
            "terrascale.orchestrator.nats.consumer.redelivered",
            () => ObserveNatsConsumerMetric(static consumer => consumer.Redelivered),
            unit: "{message}");
        natsConsumerAckPending = meter.CreateObservableGauge(
            "terrascale.orchestrator.nats.consumer.ack_pending",
            () => ObserveNatsConsumerMetric(static consumer => consumer.AckPending),
            unit: "{message}");
        natsFlowControlWaiting = meter.CreateObservableGauge(
            "terrascale.orchestrator.nats.flowcontrol.waiting",
            () => ObserveNatsConsumerMetric(static consumer => consumer.Waiting),
            unit: "{consumer}");
        natsStreamBytes = meter.CreateObservableGauge(
            "terrascale.orchestrator.nats.stream.bytes",
            ObserveNatsStreamBytes,
            unit: "By");
        natsStreamDuplicates = meter.CreateObservableGauge(
            "terrascale.orchestrator.nats.stream.duplicates",
            ObserveNatsStreamDuplicates,
            unit: "{message}");
        natsKvWatches = meter.CreateObservableGauge(
            "terrascale.orchestrator.nats.kv.watches",
            ObserveNatsStores,
            unit: "{watch}");
        natsObjectStoreObjects = meter.CreateObservableGauge(
            "terrascale.orchestrator.nats.objectstore.objects",
            ObserveNatsObjectStoreObjects,
            unit: "{object}");
        natsObjectStoreBytes = meter.CreateObservableGauge(
            "terrascale.orchestrator.nats.objectstore.bytes",
            ObserveNatsObjectStoreBytes,
            unit: "By");
        natsServerMemory = meter.CreateObservableGauge(
            "terrascale.orchestrator.nats.server.memory",
            () => ObserveNatsAggregate(aggregate => aggregate.ServerMemoryBytes, null),
            unit: "By");
        natsStorageBytes = meter.CreateObservableGauge(
            "terrascale.orchestrator.nats.storage.bytes",
            () => ObserveNatsAggregate(aggregate => aggregate.JetStreamStorageBytes, null),
            unit: "By");
        natsPartitionDuration = meter.CreateObservableGauge(
            "terrascale.orchestrator.nats.partition.duration",
            () => ObserveNatsAggregate(aggregate => aggregate.PartitionDurationMilliseconds, null),
            unit: "ms");
        natsRecoveryDuration = meter.CreateObservableGauge(
            "terrascale.orchestrator.nats.recovery.duration",
            () => ObserveNatsAggregate(aggregate => aggregate.RecoveryDurationMilliseconds, null),
            unit: "ms");
        natsCertificateExpiryDays = meter.CreateObservableGauge(
            "terrascale.orchestrator.nats.certificate.expiry.days",
            ObserveNatsCertificates,
            unit: "d");
        natsMonitoringAvailability = meter.CreateObservableGauge(
            "terrascale.orchestrator.nats.monitoring.availability",
            ObserveNatsAvailability,
            unit: "{boolean}");
        natsMeshCells = meter.CreateObservableGauge(
            "terrascale.orchestrator.nats.mesh.cells",
            ObserveNatsMeshCells,
            unit: "{cell}");
        operatorDesiredReplicas = meter.CreateObservableGauge(
            "terrascale.orchestrator.workload.desired.replicas",
            () => ObserveOperatorWorkloads(static workload => workload.DesiredReplicas),
            unit: "{replica}");
        operatorObservedReplicas = meter.CreateObservableGauge(
            "terrascale.orchestrator.workload.observed.replicas",
            () => ObserveOperatorWorkloads(static workload => workload.ObservedReplicas),
            unit: "{replica}");
        operatorReadyReplicas = meter.CreateObservableGauge(
            "terrascale.orchestrator.workload.ready.replicas",
            () => ObserveOperatorWorkloads(static workload => workload.ReadyReplicas),
            unit: "{replica}");
        operatorProgressPercent = meter.CreateObservableGauge(
            "terrascale.orchestrator.workload.progress",
            () => ObserveOperatorWorkloads(static workload => workload.ProgressPercent),
            unit: "%");
        operatorMinReplicas = meter.CreateObservableGauge(
            "terrascale.orchestrator.workload.min.replicas",
            () => ObserveOperatorWorkloads(static workload => workload.MinReplicas),
            unit: "{replica}");
        operatorMaxReplicas = meter.CreateObservableGauge(
            "terrascale.orchestrator.workload.max.replicas",
            () => ObserveOperatorWorkloads(static workload => workload.MaxReplicas),
            unit: "{replica}");
        operatorNeeds = meter.CreateObservableGauge(
            "terrascale.orchestrator.workload.needs",
            () => ObserveOperatorWorkloads(static workload => workload.Needs.Count),
            unit: "{need}");
        operatorHealthy = meter.CreateObservableGauge(
            "terrascale.orchestrator.workload.healthy",
            () => ObserveOperatorWorkloads(static workload => workload.State == "ready" ? 1 : 0),
            unit: "{boolean}");
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

    internal void ObserveNats(Func<NatsMonitoringAggregate> observe)
    {
        ArgumentNullException.ThrowIfNull(observe);
        if (Interlocked.CompareExchange(ref natsMonitoring, observe, null) is not null)
            throw new InvalidOperationException("NATS monitoring telemetry is already attached.");
    }

    /// <summary>
    /// Attaches the latest bounded operator projection. Workload gauges are deliberately
    /// sourced from this projection so desired, observed, ready, and convergence progress
    /// share the same authenticated state view as the operator-status endpoint.
    /// </summary>
    internal void ObserveOperatorStatus(Func<Operations.OperatorStatusDocument?> observe)
    {
        ArgumentNullException.ThrowIfNull(observe);
        if (Interlocked.CompareExchange(ref operatorStatusObserver, observe, null) is not null)
            throw new InvalidOperationException("Operator status telemetry is already attached.");
    }

    /// <summary>
    /// Records one NATS service endpoint request. Labels are the bounded endpoint
    /// enumeration and the result only — the requester, subject identity, and payload
    /// are never label dimensions.
    /// </summary>
    internal void RecordNatsServiceRequest(
        NatsServiceEndpointName endpoint,
        NatsServiceRequestResult result,
        double durationMilliseconds)
    {
        var tags = new TagList
        {
            { "service", "terrascale-orchestrator" },
            { "endpoint", EndpointLabel(endpoint) },
            { "result", result == NatsServiceRequestResult.Ok ? "ok" : "error" }
        };
        natsServiceRequestDuration.Record(durationMilliseconds, tags);
        natsServiceRequests.Add(1, tags);
        if (result == NatsServiceRequestResult.Error) natsServiceErrors.Add(1, tags);
    }

    /// <summary>
    /// Records message-delivery deltas between monitoring observations:
    /// delivered, redelivered, or duplicate-detected counts per bounded class pair.
    /// </summary>
    internal void RecordNatsMessages(
        NatsStreamClass streamClass,
        NatsConsumerClass consumerClass,
        string result,
        long count)
    {
        if (count <= 0) return;
        natsMessages.Add(count, new TagList
        {
            { "terrascale.cell", natsScope?.Cell ?? cell },
            { "plane", "control" },
            { "stream_class", streamClass.ToString().ToLowerInvariant() },
            { "consumer_class", consumerClass.ToString().ToLowerInvariant() },
            { "result", result }
        });
    }

    /// <summary>Records one observed advisory by its bounded canonical kind.</summary>
    internal void RecordNatsAdvisory(NatsAdvisoryKind kind, long count = 1)
    {
        if (count <= 0) return;
        natsAdvisories.Add(count, new TagList
        {
            { "terrascale.cell", natsScope?.Cell ?? cell },
            { "plane", "control" },
            { "result", kind.ToString().ToLowerInvariant() }
        });
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
        GC.KeepAlive(natsServiceRequests);
        GC.KeepAlive(natsServiceErrors);
        GC.KeepAlive(natsServiceRequestDuration);
        GC.KeepAlive(natsMessages);
        GC.KeepAlive(natsAdvisories);
        GC.KeepAlive(natsClientReconnects);
        GC.KeepAlive(natsConnections);
        GC.KeepAlive(natsRoutes);
        GC.KeepAlive(natsAccounts);
        GC.KeepAlive(natsGateways);
        GC.KeepAlive(natsJetStreamDomains);
        GC.KeepAlive(natsStreams);
        GC.KeepAlive(natsConsumers);
        GC.KeepAlive(natsConsumerLag);
        GC.KeepAlive(natsConsumerRedelivered);
        GC.KeepAlive(natsConsumerAckPending);
        GC.KeepAlive(natsFlowControlWaiting);
        GC.KeepAlive(natsStreamBytes);
        GC.KeepAlive(natsStreamDuplicates);
        GC.KeepAlive(natsKvWatches);
        GC.KeepAlive(natsObjectStoreObjects);
        GC.KeepAlive(natsObjectStoreBytes);
        GC.KeepAlive(natsServerMemory);
        GC.KeepAlive(natsStorageBytes);
        GC.KeepAlive(natsPartitionDuration);
        GC.KeepAlive(natsRecoveryDuration);
        GC.KeepAlive(natsCertificateExpiryDays);
        GC.KeepAlive(natsMonitoringAvailability);
        GC.KeepAlive(natsMeshCells);
        GC.KeepAlive(operatorDesiredReplicas);
        GC.KeepAlive(operatorObservedReplicas);
        GC.KeepAlive(operatorReadyReplicas);
        GC.KeepAlive(operatorProgressPercent);
        GC.KeepAlive(operatorMinReplicas);
        GC.KeepAlive(operatorMaxReplicas);
        GC.KeepAlive(operatorNeeds);
        GC.KeepAlive(operatorHealthy);
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

    private NatsMonitoringAggregate? CurrentNats()
    {
        var aggregate = Volatile.Read(ref natsMonitoring)?.Invoke();
        if (aggregate is not null) natsScope = aggregate;
        return aggregate;
    }

    private IEnumerable<Measurement<long>> ObserveNatsAggregate(
        Func<NatsMonitoringAggregate, long> select,
        Func<NatsMonitoringAggregate, TagList>? tags)
    {
        var aggregate = CurrentNats();
        if (aggregate is null || aggregate.Availability == NatsMonitoringAvailability.Unavailable) yield break;
        yield return new(select(aggregate), tags is null ? NatsScopeTags(aggregate) : tags(aggregate));
    }

    private static TagList NatsScopeTags(NatsMonitoringAggregate aggregate) => new()
    {
        { "terrascale.cell", aggregate.Cell },
        { "plane", NatsMonitoringLabels.Plane(aggregate.Plane) }
    };

    private IEnumerable<Measurement<long>> ObserveNatsGateways()
    {
        var aggregate = CurrentNats();
        if (aggregate is null || aggregate.Availability == NatsMonitoringAvailability.Unavailable) yield break;
        var connected = NatsScopeTags(aggregate);
        connected.Add("state", "connected");
        yield return new(aggregate.GatewaysConnected, connected);
        var disconnected = NatsScopeTags(aggregate);
        disconnected.Add("state", "disconnected");
        yield return new(aggregate.GatewaysDisconnected, disconnected);
    }

    private IEnumerable<Measurement<long>> ObserveNatsStreams()
    {
        var aggregate = CurrentNats();
        if (aggregate is null || aggregate.Availability == NatsMonitoringAvailability.Unavailable) yield break;
        foreach (var stream in aggregate.StreamsByClass)
        {
            var tags = NatsScopeTags(aggregate);
            tags.Add("stream_class", NatsMonitoringLabels.StreamClass(stream.StreamClass));
            yield return new(stream.Streams, tags);
        }
    }

    private IEnumerable<Measurement<long>> ObserveNatsConsumers() =>
        ObserveNatsConsumerMetric(static consumer => consumer.Consumers);

    private IEnumerable<Measurement<long>> ObserveNatsConsumerMetric(
        Func<NatsConsumerClassState, long> select)
    {
        var aggregate = CurrentNats();
        if (aggregate is null || aggregate.Availability == NatsMonitoringAvailability.Unavailable) yield break;
        foreach (var consumer in aggregate.ConsumersByClass)
        {
            var tags = NatsScopeTags(aggregate);
            tags.Add("stream_class", NatsMonitoringLabels.StreamClass(consumer.StreamClass));
            tags.Add("consumer_class", NatsMonitoringLabels.ConsumerClass(consumer.ConsumerClass));
            yield return new(select(consumer), tags);
        }
    }

    private IEnumerable<Measurement<long>> ObserveNatsStreamBytes()
    {
        var aggregate = CurrentNats();
        if (aggregate is null || aggregate.Availability == NatsMonitoringAvailability.Unavailable) yield break;
        foreach (var stream in aggregate.StreamsByClass)
        {
            var tags = NatsScopeTags(aggregate);
            tags.Add("stream_class", NatsMonitoringLabels.StreamClass(stream.StreamClass));
            yield return new(stream.Bytes, tags);
        }
    }

    private IEnumerable<Measurement<long>> ObserveNatsStreamDuplicates()
    {
        var aggregate = CurrentNats();
        if (aggregate is null || aggregate.Availability == NatsMonitoringAvailability.Unavailable) yield break;
        foreach (var stream in aggregate.StreamsByClass.Where(static stream => stream.Duplicates > 0))
        {
            var tags = NatsScopeTags(aggregate);
            tags.Add("stream_class", NatsMonitoringLabels.StreamClass(stream.StreamClass));
            yield return new(stream.Duplicates, tags);
        }
    }

    private IEnumerable<Measurement<long>> ObserveNatsStores()
    {
        var aggregate = CurrentNats();
        if (aggregate is null || aggregate.Availability == NatsMonitoringAvailability.Unavailable) yield break;
        foreach (var store in aggregate.StoresByClass.Where(static store => store.StoreClass == NatsStoreClass.KeyValue))
        {
            var tags = NatsScopeTags(aggregate);
            tags.Add("store_class", NatsMonitoringLabels.StoreClass(store.StoreClass));
            yield return new(store.Watches, tags);
        }
    }

    private IEnumerable<Measurement<long>> ObserveNatsObjectStoreObjects()
    {
        var aggregate = CurrentNats();
        if (aggregate is null || aggregate.Availability == NatsMonitoringAvailability.Unavailable) yield break;
        foreach (var store in aggregate.StoresByClass.Where(static store => store.StoreClass == NatsStoreClass.ObjectStore))
        {
            var tags = NatsScopeTags(aggregate);
            tags.Add("store_class", NatsMonitoringLabels.StoreClass(store.StoreClass));
            yield return new(store.Objects, tags);
        }
    }

    private IEnumerable<Measurement<long>> ObserveNatsObjectStoreBytes()
    {
        var aggregate = CurrentNats();
        if (aggregate is null || aggregate.Availability == NatsMonitoringAvailability.Unavailable) yield break;
        foreach (var store in aggregate.StoresByClass.Where(static store => store.StoreClass == NatsStoreClass.ObjectStore))
        {
            var tags = NatsScopeTags(aggregate);
            tags.Add("store_class", NatsMonitoringLabels.StoreClass(store.StoreClass));
            yield return new(store.Bytes, tags);
        }
    }

    private IEnumerable<Measurement<long>> ObserveNatsCertificates()
    {
        var aggregate = CurrentNats();
        if (aggregate is null) yield break;
        foreach (var certificate in aggregate.Certificates)
        {
            var tags = NatsScopeTags(aggregate);
            tags.Add("certificate_class", NatsMonitoringLabels.CertificateClass(certificate.CertificateClass));
            yield return new(certificate.RemainingDays(aggregate.ObservedAt), tags);
        }
    }

    private IEnumerable<Measurement<long>> ObserveNatsAvailability()
    {
        var aggregate = CurrentNats();
        if (aggregate is null) yield break;
        var tags = NatsScopeTags(aggregate);
        tags.Add("condition", NatsMonitoringLabels.Availability(aggregate.Availability));
        // The truthful self-report always exists: 1 available, 0 degraded, -1 unavailable.
        yield return new(
            aggregate.Availability switch
            {
                NatsMonitoringAvailability.Available => 1,
                NatsMonitoringAvailability.Degraded => 0,
                _ => -1
            },
            tags);
    }

    private IEnumerable<Measurement<long>> ObserveNatsMeshCells()
    {
        var aggregate = CurrentNats();
        if (aggregate is null || aggregate.Availability == NatsMonitoringAvailability.Unavailable) yield break;
        foreach (var meshCell in aggregate.Mesh.Cells)
        {
            var tags = NatsScopeTags(aggregate);
            tags.Add("state", NatsMonitoringLabels.MeshState(meshCell.State));
            yield return new(1, tags);
        }
    }

    private IEnumerable<Measurement<long>> ObserveOperatorWorkloads(
        Func<Operations.OperatorWorkloadStatus, int> select)
    {
        var snapshot = Volatile.Read(ref operatorStatusObserver)?.Invoke();
        if (snapshot is null) yield break;
        foreach (var workload in snapshot.Workloads)
        {
            var descriptor = AdmittedRoleCatalog.All.FirstOrDefault(candidate =>
                candidate.ArtifactKey == workload.Workload &&
                candidate.Role.ToString() == workload.Role);
            var workloadLabel = descriptor?.ArtifactKey ?? "other";
            var roleLabel = descriptor?.Role.ToString().ToLowerInvariant() ?? "other";
            var stateLabel = workload.State switch
            {
                "ready" or "converging" or "pending" or "waiting-for-desired-state" => workload.State,
                _ => "other"
            };
            var tags = new TagList
            {
                { "terrascale.cell", snapshot.Cell },
                { "workload", workloadLabel },
                { "role", roleLabel },
                { "state", stateLabel },
                { "scale_action", workload.PendingScaleAction }
            };
            yield return new(select(workload), tags);
        }
    }

    private static string EndpointLabel(NatsServiceEndpointName endpoint) =>
        endpoint switch
        {
            NatsServiceEndpointName.Health => "health",
            NatsServiceEndpointName.InstanceHealth => "instance_health",
            NatsServiceEndpointName.Status => "status",
            NatsServiceEndpointName.Members => "members",
            NatsServiceEndpointName.Stats => "stats",
            NatsServiceEndpointName.DirectDelivery => "direct_delivery",
            NatsServiceEndpointName.OperatorStatus => "operator_status",
            _ => throw new ArgumentOutOfRangeException(nameof(endpoint))
        };
}
