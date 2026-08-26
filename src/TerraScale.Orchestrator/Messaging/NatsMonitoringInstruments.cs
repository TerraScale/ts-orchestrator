using System.Collections.ObjectModel;
using System.Text.Json.Serialization;
using TerraScale.Orchestrator.Protocol.Messaging;

namespace TerraScale.Orchestrator.Messaging;

internal enum NatsMonitoringInstrumentKind
{
    Counter = 1,
    Gauge = 2,
    Histogram = 3
}

internal enum NatsMonitoringAlertSeverity
{
    Warning = 1,
    Critical = 2
}

/// <summary>
/// One canonical NATS monitoring instrument: its meter name, unit, bounded label
/// keys, the exact monitoring subject(s) it is sourced from, and what it does when
/// its source fails. This catalog is the snapshot evidence the dashboards and the
/// alert catalog are built from, and the pure cardinality tests assert against.
/// </summary>
internal sealed record NatsMonitoringInstrument
{
    internal NatsMonitoringInstrument(
        string name,
        string unit,
        NatsMonitoringInstrumentKind kind,
        IReadOnlyList<string> labelKeys,
        IReadOnlyList<string> sourceSubjects,
        string failureBehavior)
    {
        Name = ValidateName(name);
        Unit = unit;
        Kind = kind;
        LabelKeys = Array.AsReadOnly(labelKeys.ToArray());
        SourceSubjects = Array.AsReadOnly(sourceSubjects.ToArray());
        FailureBehavior = failureBehavior;
        foreach (var key in LabelKeys)
            if (!NatsMonitoringLabels.IsAllowedLabelKey(key))
                throw new ArgumentException($"The instrument '{name}' uses the unbounded label key '{key}'.");
        if (LabelKeys.Distinct(StringComparer.Ordinal).Count() != LabelKeys.Count)
            throw new ArgumentException("An instrument may not repeat a label key.");
    }

    internal string Name { get; }
    internal string Unit { get; }
    internal NatsMonitoringInstrumentKind Kind { get; }
    internal ReadOnlyCollection<string> LabelKeys { get; }
    internal ReadOnlyCollection<string> SourceSubjects { get; }
    internal string FailureBehavior { get; }

    internal static string ValidateName(string name)
    {
        if (name is not { Length: > 0 } ||
            !name.StartsWith("terrascale.orchestrator.nats.", StringComparison.Ordinal) ||
            !name.All(static character =>
                character is >= 'a' and <= 'z' or '.' or '_'))
            throw new ArgumentException("A NATS monitoring instrument name must be rooted and bounded.");
        return name;
    }
}

/// <summary>
/// The closed set of label keys NATS monitoring may use. The landed process telemetry
/// keys (<c>terrascale.cell</c>, <c>condition</c>, <c>state</c>, <c>outcome</c>) stay;
/// the NATS additions are plane, cluster role, service, endpoint, stream class,
/// consumer class, store class, certificate class, and result. Instance, session,
/// NKey, message, and operation identifiers are not label keys and every value
/// domain is a bounded enumeration or cell token.
/// </summary>
internal static class NatsMonitoringLabels
{
    internal static readonly IReadOnlyList<string> AllowedKeys =
    [
        "terrascale.cell",
        "plane",
        "cluster_role",
        "service",
        "endpoint",
        "stream_class",
        "consumer_class",
        "store_class",
        "certificate_class",
        "result",
        "state",
        "condition",
        "outcome"
    ];

    /// <summary>Label key fragments that must never appear in any label key.</summary>
    internal static readonly IReadOnlyList<string> ForbiddenKeyFragments =
    [
        "instance",
        "session",
        "nkey",
        "message",
        "operation",
        "consumer_name",
        "stream_name",
        "cid",
        "subject"
    ];

    internal static bool IsAllowedLabelKey(string key) =>
        AllowedKeys.Contains(key, StringComparer.Ordinal);

    internal static string Plane(NatsMonitoringPlane plane) =>
        plane switch
        {
            NatsMonitoringPlane.Control => "control",
            NatsMonitoringPlane.Product => "product",
            _ => throw new ArgumentOutOfRangeException(nameof(plane))
        };

    internal static string ClusterRole(NatsClusterRole role) =>
        role switch
        {
            NatsClusterRole.Regional => "regional",
            NatsClusterRole.GlobalAuthority => "global-authority",
            _ => throw new ArgumentOutOfRangeException(nameof(role))
        };

    internal static string StreamClass(NatsStreamClass streamClass) =>
        streamClass.ToString().ToLowerInvariant();

    internal static string ConsumerClass(NatsConsumerClass consumerClass) =>
        consumerClass.ToString().ToLowerInvariant();

    internal static string StoreClass(NatsStoreClass storeClass) =>
        storeClass.ToString().ToLowerInvariant();

    internal static string CertificateClass(NatsCertificateClass certificateClass) =>
        certificateClass.ToString().ToLowerInvariant();

    internal static string Availability(NatsMonitoringAvailability availability) =>
        availability switch
        {
            NatsMonitoringAvailability.Available => "available",
            NatsMonitoringAvailability.Degraded => "degraded",
            NatsMonitoringAvailability.Unavailable => "unavailable",
            _ => throw new ArgumentOutOfRangeException(nameof(availability))
        };

    internal static string MeshState(NatsMeshCellState state) =>
        state.ToString().ToLowerInvariant();
}

/// <summary>
/// The canonical NATS monitoring instrument catalog: every instrument, its unit,
/// its bounded label keys, its source subject, and its failure behavior. The
/// telemetry meter and this catalog must stay in lockstep — a pure test asserts the
/// meter creates exactly these instruments with exactly these units.
/// </summary>
internal static class NatsMonitoringInstrumentCatalog
{
    private static readonly string[] ServiceRequestLabels = ["service", "endpoint", "result"];
    private static readonly string[] MonitoringScopeLabels = ["terrascale.cell", "plane"];

    internal static readonly IReadOnlyList<NatsMonitoringInstrument> Instruments =
    [
        new(
            "terrascale.orchestrator.nats.service.requests",
            "{request}",
            NatsMonitoringInstrumentKind.Counter,
            ServiceRequestLabels,
            [],
            "Absent until the first request; the controller's own service endpoints never depend on it."),
        new(
            "terrascale.orchestrator.nats.service.errors",
            "{error}",
            NatsMonitoringInstrumentKind.Counter,
            ServiceRequestLabels,
            [],
            "Absent until the first error; errors never suppress the endpoint itself."),
        new(
            "terrascale.orchestrator.nats.service.request.duration",
            "ms",
            NatsMonitoringInstrumentKind.Histogram,
            ServiceRequestLabels,
            [],
            "Absent until the first request; latency is also served by the read-only stats service endpoint."),
        new(
            "terrascale.orchestrator.nats.client.reconnects",
            "{reconnect}",
            NatsMonitoringInstrumentKind.Gauge,
            MonitoringScopeLabels,
            [NatsMonitoringSubjects.Connections],
            "Holds the last observed value; supervision marks the availability gauge degraded or unavailable instead of guessing."),
        new(
            "terrascale.orchestrator.nats.connections",
            "{connection}",
            NatsMonitoringInstrumentKind.Gauge,
            MonitoringScopeLabels,
            [NatsMonitoringSubjects.Connections],
            "Holds the last observed value while degraded; disappears when unavailable."),
        new(
            "terrascale.orchestrator.nats.routes",
            "{route}",
            NatsMonitoringInstrumentKind.Gauge,
            MonitoringScopeLabels,
            [NatsMonitoringSubjects.Routes],
            "Holds the last observed value while degraded; disappears when unavailable."),
        new(
            "terrascale.orchestrator.nats.gateways",
            "{gateway}",
            NatsMonitoringInstrumentKind.Gauge,
            ["terrascale.cell", "plane", "state"],
            [NatsMonitoringSubjects.Gateways],
            "Disconnected counts keep updating; a fully unreachable server freezes the last mesh observation and marks availability degraded."),
        new(
            "terrascale.orchestrator.nats.accounts",
            "{account}",
            NatsMonitoringInstrumentKind.Gauge,
            MonitoringScopeLabels,
            [NatsMonitoringSubjects.Accounts],
            "Holds the last observed value while degraded; disappears when unavailable."),
        new(
            "terrascale.orchestrator.nats.jetstream.domains",
            "{domain}",
            NatsMonitoringInstrumentKind.Gauge,
            MonitoringScopeLabels,
            [NatsMonitoringSubjects.JetStream],
            "Holds the last observed value while degraded; disappears when unavailable."),
        new(
            "terrascale.orchestrator.nats.streams",
            "{stream}",
            NatsMonitoringInstrumentKind.Gauge,
            ["terrascale.cell", "plane", "stream_class"],
            [NatsMonitoringSubjects.JetStream],
            "Per-class counts disappear for classes that stop reporting; the total is never interpolated."),
        new(
            "terrascale.orchestrator.nats.consumers",
            "{consumer}",
            NatsMonitoringInstrumentKind.Gauge,
            ["terrascale.cell", "plane", "stream_class", "consumer_class"],
            [NatsMonitoringSubjects.JetStream],
            "Per-class counts disappear for classes that stop reporting."),
        new(
            "terrascale.orchestrator.nats.consumer.lag",
            "{message}",
            NatsMonitoringInstrumentKind.Gauge,
            ["terrascale.cell", "plane", "stream_class", "consumer_class"],
            [NatsMonitoringSubjects.JetStream],
            "Holds the last observed lag; a monitoring outage never fabricates zero lag."),
        new(
            "terrascale.orchestrator.nats.consumer.redelivered",
            "{message}",
            NatsMonitoringInstrumentKind.Gauge,
            ["terrascale.cell", "plane", "stream_class", "consumer_class"],
            [NatsMonitoringSubjects.JetStream],
            "Holds the last observed count; never reset by a monitoring restart."),
        new(
            "terrascale.orchestrator.nats.consumer.ack_pending",
            "{message}",
            NatsMonitoringInstrumentKind.Gauge,
            ["terrascale.cell", "plane", "stream_class", "consumer_class"],
            [NatsMonitoringSubjects.JetStream],
            "Holds the last observed count; never reset by a monitoring restart."),
        new(
            "terrascale.orchestrator.nats.flowcontrol.waiting",
            "{consumer}",
            NatsMonitoringInstrumentKind.Gauge,
            ["terrascale.cell", "plane", "stream_class", "consumer_class"],
            [NatsMonitoringSubjects.JetStream],
            "Holds the last observed count; pressure alerts treat a stale gauge as unknown, not zero."),
        new(
            "terrascale.orchestrator.nats.messages",
            "{message}",
            NatsMonitoringInstrumentKind.Counter,
            ["terrascale.cell", "plane", "stream_class", "consumer_class", "result"],
            [NatsMonitoringSubjects.JetStream],
            "Monotone delivery/redelivery/duplicate deltas between observations; an observation gap pauses the counter without backfill."),
        new(
            "terrascale.orchestrator.nats.stream.bytes",
            "By",
            NatsMonitoringInstrumentKind.Gauge,
            ["terrascale.cell", "plane", "stream_class"],
            [NatsMonitoringSubjects.JetStream],
            "Per-class bytes disappear for classes that stop reporting."),
        new(
            "terrascale.orchestrator.nats.stream.duplicates",
            "{message}",
            NatsMonitoringInstrumentKind.Gauge,
            ["terrascale.cell", "plane", "stream_class"],
            [NatsMonitoringSubjects.JetStream],
            "Application-level message-ID deduplication counts; absent when no deduplication ran."),
        new(
            "terrascale.orchestrator.nats.kv.watches",
            "{watch}",
            NatsMonitoringInstrumentKind.Gauge,
            ["terrascale.cell", "plane", "store_class"],
            [NatsMonitoringSubjects.JetStream],
            "Holds the last observed value while degraded."),
        new(
            "terrascale.orchestrator.nats.objectstore.objects",
            "{object}",
            NatsMonitoringInstrumentKind.Gauge,
            ["terrascale.cell", "plane", "store_class"],
            [NatsMonitoringSubjects.JetStream],
            "Holds the last observed value while degraded."),
        new(
            "terrascale.orchestrator.nats.objectstore.bytes",
            "By",
            NatsMonitoringInstrumentKind.Gauge,
            ["terrascale.cell", "plane", "store_class"],
            [NatsMonitoringSubjects.JetStream],
            "Holds the last observed value while degraded."),
        new(
            "terrascale.orchestrator.nats.server.memory",
            "By",
            NatsMonitoringInstrumentKind.Gauge,
            MonitoringScopeLabels,
            [NatsMonitoringSubjects.Server],
            "Holds the last observed value while degraded; disappears when unavailable."),
        new(
            "terrascale.orchestrator.nats.storage.bytes",
            "By",
            NatsMonitoringInstrumentKind.Gauge,
            MonitoringScopeLabels,
            [NatsMonitoringSubjects.Server, NatsMonitoringSubjects.JetStream],
            "Holds the last observed value while degraded; disappears when unavailable."),
        new(
            "terrascale.orchestrator.nats.partition.duration",
            "ms",
            NatsMonitoringInstrumentKind.Gauge,
            MonitoringScopeLabels,
            [NatsMonitoringSubjects.Gateways],
            "Zero while connected; grows while the mesh reports a full gateway partition; resets to zero on recovery, which is the recovery-duration signal."),
        new(
            "terrascale.orchestrator.nats.recovery.duration",
            "ms",
            NatsMonitoringInstrumentKind.Gauge,
            MonitoringScopeLabels,
            [NatsMonitoringSubjects.Gateways],
            "Holds the last completed recovery duration; zero before the first recovery."),
        new(
            "terrascale.orchestrator.nats.certificate.expiry.days",
            "d",
            NatsMonitoringInstrumentKind.Gauge,
            ["terrascale.cell", "plane", "certificate_class"],
            [],
            "Sourced from the monitoring identity's own credentials and rendered server configuration; missing certificates are absent, not zero."),
        new(
            "terrascale.orchestrator.nats.monitoring.availability",
            "{boolean}",
            NatsMonitoringInstrumentKind.Gauge,
            ["terrascale.cell", "plane", "condition"],
            [],
            "The truthful self-report: available, degraded, or unavailable. This is the only signal guaranteed to exist."),
        new(
            "terrascale.orchestrator.nats.mesh.cells",
            "{cell}",
            NatsMonitoringInstrumentKind.Gauge,
            ["terrascale.cell", "plane", "state"],
            [NatsSubjectTaxonomy.GlobalDirectoryQuerySubject],
            "Mesh states compose the landed directory and membership aggregates plus gateway links; a lost directory degrades to disconnected or stale, never fabricated health."),
        new(
            "terrascale.orchestrator.nats.advisories",
            "{advisory}",
            NatsMonitoringInstrumentKind.Counter,
            ["terrascale.cell", "plane", "result"],
            [NatsMonitoringSubjects.AccountAdvisories, NatsMonitoringSubjects.JetStreamAdvisories],
            "Advisory loss pauses the counter and degrades availability; it never fabricates counts and never affects control."),
    ];

    internal static NatsMonitoringInstrument Require(string name) =>
        Instruments.FirstOrDefault(instrument => instrument.Name == name) ??
        throw new InvalidOperationException($"The NATS monitoring instrument '{name}' is not cataloged.");
}

/// <summary>A typed alert-rule descriptor tied to canonical failure and recovery states.</summary>
internal sealed record NatsMonitoringAlertRule
{
    internal NatsMonitoringAlertRule(
        string id,
        string description,
        NatsMonitoringAlertSeverity severity,
        IReadOnlyList<string> instrumentNames,
        string firesWhen,
        string recoveryWhen,
        string runbook)
    {
        Id = id;
        Description = description;
        Severity = severity;
        InstrumentNames = Array.AsReadOnly(instrumentNames.ToArray());
        FiresWhen = firesWhen;
        RecoveryWhen = recoveryWhen;
        Runbook = runbook;
        foreach (var name in InstrumentNames)
            NatsMonitoringInstrumentCatalog.Require(name);
        if (InstrumentNames.Count == 0) throw new ArgumentException("An alert rule must reference at least one instrument.");
        if (InstrumentNames.Distinct(StringComparer.Ordinal).Count() != InstrumentNames.Count)
            throw new ArgumentException("An alert rule may not repeat an instrument.");
    }

    internal string Id { get; }
    internal string Description { get; }
    internal NatsMonitoringAlertSeverity Severity { get; }
    internal ReadOnlyCollection<string> InstrumentNames { get; }
    internal string FiresWhen { get; }
    internal string RecoveryWhen { get; }
    internal string Runbook { get; }
}

/// <summary>
/// Actionable NATS alert conditions, each bound to catalog instruments and to a
/// canonical failure state with an explicit recovery condition. The catalog is
/// declarative only: rendering it into a live alerting stack is a separate,
/// approved operation.
/// </summary>
internal static class NatsAlertCatalog
{
    internal static readonly IReadOnlyList<NatsMonitoringAlertRule> Rules =
    [
        new(
            "nats.gateway.partition",
            "A cell's gateway links are all down: the region is isolated from the mesh and must run on regional autonomy.",
            NatsMonitoringAlertSeverity.Critical,
            ["terrascale.orchestrator.nats.partition.duration", "terrascale.orchestrator.nats.mesh.cells"],
            "partition duration > 0 for more than 30s and mesh state disconnected for that cell",
            "partition duration returns to 0 and mesh state is healthy or stale",
            "runbooks/nats-gateway-operations.md"),
        new(
            "nats.gateway.recovery.slow",
            "A healed gateway partition did not reconverge within the recovery window.",
            NatsMonitoringAlertSeverity.Warning,
            ["terrascale.orchestrator.nats.recovery.duration"],
            "recovery duration exceeds 30s after links report connected",
            "recovery duration falls below 30s and mesh state is healthy",
            "runbooks/nats-gateway-operations.md"),
        new(
            "nats.consumer.lag",
            "Consumer lag is growing for a stream class.",
            NatsMonitoringAlertSeverity.Warning,
            ["terrascale.orchestrator.nats.consumer.lag"],
            "lag > 1000 {message} for 2 minutes on any stream/consumer class",
            "lag < 100 {message} for 5 minutes",
            "runbooks/nats-monitoring.md"),
        new(
            "nats.consumer.redelivery.storm",
            "Redeliveries dominate deliveries for a consumer class.",
            NatsMonitoringAlertSeverity.Warning,
            ["terrascale.orchestrator.nats.consumer.redelivered", "terrascale.orchestrator.nats.messages"],
            "redelivered grows faster than deliveries for 5 minutes",
            "redelivery delta returns to zero for 5 minutes",
            "runbooks/nats-monitoring.md"),
        new(
            "nats.flowcontrol.pressure",
            "Consumers are not keeping up and are holding the stream back via flow control.",
            NatsMonitoringAlertSeverity.Warning,
            ["terrascale.orchestrator.nats.flowcontrol.waiting"],
            "waiting > 0 for 5 minutes on any consumer class",
            "waiting == 0 for 5 minutes",
            "runbooks/nats-monitoring.md"),
        new(
            "nats.storage.pressure",
            "JetStream storage is approaching its declared limit.",
            NatsMonitoringAlertSeverity.Warning,
            ["terrascale.orchestrator.nats.storage.bytes", "terrascale.orchestrator.nats.stream.bytes"],
            "storage bytes exceed 80% of the topology-declared limit for 10 minutes",
            "storage bytes fall below 70% of the declared limit",
            "runbooks/nats-monitoring.md"),
        new(
            "nats.server.memory.pressure",
            "Server process memory is rising toward the container limit.",
            NatsMonitoringAlertSeverity.Warning,
            ["terrascale.orchestrator.nats.server.memory"],
            "memory exceeds 80% of the per-server container limit for 10 minutes",
            "memory falls below 70% of the container limit",
            "runbooks/nats-monitoring.md"),
        new(
            "nats.certificate.expiry.risk",
            "A TLS certificate inside the NATS plane expires soon.",
            NatsMonitoringAlertSeverity.Critical,
            ["terrascale.orchestrator.nats.certificate.expiry.days"],
            "remaining days < 30 for any certificate class",
            "certificate is rotated and remaining days > 30",
            "runbooks/nats-gateway-operations.md"),
        new(
            "nats.advisory.slow.consumer",
            "The server reports slow consumers.",
            NatsMonitoringAlertSeverity.Warning,
            ["terrascale.orchestrator.nats.advisories"],
            "slow-consumer advisory count increases",
            "no new slow-consumer advisories for 15 minutes",
            "runbooks/nats-monitoring.md"),
        new(
            "nats.advisory.leader.change",
            "A JetStream or authority leader changed — check for quorum loss.",
            NatsMonitoringAlertSeverity.Critical,
            ["terrascale.orchestrator.nats.advisories", "terrascale.orchestrator.nats.mesh.cells"],
            "leader-change advisory count increases and mesh state degrades",
            "mesh state returns to healthy with a stable leader",
            "runbooks/nats-gateway-operations.md"),
        new(
            "nats.mesh.conflicting",
            "A cell reports conflicting controller sessions.",
            NatsMonitoringAlertSeverity.Critical,
            ["terrascale.orchestrator.nats.mesh.cells"],
            "mesh state conflicting for any cell",
            "mesh state returns to healthy after the conflict resolves on renewal",
            "runbooks/nats-gateway-operations.md"),
        new(
            "nats.monitoring.unavailable",
            "NATS observability itself is blind: the last signal is too old to trust.",
            NatsMonitoringAlertSeverity.Warning,
            ["terrascale.orchestrator.nats.monitoring.availability"],
            "availability condition is unavailable for 2 minutes",
            "availability condition returns to available",
            "runbooks/nats-monitoring.md"),
    ];
}

/// <summary>
/// One typed metric snapshot entry the Grafana/Prometheus-facing projection serves:
/// instrument name, unit, label set, value, source subject, and failure behavior.
/// The snapshot is the bounded interface between the Orchestrator and whatever
/// renders dashboards; it contains no identity beyond bounded class and cell labels.
/// </summary>
internal sealed record NatsMonitoringSnapshotEntry
{
    /// <summary>
    /// The label-value length cap. It matches the longest legal label value the
    /// model can produce: a cell token, which the canonical DNS-style cell rule
    /// bounds at 63 characters. Every other label value is a short enum token.
    /// </summary>
    internal const int MaximumLabelValueLength = 63;

    internal NatsMonitoringSnapshotEntry(
        string instrument,
        string unit,
        IReadOnlyDictionary<string, string> labels,
        double value)
    {
        Instrument = NatsMonitoringInstrumentCatalog.Require(instrument).Name;
        Unit = unit;
        var bounded = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var label in labels)
        {
            if (!NatsMonitoringLabels.IsAllowedLabelKey(label.Key))
                throw new ArgumentException($"The snapshot entry uses the unbounded label key '{label.Key}'.");
            if (label.Value.Length > MaximumLabelValueLength)
                throw new ArgumentException("A snapshot label value exceeds the bounded length.");
            bounded.Add(label.Key, label.Value);
        }
        Labels = new ReadOnlyDictionary<string, string>(bounded);
        Value = value;
    }

    internal string Instrument { get; }
    internal string Unit { get; }
    internal IReadOnlyDictionary<string, string> Labels { get; }
    internal double Value { get; }
}

internal sealed record NatsMonitoringSnapshot(
    int SchemaVersion,
    string Cell,
    DateTimeOffset ObservedAt,
    NatsMonitoringAvailability Availability,
    IReadOnlyList<NatsMonitoringSnapshotEntry> Entries)
{
    internal static readonly int CurrentSchemaVersion = 1;

    /// <summary>
    /// Projects the bounded aggregate into the dashboard-facing snapshot: one entry
    /// per instrument series the current aggregate can truthfully support. Series
    /// whose source did not report are omitted, never zero-filled.
    /// </summary>
    internal static NatsMonitoringSnapshot From(NatsMonitoringAggregate aggregate)
    {
        ArgumentNullException.ThrowIfNull(aggregate);
        aggregate.Validate();
        var entries = new List<NatsMonitoringSnapshotEntry>();
        var scope = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["terrascale.cell"] = aggregate.Cell,
            ["plane"] = NatsMonitoringLabels.Plane(aggregate.Plane)
        };
        void Gauge(string instrument, double value, IReadOnlyDictionary<string, string>? labels = null)
        {
            var catalog = NatsMonitoringInstrumentCatalog.Require(instrument);
            var merged = labels is null
                ? scope
                : new Dictionary<string, string>(scope.Concat(labels), StringComparer.Ordinal);
            entries.Add(new NatsMonitoringSnapshotEntry(catalog.Name, catalog.Unit, merged, value));
        }

        Gauge("terrascale.orchestrator.nats.monitoring.availability", aggregate.Availability switch
        {
            NatsMonitoringAvailability.Available => 1,
            NatsMonitoringAvailability.Degraded => 0,
            _ => -1
        }, new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["condition"] = NatsMonitoringLabels.Availability(aggregate.Availability)
        });
        if (aggregate.Availability == NatsMonitoringAvailability.Unavailable)
            return new(CurrentSchemaVersion, aggregate.Cell, aggregate.ObservedAt, aggregate.Availability, entries);

        Gauge("terrascale.orchestrator.nats.connections", aggregate.Connections);
        Gauge("terrascale.orchestrator.nats.client.reconnects", aggregate.Reconnects);
        Gauge("terrascale.orchestrator.nats.routes", aggregate.Routes);
        Gauge("terrascale.orchestrator.nats.accounts", aggregate.Accounts);
        Gauge("terrascale.orchestrator.nats.jetstream.domains", aggregate.JetStreamDomains);
        Gauge("terrascale.orchestrator.nats.server.memory", aggregate.ServerMemoryBytes);
        Gauge("terrascale.orchestrator.nats.storage.bytes", aggregate.JetStreamStorageBytes);
        Gauge("terrascale.orchestrator.nats.partition.duration", aggregate.PartitionDurationMilliseconds);
        Gauge("terrascale.orchestrator.nats.recovery.duration", aggregate.RecoveryDurationMilliseconds);
        Gauge(
            "terrascale.orchestrator.nats.gateways",
            aggregate.GatewaysConnected,
            new Dictionary<string, string>(StringComparer.Ordinal) { ["state"] = "connected" });
        Gauge(
            "terrascale.orchestrator.nats.gateways",
            aggregate.GatewaysDisconnected,
            new Dictionary<string, string>(StringComparer.Ordinal) { ["state"] = "disconnected" });
        foreach (var group in new[]
                 {
                     (aggregate.Mesh.HealthyCells, NatsMeshCellState.Healthy),
                     (aggregate.Mesh.StaleCells, NatsMeshCellState.Stale),
                     (aggregate.Mesh.MissingCells, NatsMeshCellState.Missing),
                     (aggregate.Mesh.ConflictingCells, NatsMeshCellState.Conflicting),
                     (aggregate.Mesh.DisconnectedCells, NatsMeshCellState.Disconnected)
                 })
            Gauge(
                "terrascale.orchestrator.nats.mesh.cells",
                group.Item1,
                new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["state"] = NatsMonitoringLabels.MeshState(group.Item2)
                });
        foreach (var stream in aggregate.StreamsByClass)
        {
            var labels = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["stream_class"] = NatsMonitoringLabels.StreamClass(stream.StreamClass)
            };
            Gauge("terrascale.orchestrator.nats.streams", stream.Streams, labels);
            Gauge("terrascale.orchestrator.nats.stream.bytes", stream.Bytes, labels);
            Gauge("terrascale.orchestrator.nats.stream.duplicates", stream.Duplicates, labels);
        }
        foreach (var consumer in aggregate.ConsumersByClass)
        {
            var labels = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["stream_class"] = NatsMonitoringLabels.StreamClass(consumer.StreamClass),
                ["consumer_class"] = NatsMonitoringLabels.ConsumerClass(consumer.ConsumerClass)
            };
            Gauge("terrascale.orchestrator.nats.consumers", consumer.Consumers, labels);
            Gauge("terrascale.orchestrator.nats.consumer.lag", consumer.Lag, labels);
            Gauge("terrascale.orchestrator.nats.consumer.redelivered", consumer.Redelivered, labels);
            Gauge("terrascale.orchestrator.nats.consumer.ack_pending", consumer.AckPending, labels);
            Gauge("terrascale.orchestrator.nats.flowcontrol.waiting", consumer.Waiting, labels);
        }
        foreach (var store in aggregate.StoresByClass)
        {
            var labels = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["store_class"] = NatsMonitoringLabels.StoreClass(store.StoreClass)
            };
            Gauge("terrascale.orchestrator.nats.kv.watches", store.Watches, labels);
            Gauge("terrascale.orchestrator.nats.objectstore.objects", store.Objects, labels);
            Gauge("terrascale.orchestrator.nats.objectstore.bytes", store.Bytes, labels);
        }
        foreach (var certificate in aggregate.Certificates)
            Gauge(
                "terrascale.orchestrator.nats.certificate.expiry.days",
                certificate.RemainingDays(aggregate.ObservedAt),
                new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["certificate_class"] = NatsMonitoringLabels.CertificateClass(certificate.CertificateClass)
                });
        var snapshot = new NatsMonitoringSnapshot(
            CurrentSchemaVersion,
            aggregate.Cell,
            aggregate.ObservedAt,
            aggregate.Availability,
            entries);
        snapshot.Validate();
        return snapshot;
    }

    internal void Validate()
    {
        if (SchemaVersion != CurrentSchemaVersion || !CellTokenRule.IsValid(Cell) ||
            ObservedAt == default || !Enum.IsDefined(Availability) ||
            Entries.Select(static entry => (entry.Instrument, string.Join(',', entry.Labels.Select(static label => $"{label.Key}={label.Value}").Order(StringComparer.Ordinal))))
                .Distinct().Count() != Entries.Count)
            throw new InvalidOperationException("The NATS monitoring snapshot is invalid.");
        foreach (var entry in Entries)
        foreach (var label in entry.Labels)
            if (label.Value.Length > NatsMonitoringSnapshotEntry.MaximumLabelValueLength)
                throw new InvalidOperationException("The NATS monitoring snapshot contains an unbounded label value.");
    }

    /// <summary>
    /// Renders the snapshot as Prometheus text exposition — the bounded format the
    /// dashboards can scrape — with unit-suffixed names and sorted labels. Label
    /// values are escaped for the exposition format, and only cataloged
    /// instruments and bounded labels are representable here.
    /// </summary>
    internal string RenderPrometheus()
    {
        Validate();
        var lines = new List<string>();
        foreach (var group in Entries.GroupBy(static entry => entry.Instrument, StringComparer.Ordinal)
                     .OrderBy(static group => group.Key, StringComparer.Ordinal))
        {
            var instrument = NatsMonitoringInstrumentCatalog.Require(group.Key);
            lines.Add($"# unit {instrument.Unit} source {string.Join(",", instrument.SourceSubjects)} failure {instrument.FailureBehavior}");
            foreach (var entry in group.OrderBy(
                         static entry => string.Join(',', entry.Labels.Select(static label => $"{label.Key}={label.Value}").Order(StringComparer.Ordinal)),
                         StringComparer.Ordinal))
            {
                var labels = string.Join(',',
                    entry.Labels
                        .OrderBy(static label => label.Key, StringComparer.Ordinal)
                        .Select(static label => $"{label.Key}=\"{EscapeLabelValue(label.Value)}\""));
                lines.Add(labels.Length == 0
                    ? $"{entry.Instrument} {entry.Value}"
                    : $"{entry.Instrument}{{{labels}}} {entry.Value}");
            }
        }
        return string.Join('\n', lines) + "\n";
    }

    /// <summary>
    /// Escapes one label value for the Prometheus text exposition format:
    /// backslash, double quote, and newline are the three characters the format
    /// requires to be escaped inside a quoted label value.
    /// </summary>
    private static string EscapeLabelValue(string value) =>
        value
            .Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("\"", "\\\"", StringComparison.Ordinal)
            .Replace("\n", "\\n", StringComparison.Ordinal);
}

[JsonSerializable(typeof(NatsMonitoringSnapshot))]
[JsonSerializable(typeof(NatsMonitoringSnapshotEntry))]
internal sealed partial class NatsMonitoringSnapshotJsonContext : JsonSerializerContext;
