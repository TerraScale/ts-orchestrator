using System.Text.Json;

namespace TerraScale.Orchestrator.Messaging;

/// <summary>The trust plane a NATS observation was taken from; never a free-form label value.</summary>
internal enum NatsMonitoringPlane
{
    Control = 1,
    Product = 2
}

/// <summary>The role of the observed cluster inside the launch topology.</summary>
internal enum NatsClusterRole
{
    Regional = 1,
    GlobalAuthority = 2
}

/// <summary>
/// Bounded classification of an observed JetStream stream. Class — never a stream
/// name — is the metric label, so the label domain stays closed while stream
/// identities change.
/// </summary>
internal enum NatsStreamClass
{
    CellSpec = 1,
    CellOperations = 2,
    CellEvents = 3,
    GlobalSpec = 4,
    GlobalCi = 5,
    KeyValue = 6,
    ObjectStore = 7,
    Unknown = 8
}

/// <summary>Bounded classification of an observed JetStream consumer.</summary>
internal enum NatsConsumerClass
{
    StartupEvent = 1,
    CellSpec = 2,
    GlobalCi = 3,
    EphemeralWatch = 4,
    Unknown = 5
}

/// <summary>Bounded classification of an observed KV or Object Store bucket.</summary>
internal enum NatsStoreClass
{
    KeyValue = 1,
    ObjectStore = 2
}

/// <summary>Bounded classification of an observed X.509 certificate exposure.</summary>
internal enum NatsCertificateClass
{
    ServerListener = 1,
    GatewayLink = 2,
    MonitoringClient = 3
}

/// <summary>The canonical advisory kinds the monitoring contract consumes; unknown kinds are counted as unclassified, never dropped silently.</summary>
internal enum NatsAdvisoryKind
{
    SlowConsumer = 1,
    LeaderChange = 2,
    AuthenticationFailure = 3,
    MaxDeliveries = 4,
    ResourceExhausted = 5,
    Unclassified = 6
}

/// <summary>Bounded, aggregate observation of client connections on one observed server.</summary>
internal sealed record NatsConnectionsObservation(
    int SchemaVersion,
    string Cell,
    NatsMonitoringPlane Plane,
    long Connections,
    long Reconnects,
    DateTimeOffset ObservedAt) : INatsMonitoringObservation
{
    internal static readonly int CurrentSchemaVersion = 1;

    internal static NatsConnectionsObservation Observe(
        string cell,
        NatsMonitoringPlane plane,
        long connections,
        long reconnects,
        DateTimeOffset observedAt) =>
        new(CurrentSchemaVersion, cell, plane, connections, reconnects, observedAt);

    public void Validate()
    {
        if (SchemaVersion != CurrentSchemaVersion || !CellTokenRule.IsValid(Cell) ||
            Connections < 0 || Reconnects < 0 || ObservedAt == default)
            throw new InvalidOperationException("The NATS connections observation is invalid.");
    }
}

/// <summary>Bounded, aggregate observation of cluster routes on one observed server.</summary>
internal sealed record NatsRoutesObservation(
    int SchemaVersion,
    string Cell,
    long Routes,
    DateTimeOffset ObservedAt) : INatsMonitoringObservation
{
    internal static readonly int CurrentSchemaVersion = 1;

    internal static NatsRoutesObservation Observe(string cell, long routes, DateTimeOffset observedAt) =>
        new(CurrentSchemaVersion, cell, routes, observedAt);

    public void Validate()
    {
        if (SchemaVersion != CurrentSchemaVersion || !CellTokenRule.IsValid(Cell) ||
            Routes < 0 || ObservedAt == default)
            throw new InvalidOperationException("The NATS routes observation is invalid.");
    }
}

/// <summary>
/// Bounded, aggregate observation of one server's outbound gateway links. The
/// disconnected count is the mesh-partition signal that feeds the disconnected
/// mesh-health state; no remote address, name, or identity is retained.
/// </summary>
internal sealed record NatsGatewaysObservation(
    int SchemaVersion,
    string Cell,
    int ConnectedGateways,
    int DisconnectedGateways,
    DateTimeOffset ObservedAt) : INatsMonitoringObservation
{
    internal static readonly int CurrentSchemaVersion = 1;

    internal static NatsGatewaysObservation Observe(
        string cell,
        int connected,
        int disconnected,
        DateTimeOffset observedAt) =>
        new(CurrentSchemaVersion, cell, connected, disconnected, observedAt);

    internal bool FullyDisconnected => ConnectedGateways == 0 && DisconnectedGateways > 0;

    public void Validate()
    {
        if (SchemaVersion != CurrentSchemaVersion || !CellTokenRule.IsValid(Cell) ||
            ConnectedGateways < 0 || DisconnectedGateways < 0 || ObservedAt == default)
            throw new InvalidOperationException("The NATS gateways observation is invalid.");
    }
}

/// <summary>Bounded, aggregate observation of accounts known to one observed server.</summary>
internal sealed record NatsAccountsObservation(
    int SchemaVersion,
    string Cell,
    long Accounts,
    long Connections,
    DateTimeOffset ObservedAt) : INatsMonitoringObservation
{
    internal static readonly int CurrentSchemaVersion = 1;

    internal static NatsAccountsObservation Observe(
        string cell,
        long accounts,
        long connections,
        DateTimeOffset observedAt) =>
        new(CurrentSchemaVersion, cell, accounts, connections, observedAt);

    public void Validate()
    {
        if (SchemaVersion != CurrentSchemaVersion || !CellTokenRule.IsValid(Cell) ||
            Accounts < 0 || Connections < 0 || ObservedAt == default)
            throw new InvalidOperationException("The NATS accounts observation is invalid.");
    }
}

/// <summary>
/// Bounded, aggregate JetStream observation for one observed server: domains,
/// stream and consumer totals, and the memory/storage gauges the resource
/// instruments expose. No stream or consumer identity is retained here — the
/// per-class breakdowns live in <see cref="NatsStreamClassState"/> and
/// <see cref="NatsConsumerClassState"/>.
/// </summary>
internal sealed record NatsJetStreamObservation(
    int SchemaVersion,
    string Cell,
    long Domains,
    long Streams,
    long Consumers,
    long MemoryBytes,
    long StorageBytes,
    DateTimeOffset ObservedAt) : INatsMonitoringObservation
{
    internal static readonly int CurrentSchemaVersion = 1;

    internal static NatsJetStreamObservation Observe(
        string cell,
        long domains,
        long streams,
        long consumers,
        long memoryBytes,
        long storageBytes,
        DateTimeOffset observedAt) =>
        new(CurrentSchemaVersion, cell, domains, streams, consumers, memoryBytes, storageBytes, observedAt);

    public void Validate()
    {
        if (SchemaVersion != CurrentSchemaVersion || !CellTokenRule.IsValid(Cell) ||
            Domains < 0 || Streams < 0 || Consumers < 0 ||
            MemoryBytes < 0 || StorageBytes < 0 || ObservedAt == default)
            throw new InvalidOperationException("The NATS JetStream observation is invalid.");
    }
}

/// <summary>Bounded per-class stream state: counts, retained bytes, and duplicate detections.</summary>
internal sealed record NatsStreamClassState(
    NatsStreamClass StreamClass,
    long Streams,
    long Messages,
    long Bytes,
    long Duplicates) : INatsMonitoringObservation
{
    public void Validate()
    {
        if (!Enum.IsDefined(StreamClass) || Streams < 0 || Messages < 0 || Bytes < 0 || Duplicates < 0)
            throw new InvalidOperationException("The NATS stream class state is invalid.");
    }
}

/// <summary>
/// Bounded per-class consumer state: the lag, delivery, redelivery, duplicate, and
/// flow-control pressure signals. Consumer identity (durable name, subject, session)
/// is deliberately not representable here.
/// </summary>
internal sealed record NatsConsumerClassState(
    NatsStreamClass StreamClass,
    NatsConsumerClass ConsumerClass,
    long Consumers,
    long Lag,
    long Deliveries,
    long Redelivered,
    long AckPending,
    long Waiting) : INatsMonitoringObservation
{
    public void Validate()
    {
        if (!Enum.IsDefined(StreamClass) || !Enum.IsDefined(ConsumerClass) ||
            Consumers < 0 || Lag < 0 || Deliveries < 0 || Redelivered < 0 ||
            AckPending < 0 || Waiting < 0)
            throw new InvalidOperationException("The NATS consumer class state is invalid.");
    }
}

/// <summary>Bounded per-class store usage: KV watches and Object Store consumption.</summary>
internal sealed record NatsStoreClassState(
    NatsStoreClass StoreClass,
    long Buckets,
    long Watches,
    long Objects,
    long Bytes)
{
    public void Validate()
    {
        if (!Enum.IsDefined(StoreClass) || Buckets < 0 || Watches < 0 || Objects < 0 || Bytes < 0)
            throw new InvalidOperationException("The NATS store class state is invalid.");
    }
}

/// <summary>Bounded observation of one server's process and JetStream resource use.</summary>
internal sealed record NatsServerResourceObservation(
    int SchemaVersion,
    string Cell,
    long ServerMemoryBytes,
    long JetStreamStorageBytes,
    DateTimeOffset ObservedAt) : INatsMonitoringObservation
{
    internal static readonly int CurrentSchemaVersion = 1;

    internal static NatsServerResourceObservation Observe(
        string cell,
        long serverMemoryBytes,
        long jetStreamStorageBytes,
        DateTimeOffset observedAt) =>
        new(CurrentSchemaVersion, cell, serverMemoryBytes, jetStreamStorageBytes, observedAt);

    public void Validate()
    {
        if (SchemaVersion != CurrentSchemaVersion || !CellTokenRule.IsValid(Cell) ||
            ServerMemoryBytes < 0 || JetStreamStorageBytes < 0 || ObservedAt == default)
            throw new InvalidOperationException("The NATS server resource observation is invalid.");
    }
}

/// <summary>
/// Bounded certificate-expiry observation. The absolute not-after instant is kept
/// for evaluation only; exposed signals are the bounded certificate class and the
/// derived remaining days.
/// </summary>
internal sealed record NatsCertificateObservation(
    int SchemaVersion,
    string Cell,
    NatsCertificateClass CertificateClass,
    DateTimeOffset NotAfter,
    DateTimeOffset ObservedAt)
{
    internal static readonly int CurrentSchemaVersion = 1;

    internal static NatsCertificateObservation Observe(
        string cell,
        NatsCertificateClass certificateClass,
        DateTimeOffset notAfter,
        DateTimeOffset observedAt) =>
        new(CurrentSchemaVersion, cell, certificateClass, notAfter, observedAt);

    internal long RemainingDays(DateTimeOffset now)
    {
        Validate();
        var remaining = NotAfter - now;
        return remaining <= TimeSpan.Zero ? 0 : (long)Math.Ceiling(remaining.TotalDays);
    }

    public void Validate()
    {
        if (SchemaVersion != CurrentSchemaVersion || !CellTokenRule.IsValid(Cell) ||
            !Enum.IsDefined(CertificateClass) || NotAfter == default || ObservedAt == default)
            throw new InvalidOperationException("The NATS certificate observation is invalid.");
    }
}

/// <summary>Bounded count of advisories observed per canonical kind since monitoring started.</summary>
internal sealed record NatsAdvisoryCount(NatsAdvisoryKind Kind, long Occurrences)
{
    public void Validate()
    {
        if (!Enum.IsDefined(Kind) || Occurrences < 0)
            throw new InvalidOperationException("The NATS advisory count is invalid.");
    }
}

/// <summary>
/// The mesh-health state of one observed cell, composed from membership, directory,
/// and gateway-link evidence. <see cref="Disconnected"/> is the partition state: the
/// cell's gateway links are down while its server-side evidence is not otherwise stale.
/// </summary>
internal enum NatsMeshCellState
{
    Healthy = 1,
    Stale = 2,
    Missing = 3,
    Conflicting = 4,
    Disconnected = 5
}

internal sealed record NatsMeshCell(string Cell, NatsMeshCellState State)
{
    public void Validate()
    {
        if (!CellTokenRule.IsValid(Cell) || !Enum.IsDefined(State))
            throw new InvalidOperationException("The NATS mesh cell state is invalid.");
    }
}

/// <summary>
/// The aggregate mesh health: healthy, stale, missing, conflicting, and disconnected
/// cells, each bounded by the declared topology. This composes the landed membership
/// and directory aggregates (T-21) with the gateway-partition signal; it never
/// replaces or mutates them.
/// </summary>
internal sealed record NatsMeshHealth(
    int SchemaVersion,
    DateTimeOffset ObservedAt,
    IReadOnlyList<NatsMeshCell> Cells)
{
    internal static readonly int CurrentSchemaVersion = 1;

    internal int Count(NatsMeshCellState state) => Cells.Count(cell => cell.State == state);
    internal int HealthyCells => Count(NatsMeshCellState.Healthy);
    internal int StaleCells => Count(NatsMeshCellState.Stale);
    internal int MissingCells => Count(NatsMeshCellState.Missing);
    internal int ConflictingCells => Count(NatsMeshCellState.Conflicting);
    internal int DisconnectedCells => Count(NatsMeshCellState.Disconnected);

    /// <summary>
    /// Composes per-cell membership health and directory staleness with the gateway
    /// link observations. A cell absent from the directory is missing; a cell whose
    /// live membership reports conflicting sessions is conflicting even when the
    /// directory lease is current; a cell whose observed gateway links are all down
    /// is disconnected — the regional-autonomy signal, distinct from stale data.
    /// </summary>
    internal static NatsMeshHealth Evaluate(
        IEnumerable<string> expectedCells,
        IReadOnlyDictionary<string, RegionalRuntimeMembershipHealth> membershipByCell,
        GlobalCellDirectorySnapshot directory,
        IReadOnlyDictionary<string, NatsGatewaysObservation> gatewaysByCell,
        DateTimeOffset observedAt)
    {
        ArgumentNullException.ThrowIfNull(expectedCells);
        ArgumentNullException.ThrowIfNull(membershipByCell);
        ArgumentNullException.ThrowIfNull(directory);
        ArgumentNullException.ThrowIfNull(gatewaysByCell);
        var cells = expectedCells
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .Select(cell => new NatsMeshCell(cell, StateFor(cell, membershipByCell, directory, gatewaysByCell, observedAt)))
            .ToArray();
        var health = new NatsMeshHealth(CurrentSchemaVersion, observedAt, cells);
        health.Validate();
        return health;
    }

    private static NatsMeshCellState StateFor(
        string cell,
        IReadOnlyDictionary<string, RegionalRuntimeMembershipHealth> membershipByCell,
        GlobalCellDirectorySnapshot directory,
        IReadOnlyDictionary<string, NatsGatewaysObservation> gatewaysByCell,
        DateTimeOffset observedAt)
    {
        // A fully-disconnected gateway view is the partition signal and outranks
        // directory presence: the cell's server is alive and reporting, only its
        // mesh links are down — regional autonomy, not missing data.
        if (gatewaysByCell.TryGetValue(cell, out var gateways) && gateways.FullyDisconnected)
            return NatsMeshCellState.Disconnected;
        var entry = directory.Cells.FirstOrDefault(candidate => candidate.Cell == cell);
        if (entry is null || entry.LeaseExpiresAt <= observedAt)
        {
            // No current advertisement: the cell is missing from the converged view.
            // A previously observed entry that has gone stale distinguishes a lost
            // publisher from a never-advertised cell only by presence, which is the
            // missing signal here.
            return entry is null ? NatsMeshCellState.Missing : NatsMeshCellState.Stale;
        }
        if (membershipByCell.TryGetValue(cell, out var membership) &&
            membership.ConflictingControllers > 0)
            return NatsMeshCellState.Conflicting;
        return entry.Membership.Condition == RegionalRuntimeMembershipCondition.Healthy
            ? NatsMeshCellState.Healthy
            : NatsMeshCellState.Stale;
    }

    public void Validate()
    {
        if (SchemaVersion != CurrentSchemaVersion || ObservedAt == default ||
            Cells.Count == 0 ||
            Cells.Select(static cell => cell.Cell).Distinct(StringComparer.Ordinal).Count() != Cells.Count ||
            !Cells.SequenceEqual(Cells.OrderBy(static cell => cell.Cell, StringComparer.Ordinal)))
            throw new InvalidOperationException("The NATS mesh health projection is invalid.");
        foreach (var cell in Cells) cell.Validate();
    }
}

/// <summary>Truthful availability of the monitoring signal itself.</summary>
internal enum NatsMonitoringAvailability
{
    Available = 1,
    Degraded = 2,
    Unavailable = 3
}

/// <summary>
/// The bounded NATS monitoring aggregate the observability instruments project. It
/// carries only counts, class-scoped states, durations, and availability — never a
/// connection, stream, consumer, session, NKey, or message identity.
/// </summary>
internal sealed record NatsMonitoringAggregate(
    int SchemaVersion,
    string Cell,
    NatsMonitoringPlane Plane,
    NatsClusterRole ClusterRole,
    DateTimeOffset ObservedAt,
    NatsMonitoringAvailability Availability,
    NatsMeshHealth Mesh,
    long Connections,
    long Reconnects,
    long Routes,
    long Accounts,
    long JetStreamDomains,
    long GatewaysConnected,
    long GatewaysDisconnected,
    long ServerMemoryBytes,
    long JetStreamStorageBytes,
    long PartitionDurationMilliseconds,
    long RecoveryDurationMilliseconds,
    IReadOnlyList<NatsStreamClassState> StreamsByClass,
    IReadOnlyList<NatsConsumerClassState> ConsumersByClass,
    IReadOnlyList<NatsStoreClassState> StoresByClass,
    IReadOnlyList<NatsAdvisoryCount> Advisories,
    IReadOnlyList<NatsCertificateObservation> Certificates)
{
    internal static readonly int CurrentSchemaVersion = 1;

    public void Validate()
    {
        if (SchemaVersion != CurrentSchemaVersion || !CellTokenRule.IsValid(Cell) ||
            !Enum.IsDefined(Plane) || !Enum.IsDefined(ClusterRole) ||
            !Enum.IsDefined(Availability) || ObservedAt == default ||
            Connections < 0 || Reconnects < 0 || Routes < 0 || Accounts < 0 ||
            JetStreamDomains < 0 || GatewaysConnected < 0 || GatewaysDisconnected < 0 ||
            ServerMemoryBytes < 0 || JetStreamStorageBytes < 0 ||
            PartitionDurationMilliseconds < 0 || RecoveryDurationMilliseconds < 0)
            throw new InvalidOperationException("The NATS monitoring aggregate is invalid.");
        Mesh.Validate();
        foreach (var stream in StreamsByClass) stream.Validate();
        foreach (var consumer in ConsumersByClass) consumer.Validate();
        foreach (var store in StoresByClass) store.Validate();
        foreach (var advisory in Advisories) advisory.Validate();
        foreach (var certificate in Certificates) certificate.Validate();
        if (StreamsByClass.Select(static stream => stream.StreamClass).Distinct().Count() != StreamsByClass.Count ||
            ConsumersByClass
                .Select(static consumer => (consumer.StreamClass, consumer.ConsumerClass))
                .Distinct().Count() != ConsumersByClass.Count ||
            StoresByClass.Select(static store => store.StoreClass).Distinct().Count() != StoresByClass.Count ||
            Advisories.Select(static advisory => advisory.Kind).Distinct().Count() != Advisories.Count ||
            Certificates.Select(static certificate => certificate.CertificateClass).Distinct().Count() != Certificates.Count)
            throw new InvalidOperationException("The NATS monitoring aggregate contains duplicate class entries.");
    }
}

/// <summary>
/// Maps a raw JetStream stream or consumer name onto its bounded metric class. The
/// mapping is total: every name maps, unknown names map to <see cref="NatsStreamClass.Unknown"/>
/// or <see cref="NatsConsumerClass.Unknown"/>, so an unexpected name can never widen
/// the label domain.
/// </summary>
internal static class NatsMonitoringClassifier
{
    internal static NatsStreamClass ClassifyStream(string streamName)
    {
        if (string.IsNullOrEmpty(streamName)) return NatsStreamClass.Unknown;
        if (streamName.StartsWith("KV_", StringComparison.Ordinal)) return NatsStreamClass.KeyValue;
        if (streamName.StartsWith("OBJ_", StringComparison.Ordinal)) return NatsStreamClass.ObjectStore;
        return streamName switch
        {
            "CELL_SPEC" => NatsStreamClass.CellSpec,
            "CELL_OPERATIONS" => NatsStreamClass.CellOperations,
            "CELL_EVENTS" => NatsStreamClass.CellEvents,
            "GLOBAL_SPEC" => NatsStreamClass.GlobalSpec,
            "GLOBAL_CI" => NatsStreamClass.GlobalCi,
            _ => NatsStreamClass.Unknown
        };
    }

    internal static NatsConsumerClass ClassifyConsumer(string? consumerName)
    {
        if (string.IsNullOrEmpty(consumerName)) return NatsConsumerClass.Unknown;
        if (consumerName.StartsWith("gitops_cell_spec_", StringComparison.Ordinal)) return NatsConsumerClass.CellSpec;
        if (consumerName.StartsWith("runtime_startup", StringComparison.Ordinal)) return NatsConsumerClass.StartupEvent;
        if (consumerName.StartsWith("ci_", StringComparison.Ordinal)) return NatsConsumerClass.GlobalCi;
        // NATS.Net KeyValue/ObjectStore watches use ephemeral push consumers whose
        // delivered durable name is an internal NUID: classify by shape, never identity.
        if (consumerName.Length is 22 or 23 && consumerName.All(char.IsAsciiLetterOrDigit)) return NatsConsumerClass.EphemeralWatch;
        return NatsConsumerClass.Unknown;
    }

    internal static NatsAdvisoryKind ClassifyAdvisory(string? advisorySubject)
    {
        if (string.IsNullOrEmpty(advisorySubject)) return NatsAdvisoryKind.Unclassified;
        if (advisorySubject.Contains("SLOW_CONSUMER", StringComparison.Ordinal)) return NatsAdvisoryKind.SlowConsumer;
        if (advisorySubject.Contains("LEADER", StringComparison.Ordinal) ||
            advisorySubject.Contains("RAFT", StringComparison.Ordinal)) return NatsAdvisoryKind.LeaderChange;
        if (advisorySubject.Contains("AUTH", StringComparison.Ordinal) ||
            advisorySubject.Contains("AUTHENTICATION", StringComparison.Ordinal)) return NatsAdvisoryKind.AuthenticationFailure;
        if (advisorySubject.Contains("MAX_DELIVERIES", StringComparison.Ordinal)) return NatsAdvisoryKind.MaxDeliveries;
        if (advisorySubject.Contains("RESOURCE", StringComparison.Ordinal) ||
            advisorySubject.Contains("MAX_MEMORY", StringComparison.Ordinal) ||
            advisorySubject.Contains("MAX_STORAGE", StringComparison.Ordinal)) return NatsAdvisoryKind.ResourceExhausted;
        return NatsAdvisoryKind.Unclassified;
    }
}

/// <summary>
/// Parses bounded observations from raw <c>$SYS</c> monitoring and advisory payloads.
/// Parsing is defensive by contract: any shape the server sends that does not match
/// the expected bounded form yields <c>null</c> (a failed observation the supervisor
/// counts), never an exception and never a partial identity.
/// </summary>
/// <summary>Implemented by every bounded observation so fail-closed parsing is compile-time checked.</summary>
internal interface INatsMonitoringObservation
{
    void Validate();
}

internal static class NatsMonitoringParsers
{
    /// <summary>
    /// The bounded reply cap: a monitoring reply larger than this is treated as a
    /// hostile or malformed shape (a failed observation), never parsed. Real
    /// system-service replies are kilobytes; four MiB is orders of magnitude above
    /// the largest legitimate detailed census.
    /// </summary>
    internal const int MaximumReplyBytes = 4 * 1024 * 1024;

    /// <summary>
    /// Fail-closed validation: a candidate observation whose <see cref="INatsMonitoringObservation.Validate"/>
    /// rejects it (a hostile or malformed value) becomes a null observation — a
    /// shape mismatch the supervisor counts — never an exception into the
    /// observation loop.
    /// </summary>
    private static TObservation? ValidOrNull<TObservation>(TObservation? observation)
        where TObservation : class, INatsMonitoringObservation
    {
        if (observation is null) return null;
        try
        {
            observation.Validate();
            return observation;
        }
        catch (InvalidOperationException)
        {
            return null;
        }
    }

    internal static NatsConnectionsObservation? Connections(string json, string cell, NatsMonitoringPlane plane, DateTimeOffset observedAt)
    {
        if (!TryDocument(json, out var root)) return null;
        // The system-service reply envelope is {"server": {...}, "data": {...}};
        // the census fields live under data.
        var data = EnvelopeData(root);
        var total = ReadLong(data, "total") ?? ReadLong(data, "num_connections");
        if (total is null) return null;
        var reconnects = 0L;
        if (data.TryGetProperty("connections", out var connections) && connections.ValueKind == JsonValueKind.Array)
            foreach (var connection in connections.EnumerateArray())
                reconnects += ReadLong(connection, "num_reconnects") ?? 0;
        return ValidOrNull(NatsConnectionsObservation.Observe(cell, plane, total.Value, reconnects, observedAt));
    }

    internal static NatsRoutesObservation? Routes(string json, string cell, DateTimeOffset observedAt)
    {
        if (!TryDocument(json, out var root)) return null;
        var routes = ReadLong(EnvelopeData(root), "num_routes");
        if (routes is null) return null;
        return ValidOrNull(NatsRoutesObservation.Observe(cell, routes.Value, observedAt));
    }

    internal static NatsGatewaysObservation? Gateways(string json, string cell, DateTimeOffset observedAt)
    {
        if (!TryDocument(json, out var root)) return null;
        if (!root.TryGetProperty("data", out var data) || data.ValueKind != JsonValueKind.Object)
            return null;
        var connected = 0;
        var disconnected = 0;
        if (data.TryGetProperty("outbound_gateways", out var gateways) && gateways.ValueKind == JsonValueKind.Object)
            foreach (var gateway in gateways.EnumerateObject())
            {
                var isObject = gateway.Value.ValueKind == JsonValueKind.Object;
                var hasConnection = isObject &&
                                    gateway.Value.TryGetProperty("connection", out var connection) &&
                                    connection.ValueKind == JsonValueKind.Object;
                if (hasConnection) connected++;
                else if (isObject) disconnected++;
            }
        var observation = NatsGatewaysObservation.Observe(cell, connected, disconnected, observedAt);
        return ValidOrNull(observation);
    }

    internal static NatsAccountsObservation? Accounts(string json, string cell, DateTimeOffset observedAt)
    {
        if (!TryDocument(json, out var root)) return null;
        // accountz replies with one account per document in a RequestMany stream; the
        // aggregate counts the documents it could parse. Every census field — the
        // account name, the account total, and the connection counts — lives in the
        // envelope's data payload.
        var data = EnvelopeData(root);
        var name = ReadString(data, "name");
        if (name is null) return null;
        var accounts = ReadLong(data, "account_total") ?? 1;
        var connections = 0L;
        if (ReadLong(data, "num_connections") is { } accountConnections) connections = accountConnections;
        if (ReadLong(data, "total") is { } total) connections = total;
        return ValidOrNull(NatsAccountsObservation.Observe(cell, accounts, connections, observedAt));
    }

    internal static NatsServerResourceObservation? ServerResources(string json, string cell, DateTimeOffset observedAt)
    {
        if (!TryDocument(json, out var root)) return null;
        var data = EnvelopeData(root);
        var memory = ReadLong(data, "mem");
        if (memory is null) return null;
        var storage = 0L;
        if (data.TryGetProperty("jetstream", out var jetstream) && jetstream.ValueKind == JsonValueKind.Object)
            storage = ReadLong(jetstream, "storage") ?? 0;
        return ValidOrNull(NatsServerResourceObservation.Observe(cell, memory.Value, storage, observedAt));
    }

    internal static NatsJetStreamObservation? JetStream(string json, string cell, DateTimeOffset observedAt)
    {
        if (!TryDocument(json, out var root)) return null;
        var source = EnvelopeData(root);
        var memory = ReadLong(source, "memory");
        var storage = ReadLong(source, "storage");
        var streams = ReadLong(source, "streams");
        var consumers = ReadLong(source, "consumers");
        if (memory is null || storage is null) return null;
        var domains = 0L;
        if (source.TryGetProperty("account_details", out var details) && details.ValueKind == JsonValueKind.Array)
            domains = details.GetArrayLength();
        return ValidOrNull(NatsJetStreamObservation.Observe(
            cell,
            domains,
            streams ?? 0,
            consumers ?? 0,
            memory.Value,
            storage.Value,
            observedAt));
    }

    /// <summary>
    /// Extracts the per-class stream detail from a detailed <c>JSZ</c> reply. Stream
    /// and consumer names are classified immediately and never leave this method;
    /// only bounded class states are returned.
    /// </summary>
    internal static (IReadOnlyList<NatsStreamClassState> Streams, IReadOnlyList<NatsConsumerClassState> Consumers)?
        JetStreamDetail(string json)
    {
        if (!TryDocument(json, out var root)) return null;
        var source = EnvelopeData(root);
        if (!source.TryGetProperty("stream_detail", out var streams) || streams.ValueKind != JsonValueKind.Array)
            return null;
        // The whole detail build is fail-closed: a hostile value in any state, or
        // an arithmetic overflow while merging per-class sums, invalidates the
        // detail observation instead of reaching the observation loop.
        try
        {
            var streamStates = new Dictionary<NatsStreamClass, NatsStreamClassState>();
            var consumerStates = new Dictionary<(NatsStreamClass, NatsConsumerClass), NatsConsumerClassState>();
            foreach (var stream in streams.EnumerateArray())
            {
                var name = ReadString(stream, "name");
                if (name is null) continue;
                var streamClass = NatsMonitoringClassifier.ClassifyStream(name);
                var state = ReadStreamState(stream, streamClass);
                streamStates[streamClass] = state;
                if (!stream.TryGetProperty("consumer_detail", out var consumers) ||
                    consumers.ValueKind != JsonValueKind.Array)
                    continue;
                foreach (var consumer in consumers.EnumerateArray())
                {
                    var consumerClass = NatsMonitoringClassifier.ClassifyConsumer(ReadString(consumer, "name"));
                    var key = (streamClass, consumerClass);
                    var existing = consumerStates.GetValueOrDefault(key);
                    consumerStates[key] = MergeConsumerState(existing, ReadConsumerState(consumer, streamClass, consumerClass));
                }
            }
            var mergedStreams = streamStates.Values
                .OrderBy(static state => state.StreamClass)
                .Select(ValidOrNull)
                .ToArray();
            var mergedConsumers = consumerStates.Values
                .OrderBy(static state => state.StreamClass)
                .ThenBy(static state => state.ConsumerClass)
                .Select(ValidOrNull)
                .ToArray();
            // Merged per-class sums are revalidated: overflow while adding two
            // legitimate counters wraps negative and must invalidate the detail.
            if (mergedStreams.Any(static state => state is null) ||
                mergedConsumers.Any(static state => state is null))
                return null;
            return (
                mergedStreams.Cast<NatsStreamClassState>().ToArray(),
                mergedConsumers.Cast<NatsConsumerClassState>().ToArray());
        }
        catch (InvalidOperationException)
        {
            return null;
        }
        catch (OverflowException)
        {
            return null;
        }
    }

    private static NatsStreamClassState ReadStreamState(JsonElement stream, NatsStreamClass streamClass)
    {
        var messages = 0L;
        var bytes = 0L;
        // JetStream detail carries no duplicate-detection counter: the duplicate
        // signal is application-level (message-ID deduplication) and is supplied by
        // the adapter, not inferred from server state.
        const long duplicates = 0;
        if (stream.TryGetProperty("state", out var state) && state.ValueKind == JsonValueKind.Object)
        {
            bytes = ReadLong(state, "bytes") ?? 0;
            messages = ReadLong(state, "messages") ?? 0;
        }
        var result = new NatsStreamClassState(streamClass, 1, messages, bytes, duplicates);
        result.Validate();
        return result;
    }

    private static NatsConsumerClassState ReadConsumerState(
        JsonElement consumer,
        NatsStreamClass streamClass,
        NatsConsumerClass consumerClass)
    {
        var delivered = 0L;
        var redelivered = 0L;
        var ackPending = 0L;
        var waiting = 0L;
        var lag = 0L;
        if (consumer.TryGetProperty("delivered", out var deliveredElement) && deliveredElement.ValueKind == JsonValueKind.Object)
        {
            delivered = ReadLong(deliveredElement, "consumer_seq") ?? 0;
        }
        if (consumer.TryGetProperty("ack_floor", out var ackFloor) && ackFloor.ValueKind == JsonValueKind.Object)
        {
            var acked = ReadLong(ackFloor, "consumer_seq") ?? 0;
            redelivered = Math.Max(0, delivered - acked);
        }
        ackPending = ReadLong(consumer, "num_ack_pending") ?? 0;
        waiting = ReadLong(consumer, "num_waiting") ?? 0;
        lag = ReadLong(consumer, "num_pending") ?? 0;
        var result = new NatsConsumerClassState(streamClass, consumerClass, 1, lag, delivered, redelivered, ackPending, waiting);
        result.Validate();
        return result;
    }

    private static NatsConsumerClassState MergeConsumerState(NatsConsumerClassState? existing, NatsConsumerClassState observed) =>
        existing is null
            ? observed
            : new(
                existing.StreamClass,
                existing.ConsumerClass,
                existing.Consumers + observed.Consumers,
                existing.Lag + observed.Lag,
                existing.Deliveries + observed.Deliveries,
                existing.Redelivered + observed.Redelivered,
                existing.AckPending + observed.AckPending,
                existing.Waiting + observed.Waiting);

    internal static bool TryDocument(string json, out JsonElement root)
    {
        root = default;
        if (string.IsNullOrWhiteSpace(json)) return false;
        // Bounded input: an oversized reply is a hostile shape, not a census.
        if (json.Length > MaximumReplyBytes) return false;
        try
        {
            using var document = JsonDocument.Parse(json);
            if (document.RootElement.ValueKind != JsonValueKind.Object) return false;
            root = document.RootElement.Clone();
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    /// <summary>
    /// The system-service reply envelope is <c>{"server": {...}, "data": {...}}</c>.
    /// Parsers read only the data payload; the server descriptor carries no
    /// monitoring signal and is dropped here.
    /// </summary>
    internal static JsonElement EnvelopeData(JsonElement root) =>
        root.TryGetProperty("data", out var data) && data.ValueKind == JsonValueKind.Object
            ? data
            : root;

    internal static long? ReadLong(JsonElement element, string name) =>
        element.ValueKind == JsonValueKind.Object &&
        element.TryGetProperty(name, out var value)
            ? value.ValueKind switch
            {
                JsonValueKind.Number => value.TryGetInt64(out var parsed) ? parsed : null,
                JsonValueKind.String when value.GetString() is { } text &&
                                           long.TryParse(text, out var parsed) => parsed,
                _ => null
            }
        : null;

    internal static string? ReadString(JsonElement element, string name) =>
        element.ValueKind == JsonValueKind.Object &&
        element.TryGetProperty(name, out var value) &&
        value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
}
