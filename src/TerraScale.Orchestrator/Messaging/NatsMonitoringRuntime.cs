using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Channels;
using NATS.Client.Core;
using NATS.Net;
using TerraScale.Orchestrator.Observability;

namespace TerraScale.Orchestrator.Messaging;

internal sealed record NatsMonitoringRuntimeOptions(
    string Url,
    string Cell,
    NatsMonitoringPlane Plane,
    NatsClusterRole ClusterRole,
    IReadOnlyList<string> ExpectedCells,
    string? CredsFile = null,
    string? NKeyFile = null,
    NatsTlsFiles? Tls = null,
    string? ClientCertificateFile = null,
    string? ClientKeyFile = null,
    TimeSpan? PollInterval = null)
{
    internal static readonly TimeSpan DefaultPollInterval = TimeSpan.FromSeconds(15);

    internal TimeSpan EffectivePollInterval => PollInterval ?? DefaultPollInterval;

    internal void Validate()
    {
        if (!CellTokenRule.IsValid(Cell))
            throw new ArgumentException("The monitoring cell is not a bounded token.");
        if (string.IsNullOrWhiteSpace(Url))
            throw new ArgumentException("The monitoring URL is required.");
        if (ExpectedCells.Count is < 1 or > 8 ||
            ExpectedCells.Any(cell => !CellTokenRule.IsValid(cell)) ||
            ExpectedCells.Distinct(StringComparer.Ordinal).Count() != ExpectedCells.Count)
            throw new ArgumentException("The expected cells must be a bounded, unique cell list.");
        if (EffectivePollInterval < TimeSpan.FromSeconds(1))
            throw new ArgumentException("The monitoring poll interval is below its bounded minimum.");
    }
}

/// <summary>
/// The NATS monitoring adapter: one read-only observer identity that consumes
/// exactly the allowlisted <c>$SYS</c> monitoring and advisory subjects, projects
/// them into the bounded observation model, and serves the latest truthful
/// aggregate. Supervision is one-directional: observation failures degrade the
/// aggregate's availability and nothing else — the adapter holds no capability that
/// could delay or fail regional control, and its consumer loops never throw past
/// their own supervision boundary.
/// </summary>
internal sealed class NatsMonitoringRuntime : IAsyncDisposable
{
    /// <summary>
    /// Per-subject reply window: a RequestMany stream ends only at its reply
    /// subscription timeout, and every server answers these system services within
    /// milliseconds on a healthy mesh, so a short bounded window keeps a whole
    /// six-subject observation round cheap while a wedged server costs at most six
    /// windows.
    /// </summary>
    private static readonly TimeSpan ReplyWindow = TimeSpan.FromMilliseconds(750);

    internal static NatsSubOpts AdvisorySubscriptionOptions() => new()
    {
        ChannelOpts = new NatsSubChannelOpts
        {
            Capacity = NatsMonitoringPayload.MaximumAdvisoryChannelCapacity,
            FullMode = BoundedChannelFullMode.DropOldest
        }
    };

    internal static NatsSubOpts ReplySubscriptionOptions(int expectedCells) => new()
    {
        MaxMsgs = Math.Clamp(expectedCells, 1, NatsMonitoringPayload.MaximumChannelCapacity),
        Timeout = ReplyWindow,
        ChannelOpts = new NatsSubChannelOpts
        {
            Capacity = NatsMonitoringPayload.MaximumChannelCapacity,
            FullMode = BoundedChannelFullMode.DropOldest
        }
    };

    private readonly NatsMonitoringRuntimeOptions options;
    private readonly OrchestratorTelemetry? telemetry;
    private readonly Func<GlobalCellDirectorySnapshot>? directory;
    private readonly NatsClient client;
    private readonly CancellationTokenSource stopping = new();
    private readonly object gate = new();
    private readonly Dictionary<NatsAdvisoryKind, long> advisories = new();
    private readonly Dictionary<(NatsStreamClass, NatsConsumerClass), long> lastDelivered = new();
    private readonly Dictionary<(NatsStreamClass, NatsConsumerClass), long> lastRedelivered = new();
    private Task? runLoop;
    private readonly List<Task> advisoryLoops = new();
    private readonly Func<CancellationToken, Task> observeRound;
    private NatsMonitoringAggregate? current;
    private DateTimeOffset? lastSuccessfulRound;
    private int consecutiveFailedRounds;
    private int disposed;

    /// <summary>
    /// The round executor is injectable so the supervision boundary can be tested
    /// without a server; production always uses <see cref="ObserveRoundAsync"/>.
    /// </summary>
    internal NatsMonitoringRuntime(
        NatsMonitoringRuntimeOptions options,
        OrchestratorTelemetry? telemetry,
        Func<GlobalCellDirectorySnapshot>? directory,
        NatsClient client,
        Func<CancellationToken, Task>? observeRound = null)
    {
        this.options = options;
        this.telemetry = telemetry;
        this.directory = directory;
        this.client = client;
        this.observeRound = observeRound ?? ObserveRoundAsync;
    }

    internal static async Task<NatsMonitoringRuntime> StartAsync(
        NatsMonitoringRuntimeOptions options,
        OrchestratorTelemetry? telemetry = null,
        Func<GlobalCellDirectorySnapshot>? directory = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        var clientOptions = new NatsOpts
        {
            Url = options.Url,
            RetryOnInitialConnect = false,
            ConnectTimeout = TimeSpan.FromSeconds(3),
            RequestTimeout = TimeSpan.FromSeconds(5)
        };
        if (options.CredsFile is not null || options.NKeyFile is not null)
        {
            clientOptions = clientOptions with
            {
                AuthOpts = new NatsAuthOpts
                {
                    CredsFile = options.CredsFile,
                    NKeyFile = options.NKeyFile
                }
            };
        }
        if (options.Tls is not null)
            clientOptions = clientOptions with
            {
                TlsOpts = new NatsTlsOpts
                {
                    Mode = TlsMode.Require,
                    CaFile = options.Tls.CaFile,
                    CertFile = options.Tls.CertificateFile,
                    KeyFile = options.Tls.KeyFile
                }
            };
        var client = new NatsClient(clientOptions);
        NatsMonitoringRuntime? runtime = null;
        try
        {
            // Bounded startup: the NATS client's TLS handshake path has no internal
            // timeout, so a wedged handshake must surface as a fast failure here —
            // observability startup may never hang, retry-storm, or block control.
            // The caller's cancellation remains authoritative within that bound.
            await client.ConnectAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10), cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            runtime = new NatsMonitoringRuntime(options, telemetry, directory, client);
            // The advisory subscriptions are bound to the runtime's own stopping
            // token, never to the startup-scoped cancellation: they must live and
            // die with the observer, not with whoever started it.
            runtime.SubscribeAdvisories();
            runtime.runLoop = runtime.ObserveAsync(runtime.stopping.Token);
            // The telemetry attachment makes the bounded NATS gauges live: without
            // it the instruments would exist but never observe anything.
            telemetry?.ObserveNats(() => runtime.Current);
            cancellationToken.ThrowIfCancellationRequested();
            return runtime;
        }
        catch
        {
            // Startup owns the client until the runtime has been fully composed.
            // A canceled or failed handshake must release it even though no
            // runtime instance is available to perform normal disposal.
            try
            {
                if (runtime is not null)
                    await runtime.DisposeAsync();
                else
                    await client.DisposeAsync();
            }
            catch
            {
                // Preserve the startup failure as the actionable error; cleanup
                // is best effort at this boundary.
            }
            throw;
        }
    }

    /// <summary>
    /// The latest truthful aggregate. Availability is re-evaluated against the
    /// real observation clock on every read, so a monitor whose loop has died or
    /// whose data has aged out reports degraded or unavailable here even though
    /// its last stored aggregate said available.
    /// </summary>
    internal NatsMonitoringAggregate Current
    {
        get
        {
            lock (gate)
            {
                var aggregate = current ?? EmptyAggregate(NatsMonitoringAvailability.Unavailable);
                var availability = NatsMonitoringSupervision.Availability(
                    lastSuccessfulRound,
                    consecutiveFailedRounds,
                    DateTimeOffset.UtcNow);
                return availability == aggregate.Availability
                    ? aggregate
                    : aggregate with { Availability = availability };
            }
        }
    }

    internal NatsMonitoringSnapshot Snapshot() => NatsMonitoringSnapshot.From(Current);

    private NatsMonitoringAggregate EmptyAggregate(NatsMonitoringAvailability availability)
    {
        var aggregate = new NatsMonitoringAggregate(
            NatsMonitoringAggregate.CurrentSchemaVersion,
            options.Cell,
            options.Plane,
            options.ClusterRole,
            DateTimeOffset.UtcNow,
            availability,
            new NatsMeshHealth(
                NatsMeshHealth.CurrentSchemaVersion,
                DateTimeOffset.UtcNow,
                options.ExpectedCells
                    .Order(StringComparer.Ordinal)
                    .Select(cell => new NatsMeshCell(cell, NatsMeshCellState.Missing))
                    .ToArray()),
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            [],
            [],
            [],
            [],
            []);
        aggregate.Validate();
        return aggregate;
    }

    private void SubscribeAdvisories()
    {
        foreach (var subject in NatsMonitoringSubjects.AdvisorySubscriptions)
            advisoryLoops.Add(ConsumeAdvisoriesAsync(subject, stopping.Token));
    }

    private async Task ConsumeAdvisoriesAsync(string subject, CancellationToken cancellationToken)
    {
        try
        {
            await foreach (var message in client.SubscribeAsync<byte[]>(
                               subject,
                               serializer: NatsMonitoringPayload.DiscardDeserializer,
                               opts: AdvisorySubscriptionOptions(),
                               cancellationToken: cancellationToken))
            {
                // Advisory payloads can carry account or identity context; only the
                // bounded kind classification and a count survive this boundary.
                RecordAdvisory(NatsMonitoringClassifier.ClassifyAdvisory(message.Subject));
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Normal observer shutdown.
        }
        catch
        {
            // Advisory loss affects only advisory counters. It cannot fault the
            // observation loop or regional control. A future runtime instance can
            // establish a fresh subscription without retaining this failed loop.
        }
    }

    private void RecordAdvisory(NatsAdvisoryKind kind)
    {
        lock (gate)
        {
            advisories[kind] = advisories.GetValueOrDefault(kind) + 1;
        }
        telemetry?.RecordNatsAdvisory(kind);
    }

    private async Task ObserveAsync(CancellationToken cancellationToken)
    {
        try
        {
            // The first observation round runs immediately: callers must see a truthful
            // aggregate as soon as the identity connects, not one poll interval later.
            await TryRoundAsync(observeRound, cancellationToken);
            using var timer = new PeriodicTimer(options.EffectivePollInterval);
            while (await timer.WaitForNextTickAsync(cancellationToken))
                await TryRoundAsync(observeRound, cancellationToken);
        }
        catch (Exception exception) when (IsRoundFailure(exception, cancellationToken))
        {
            // The loop itself died (not a single failed round): report observability
            // unavailable truthfully and let the death surface to disposal.
            RecordRoundFailure(exception);
            throw;
        }
    }

    /// <summary>
    /// A round failure is any exception that is not ordinary shutdown:
    /// cancellation of the stopping token is the normal end of the loop, and
    /// everything else — transport, timeout, or an unexpected fault from a
    /// hostile reply — is a failure the supervisor must count.
    /// </summary>
    private static bool IsRoundFailure(Exception exception, CancellationToken cancellationToken) =>
        !(exception is OperationCanceledException && cancellationToken.IsCancellationRequested);

    /// <summary>
    /// Supervision boundary: any failure in one round — transport, timeout, or an
    /// unexpected fault from a hostile reply — degrades observability truthfully
    /// and is retried on the next tick. The loop never dies from a round failure,
    /// and nothing here can affect control paths.
    /// </summary>
    private async Task TryRoundAsync(Func<CancellationToken, Task> round, CancellationToken cancellationToken)
    {
        try
        {
            await round(cancellationToken);
        }
        catch (Exception exception) when (IsRoundFailure(exception, cancellationToken))
        {
            RecordRoundFailure(exception);
        }
    }

    /// <summary>Test seam: drives one round through the supervision boundary.</summary>
    internal Task TryRoundForTestAsync(Func<CancellationToken, Task> round) =>
        TryRoundAsync(round, stopping.Token);

    /// <summary>
    /// Records one failed round from an exception: the sanitized failure
    /// description carries the exception type plus redacted, length-bounded
    /// message text; raw exception detail never survives this boundary.
    /// </summary>
    private void RecordRoundFailure(Exception exception) =>
        RecordRoundFailure($"{exception.GetType().Name}: {NatsMonitoringRedaction.Sanitize(exception.Message)}");

    private void RecordRoundFailure(string sanitizedDescription)
    {
        Interlocked.Increment(ref consecutiveFailedRounds);
        lastRoundError = sanitizedDescription;
        ReevaluateAvailability();
    }

    private async Task ObserveRoundAsync(CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref startedRounds);
        var observedAt = DateTimeOffset.UtcNow;
        NatsConnectionsObservation? connections = null;
        NatsRoutesObservation? routes = null;
        NatsAccountsObservation? accounts = null;
        NatsServerResourceObservation? resources = null;
        NatsJetStreamObservation? jetStream = null;
        (IReadOnlyList<NatsStreamClassState> Streams, IReadOnlyList<NatsConsumerClassState> Consumers)? detail = null;
        var ownCluster = $"orchestrator-control-{options.Cell}";
        // The link census is per-round: a cluster that stopped answering must not
        // keep its previous map, or a severed cell would stay "connected" forever.
        lock (RespondingLinks)
        {
            RespondingLinks.Clear();
        }

        foreach (var subject in NatsMonitoringSubjects.Requests)
        {
            // Each reply is one server's own document. The observer pins one
            // server for its resource/JetStream/connection signals, but the
            // gateway link census aggregates every responding cluster: a
            // severed cell stops answering GATEWAYZ entirely, and its peers
            // report the broken link from their side.
            await foreach (var reply in client.Connection.RequestManyAsync<string, byte[]>(
                               subject,
                               subject == NatsMonitoringSubjects.JetStream ? """{"streams":true,"consumers":true}""" : string.Empty,
                               replySerializer: NatsMonitoringPayload.Deserializer,
                               replyOpts: ReplySubscriptionOptions(options.ExpectedCells.Count),
                               cancellationToken: cancellationToken))
            {
                if (reply.Data is not { Length: > 0 and <= NatsMonitoringParsers.MaximumReplyBytes }) continue;
                var payload = Encoding.UTF8.GetString(reply.Data);
                switch (subject)
                {
                    case NatsMonitoringSubjects.Gateways:
                        AccumulateGatewayReply(payload, ownCluster, observedAt);
                        break;
                    default:
                        if (!IsOwnClusterReply(payload, ownCluster)) continue;
                        switch (subject)
                        {
                            case NatsMonitoringSubjects.Connections:
                                connections = NatsMonitoringParsers.Connections(payload, options.Cell, options.Plane, observedAt);
                                break;
                            case NatsMonitoringSubjects.Routes:
                                routes = NatsMonitoringParsers.Routes(payload, options.Cell, observedAt);
                                break;
                            case NatsMonitoringSubjects.Server:
                                resources = NatsMonitoringParsers.ServerResources(payload, options.Cell, observedAt);
                                break;
                            case NatsMonitoringSubjects.JetStream:
                                jetStream = NatsMonitoringParsers.JetStream(payload, options.Cell, observedAt);
                                detail = NatsMonitoringParsers.JetStreamDetail(payload);
                                break;
                            case NatsMonitoringSubjects.Accounts:
                                var account = NatsMonitoringParsers.Accounts(payload, options.Cell, observedAt);
                                if (account is not null) accounts = account;
                                break;
                        }
                        break;
                }
            }
        }

        // A round is successful when at least the resource and JetStream shapes were
        // observed; every other shape is optional and its absence degrades only its
        // own instruments.
        if (resources is null || jetStream is null)
        {
            RecordRoundFailure(
                $"incomplete round: resources={resources is not null} jetStream={jetStream is not null}");
            return;
        }

        var certificates = ObserveCertificates(observedAt);
        var gatewaysByCell = BuildMeshGatewayObservations(observedAt);
        var directorySnapshot = directory?.Invoke();
        if (directorySnapshot is not null)
        {
            try
            {
                directorySnapshot.Validate();
            }
            catch (InvalidOperationException)
            {
                directorySnapshot = null;
            }
        }
        var membershipByCell = directorySnapshot?.Cells
            .ToDictionary(
                static cell => cell.Cell,
                static cell => cell.Membership,
                StringComparer.Ordinal);
        var mesh = NatsMeshHealth.Evaluate(
            options.ExpectedCells,
            membershipByCell ?? new Dictionary<string, RegionalRuntimeMembershipHealth>(StringComparer.Ordinal),
            directorySnapshot ?? EmptyDirectorySnapshot(observedAt),
            gatewaysByCell,
            observedAt);

        var streams = detail?.Streams ?? [];
        var consumers = detail?.Consumers ?? [];
        var ownGateways = gatewaysByCell.GetValueOrDefault(options.Cell);
        var partition = TrackPartition(ownGateways is not null && ownGateways.FullyDisconnected, observedAt);
        var aggregate = new NatsMonitoringAggregate(
            NatsMonitoringAggregate.CurrentSchemaVersion,
            options.Cell,
            options.Plane,
            options.ClusterRole,
            observedAt,
            NatsMonitoringAvailability.Available,
            mesh,
            connections?.Connections ?? 0,
            connections?.Reconnects ?? 0,
            routes?.Routes ?? 0,
            accounts?.Accounts ?? 0,
            jetStream.Domains,
            ownGateways?.ConnectedGateways ?? 0,
            ownGateways?.DisconnectedGateways ?? 0,
            resources.ServerMemoryBytes,
            jetStream.StorageBytes,
            partition.PartitionMilliseconds,
            partition.RecoveryMilliseconds,
            streams,
            consumers,
            [],
            LockAdvisories(),
            certificates);
        aggregate.Validate();

        RecordDeliveryDeltas(consumers);

        CompleteRound(aggregate);
    }

    /// <summary>
    /// Commits one successful observation round: the aggregate becomes current,
    /// the success clock restarts, and failure state clears.
    /// </summary>
    private void CompleteRound(NatsMonitoringAggregate aggregate)
    {
        lock (gate)
        {
            current = aggregate;
            lastSuccessfulRound = aggregate.ObservedAt;
            consecutiveFailedRounds = 0;
            lastRoundError = null;
            Interlocked.Increment(ref completedRounds);
        }
    }

    private DateTimeOffset? partitionStartedAt;
    private long lastRecoveryMilliseconds;
    private volatile string? lastRoundError;
    private long completedRounds;
    private long startedRounds;

    /// <summary>
    /// Diagnostic for tests and operators: why the last observation round failed,
    /// if it did. The text is sanitized through the monitoring redaction boundary
    /// and length-bounded; it never carries raw exception detail.
    /// </summary>
    internal string? LastRoundError => lastRoundError;
    internal long CompletedRounds => Interlocked.Read(ref completedRounds);
    internal long StartedRounds => Interlocked.Read(ref startedRounds);

    /// <summary>Test seam: commits a successful round through the real commit path.</summary>
    internal void CompleteRoundForTest(NatsMonitoringAggregate aggregate) => CompleteRound(aggregate);

    /// <summary>
    /// True when a system-service reply document is from the observer's own cell
    /// cluster: the reply envelope's server descriptor names its cluster. Only the
    /// pinned cluster's documents aggregate into this observer's signals.
    /// </summary>
    private static bool IsOwnClusterReply(string json, string ownCluster)
    {
        if (!NatsMonitoringParsers.TryDocument(json, out var root) ||
            !root.TryGetProperty("server", out var server) ||
            server.ValueKind != System.Text.Json.JsonValueKind.Object)
            return false;
        return NatsMonitoringParsers.ReadString(server, "cluster") == ownCluster;
    }

    /// <summary>
    /// Tracks gateway-partition and recovery durations under the state lock: the
    /// partition gauge grows from the first fully-disconnected observation, and the
    /// recovery gauge holds the duration of the last completed partition.
    /// </summary>
    private (long PartitionMilliseconds, long RecoveryMilliseconds) TrackPartition(
        bool isolated,
        DateTimeOffset observedAt)
    {
        lock (gate)
        {
            if (isolated)
            {
                partitionStartedAt ??= observedAt;
                return ((long)(observedAt - partitionStartedAt.Value).TotalMilliseconds, lastRecoveryMilliseconds);
            }
            if (partitionStartedAt is { } started)
            {
                lastRecoveryMilliseconds = (long)(observedAt - started).TotalMilliseconds;
                partitionStartedAt = null;
            }
            return (0, lastRecoveryMilliseconds);
        }
    }

    private static GlobalCellDirectorySnapshot EmptyDirectorySnapshot(DateTimeOffset observedAt) => new(
        1,
        observedAt,
        0,
        0,
        0,
        GlobalCellDirectoryCondition.Unavailable,
        []);

    private IReadOnlyList<NatsAdvisoryCount> LockAdvisories()
    {
        lock (gate)
        {
            return advisories
                .Select(pair => new NatsAdvisoryCount(pair.Key, pair.Value))
                .OrderBy(static count => count.Kind)
                .ToArray();
        }
    }

    private IReadOnlyList<NatsCertificateObservation> ObserveCertificates(DateTimeOffset observedAt)
    {
        if (options.ClientCertificateFile is null || options.ClientKeyFile is null) return [];
        try
        {
            using var certificate = X509Certificate2.CreateFromPemFile(
                options.ClientCertificateFile,
                options.ClientKeyFile);
            var observation = NatsCertificateObservation.Observe(
                options.Cell,
                NatsCertificateClass.MonitoringClient,
                new DateTimeOffset(DateTime.SpecifyKind(certificate.NotAfter, DateTimeKind.Utc), TimeSpan.Zero),
                observedAt);
            observation.Validate();
            return [observation];
        }
        catch
        {
            // A certificate that cannot be read is an absent signal, never a fake one.
            return [];
        }
    }

    private void RecordDeliveryDeltas(IReadOnlyList<NatsConsumerClassState> consumers)
    {
        if (telemetry is null) return;
        lock (gate)
        {
            foreach (var consumer in consumers)
            {
                var key = (consumer.StreamClass, consumer.ConsumerClass);
                var previousDelivered = lastDelivered.GetValueOrDefault(key);
                var previousRedelivered = lastRedelivered.GetValueOrDefault(key);
                if (consumer.Deliveries > previousDelivered)
                    telemetry.RecordNatsMessages(
                        consumer.StreamClass,
                        consumer.ConsumerClass,
                        "delivered",
                        consumer.Deliveries - previousDelivered);
                if (consumer.Redelivered > previousRedelivered)
                    telemetry.RecordNatsMessages(
                        consumer.StreamClass,
                        consumer.ConsumerClass,
                        "redelivered",
                        consumer.Redelivered - previousRedelivered);
                lastDelivered[key] = consumer.Deliveries;
                lastRedelivered[key] = consumer.Redelivered;
            }
        }
    }

    /// <summary>
    /// Builds the per-cell gateway observations from every responding cluster's
    /// outbound link map: a cell is connected only while at least one peer (or its
    /// own report) shows a live link; a cell none of the respondents can reach —
    /// including one that stopped answering — is disconnected. Cluster names map
    /// to cells through the canonical control naming; unknown clusters are
    /// ignored rather than misclassified.
    /// </summary>
    private IReadOnlyDictionary<string, NatsGatewaysObservation> BuildMeshGatewayObservations(
        DateTimeOffset observedAt)
    {
        var result = new Dictionary<string, NatsGatewaysObservation>(StringComparer.Ordinal);
        foreach (var cell in options.ExpectedCells)
        {
            var connected = 0;
            var disconnected = 0;
            var responded = false;
            foreach (var (responder, links) in RespondingLinks)
            {
                foreach (var (remoteCluster, isConnected) in links)
                {
                    if (!remoteCluster.StartsWith("orchestrator-control-", StringComparison.Ordinal)) continue;
                    var remoteCell = remoteCluster["orchestrator-control-".Length..];
                    if (remoteCell != cell || remoteCell == responder) continue;
                    if (isConnected) connected++;
                    else disconnected++;
                }
                if (responder == cell && links.Count > 0) responded = true;
            }
            // A cell that reports its own links participates in its own census:
            // its own outbound map contributes the same connected/disconnected
            // counts the peers see from their side.
            var observation = NatsGatewaysObservation.Observe(cell, connected, disconnected, observedAt);
            observation.Validate();
            result[cell] = responded || connected + disconnected > 0
                ? observation
                : observation with { ConnectedGateways = 0, DisconnectedGateways = Math.Max(1, options.ExpectedCells.Count - 1) };
        }
        return result;
    }

    /// <summary>Per-responding-cluster outbound link maps collected this round.</summary>
    private readonly Dictionary<string, IReadOnlyDictionary<string, bool>> RespondingLinks = new(StringComparer.Ordinal);

    /// <summary>Accumulates one cluster's GATEWAYZ reply into the round's link census.</summary>
    private void AccumulateGatewayReply(string json, string ownCluster, DateTimeOffset observedAt)
    {
        if (!NatsMonitoringParsers.TryDocument(json, out var root)) return;
        var responder = NatsMonitoringParsers.ReadString(
            root.TryGetProperty("server", out var server) && server.ValueKind == System.Text.Json.JsonValueKind.Object
                ? server
                : root,
            "cluster");
        if (responder is null || !responder.StartsWith("orchestrator-control-", StringComparison.Ordinal)) return;
        var links = ParseOutboundLinks(json);
        lock (RespondingLinks)
        {
            RespondingLinks[responder] = links;
        }
    }

    private static IReadOnlyDictionary<string, bool> ParseOutboundLinks(string reply)
    {
        var links = new Dictionary<string, bool>(StringComparer.Ordinal);
        if (!NatsMonitoringParsers.TryDocument(reply, out var root) ||
            !root.TryGetProperty("data", out var data) ||
            data.ValueKind != System.Text.Json.JsonValueKind.Object ||
            !data.TryGetProperty("outbound_gateways", out var gateways) ||
            gateways.ValueKind != System.Text.Json.JsonValueKind.Object)
            return links;
        foreach (var gateway in gateways.EnumerateObject())
        {
            var connected = gateway.Value.ValueKind == System.Text.Json.JsonValueKind.Object &&
                            gateway.Value.TryGetProperty("connection", out var connection) &&
                            connection.ValueKind == System.Text.Json.JsonValueKind.Object;
            links.TryAdd(gateway.Name, connected);
        }
        return links;
    }

    private void ReevaluateAvailability()
    {
        lock (gate)
        {
            if (current is null) return;
            var availability = NatsMonitoringSupervision.Availability(
                lastSuccessfulRound,
                consecutiveFailedRounds,
                DateTimeOffset.UtcNow);
            if (availability == current.Availability) return;
            current = current with { Availability = availability };
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        await stopping.CancelAsync();
        // Dispose the client first: connection teardown is what ends the advisory
        // subscriptions, so awaiting the loops before disposing them would wait on
        // enumerations that only the disposed connection can complete.
        try
        {
            await client.DisposeAsync();
        }
        finally
        {
            foreach (var loop in advisoryLoops) await IgnoreMonitoringFailureAsync(loop);
            if (runLoop is not null) await IgnoreMonitoringFailureAsync(runLoop);
            stopping.Dispose();
        }
    }

    private static async Task IgnoreMonitoringFailureAsync(Task loop)
    {
        try
        {
            await loop;
        }
        catch (OperationCanceledException)
        {
            // Ordinary shutdown.
        }
        catch (Exception)
        {
            // Any other ending of a monitoring loop — transport failure or an
            // unexpected fault — is an observability outage only; it must never
            // surface as a control failure or break disposal of the observer.
        }
    }
}
