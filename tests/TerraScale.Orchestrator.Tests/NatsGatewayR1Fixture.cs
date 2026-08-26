using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using NATS.Client.Core;
using NATS.Client.JetStream;
using NATS.Net;
using TerraScale.Orchestrator.Development;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

/// <summary>One issued certificate pair plus its SPIFFE identity; file references only.</summary>
internal sealed record NatsGatewayR1Certificate(
    string CertificateFile,
    string KeyFile,
    string SpiffeId);

/// <summary>The RF1 fixture's private PKI: one CA, per-server per-transport certificates, and client certificates.</summary>
internal sealed record NatsGatewayR1Pki(
    string CaFile,
    Dictionary<(string Server, NatsGatewayTransport Transport), NatsGatewayR1Certificate> ServerCertificates,
    Dictionary<string, NatsGatewayR1Certificate> ClientCertificates);

/// <summary>The RF1 fixture's trust root: operator public identity, its seed (in-process only), JWT file, and accounts.</summary>
internal sealed record NatsGatewayR1Trust(
    string OperatorPublicKey,
    string OperatorSeed,
    string OperatorJwtFile,
    Dictionary<string, NatsGatewayConformanceAccount> Accounts);

/// <summary>The observed gateway link state of one cluster: remote cluster name to connection state.</summary>
internal sealed record NatsGatewayR1LinkSnapshot(
    IReadOnlyDictionary<string, IReadOnlyDictionary<string, string>> OutboundByCluster);

/// <summary>
/// A real-NATS gateway supercluster at the RF1 regional-development fidelity:
/// one pinned nats-server per region (GRU/SFO/FRA) running as its own
/// hardened rootless Podman container on two private fixture networks, under
/// one operator JWT with the typed plan's account model, imports, and
/// exports. Every server configuration is rendered by
/// <see cref="NatsGatewayConfigurationRenderer"/> from the typed
/// <see cref="NatsGatewayPlan"/> — never written by hand — and because the
/// fixture endpoints are private fixture-network addresses (not loopback),
/// the plan validates against the production admission profile.
///
/// The client network carries the host-published loopback client ports and
/// is never severed. The internal gateway network carries only gateway
/// links; <see cref="SeverGatewayLinksAsync"/> removes one region's
/// gateway-network interface, which kills every gateway link to and from
/// that region at the transport level while the server process, its client
/// listener, and its local clients stay alive — a real link fault, not a
/// process restart, reload, or new connection. Gateway link state is
/// observed in-band through the pinned server's
/// <c>$SYS.REQ.SERVER.PING.GATEWAYZ</c> system service.
///
/// This is regional-development (RF1) evidence, not production R3/quorum
/// evidence; quorum stays with <see cref="NatsControlR3L0cFixture"/>, and
/// the L0C gateway conformance shape stays with
/// <see cref="NatsGatewaySuperclusterFixture"/>.
/// </summary>
internal sealed class NatsGatewayR1Fixture : IAsyncDisposable
{
    /// <summary>RF1: one control server per region.</summary>
    internal const int ServersPerRegion = 1;

    /// <summary>
    /// The fixture admits at most this much container memory at startup:
    /// three servers times the plane's 256 MiB per-container limit.
    /// </summary>
    internal const int FixtureStartupMemoryLimitMiB =
        3 * NatsGatewayR1ContainerPlane.ServerMemoryLimitMiB;

    /// <summary>Bound on automatic recovery after a healed gateway link.</summary>
    internal static readonly TimeSpan HealDeadline = TimeSpan.FromSeconds(30);

    internal const string GatewayStateSubject = "$SYS.REQ.SERVER.PING.GATEWAYZ";
    internal const string ConnectedState = "CONNECTED";

    private const UnixFileMode PrivateFileMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private const UnixFileMode PrivateDirectoryMode = PrivateFileMode | UnixFileMode.UserExecute;

    private readonly string directory;
    private readonly Dictionary<string, Process> processes = new(StringComparer.Ordinal);
    private readonly Dictionary<string, ConcurrentQueue<string>> processOutput = new(StringComparer.Ordinal);
    private readonly Dictionary<string, Task> processDrain = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> configurations = new(StringComparer.Ordinal);
    private readonly Dictionary<string, int> clientPorts = new(StringComparer.Ordinal);
    private readonly NatsGatewayR1ContainerPlane plane;
    private readonly LocalNatsServerLease.Handle lease;
    private int disposed;

    private NatsGatewayR1Fixture(
        string directory,
        Dictionary<string, string> configurations,
        Dictionary<string, int> clientPorts,
        NatsGatewayR1ContainerPlane plane,
        LocalNatsServerLease.Handle lease,
        NatsGatewayPlan plan,
        string caFile,
        string operatorJwtFile,
        IReadOnlyDictionary<string, NatsGatewayConformanceAccount> accounts,
        IReadOnlyDictionary<string, NatsGatewayConformanceIdentity> users)
    {
        this.directory = directory;
        this.configurations = configurations;
        this.clientPorts = clientPorts;
        this.plane = plane;
        this.lease = lease;
        Plan = plan;
        CaFile = caFile;
        OperatorJwtFile = operatorJwtFile;
        Accounts = accounts;
        Users = users;
    }

    /// <summary>The validated RF1 plan the servers were rendered from.</summary>
    internal NatsGatewayPlan Plan { get; }

    internal string CaFile { get; }

    internal string OperatorJwtFile { get; }

    internal IReadOnlyDictionary<string, NatsGatewayConformanceAccount> Accounts { get; }

    internal IReadOnlyDictionary<string, NatsGatewayConformanceIdentity> Users { get; }

    internal IReadOnlyDictionary<string, string> Configurations => configurations;

    /// <summary>The host-published loopback client ports; free again after clean cleanup.</summary>
    internal IReadOnlyDictionary<string, int> ClientPorts => clientPorts;

    /// <summary>Every server name in stable cell order.</summary>
    internal IReadOnlyList<string> ServerNames =>
        [.. Plan.Clusters.SelectMany(static cluster => cluster.Servers.Select(static server => server.ServerName))];

    internal string DirectoryPath => directory;

    /// <summary>Sanitized last diagnostic lines per server, for failure messages only.</summary>
    internal IReadOnlyDictionary<string, string> SanitizedServerDiagnostics() =>
        processes.ToDictionary(
            pair => pair.Key,
            pair =>
            {
                if (!processOutput.TryGetValue(pair.Key, out var output))
                    return string.Empty;
                return string.Join(
                    " | ",
                    output
                        .Select(SanitizeDiagnosticLine)
                        .Where(line => line.Contains("error", StringComparison.OrdinalIgnoreCase) ||
                                       line.Contains("violat", StringComparison.OrdinalIgnoreCase) ||
                                       line.Contains("auth", StringComparison.OrdinalIgnoreCase) ||
                                       line.Contains("gateway", StringComparison.OrdinalIgnoreCase) ||
                                       line.Contains("route", StringComparison.OrdinalIgnoreCase) ||
                                       line.Contains("jetstream", StringComparison.OrdinalIgnoreCase))
                        .TakeLast(8));
            },
            StringComparer.Ordinal);

    public static async Task<NatsGatewayR1Fixture> StartAsync(
        CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("The RF1 gateway fixture requires Linux.");

        var lease = await LocalNatsServerLease.AcquireAsync(cancellationToken);
        var directory = Path.Combine(Path.GetTempPath(), $"ts-orch-nats-gateway-r1-{Guid.NewGuid():N}");
        NatsGatewayR1Fixture? fixture = null;
        try
        {
            CreatePrivateDirectory(directory);
            string[] cells = ["fra", "gru", "sfo"];

            // Deterministic ports: client (host-published), route, and gateway
            // listeners each get one reserved loopback port per server.
            var portReservations = ReserveLoopbackPorts(cells.Length * 3);
            Dictionary<string, int> clientPorts;
            Dictionary<string, int> routePorts;
            Dictionary<string, int> gatewayPorts;
            try
            {
                clientPorts = IndexPorts(cells, portReservations, 0);
                routePorts = IndexPorts(cells, portReservations, 1);
                gatewayPorts = IndexPorts(cells, portReservations, 2);
            }
            finally
            {
                foreach (var listener in portReservations)
                    listener.Stop();
            }

            var placements = new List<NatsGatewayR1Placement>();
            foreach (var (cell, index) in cells.Select(static (cell, index) => (cell, index)))
            {
                var serverName = NatsGatewayPlaneTopology.ControlServerName(cell, 1);
                placements.Add(new NatsGatewayR1Placement(
                    serverName,
                    // The container name is also the server's DNS-resolvable
                    // gateway address on the internal gateway network.
                    $"ts-r1-{serverName}-{Guid.NewGuid().ToString("N")[..8]}",
                    clientPorts[serverName],
                    NatsGatewayR1ContainerPlane.GatewayAddressFor(index)));
            }

            var plane = await NatsGatewayR1ContainerPlane.CreateAsync(placements, cancellationToken);
            try
            {
                var pki = CreatePki(directory, placements);
                var trust = CreateTrust(directory);
                var identities = CreateUsers(directory, pki, trust);
                var gatewayAddresses = placements.ToDictionary(
                    static placement => placement.ServerName,
                    static placement => placement.GatewayNetworkAddress,
                    StringComparer.Ordinal);
                var plan = BuildRf1Plan(
                    directory,
                    cells,
                    clientPorts,
                    routePorts,
                    gatewayPorts,
                    gatewayAddresses,
                    pki);
                // The fixture's endpoint hosts are fixed addresses on the
                // private gateway network and an all-interface client bind —
                // never loopback — so the plan passes the production
                // admission profile, stricter than the loopback conformance
                // lane. This is still RF1 regional-development evidence,
                // never R3/quorum evidence.
                NatsGatewayPlanValidation.EnsureValid(plan);

                var context = new NatsGatewayRenderContext(
                    trust.OperatorJwtFile,
                    [.. trust.Accounts.Values.Select(account => new NatsGatewayRenderAccount(
                        account.Name, account.PublicKey, account.Jwt))]);
                var configurations = new Dictionary<string, string>(StringComparer.Ordinal);
                foreach (var cluster in plan.Clusters)
                {
                    foreach (var server in cluster.Servers)
                    {
                        var rendered = NatsGatewayConfigurationRenderer.Render(
                            plan,
                            cluster.Cell,
                            server.ServerName,
                            context);
                        if (NatsGatewayConfigurationRenderer.ScanForSecrets(rendered).Count > 0)
                            throw new InvalidOperationException("The rendered RF1 gateway configuration failed the secret scan.");
                        var path = Path.Combine(directory, $"{server.ServerName}.conf");
                        await File.WriteAllTextAsync(path, rendered, cancellationToken);
                        SetPrivateFile(path);
                        configurations[server.ServerName] = path;
                        CreatePrivateDirectory(Path.Combine(directory, $"store-{server.ServerName}"));
                    }
                }

                fixture = new NatsGatewayR1Fixture(
                    directory,
                    configurations,
                    clientPorts,
                    plane,
                    lease,
                    plan,
                    pki.CaFile,
                    trust.OperatorJwtFile,
                    trust.Accounts,
                    identities);
                foreach (var placement in placements)
                    fixture.StartServer(placement);
                await fixture.WaitForServersAsync(cancellationToken);
                await fixture.WaitForJetStreamReadinessAsync(cancellationToken);
                await fixture.WaitForFullMeshAsync(cancellationToken);
                return fixture;
            }
            catch
            {
                await plane.DisposeAsync();
                throw;
            }
        }
        catch (Exception startupFailure)
        {
            Exception? cleanupFailure = null;
            if (fixture is not null)
            {
                try
                {
                    await fixture.DisposeAsync();
                }
                catch (Exception exception)
                {
                    cleanupFailure = exception;
                }
            }
            else
            {
                try
                {
                    await new LocalNatsServerLease.DirectoryCleanupOwner(directory, lease).DisposeAsync();
                }
                catch (Exception exception)
                {
                    cleanupFailure = exception;
                }
            }
            if (cleanupFailure is not null)
                throw new AggregateException(startupFailure, cleanupFailure);
            throw;
        }
    }

    internal NatsOpts ClientOptions(NatsGatewayConformanceIdentity identity, string serverName) => new()
    {
        Url = $"tls://127.0.0.1:{clientPorts[serverName]}",
        RetryOnInitialConnect = false,
        ConnectTimeout = TimeSpan.FromSeconds(2),
        RequestTimeout = TimeSpan.FromSeconds(2),
        TlsOpts = new NatsTlsOpts
        {
            Mode = TlsMode.Require,
            CaFile = CaFile,
            CertFile = identity.CertificateFile,
            KeyFile = identity.KeyFile,
        },
        AuthOpts = new NatsAuthOpts { CredsFile = identity.CredentialsFile },
    };

    /// <summary>Connects to the RF1 control server of one region.</summary>
    internal async Task<NatsClient> ConnectAsync(
        NatsGatewayConformanceIdentity identity,
        string cell,
        CancellationToken cancellationToken = default) =>
        await ConnectToServerAsync(
            identity,
            NatsGatewayPlaneTopology.ControlServerName(cell, 1),
            cancellationToken);

    internal async Task<NatsClient> ConnectToServerAsync(
        NatsGatewayConformanceIdentity identity,
        string serverName,
        CancellationToken cancellationToken = default)
    {
        var client = new NatsClient(ClientOptions(identity, serverName));
        try
        {
            await client.ConnectAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5), cancellationToken);
            return client;
        }
        catch
        {
            await client.DisposeAsync();
            throw;
        }
    }

    /// <summary>
    /// Severs every gateway link of one region's server by removing its
    /// internal gateway-network interface. The server process, its client
    /// listener, and its local clients stay alive.
    /// </summary>
    internal async Task SeverGatewayLinksAsync(string cell, CancellationToken cancellationToken = default)
    {
        await plane.SeverGatewayLinksAsync(NatsGatewayPlaneTopology.ControlServerName(cell, 1), cancellationToken);
    }

    /// <summary>
    /// Heals one region's severed gateway links by re-attaching its
    /// gateway-network interface with the same fixed address; the servers'
    /// own gateway reconnect logic re-establishes the links.
    /// </summary>
    internal async Task HealGatewayLinksAsync(string cell, CancellationToken cancellationToken = default)
    {
        await plane.HealGatewayLinksAsync(NatsGatewayPlaneTopology.ControlServerName(cell, 1), cancellationToken);
    }

    /// <summary>True while one region's server process is still running.</summary>
    internal bool ServerIsRunning(string cell) =>
        plane.IsRunning(NatsGatewayPlaneTopology.ControlServerName(cell, 1));

    /// <summary>
    /// The gateway link state of every responding cluster, observed in-band
    /// through the pinned server's <c>$SYS.REQ.SERVER.PING.GATEWAYZ</c>
    /// system service: own cluster name to remote cluster name to outbound
    /// connection state. Contains no credentials, addresses, or payloads.
    /// </summary>
    internal async Task<NatsGatewayR1LinkSnapshot> GatewayLinkStateAsync(
        CancellationToken cancellationToken = default)
    {
        await using var observer = await ConnectToServerAsync(
            Users["system-observer"],
            NatsGatewayPlaneTopology.ControlServerName("gru", 1),
            cancellationToken);
        var outbound = new Dictionary<string, IReadOnlyDictionary<string, string>>(StringComparer.Ordinal);
        await foreach (var reply in observer.Connection.RequestManyAsync<string, string>(
                           GatewayStateSubject,
                           string.Empty,
                           cancellationToken: cancellationToken))
        {
            if (reply.Data is not { Length: > 0 })
                continue;
            if (TryParseGatewayz(reply.Data, out var cluster, out var remotes) &&
                cluster is not null &&
                !outbound.ContainsKey(cluster))
            {
                outbound[cluster] = remotes;
            }
        }
        return new NatsGatewayR1LinkSnapshot(outbound);
    }

    /// <summary>True when every cluster reports every remote cluster connected.</summary>
    internal bool IsFullMeshConnected(NatsGatewayR1LinkSnapshot snapshot) =>
        Plan.Clusters.All(cluster =>
            snapshot.OutboundByCluster.TryGetValue(cluster.ClusterName, out var remotes) &&
            Plan.Clusters
                .Where(other => other.Cell != cluster.Cell)
                .All(other =>
                    remotes.TryGetValue(other.ClusterName, out var state) &&
                    string.Equals(state, ConnectedState, StringComparison.Ordinal)));

    /// <summary>Names of containers and networks the fixture still owns right now.</summary>
    internal async Task<(IReadOnlyList<string> Containers, IReadOnlyList<string> Networks)>
        ListOwnedResourcesAsync(CancellationToken cancellationToken = default) =>
        (await plane.ListOwnedContainersAsync(cancellationToken),
            await plane.ListOwnedNetworksAsync(cancellationToken));

    private static bool TryParseGatewayz(
        string json,
        out string? cluster,
        out IReadOnlyDictionary<string, string> remotes)
    {
        cluster = null;
        var remoteStates = new Dictionary<string, string>(StringComparer.Ordinal);
        remotes = remoteStates;
        try
        {
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            if (!root.TryGetProperty("data", out var data) ||
                !data.TryGetProperty("name", out var name) ||
                name.GetString() is not { Length: > 0 } clusterName)
                return false;
            // The pinned server reports outbound gateways as a map of remote
            // cluster name to { configured, connection? }: an entry is
            // connected exactly when its connection object is present.
            if (data.TryGetProperty("outbound_gateways", out var gateways) &&
                gateways.ValueKind == JsonValueKind.Object)
            {
                foreach (var gateway in gateways.EnumerateObject())
                {
                    var connected = gateway.Value.ValueKind == JsonValueKind.Object &&
                                    gateway.Value.TryGetProperty("connection", out var connection) &&
                                    connection.ValueKind == JsonValueKind.Object;
                    remoteStates.TryAdd(gateway.Name, connected ? ConnectedState : "disconnected");
                }
            }
            cluster = clusterName;
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private void StartServer(NatsGatewayR1Placement placement)
    {
        var process = plane.Start(placement, configurations[placement.ServerName]);
        processes[placement.ServerName] = process;
        var lines = new ConcurrentQueue<string>();
        processOutput[placement.ServerName] = lines;
        processDrain[placement.ServerName] = DrainProcessOutputAsync(process, lines);
    }

    private async Task WaitForServersAsync(CancellationToken cancellationToken)
    {
        foreach (var serverName in processes.Keys.Order(StringComparer.Ordinal))
            await WaitForServerAsync(serverName, cancellationToken);
    }

    private async Task WaitForServerAsync(string serverName, CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < 300; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (processes.TryGetValue(serverName, out var process) && process.HasExited)
                throw new InvalidOperationException(GetServerExitDiagnostic(serverName, process));
            try
            {
                await using var client = await ConnectToServerAsync(
                    Users["gru-operator-read"], serverName, cancellationToken);
                await client.PingAsync(cancellationToken);
                return;
            }
            catch (NatsException)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(100), cancellationToken);
            }
        }
        var diagnostics = SanitizedServerDiagnostics()
            .Select(pair => $"{pair.Key}: {pair.Value}")
            .Where(line => line.Length > 0)
            .ToArray();
        throw new TimeoutException(
            $"The RF1 gateway server '{serverName}' did not become ready within 30 seconds. " +
            $"Server diagnostics: {string.Join(" ;; ", diagnostics)}");
    }

    /// <summary>
    /// Waits until each region's JetStream domain is serving API requests
    /// through its own server, mirroring the L0C lane's readiness gate: an
    /// answered stream lookup — existing stream or 404 — proves a serving
    /// meta layer.
    /// </summary>
    private async Task WaitForJetStreamReadinessAsync(CancellationToken cancellationToken)
    {
        // The global authority assets do not exist yet, so an answered lookup
        // proves each domain's meta layer is serving through a 404 — the same
        // gate the L0C lane uses. Every region's infrastructure identity may
        // read the global stream's existence in its own domain.
        foreach (var cluster in Plan.Clusters)
        {
            foreach (var server in cluster.Servers)
            {
                await WaitForServerJetStreamAsync(
                    cluster.Cell,
                    server.ServerName,
                    GlobalNatsTopology.CellSpecStream,
                    cancellationToken);
            }
        }
    }

    private async Task WaitForServerJetStreamAsync(
        string cell,
        string serverName,
        string probeStream,
        CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < 300; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (processes.TryGetValue(serverName, out var process) && process.HasExited)
                throw new InvalidOperationException(GetServerExitDiagnostic(serverName, process));
            try
            {
                await using var infrastructure = await ConnectToServerAsync(
                    Users[$"{cell}-infrastructure"], serverName, cancellationToken);
                try
                {
                    _ = await infrastructure.CreateJetStreamContext()
                        .GetStreamAsync(probeStream, cancellationToken: cancellationToken);
                    return;
                }
                catch (NatsJSApiException exception) when (exception.Error.Code == 404)
                {
                    return;
                }
            }
            catch (NatsException)
            {
                // Includes the JetStream API's "temporarily unavailable"
                // answer while the meta layer is still forming; the next
                // attempt re-probes.
                await Task.Delay(TimeSpan.FromMilliseconds(200), cancellationToken);
            }
        }
        var diagnostics = SanitizedServerDiagnostics()
            .Select(pair => $"{pair.Key}: {pair.Value}")
            .Where(line => line.Length > 0)
            .ToArray();
        throw new TimeoutException(
            $"The JetStream domain of RF1 cluster '{cell}' did not become ready through server '{serverName}' within 60 seconds. " +
            $"Server diagnostics: {string.Join(" ;; ", diagnostics)}");
    }

    /// <summary>
    /// Waits until the full directed mesh is observed as connected: every
    /// cluster reports an outbound gateway connection in state CONNECTED to
    /// every other cluster.
    /// </summary>
    private async Task WaitForFullMeshAsync(CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < 200; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var snapshot = await GatewayLinkStateAsync(cancellationToken);
            if (IsFullMeshConnected(snapshot))
                return;
            await Task.Delay(TimeSpan.FromMilliseconds(300), cancellationToken);
        }
        var snapshotText = DescribeLinkState(await GatewayLinkStateAsync(cancellationToken));
        var diagnostics = SanitizedServerDiagnostics()
            .Select(pair => $"{pair.Key}: {pair.Value}")
            .Where(line => line.Length > 0)
            .ToArray();
        throw new TimeoutException(
            $"The RF1 gateway full mesh did not become connected within 60 seconds. Observed: {snapshotText}. " +
            $"Server diagnostics: {string.Join(" ;; ", diagnostics)}");
    }

    internal string DescribeLinkState(NatsGatewayR1LinkSnapshot snapshot) =>
        string.Join(
            "; ",
            Plan.Clusters
                .Select(cluster =>
                {
                    snapshot.OutboundByCluster.TryGetValue(cluster.ClusterName, out var remotes);
                    var described = remotes is null
                        ? "no-response"
                        : string.Join(
                            ",",
                            Plan.Clusters
                                .Where(other => other.Cell != cluster.Cell)
                                .Select(other => $"{other.ClusterName}={remotes.GetValueOrDefault(other.ClusterName, "unreported")}"));
                    return $"{cluster.ClusterName}->({described})";
                })
                .Order(StringComparer.Ordinal));

    /// <summary>
    /// Reduces the production control supercluster to the RF1
    /// regional-development shape: one server per region, each in its own
    /// container failure domain on the fixture's private networks. The
    /// account model, mesh, imports, exports, canonical names, and domains
    /// are the production plan's own.
    /// </summary>
    private static NatsGatewayPlan BuildRf1Plan(
        string directory,
        string[] cells,
        Dictionary<string, int> clientPorts,
        Dictionary<string, int> routePorts,
        Dictionary<string, int> gatewayPorts,
        IReadOnlyDictionary<string, string> gatewayAddresses,
        NatsGatewayR1Pki pki)
    {
        var production = NatsGatewayPlaneTopology.CreateControlSupercluster();
        var clusters = new List<NatsGatewayCluster>();
        foreach (var cell in cells)
        {
            var productionCluster = production.Cluster(cell)!;
            var name = NatsGatewayPlaneTopology.ControlServerName(cell, 1);
            var gatewayAddress = gatewayAddresses[name];
            var server = new NatsGatewayServerIdentity(
                name,
                // One container per server: each server is its own failure domain.
                name,
                // The client listener binds every interface: the host-published
                // loopback port is forwarded onto the container's client
                // network, which is never severed.
                new NatsGatewayEndpoint("0.0.0.0", clientPorts[name]),
                // The single-server cluster's mandatory self-route binds every
                // interface and solicits itself over the container's own
                // loopback. This preserves the region's JetStream domain and
                // durable state through the severance window; the JetStream
                // API itself answers 503 for the whole window on this shape
                // (observed window-long, not transient settling — see the
                // during-fault probe in the partition scenario). What
                // continuity means here — and what the scenario proves — is
                // that no regional state is lost: the same stream and
                // durable consumer resume with exact delivery and duplicate
                // counts after the heal.
                new NatsGatewayEndpoint("0.0.0.0", routePorts[name]),
                // Gateway peers dial this server's fixed address on the
                // internal gateway network, which carries every gateway link.
                new NatsGatewayEndpoint(gatewayAddress, gatewayPorts[name]),
                ServerProfiles(pki, name, cells),
                new NatsGatewayProcessIdentity(
                    NatsGatewayPlaneTopology.ControlUnitName(cell, 1),
                    $"{NatsGatewayPlaneTopology.ControlCgroupSlice}/{NatsGatewayPlaneTopology.ControlUnitName(cell, 1)}"),
                Path.Combine(directory, $"store-{name}"));
            clusters.Add(new NatsGatewayCluster(
                NatsGatewayPlane.Control,
                cell,
                productionCluster.ClusterName,
                productionCluster.JetStreamDomain,
                productionCluster.OperatorName,
                [server],
                productionCluster.Accounts,
                productionCluster.JetStreamAssets,
                productionCluster.CgroupSlice,
                productionCluster.TrustGeneration,
                productionCluster.ConfigurationGeneration));
        }

        return new NatsGatewayPlan(
            NatsGatewayPlane.Control,
            production.OperatorName,
            production.TrustGeneration,
            production.ConfigurationGeneration,
            [.. clusters],
            NatsGatewayMesh.FullMesh(cells),
            production.Accounts,
            production.Exports,
            production.Imports);
    }

    private static IReadOnlyList<NatsGatewayCertificateProfile> ServerProfiles(
        NatsGatewayR1Pki pki,
        string serverName,
        string[] cells)
    {
        return
        [
            new NatsGatewayCertificateProfile(
                NatsGatewayTransport.Client,
                pki.ServerCertificates[(serverName, NatsGatewayTransport.Client)].CertificateFile,
                pki.ServerCertificates[(serverName, NatsGatewayTransport.Client)].KeyFile,
                pki.CaFile,
                [NatsGatewayPlaneTopology.ControlClientSpiffePrefix]),
            new NatsGatewayCertificateProfile(
                NatsGatewayTransport.Route,
                pki.ServerCertificates[(serverName, NatsGatewayTransport.Route)].CertificateFile,
                pki.ServerCertificates[(serverName, NatsGatewayTransport.Route)].KeyFile,
                pki.CaFile,
                // An RF1 regional cluster has no route peers; the profile
                // carries its own identity for the loopback self-route that
                // keeps the single-node JetStream meta layer serving.
                [NatsGatewayPlaneTopology.ControlServerSpiffeId(serverName)]),
            new NatsGatewayCertificateProfile(
                NatsGatewayTransport.Gateway,
                pki.ServerCertificates[(serverName, NatsGatewayTransport.Gateway)].CertificateFile,
                pki.ServerCertificates[(serverName, NatsGatewayTransport.Gateway)].KeyFile,
                pki.CaFile,
                cells.Where(other => other != serverName.Split('-')[0])
                    .Select(other => NatsGatewayPlaneTopology.ControlServerSpiffeId(
                        NatsGatewayPlaneTopology.ControlServerName(other, 1)))),
        ];
    }

    private static Dictionary<string, int> IndexPorts(string[] cells, TcpListener[] reservations, int slot)
    {
        var ports = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var (cell, index) in cells.Select(static (cell, index) => (cell, index)))
        {
            ports[NatsGatewayPlaneTopology.ControlServerName(cell, 1)] =
                GetReservedPort(reservations[(slot * cells.Length) + index]);
        }
        return ports;
    }

    private static NatsGatewayR1Trust CreateTrust(string root)
    {
        CreatePrivateDirectory(Path.Combine(root, "trust"));
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var operatorSeed = NKeys.CreateOperatorSeed();
        var operatorPublicKey = NKeys.PublicKeyFromSeed(operatorSeed);
        string[] cells = ["fra", "gru", "sfo"];
        var system = CreateAccount(operatorSeed, operatorPublicKey, "system", now, enableJetStream: false);
        var operatorJwt = EncodeJwt(
            operatorSeed,
            operatorPublicKey,
            new Dictionary<string, object?>
            {
                ["iat"] = now,
                ["iss"] = operatorPublicKey,
                ["jti"] = Jti(operatorPublicKey, now, "operator"),
                ["name"] = "gateway-rf1-operator",
                ["nats"] = new Dictionary<string, object?>
                {
                    ["system_account"] = system.PublicKey,
                },
                ["sub"] = operatorPublicKey,
                ["type"] = "operator",
            });
        var operatorJwtFile = WritePrivateFile(root, "trust/operator.jwt", operatorJwt);
        var authority = CreateAccount(operatorSeed, operatorPublicKey, GlobalNatsAccountNames.GlobalAuthority, now);
        var directory = CreateAccount(
            operatorSeed,
            operatorPublicKey,
            GlobalNatsAccountNames.GlobalDirectory,
            now,
            exports: [ServiceExport(GlobalNatsTopology.CellDirectorySubject)]);
        var regional = cells.ToDictionary(
            cell => cell,
            cell => CreateAccount(
                operatorSeed,
                operatorPublicKey,
                GlobalNatsAccountNames.RegionalControl(cell),
                now,
                imports: cell == "gru"
                    ? []
                    : [ServiceImport(GlobalNatsTopology.CellDirectorySubject, directory.PublicKey)]),
            StringComparer.Ordinal);
        var accounts = new Dictionary<string, NatsGatewayConformanceAccount>(StringComparer.Ordinal)
        {
            ["system"] = system,
            [GlobalNatsAccountNames.GlobalAuthority] = authority,
            [GlobalNatsAccountNames.GlobalDirectory] = directory,
        };
        foreach (var account in regional.Values)
            accounts.Add(account.Name, account);
        return new(operatorPublicKey, operatorSeed, operatorJwtFile, accounts);
    }

    private static NatsGatewayConformanceAccount CreateAccount(
        string operatorSeed,
        string operatorPublicKey,
        string name,
        long issuedAt,
        bool enableJetStream = true,
        IReadOnlyList<Dictionary<string, object?>>? imports = null,
        IReadOnlyList<Dictionary<string, object?>>? exports = null)
    {
        var accountSeed = NKeys.CreateAccountSeed();
        var accountPublicKey = NKeys.PublicKeyFromSeed(accountSeed);
        var limits = new Dictionary<string, object?>
        {
            ["conn"] = -1,
            ["data"] = -1,
            ["exports"] = -1,
            ["imports"] = -1,
            ["leaf"] = -1,
            ["payload"] = -1,
            ["subs"] = -1,
            ["wildcards"] = true,
        };
        if (enableJetStream)
        {
            limits["consumer"] = -1;
            limits["disk_storage"] = -1;
            limits["mem_storage"] = -1;
            limits["streams"] = -1;
        }
        var nats = new Dictionary<string, object?>
        {
            ["limits"] = limits,
            ["type"] = "account",
            ["version"] = 2,
        };
        if (imports is { Count: > 0 }) nats["imports"] = imports;
        if (exports is { Count: > 0 }) nats["exports"] = exports;
        var claims = new Dictionary<string, object?>
        {
            ["iat"] = issuedAt,
            ["iss"] = operatorPublicKey,
            ["jti"] = Jti(accountPublicKey, issuedAt, name),
            ["name"] = name,
            ["nats"] = nats,
            ["sub"] = accountPublicKey,
        };
        var jwt = EncodeJwt(operatorSeed, operatorPublicKey, claims);
        return new NatsGatewayConformanceAccount(name, accountPublicKey, accountSeed, jwt);
    }

    private static IReadOnlyDictionary<string, NatsGatewayConformanceIdentity> CreateUsers(
        string root,
        NatsGatewayR1Pki pki,
        NatsGatewayR1Trust trust)
    {
        var directory = GlobalNatsAccountNames.GlobalDirectory;
        var regionalFra = GlobalNatsAccountNames.RegionalControl("fra");
        var regionalGru = GlobalNatsAccountNames.RegionalControl("gru");
        var regionalSfo = GlobalNatsAccountNames.RegionalControl("sfo");
        var directoryService = Permissions(GlobalNatsPermissions.Create("gru", GlobalNatsRole.CellDirectoryService));
        var readerFra = Permissions(GlobalNatsPermissions.Create("fra", GlobalNatsRole.CellDirectoryReader));
        var readerPlan = Permissions(GlobalNatsPermissions.Create("sfo", GlobalNatsRole.CellDirectoryReader));
        // The SFO directory publisher holds only its own cell's advertisement key
        // in the GRU-owned GLOBAL_CELLS bucket: the exact production publisher
        // permission plan, exercised from a remote cell.
        var publisherSfo = Permissions(GlobalNatsPermissions.Create("sfo", GlobalNatsRole.CellDirectoryPublisher));
        // A watch-only directory identity for the GRU-side projection runtime.
        var watcherGru = (
            Publish: new List<string>
            {
                "$JS.API.CONSUMER.CREATE.KV_GLOBAL_CELLS",
                "$JS.API.CONSUMER.CREATE.KV_GLOBAL_CELLS.>",
                "$JS.API.STREAM.INFO.KV_GLOBAL_CELLS",
                "$JS.FC.KV_GLOBAL_CELLS.>",
            },
            Subscribe: new List<string> { "$KV.GLOBAL_CELLS.>", "_INBOX.>" });
        // The global-directory account's infrastructure identity: the only R1
        // identity that may create the GRU-owned GLOBAL_CELLS bucket, mirroring
        // the L0C lane's global-directory infrastructure role. JetStream state is
        // account-scoped, so the bucket must live in the directory account.
        var directoryInfrastructure = (
            Publish: new List<string>
            {
                "$JS.API.STREAM.CREATE.KV_GLOBAL_CELLS",
                "$JS.API.STREAM.UPDATE.KV_GLOBAL_CELLS",
                "$JS.API.STREAM.INFO.KV_GLOBAL_CELLS",
            },
            Subscribe: new List<string> { "_INBOX.>" });
        // The SFO probe is the one client held across the fault. Besides the
        // approved cross-mesh directory request it may use its own region's
        // versioned status and members queries, which stay local to SFO and
        // prove regional continuity while the region is isolated.
        var sfoRegional = new NatsTopology("sfo", ServersPerRegion);
        var sfoProbe = (
            Publish: new List<string>(readerPlan.Publish) { sfoRegional.StatusSubject, sfoRegional.MembersSubject },
            Subscribe: readerPlan.Subscribe);
        var gruRegional = new NatsTopology("gru", ServersPerRegion);
        return new Dictionary<string, NatsGatewayConformanceIdentity>(StringComparer.Ordinal)
        {
            ["directory-service-gru"] = CreateUser(
                root, pki, trust, directory, "directory-service-gru", directoryService),
            ["directory-publisher-sfo"] = CreateUser(
                root, pki, trust, directory, "directory-publisher-sfo", publisherSfo),
            ["directory-watcher-gru"] = CreateUser(
                root, pki, trust, directory, "directory-watcher-gru", watcherGru),
            ["directory-infrastructure-gru"] = CreateUser(
                root, pki, trust, directory, "directory-infrastructure-gru", directoryInfrastructure),
            ["directory-reader-sfo"] = CreateUser(
                root, pki, trust, regionalSfo, "directory-reader-sfo", sfoProbe),
            ["directory-reader-fra"] = CreateUser(
                root, pki, trust, regionalFra, "directory-reader-fra", readerFra),
            ["gru-operator-read"] = CreateUser(
                root, pki, trust, regionalGru, "gru-operator-read",
                new([gruRegional.StatusSubject, gruRegional.MembersSubject], ["_INBOX.>"])),
            ["gru-infrastructure"] = CreateUser(
                root, pki, trust, regionalGru, "gru-infrastructure",
                new(
                    [
                        $"$JS.API.STREAM.CREATE.{GlobalNatsTopology.CellSpecStream}",
                        $"$JS.API.STREAM.UPDATE.{GlobalNatsTopology.CellSpecStream}",
                        $"$JS.API.STREAM.INFO.{GlobalNatsTopology.CellSpecStream}",
                        $"$JS.API.STREAM.CREATE.KV_{GlobalNatsTopology.CellsBucket}",
                        $"$JS.API.STREAM.UPDATE.KV_{GlobalNatsTopology.CellsBucket}",
                        $"$JS.API.STREAM.INFO.KV_{GlobalNatsTopology.CellsBucket}",
                        "$JS.API.CONSUMER.CREATE.KV_GLOBAL_CELLS.>",
                        "$JS.FC.KV_GLOBAL_CELLS.>",
                        $"$KV.{GlobalNatsTopology.CellsBucket}.>",
                    ],
                    ["_INBOX.>"])),
            ["sfo-infrastructure"] = CreateUser(
                root, pki, trust, regionalSfo, "sfo-infrastructure",
                new(
                    [
                        "$JS.API.STREAM.CREATE.CELL_SPEC",
                        "$JS.API.STREAM.UPDATE.CELL_SPEC",
                        "$JS.API.STREAM.INFO.CELL_SPEC",
                        "$JS.API.CONSUMER.CREATE.CELL_SPEC.>",
                        "$JS.API.CONSUMER.INFO.CELL_SPEC.>",
                        "$JS.API.CONSUMER.MSG.NEXT.CELL_SPEC.>",
                        "$JS.FC.CELL_SPEC.>",
                        "$JS.ACK.CELL_SPEC.>",
                        $"{TerraScale.Orchestrator.Protocol.Messaging.NatsSubjectTaxonomy.RegionalRoot("sfo")}.desired.>",
                        // Read-only existence probes: the global authority assets
                        // must never exist inside a regional JetStream domain,
                        // so the isolated cell can prove absence (404), not
                        // just denial.
                        $"$JS.API.STREAM.INFO.{GlobalNatsTopology.CellSpecStream}",
                        $"$JS.API.STREAM.INFO.KV_{GlobalNatsTopology.CellsBucket}",
                    ],
                    ["_INBOX.>"])),
            ["fra-infrastructure"] = CreateUser(
                root, pki, trust, regionalFra, "fra-infrastructure",
                new(
                    [
                        $"$JS.API.STREAM.INFO.{GlobalNatsTopology.CellSpecStream}",
                        $"$JS.API.STREAM.INFO.KV_{GlobalNatsTopology.CellsBucket}",
                    ],
                    ["_INBOX.>"])),
            ["sfo-local-service"] = CreateUser(
                root, pki, trust, regionalSfo, "sfo-local-service",
                new(["_INBOX.>"], [sfoRegional.StatusSubject])),
            ["system-observer"] = CreateUser(
                root, pki, trust, "system", "system-observer",
                new([GatewayStateSubject, "_INBOX.>"], ["_INBOX.>"])),
            // The read-only monitoring identity (issue #23): exactly the allowlisted
            // $SYS request subjects plus the advisory subscriptions and an inbox.
            ["system-monitor"] = CreateUser(
                root, pki, trust, "system", "system-monitor",
                new(
                    NatsMonitoringPermissions.Create().Publish,
                    NatsMonitoringPermissions.Create().Subscribe)),
        };
    }

    private static (IReadOnlyList<string> Publish, IReadOnlyList<string> Subscribe) Permissions(
        GlobalNatsPermissionPlan plan) => (plan.Publish, plan.Subscribe);

    private static NatsGatewayConformanceIdentity CreateUser(
        string root,
        NatsGatewayR1Pki pki,
        NatsGatewayR1Trust trust,
        string accountName,
        string name,
        (IReadOnlyList<string> Publish, IReadOnlyList<string> Subscribe) permissions)
    {
        var account = trust.Accounts[accountName];
        var seed = NKeys.CreateUserSeed();
        var publicKey = NKeys.PublicKeyFromSeed(seed);
        var issuedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var claims = new Dictionary<string, object?>
        {
            ["iat"] = issuedAt,
            ["iss"] = account.PublicKey,
            ["jti"] = Jti(publicKey, issuedAt, name),
            ["name"] = name,
            ["nats"] = new Dictionary<string, object?>
            {
                ["data"] = -1,
                ["payload"] = -1,
                ["pub"] = new Dictionary<string, object?> { ["allow"] = permissions.Publish.ToArray() },
                ["sub"] = new Dictionary<string, object?> { ["allow"] = permissions.Subscribe.ToArray() },
                ["subs"] = -1,
                ["type"] = "user",
                ["version"] = 2,
            },
            ["sub"] = publicKey,
        };
        var jwt = EncodeJwt(account.Seed, account.PublicKey, claims);
        var credentialsFile = WritePrivateFile(
            root,
            $"users/{name}.creds",
            $"-----BEGIN NATS USER JWT-----\n{jwt}\n------END NATS USER JWT------\n\n" +
            $"-----BEGIN USER NKEY SEED-----\n{seed}\n------END USER NKEY SEED------\n");
        var certificate = pki.ClientCertificates[name];
        return new NatsGatewayConformanceIdentity(
            name,
            publicKey,
            accountName,
            credentialsFile,
            certificate.CertificateFile,
            certificate.KeyFile,
            certificate.SpiffeId);
    }

    private static Dictionary<string, object?> ServiceExport(string subject) => new()
    {
        ["subject"] = subject,
        ["type"] = "service",
        ["response_type"] = "Singleton",
    };

    private static Dictionary<string, object?> ServiceImport(string subject, string sourceAccount) => new()
    {
        ["account"] = sourceAccount,
        ["subject"] = subject,
        ["to"] = subject,
        ["type"] = "service",
    };

    private static string EncodeJwt(
        string issuerSeed,
        string issuerPublicKey,
        IReadOnlyDictionary<string, object?> claims)
    {
        var header = JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string, object?>
        {
            ["alg"] = "ed25519-nkey",
            ["typ"] = "JWT",
        });
        var body = JsonSerializer.SerializeToUtf8Bytes(claims);
        var headerSegment = Base64Url(header);
        var bodySegment = Base64Url(body);
        // NATS JWTs with a top-level `type` are v1 claims and sign only the
        // encoded payload. v2 account/user claims with nested nats.type/version
        // sign the encoded header plus payload.
        var signingInput = claims.ContainsKey("type")
            ? bodySegment
            : $"{headerSegment}.{bodySegment}";
        using var key = NKeys.FromSeed(issuerSeed);
        var signature = key.Sign(Encoding.ASCII.GetBytes(signingInput));
        return $"{headerSegment}.{bodySegment}.{Base64Url(signature)}";
    }

    private static string Jti(string subject, long issuedAt, string name)
    {
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes($"{subject}|{issuedAt}|{name}"));
        return Base32(digest);
    }

    private static string Base64Url(ReadOnlySpan<byte> bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static string Base32(ReadOnlySpan<byte> bytes)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        Span<char> output = stackalloc char[(bytes.Length * 8 + 4) / 5];
        var buffer = 0;
        var bits = 0;
        var index = 0;
        foreach (var value in bytes)
        {
            buffer = (buffer << 8) | value;
            bits += 8;
            while (bits >= 5)
            {
                bits -= 5;
                output[index++] = alphabet[(buffer >> bits) & 31];
            }
        }
        if (bits > 0) output[index++] = alphabet[(buffer << (5 - bits)) & 31];
        return new(output[..index]);
    }

    private static NatsGatewayR1Pki CreatePki(
        string root,
        IReadOnlyList<NatsGatewayR1Placement> placements)
    {
        var pkiRoot = Path.Combine(root, "pki");
        CreatePrivateDirectory(pkiRoot);
        using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var caRequest = new CertificateRequest(
            "CN=TerraScale gateway RF1 CA",
            caKey,
            HashAlgorithmName.SHA256);
        caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 1, true));
        caRequest.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign,
            true));
        caRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(caRequest.PublicKey, false));
        using var ca = caRequest.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddHours(2));
        var caFile = WriteCertificate(pkiRoot, "ca.pem", ca, caKey, privateKey: false);

        var serverCertificates = new Dictionary<(string Server, NatsGatewayTransport Transport), NatsGatewayR1Certificate>(
            new ServerTransportEqualityComparer());
        foreach (var placement in placements)
        {
            foreach (var transport in new[]
                     {
                         NatsGatewayTransport.Client,
                         NatsGatewayTransport.Route,
                         NatsGatewayTransport.Gateway,
                     })
            {
                serverCertificates[(placement.ServerName, transport)] = CreateLeaf(
                    pkiRoot,
                    $"{placement.ServerName}-{transport.ToString().ToLowerInvariant()}",
                    $"spiffe://terrascale.tech/control/nats/server/{placement.ServerName}",
                    ca,
                    serverAuthentication: true,
                    clientAuthentication: true,
                    // Gateway and route peers dial the server's fixed address
                    // on the internal gateway network, and the test clients
                    // dial the host-published loopback port, so every server
                    // certificate carries both addresses.
                    addresses: [placement.GatewayNetworkAddress]);
            }
        }

        var clientCertificates = new Dictionary<string, NatsGatewayR1Certificate>(StringComparer.Ordinal);
        foreach (var name in new[]
                 {
                     "directory-service-gru", "directory-publisher-sfo", "directory-watcher-gru",
                     "directory-infrastructure-gru",
                     "directory-reader-sfo", "directory-reader-fra",
                     "gru-operator-read", "gru-infrastructure", "sfo-infrastructure",
                     "fra-infrastructure", "sfo-local-service", "system-observer",
                     "system-monitor",
                 })
        {
            clientCertificates[name] = CreateLeaf(
                pkiRoot,
                name,
                $"spiffe://terrascale.tech/control/nats/client/{name}",
                ca,
                serverAuthentication: false,
                clientAuthentication: true,
                addresses: []);
        }
        return new(caFile, serverCertificates, clientCertificates);
    }

    private static NatsGatewayR1Certificate CreateLeaf(
        string root,
        string name,
        string spiffeId,
        X509Certificate2 ca,
        bool serverAuthentication,
        bool clientAuthentication,
        IReadOnlyList<string> addresses)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN={name}", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
            true));
        var usages = new OidCollection();
        if (serverAuthentication) usages.Add(new Oid("1.3.6.1.5.5.7.3.1"));
        if (clientAuthentication) usages.Add(new Oid("1.3.6.1.5.5.7.3.2"));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(usages, true));
        var alternativeNames = new SubjectAlternativeNameBuilder();
        alternativeNames.AddUri(new Uri(spiffeId));
        alternativeNames.AddDnsName("localhost");
        alternativeNames.AddIpAddress(IPAddress.Loopback);
        foreach (var address in addresses)
            alternativeNames.AddIpAddress(IPAddress.Parse(address));
        request.CertificateExtensions.Add(alternativeNames.Build());
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        using var issued = request.Create(
            ca,
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddHours(1),
            RandomNumberGenerator.GetBytes(16));
        using var withKey = issued.CopyWithPrivateKey(key);
        return new(
            WriteCertificate(root, $"{name}.pem", withKey, key, privateKey: true),
            Path.Combine(root, $"{name}.key.pem"),
            spiffeId);
    }

    private static string WriteCertificate(
        string root,
        string name,
        X509Certificate2 certificate,
        ECDsa key,
        bool privateKey)
    {
        var certificateFile = Path.Combine(root, name);
        var keyFile = Path.Combine(root, Path.GetFileNameWithoutExtension(name) + ".key.pem");
        File.WriteAllText(certificateFile, PemEncoding.WriteString("CERTIFICATE", certificate.Export(X509ContentType.Cert)));
        SetPrivateFile(certificateFile);
        if (privateKey)
        {
            File.WriteAllText(keyFile, PemEncoding.WriteString("PRIVATE KEY", key.ExportPkcs8PrivateKey()));
            SetPrivateFile(keyFile);
        }
        return certificateFile;
    }

    private static string WritePrivateFile(string root, string relativePath, string contents)
    {
        var path = Path.Combine(root, relativePath);
        CreatePrivateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, contents);
        SetPrivateFile(path);
        return path;
    }

    private static void CreatePrivateDirectory(string path)
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("The RF1 gateway fixture requires Linux file permissions.");
        Directory.CreateDirectory(path, PrivateDirectoryMode);
    }

    private static void SetPrivateFile(string path)
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("The RF1 gateway fixture requires Linux file permissions.");
        File.SetUnixFileMode(path, PrivateFileMode);
    }

    private static TcpListener[] ReserveLoopbackPorts(int count)
    {
        var listeners = new List<TcpListener>(count);
        try
        {
            for (var index = 0; index < count; index++)
            {
                var listener = new TcpListener(IPAddress.Loopback, 0);
                listener.Start();
                listeners.Add(listener);
            }
            return listeners.ToArray();
        }
        catch
        {
            foreach (var listener in listeners)
                listener.Stop();
            throw;
        }
    }

    private static int GetReservedPort(TcpListener listener) =>
        ((IPEndPoint)listener.LocalEndpoint).Port;

    private static async Task DrainProcessOutputAsync(Process process, ConcurrentQueue<string> lines)
    {
        // Never expose process output verbatim: it can contain server
        // diagnostics or credential context. Lines are retained only for the
        // sanitized failure-message path.
        var readers = new[]
        {
            ReadLinesAsync(process.StandardOutput, lines),
            ReadLinesAsync(process.StandardError, lines),
        };
        await Task.WhenAll(readers);
    }

    private static async Task ReadLinesAsync(StreamReader reader, ConcurrentQueue<string> lines)
    {
        while (await reader.ReadLineAsync() is { } line)
        {
            lines.Enqueue(line);
            while (lines.Count > 500)
            {
                lines.TryDequeue(out _);
            }
        }
    }

    private string GetServerExitDiagnostic(string serverName, Process process)
    {
        var state = process.HasExited ? $"exit-code={process.ExitCode}" : "running";
        if (!processOutput.TryGetValue(serverName, out var output))
            return $"The RF1 gateway server '{serverName}' exited during readiness ({state}).";
        var diagnostics = output
            .Select(SanitizeDiagnosticLine)
            .ToList();
        var priority = diagnostics
            .Where(line => line.Contains("error", StringComparison.OrdinalIgnoreCase) ||
                           line.Contains("fatal", StringComparison.OrdinalIgnoreCase) ||
                           line.Contains("failed", StringComparison.OrdinalIgnoreCase) ||
                           line.Contains("panic", StringComparison.OrdinalIgnoreCase))
            .Take(6)
            .ToArray();
        var selected = priority.Length > 0
            ? priority
            : diagnostics.TakeLast(10).ToArray();
        var suffix = selected.Length == 0
            ? string.Empty
            : $" diagnostics={string.Join(" | ", selected)}";
        return $"The RF1 gateway server '{serverName}' exited during readiness ({state}).{suffix}";
    }

    private static string SanitizeDiagnosticLine(string line)
    {
        line = Regex.Replace(
            line,
            @"-----BEGIN [^-]+-----.*?-----END [^-]+-----",
            "[redacted-secret-block]",
            RegexOptions.CultureInvariant);
        line = Regex.Replace(
            line,
            @"\b[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\b",
            "<redacted-jwt>",
            RegexOptions.CultureInvariant);
        line = Regex.Replace(
            line,
            @"\bS[A-Z][A-Z0-9]{20,}\b",
            "[redacted-nkey-seed]",
            RegexOptions.CultureInvariant);
        return line.Replace("/tmp/ts-orch-nats-gateway-r1-", "<rf1-fixture-root>/", StringComparison.Ordinal);
    }

    private static async Task DeleteDirectoryWithRetryAsync(string path)
    {
        for (var attempt = 0; attempt < 50; attempt++)
        {
            try
            {
                if (Directory.Exists(path)) Directory.Delete(path, recursive: true);
                if (!Directory.Exists(path)) return;
            }
            catch (IOException) when (attempt < 49)
            {
            }
            catch (UnauthorizedAccessException) when (attempt < 49)
            {
            }
            await Task.Delay(TimeSpan.FromMilliseconds(100));
        }
        throw new IOException("The RF1 gateway fixture directory could not be removed.");
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.CompareExchange(ref disposed, 1, 0) != 0) return;
        var cleanup = new LocalNatsServerLease.Cleanup();
        try
        {
            foreach (var serverName in processes.Keys.ToArray())
            {
                var process = processes[serverName];
                if (await cleanup.AttemptAsync(() => plane.StopAsync(serverName, process)))
                    cleanup.Attempt(process.Dispose);
                processes.Remove(serverName);
            }
            foreach (var task in processDrain.Values)
            {
                await cleanup.AttemptAsync(() => task.WaitAsync(TimeSpan.FromSeconds(1)));
            }
            await cleanup.AttemptAsync(() => plane.DisposeAsync().AsTask());
            await cleanup.AttemptAsync(() => DeleteDirectoryWithRetryAsync(directory));
            if (await lease.ReleaseIfCleanAsync(cleanup))
            {
                Volatile.Write(ref disposed, 2);
                LocalNatsServerLease.CompleteRetention(this);
            }
            cleanup.ThrowIfFailed();
        }
        finally
        {
            if (Volatile.Read(ref disposed) == 1)
            {
                LocalNatsServerLease.Retain(this);
                Volatile.Write(ref disposed, 0);
            }
        }
    }

    private sealed class ServerTransportEqualityComparer : IEqualityComparer<(string Server, NatsGatewayTransport Transport)>
    {
        public bool Equals((string Server, NatsGatewayTransport Transport) x, (string Server, NatsGatewayTransport Transport) y) =>
            x.Server == y.Server && x.Transport == y.Transport;

        public int GetHashCode((string Server, NatsGatewayTransport Transport) obj) =>
            HashCode.Combine(StringComparer.Ordinal.GetHashCode(obj.Server), obj.Transport);
    }
}
