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
using NATS.Client.KeyValueStore;
using NATS.Net;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// A real-NATS gateway supercluster at the landed L0C fidelity: three pinned
/// nats-server clusters (GRU/SFO/FRA, two servers each — real mTLS routes and
/// a real gateway mesh) in one rootless Podman pod, under one operator JWT
/// with the typed plan's account model, imports, and exports. Every server
/// configuration is rendered by
/// <see cref="NatsGatewayConfigurationRenderer"/> from the typed
/// <see cref="NatsGatewayPlan"/> — never written by hand. This lane validates
/// gateway/route/client TLS, JWT authorization, and domain isolation; it is
/// not R3 quorum evidence (that stays with <see cref="NatsControlR3L0cFixture"/>).
/// </summary>
internal sealed class NatsGatewaySuperclusterFixture : IAsyncDisposable
{
    internal const int ServersPerRegion = 2;

    private const UnixFileMode PrivateFileMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private const UnixFileMode PrivateDirectoryMode = PrivateFileMode | UnixFileMode.UserExecute;

    private readonly string directory;
    private readonly Dictionary<string, Process> processes = new(StringComparer.Ordinal);
    private readonly Dictionary<string, ConcurrentQueue<string>> processOutput = new(StringComparer.Ordinal);
    private readonly Dictionary<string, Task> processDrain = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> configurations = new(StringComparer.Ordinal);
    private readonly Dictionary<string, int> clientPorts = new(StringComparer.Ordinal);
    private readonly ContainerizedNatsCluster containerCluster;
    private readonly LocalNatsServerLease.Handle lease;
    private int disposed;

    private NatsGatewaySuperclusterFixture(
        string directory,
        Dictionary<string, string> configurations,
        Dictionary<string, int> clientPorts,
        ContainerizedNatsCluster containerCluster,
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
        this.containerCluster = containerCluster;
        this.lease = lease;
        Plan = plan;
        CaFile = caFile;
        OperatorJwtFile = operatorJwtFile;
        Accounts = accounts;
        Users = users;
    }

    /// <summary>The validated loopback conformance plan the servers were rendered from.</summary>
    internal NatsGatewayPlan Plan { get; }

    internal string CaFile { get; }

    internal string OperatorJwtFile { get; }

    internal IReadOnlyDictionary<string, NatsGatewayConformanceAccount> Accounts { get; }

    internal IReadOnlyDictionary<string, NatsGatewayConformanceIdentity> Users { get; }

    internal IReadOnlyDictionary<string, string> Configurations => configurations;

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
                                       line.Contains("route", StringComparison.OrdinalIgnoreCase) ||
                                       line.Contains("jetstream", StringComparison.OrdinalIgnoreCase))
                        .TakeLast(8));
            },
            StringComparer.Ordinal);

    internal string DirectoryPath => directory;

    public static async Task<NatsGatewaySuperclusterFixture> StartAsync(
        CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("The gateway conformance fixture requires Linux.");

        var lease = await LocalNatsServerLease.AcquireAsync(cancellationToken);
        var directory = Path.Combine(Path.GetTempPath(), $"ts-orch-nats-gateway-{Guid.NewGuid():N}");
        NatsGatewaySuperclusterFixture? fixture = null;
        try
        {
            CreatePrivateDirectory(directory);
            var pki = CreatePki(directory);
            string[] cells = ["fra", "gru", "sfo"];
            var serverNames = cells.SelectMany(cell =>
                Enumerable.Range(1, ServersPerRegion)
                    .Select(index => NatsGatewayPlaneTopology.ControlServerName(cell, index)));

            var portReservations = ReserveLoopbackPorts(cells.Length * ServersPerRegion * 3);
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

            var trust = CreateTrust(directory);
            var identities = CreateUsers(directory, pki, trust);
            var plan = BuildPlan(directory, cells, clientPorts, routePorts, gatewayPorts, pki);
            NatsGatewayPlanValidation.EnsureValid(plan, NatsGatewayValidationOptions.LocalConformance);

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
                        context,
                        NatsGatewayValidationOptions.LocalConformance);
                    if (NatsGatewayConfigurationRenderer.ScanForSecrets(rendered).Count > 0)
                        throw new InvalidOperationException("The rendered gateway configuration failed the secret scan.");
                    var path = Path.Combine(directory, $"{server.ServerName}.conf");
                    await File.WriteAllTextAsync(path, rendered, cancellationToken);
                    SetPrivateFile(path);
                    configurations[server.ServerName] = path;
                    CreatePrivateDirectory(Path.Combine(directory, $"store-{server.ServerName}"));
                }
            }

            var containerCluster = await ContainerizedNatsCluster.CreateAsync(
                directory,
                cancellationToken: cancellationToken);
            fixture = new NatsGatewaySuperclusterFixture(
                directory,
                configurations,
                clientPorts,
                containerCluster,
                lease,
                plan,
                pki.CaFile,
                trust.OperatorJwtFile,
                trust.Accounts,
                identities);
            foreach (var serverName in serverNames)
                fixture.StartServer(serverName);
            await fixture.WaitForServersAsync(cancellationToken);
            await fixture.WaitForJetStreamReadinessAsync(cancellationToken);
            return fixture;
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

    /// <summary>Connects to the first server of one region's cluster.</summary>
    internal async Task<NatsClient> ConnectAsync(
        NatsGatewayConformanceIdentity identity,
        string cell,
        int server = 1,
        CancellationToken cancellationToken = default) =>
        await ConnectToServerAsync(
            identity,
            NatsGatewayPlaneTopology.ControlServerName(cell, server),
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

    /// <summary>Stops and restarts one server with a newly rendered configuration generation.</summary>
    internal async Task RestartServerAsync(
        string serverName,
        string renderedConfiguration,
        CancellationToken cancellationToken = default)
    {
        if (!configurations.TryGetValue(serverName, out var current))
            throw new InvalidOperationException($"The server '{serverName}' is not running.");
        var store = ServerStoreDirectory(serverName);
        if (!renderedConfiguration.Contains($"store_dir: \"{store}\"", StringComparison.Ordinal))
            throw new InvalidOperationException("The replacement configuration must keep the server's store directory.");
        await StopServerAsync(serverName, cancellationToken);
        await File.WriteAllTextAsync(current, renderedConfiguration, cancellationToken);
        SetPrivateFile(current);
        StartServer(serverName);
        await WaitForServerAsync(serverName, cancellationToken);
    }

    internal string ServerStoreDirectory(string serverName) =>
        Path.Combine(directory, $"store-{serverName}");

    internal async Task StopServerAsync(string serverName, CancellationToken cancellationToken = default)
    {
        if (!processes.Remove(serverName, out var process))
            throw new InvalidOperationException($"The server '{serverName}' is not running.");
        if (!process.HasExited)
            await containerCluster.StopAsync(process, cancellationToken);
        process.Dispose();
        await Task.Delay(TimeSpan.FromMilliseconds(300), cancellationToken);
    }

    private void StartServer(string serverName)
    {
        var process = containerCluster.Start(configurations[serverName]);
        processes[serverName] = process;
        var lines = new ConcurrentQueue<string>();
        processOutput[serverName] = lines;
        processDrain[serverName] = DrainProcessOutputAsync(process, lines);
    }

    private async Task WaitForServersAsync(CancellationToken cancellationToken)
    {
        foreach (var serverName in processes.Keys.Order(StringComparer.Ordinal))
            await WaitForServerAsync(serverName, cancellationToken);
    }

    /// <summary>
    /// Waits until every cluster's JetStream meta layer is serving API
    /// requests, mirroring the R3 lane's JetStream quorum wait. A cluster is
    /// ready when its JetStream API answers a read-only stream lookup: an
    /// existing stream or a 404 proves a serving meta layer, while timeouts,
    /// no-responder, and not-yet-available answers mean the cluster is still
    /// forming. Without this gate, stream and bucket creation can race
    /// cluster formation under parallel module load.
    /// </summary>
    private async Task WaitForJetStreamReadinessAsync(CancellationToken cancellationToken)
    {
        foreach (var cluster in Plan.Clusters)
        {
            foreach (var server in cluster.Servers)
            {
                await WaitForServerJetStreamAsync(cluster.Cell, server.ServerName, cancellationToken);
            }
        }
    }

    private async Task WaitForServerJetStreamAsync(
        string cell,
        string serverName,
        CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < 150; attempt++)
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
                        .GetStreamAsync(GlobalNatsTopology.CellSpecStream, cancellationToken: cancellationToken);
                    return;
                }
                catch (NatsJSApiException exception) when (exception.Error.Code == 404)
                {
                    // The JetStream API answered: the cluster's meta layer is
                    // serving even though the conformance stream does not
                    // exist yet.
                    return;
                }
            }
            catch (NatsException) when (attempt < 149)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(200), cancellationToken);
            }
        }
        throw new TimeoutException(
            $"The JetStream domain of gateway conformance cluster '{cell}' did not become ready " +
            $"through server '{serverName}' within 30 seconds.");
    }

    private async Task WaitForServerAsync(string serverName, CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < 150; attempt++)
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
            catch (NatsException) when (attempt < 149)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(100), cancellationToken);
            }
        }
        throw new TimeoutException($"The gateway conformance server '{serverName}' did not become ready within 15 seconds.");
    }

    /// <summary>
    /// Reduces the production control supercluster to the loopback conformance
    /// shape: two servers per region on 127.0.0.1 with fixture PKI files and
    /// fixture store directories. The account model, mesh, imports, exports,
    /// canonical names, and domains are the production plan's own.
    /// </summary>
    private static NatsGatewayPlan BuildPlan(
        string directory,
        string[] cells,
        Dictionary<string, int> clientPorts,
        Dictionary<string, int> routePorts,
        Dictionary<string, int> gatewayPorts,
        GatewayPki pki)
    {
        var production = NatsGatewayPlaneTopology.CreateControlSupercluster();
        var clusters = new List<NatsGatewayCluster>();
        foreach (var cell in cells)
        {
            var productionCluster = production.Cluster(cell)!;
            var names = Enumerable.Range(1, ServersPerRegion)
                .Select(index => NatsGatewayPlaneTopology.ControlServerName(cell, index))
                .ToArray();
            var servers = names.Select(name => new NatsGatewayServerIdentity(
                name,
                "127.0.0.1",
                new NatsGatewayEndpoint("127.0.0.1", clientPorts[name]),
                new NatsGatewayEndpoint("127.0.0.1", routePorts[name]),
                new NatsGatewayEndpoint("127.0.0.1", gatewayPorts[name]),
                ServerProfiles(pki, name, names, cells),
                new NatsGatewayProcessIdentity(
                    UnitName(name),
                    $"{NatsGatewayPlaneTopology.ControlCgroupSlice}/{UnitName(name)}"),
                Path.Combine(directory, $"store-{name}"))).ToArray();
            clusters.Add(new NatsGatewayCluster(
                NatsGatewayPlane.Control,
                cell,
                productionCluster.ClusterName,
                productionCluster.JetStreamDomain,
                productionCluster.OperatorName,
                servers,
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

    private static string UnitName(string serverName)
    {
        var cell = serverName.Split('-')[0];
        return NatsGatewayPlaneTopology.ControlUnitName(cell, int.Parse(serverName[^1..]));
    }

    private static IReadOnlyList<NatsGatewayCertificateProfile> ServerProfiles(
        GatewayPki pki,
        string serverName,
        IReadOnlyList<string> siblings,
        string[] cells)
    {
        var localCell = serverName.Split('-')[0];
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
                siblings.Where(sibling => sibling != serverName)
                    .Select(NatsGatewayPlaneTopology.ControlServerSpiffeId)),
            new NatsGatewayCertificateProfile(
                NatsGatewayTransport.Gateway,
                pki.ServerCertificates[(serverName, NatsGatewayTransport.Gateway)].CertificateFile,
                pki.ServerCertificates[(serverName, NatsGatewayTransport.Gateway)].KeyFile,
                pki.CaFile,
                cells.Where(other => other != localCell).SelectMany(other =>
                        Enumerable.Range(1, ServersPerRegion)
                            .Select(index => NatsGatewayPlaneTopology.ControlServerSpiffeId(
                                NatsGatewayPlaneTopology.ControlServerName(other, index))))),
        ];
    }

    private static Dictionary<string, int> IndexPorts(string[] cells, TcpListener[] reservations, int slot)
    {
        var ports = new Dictionary<string, int>(StringComparer.Ordinal);
        var index = 0;
        foreach (var _ in cells)
        {
            foreach (var server in Enumerable.Range(1, ServersPerRegion))
            {
                ports[NatsGatewayPlaneTopology.ControlServerName(cells[index / ServersPerRegion], server)] =
                    GetReservedPort(reservations[slot * cells.Length * ServersPerRegion + index]);
                index++;
            }
        }
        return ports;
    }

    private static GatewayTrust CreateTrust(string root)
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
                ["name"] = "gateway-conformance-operator",
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
        GatewayPki pki,
        GatewayTrust trust)
    {
        var directory = GlobalNatsAccountNames.GlobalDirectory;
        var regionalFra = GlobalNatsAccountNames.RegionalControl("fra");
        var regionalGru = GlobalNatsAccountNames.RegionalControl("gru");
        var regionalSfo = GlobalNatsAccountNames.RegionalControl("sfo");
        var directoryService = Permissions(GlobalNatsPermissions.Create("gru", GlobalNatsRole.CellDirectoryService));
        var readerSfo = Permissions(GlobalNatsPermissions.Create("sfo", GlobalNatsRole.CellDirectoryReader));
        var readerFra = Permissions(GlobalNatsPermissions.Create("fra", GlobalNatsRole.CellDirectoryReader));
        var gruRegionalRoot = TerraScale.Orchestrator.Protocol.Messaging.NatsSubjectTaxonomy.RegionalRoot("gru");
        return new Dictionary<string, NatsGatewayConformanceIdentity>(StringComparer.Ordinal)
        {
            ["directory-service-gru"] = CreateUser(
                root, pki, trust, directory, "directory-service-gru", directoryService),
            ["directory-reader-sfo"] = CreateUser(
                root, pki, trust, regionalSfo, "directory-reader-sfo", readerSfo),
            ["directory-reader-fra"] = CreateUser(
                root, pki, trust, regionalFra, "directory-reader-fra", readerFra),
            ["gru-operator-read"] = CreateUser(
                root, pki, trust, regionalGru, "gru-operator-read",
                new([$"{gruRegionalRoot}.query.status", $"{gruRegionalRoot}.query.members",
                    $"{gruRegionalRoot}.query.stats", $"{gruRegionalRoot}.query.operator-status"], ["_INBOX.>"])),
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
        };
    }

    private static (IReadOnlyList<string> Publish, IReadOnlyList<string> Subscribe) Permissions(
        GlobalNatsPermissionPlan plan) => (plan.Publish, plan.Subscribe);

    private static NatsGatewayConformanceIdentity CreateUser(
        string root,
        GatewayPki pki,
        GatewayTrust trust,
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

    private static GatewayPki CreatePki(string root)
    {
        var pkiRoot = Path.Combine(root, "pki");
        CreatePrivateDirectory(pkiRoot);
        using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var caRequest = new CertificateRequest(
            "CN=TerraScale gateway conformance CA",
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

        var serverCertificates = new Dictionary<(string Server, NatsGatewayTransport Transport), GatewayCertificate>(
            new ServerTransportEqualityComparer());
        string[] cells = ["fra", "gru", "sfo"];
        foreach (var cell in cells)
        {
            foreach (var index in Enumerable.Range(1, ServersPerRegion))
            {
                var name = NatsGatewayPlaneTopology.ControlServerName(cell, index);
                foreach (var transport in new[]
                         {
                             NatsGatewayTransport.Client,
                             NatsGatewayTransport.Route,
                             NatsGatewayTransport.Gateway,
                         })
                {
                    serverCertificates[(name, transport)] = CreateLeaf(
                        pkiRoot,
                        $"{name}-{transport.ToString().ToLowerInvariant()}",
                        $"spiffe://terrascale.tech/control/nats/server/{name}",
                        ca,
                        serverAuthentication: true,
                        clientAuthentication: true,
                        includeLoopbackNames: true);
                }
            }
        }

        var clientCertificates = new Dictionary<string, GatewayCertificate>(StringComparer.Ordinal);
        foreach (var name in new[]
                 {
                     "directory-service-gru", "directory-reader-sfo", "directory-reader-fra",
                     "gru-operator-read", "gru-infrastructure", "sfo-infrastructure", "fra-infrastructure",
                 })
        {
            clientCertificates[name] = CreateLeaf(
                pkiRoot,
                name,
                $"spiffe://terrascale.tech/control/nats/client/{name}",
                ca,
                serverAuthentication: false,
                clientAuthentication: true,
                includeLoopbackNames: false);
        }
        return new(caFile, serverCertificates, clientCertificates);
    }

    private static GatewayCertificate CreateLeaf(
        string root,
        string name,
        string spiffeId,
        X509Certificate2 ca,
        bool serverAuthentication,
        bool clientAuthentication,
        bool includeLoopbackNames)
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
        var names = new SubjectAlternativeNameBuilder();
        names.AddUri(new Uri(spiffeId));
        if (includeLoopbackNames)
        {
            names.AddDnsName("localhost");
            names.AddIpAddress(IPAddress.Loopback);
        }
        request.CertificateExtensions.Add(names.Build());
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
            throw new PlatformNotSupportedException("The gateway conformance fixture requires Linux file permissions.");
        Directory.CreateDirectory(path, PrivateDirectoryMode);
    }

    private static void SetPrivateFile(string path)
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("The gateway conformance fixture requires Linux file permissions.");
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
            return $"The gateway conformance server '{serverName}' exited during readiness ({state}).";
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
        return $"The gateway conformance server '{serverName}' exited during readiness ({state}).{suffix}";
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
        return line.Replace("/tmp/ts-orch-nats-gateway-", "<fixture-root>/", StringComparison.Ordinal);
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
        throw new IOException("The gateway conformance fixture directory could not be removed.");
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
                if (await cleanup.AttemptAsync(() => containerCluster.StopAsync(process)))
                    cleanup.Attempt(process.Dispose);
                processes.Remove(serverName);
            }
            foreach (var task in processDrain.Values)
            {
                await cleanup.AttemptAsync(() => task.WaitAsync(TimeSpan.FromSeconds(1)));
            }
            await cleanup.AttemptAsync(() => containerCluster.DisposeAsync().AsTask());
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

    internal sealed record GatewayCertificate(
        string CertificateFile,
        string KeyFile,
        string SpiffeId);

    internal sealed record GatewayPki(
        string CaFile,
        Dictionary<(string Server, NatsGatewayTransport Transport), GatewayCertificate> ServerCertificates,
        Dictionary<string, GatewayCertificate> ClientCertificates);

    internal sealed record GatewayTrust(
        string OperatorPublicKey,
        string OperatorSeed,
        string OperatorJwtFile,
        Dictionary<string, NatsGatewayConformanceAccount> Accounts);
}

/// <summary>An account's public identity and its seed, used only inside the fixture process.</summary>
internal sealed record NatsGatewayConformanceAccount(
    string Name,
    string PublicKey,
    string Seed,
    string Jwt);

/// <summary>A user identity: public key, owning account, credentials file, and client certificate.</summary>
internal sealed record NatsGatewayConformanceIdentity(
    string Name,
    string PublicKey,
    string AccountName,
    string CredentialsFile,
    string CertificateFile,
    string KeyFile,
    string SpiffeId);
