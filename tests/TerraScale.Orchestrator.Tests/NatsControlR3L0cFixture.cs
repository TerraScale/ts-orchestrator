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
using TerraScale.Orchestrator.Protocol.Messaging;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// A deliberately ephemeral three-member NATS control cluster. It is a test fixture,
/// not a production bootstrap implementation: every key, certificate, JWT, config,
/// store, and server container is created below a private temporary directory.
/// </summary>
internal sealed class NatsControlR3L0cFixture : IAsyncDisposable
{
    private const string ClusterName = "terrascale-orchestrator-r3-l0c";
    private const string Cell = "gru";
    private const int MemberCount = 3;
    private const UnixFileMode PrivateFileMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private const UnixFileMode PrivateDirectoryMode = PrivateFileMode | UnixFileMode.UserExecute;
    private readonly string directory;
    private readonly string[] configurations;
    private readonly Process?[] processes;
    private readonly Task<string>?[] processOutput;
    private readonly ContainerizedNatsCluster containerCluster;
    private readonly LocalNatsServerLease.Handle lease;
    private int disposed;

    private NatsControlR3L0cFixture(
        string directory,
        string[] configurations,
        Process?[] processes,
        Task<string>?[] processOutput,
        ContainerizedNatsCluster containerCluster,
        LocalNatsServerLease.Handle lease,
        IReadOnlyList<int> clientPorts,
        string globalAuthorityAccountPublicKey,
        string globalAuthorityAccountJwt,
        string globalDirectoryAccountPublicKey,
        string globalDirectoryAccountJwt,
        string regionalControlGruAccountPublicKey,
        string regionalControlGruAccountJwt,
        string regionalControlSfoAccountPublicKey,
        string regionalControlSfoAccountJwt,
        NatsControlR3L0cIdentity controller,
        NatsControlR3L0cIdentity controllerTwo,
        NatsControlR3L0cIdentity infrastructure,
        NatsControlR3L0cIdentity globalDirectoryInfrastructure,
        NatsControlR3L0cIdentity journalWriter,
        NatsControlR3L0cIdentity cellDirectoryPublisher,
        NatsControlR3L0cIdentity cellDirectoryReader,
        NatsControlR3L0cIdentity cellDirectoryService,
        NatsControlR3L0cIdentity authority,
        NatsControlR3L0cIdentity operatorRead,
        NatsControlR3L0cIdentity wrongAccount)
    {
        this.directory = directory;
        this.configurations = configurations;
        this.processes = processes;
        this.processOutput = processOutput;
        this.containerCluster = containerCluster;
        this.lease = lease;
        GlobalAuthorityAccountPublicKey = globalAuthorityAccountPublicKey;
        GlobalAuthorityAccountJwt = globalAuthorityAccountJwt;
        GlobalDirectoryAccountPublicKey = globalDirectoryAccountPublicKey;
        GlobalDirectoryAccountJwt = globalDirectoryAccountJwt;
        RegionalControlGruAccountPublicKey = regionalControlGruAccountPublicKey;
        RegionalControlGruAccountJwt = regionalControlGruAccountJwt;
        RegionalControlSfoAccountPublicKey = regionalControlSfoAccountPublicKey;
        RegionalControlSfoAccountJwt = regionalControlSfoAccountJwt;
        Controller = controller;
        ControllerTwo = controllerTwo;
        Infrastructure = infrastructure;
        GlobalDirectoryInfrastructure = globalDirectoryInfrastructure;
        JournalWriter = journalWriter;
        CellDirectoryPublisher = cellDirectoryPublisher;
        CellDirectoryReader = cellDirectoryReader;
        CellDirectoryService = cellDirectoryService;
        Authority = authority;
        Operator = operatorRead;
        WrongAccount = wrongAccount;
        Topology = new NatsTopology(Cell, MemberCount, "controller-1");
        CaFile = Path.Combine(directory, "pki", "ca.pem");
        ClientPorts = clientPorts;
    }

    public NatsTopology Topology { get; }

    internal string GlobalAuthorityAccountPublicKey { get; }

    internal string GlobalAuthorityAccountJwt { get; }

    internal string GlobalDirectoryAccountPublicKey { get; }

    internal string GlobalDirectoryAccountJwt { get; }

    internal string RegionalControlGruAccountPublicKey { get; }

    internal string RegionalControlGruAccountJwt { get; }

    internal string RegionalControlSfoAccountPublicKey { get; }

    internal string RegionalControlSfoAccountJwt { get; }

    public NatsControlR3L0cIdentity Controller { get; }

    public NatsControlR3L0cIdentity ControllerTwo { get; }

    public NatsControlR3L0cIdentity Infrastructure { get; }

    public NatsControlR3L0cIdentity GlobalDirectoryInfrastructure { get; }

    public NatsControlR3L0cIdentity JournalWriter { get; }

    public NatsControlR3L0cIdentity CellDirectoryPublisher { get; }

    public NatsControlR3L0cIdentity CellDirectoryReader { get; }

    public NatsControlR3L0cIdentity CellDirectoryService { get; }

    public NatsControlR3L0cIdentity Authority { get; }

    public NatsControlR3L0cIdentity Operator { get; }

    public NatsControlR3L0cIdentity WrongAccount { get; }

    public string CaFile { get; }

    internal string DirectoryPath => directory;

    internal bool UsedBatchPublishCompatibilityFallback { get; private set; }

    public IReadOnlyList<int> ClientPorts { get; }

    public IReadOnlyList<int> ProcessIds => processes
        .Where(static process => process is not null)
        .Select(static process => process!.Id)
        .ToArray();

    public static async Task<NatsControlR3L0cFixture> StartAsync(
        CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("The real NATS L0C fixture requires Linux.");

        var lease = await LocalNatsServerLease.AcquireAsync(cancellationToken);
        var directory = Path.Combine(Path.GetTempPath(), $"ts-orch-nats-r3-l0c-{Guid.NewGuid():N}");
        NatsControlR3L0cFixture? fixture = null;
        try
        {
            CreatePrivateDirectory(directory);
            var pki = CreatePki(directory);
            var identities = CreateIdentities(directory, pki);
            var configurations = new string[MemberCount];
            var processes = new Process?[MemberCount];
            var processOutput = new Task<string>?[MemberCount];
            int[] clientPorts;
            int[] routePorts;

            var portReservations = ReserveLoopbackPorts(MemberCount * 2);
            try
            {
                clientPorts = portReservations
                    .Take(MemberCount)
                    .Select(static listener => GetReservedPort(listener))
                    .ToArray();
                routePorts = portReservations
                    .Skip(MemberCount)
                    .Select(static listener => GetReservedPort(listener))
                    .ToArray();

                for (var member = 0; member < MemberCount; member++)
                {
                    configurations[member] = WriteConfiguration(
                        directory,
                        member,
                        clientPorts[member],
                        routePorts[member],
                        clientPorts,
                        routePorts,
                        pki.ServerCertificates[member],
                        identities.OperatorJwtFile,
                        identities.GlobalAuthorityAccountPublicKey,
                        identities.GlobalAuthorityAccountJwt,
                        identities.GlobalDirectoryAccountPublicKey,
                        identities.GlobalDirectoryAccountJwt,
                        identities.RegionalControlGruAccountPublicKey,
                        identities.RegionalControlGruAccountJwt,
                        identities.RegionalControlSfoAccountPublicKey,
                        identities.RegionalControlSfoAccountJwt,
                        identities.SystemAccountPublicKey,
                        identities.SystemAccountJwt,
                        identities.WrongAccountPublicKey,
                        identities.WrongAccountJwt,
                        pki.CaFile);
                }
            }
            finally
            {
                foreach (var listener in portReservations)
                    listener.Stop();
            }

            var containerCluster = await ContainerizedNatsCluster.CreateAsync(
                directory,
                clientPorts.Concat(routePorts),
                cancellationToken: cancellationToken);
            fixture = new NatsControlR3L0cFixture(
                directory,
                configurations,
                processes,
                processOutput,
                containerCluster,
                lease,
                clientPorts,
                identities.GlobalAuthorityAccountPublicKey,
                identities.GlobalAuthorityAccountJwt,
                identities.GlobalDirectoryAccountPublicKey,
                identities.GlobalDirectoryAccountJwt,
                identities.RegionalControlGruAccountPublicKey,
                identities.RegionalControlGruAccountJwt,
                identities.RegionalControlSfoAccountPublicKey,
                identities.RegionalControlSfoAccountJwt,
                identities.Controller,
                identities.ControllerTwo,
                identities.Infrastructure,
                identities.GlobalDirectoryInfrastructure,
                identities.JournalWriter,
                identities.CellDirectoryPublisher,
                identities.CellDirectoryReader,
                identities.CellDirectoryService,
                identities.Authority,
                identities.Operator,
                identities.WrongAccount);

            for (var member = 0; member < MemberCount; member++)
                fixture.StartMember(member);

            await fixture.WaitForClusterAsync(cancellationToken);
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

    public NatsOpts ClientOptions(
        NatsControlR3L0cIdentity identity,
        int member = 0,
        bool authenticate = true) => new NatsOpts
        {
            Url = $"tls://127.0.0.1:{ClientPorts[member]}",
            RetryOnInitialConnect = false,
            ConnectTimeout = TimeSpan.FromSeconds(2),
            RequestTimeout = TimeSpan.FromSeconds(3),
            TlsOpts = new NatsTlsOpts
            {
                Mode = TlsMode.Require,
                CaFile = CaFile,
                CertFile = identity.CertificateFile,
                KeyFile = identity.KeyFile,
            }
        } with
        {
            AuthOpts = authenticate ? new NatsAuthOpts { CredsFile = identity.CredentialsFile } : new NatsAuthOpts()
        };

    public async Task<NatsClient> ConnectAsync(
        NatsControlR3L0cIdentity identity,
        int member = 0,
        bool authenticate = true,
        CancellationToken cancellationToken = default)
    {
        var client = new NatsClient(ClientOptions(identity, member, authenticate));
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

    public async Task ProvisionAsync(CancellationToken cancellationToken = default)
    {
        await using var infrastructure = await ConnectAsync(Infrastructure, cancellationToken: cancellationToken);
        await RetryNatsAsync(
            async () =>
            {
                try
                {
                    await NatsOperationJournalProvisioner.ProvisionTopologyAsync(
                        infrastructure, Topology, cancellationToken);
                }
                catch (InvalidOperationException exception) when (
                    exception.Message.Contains("can not unmarshal", StringComparison.Ordinal))
                {
                    // NATS.Net 2.7 serializes the newer PersistMode field as numeric
                    // zero in the explicit journal update. nats-server 2.14 rejects
                    // that wire form. The server default is false, so recreate the
                    // exact protected streams and validate the returned field without
                    // claiming the production setter itself is qualified on this pair.
                    UsedBatchPublishCompatibilityFallback = true;
                    await NatsOperationJournalProvisioner.ProvisionControllerTopologyAsync(
                        infrastructure, Topology, cancellationToken);
                    await ProvisionJournalWithoutLegacyBatchPatchAsync(
                        infrastructure, Topology.Operations, cancellationToken);
                    await ProvisionJournalWithoutLegacyBatchPatchAsync(
                        infrastructure, Topology.OperationProofConsumptions, cancellationToken);
                }
            },
            cancellationToken);
    }

    public async Task ProvisionGlobalCellDirectoryAsync(CancellationToken cancellationToken = default)
    {
        await using var infrastructure = await ConnectAsync(
            GlobalDirectoryInfrastructure,
            cancellationToken: cancellationToken);
        var stores = infrastructure.CreateJetStreamContext().CreateKeyValueStoreContext();
        await RetryNatsAsync(
            async () => _ = await stores.CreateOrUpdateStoreAsync(
                new GlobalNatsTopology(3).Cells,
                cancellationToken),
            cancellationToken);
    }

    private static async Task ProvisionJournalWithoutLegacyBatchPatchAsync(
        NatsClient client,
        NatsKVConfig configuration,
        CancellationToken cancellationToken)
    {
        var jetStream = client.CreateJetStreamContext();
        await jetStream.CreateOrUpdateStreamAsync(
            NatsOperationJournalStore.CanonicalStream(configuration),
            cancellationToken);
        var update = JsonSerializer.SerializeToNode(
                NatsOperationJournalStore.CanonicalStream(configuration))?.AsObject()
            ?? throw new InvalidOperationException("Unable to serialize the operation journal stream configuration.");
        update["persist_mode"] = "default";
        // nats-server 2.14 names this wire field allow_batched; older server
        // revisions and the production helper use allow_batch_publish.
        update["allow_batched"] = false;
        var updateResponse = await client.RequestAsync<string, string>(
            $"$JS.API.STREAM.UPDATE.KV_{configuration.Bucket}",
            JsonSerializer.Serialize(update),
            cancellationToken: cancellationToken);
        updateResponse.EnsureSuccess();
        var store = await jetStream.CreateKeyValueStoreContext().GetStoreAsync(
            configuration.Bucket,
            cancellationToken);
        var status = await store.GetStatusAsync(cancellationToken);
        NatsOperationJournalStore.ValidateConfiguration(status.Info.Config, configuration);
        var response = await client.RequestAsync<string, string>(
            $"$JS.API.STREAM.INFO.KV_{configuration.Bucket}",
            string.Empty,
            cancellationToken: cancellationToken);
        response.EnsureSuccess();
        var root = JsonElement.Parse(response.Data ??
            throw new InvalidOperationException("JetStream returned no stream information response."));
        ValidateServerBatchPublishDisabled(root);
    }

    private static void ValidateServerBatchPublishDisabled(JsonElement response)
    {
        if (!response.TryGetProperty("config", out var config))
            throw new InvalidOperationException("JetStream returned no stream configuration response.");
        if (config.TryGetProperty("allow_batched", out var enabled) &&
            enabled.ValueKind != JsonValueKind.False)
            throw new InvalidOperationException("The compatibility journal stream enabled batch publishing.");
    }

    public async Task KillMemberAsync(int member, CancellationToken cancellationToken = default)
    {
        ValidateMember(member);
        var process = processes[member] ?? throw new InvalidOperationException("The NATS member is not running.");
        if (!process.HasExited)
        {
            await containerCluster.StopAsync(process, cancellationToken);
        }
        process.Dispose();
        processes[member] = null;
        await Task.Delay(TimeSpan.FromMilliseconds(500), cancellationToken);
        await WaitForJetStreamQuorumAsync(cancellationToken);
    }

    public async Task RestartMemberAsync(
        int member,
        CancellationToken cancellationToken = default)
    {
        ValidateMember(member);
        if (processes[member] is not null)
            throw new InvalidOperationException("The NATS member must be stopped before it is restarted.");
        StartMember(member);
        await WaitForMemberAsync(member, cancellationToken);
    }

    public async Task WaitForMemberAsync(
        int member,
        CancellationToken cancellationToken = default)
    {
        ValidateMember(member);
        for (var attempt = 0; attempt < 100; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (processes[member] is { HasExited: true })
                throw new InvalidOperationException($"NATS member {member + 1} exited during readiness.");
            try
            {
                await using var client = await ConnectAsync(Operator, member, cancellationToken: cancellationToken);
                await client.PingAsync(cancellationToken);
                return;
            }
            catch (NatsException) when (attempt < 99)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(100), cancellationToken);
            }
        }
        throw new TimeoutException($"NATS member {member + 1} did not become ready within 10 seconds.");
    }

    private async Task WaitForJetStreamQuorumAsync(CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < 60; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                await using var infrastructure = await ConnectAsync(
                    Infrastructure,
                    cancellationToken: cancellationToken);
                var stream = await infrastructure.CreateJetStreamContext()
                    .GetStreamAsync("KV_ORCH_OPERATIONS", cancellationToken: cancellationToken);
                if (stream.Info.Config.NumReplicas == MemberCount)
                    return;
            }
            catch (NatsException) when (attempt < 59)
            {
            }
            await Task.Delay(TimeSpan.FromMilliseconds(250), cancellationToken);
        }
        throw new TimeoutException("The R3 JetStream journal did not regain quorum after member loss.");
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.CompareExchange(ref disposed, 1, 0) != 0) return;
        var cleanup = new LocalNatsServerLease.Cleanup();
        try
        {
            for (var member = 0; member < processes.Length; member++)
            {
                var process = processes[member];
                if (process is null) continue;
                if (await cleanup.AttemptAsync(() => containerCluster.StopAsync(process)) &&
                    cleanup.Attempt(process.Dispose))
                    processes[member] = null;
            }
            foreach (var task in processOutput.Where(static task => task is not null))
            {
                await cleanup.AttemptAsync(() => task!.WaitAsync(TimeSpan.FromSeconds(1)));
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

    private async Task WaitForClusterAsync(CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < 120; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            for (var member = 0; member < processes.Length; member++)
            {
                if (processes[member] is { HasExited: true })
                    throw new InvalidOperationException(GetMemberExitDiagnostic(member));
            }
            try
            {
                for (var member = 0; member < MemberCount; member++)
                {
                    await using var client = await ConnectAsync(Operator, member, cancellationToken: cancellationToken);
                    await client.PingAsync(cancellationToken);
                }
                return;
            }
            catch (NatsException) when (attempt < 119)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(100), cancellationToken);
            }
        }
        throw new TimeoutException("The three-member NATS R3 cluster did not become ready within 12 seconds.");
    }

    private void StartMember(int member)
    {
        var process = containerCluster.Start(configurations[member]);
        processes[member] = process;
        processOutput[member] = DrainProcessOutputAsync(process);
    }

    private static async Task<string> DrainProcessOutputAsync(Process process)
    {
        var standardOutput = process.StandardOutput.ReadToEndAsync();
        var standardError = process.StandardError.ReadToEndAsync();
        await Task.WhenAll(standardOutput, standardError);
        // Never expose process output: it can contain server diagnostics or credential
        // context. The result is retained only to keep the pipes drained.
        return string.Concat(await standardOutput, await standardError);
    }

    private string GetMemberExitDiagnostic(int member)
    {
        var process = processes[member];
        var state = process is null
            ? "not-started"
            : process.HasExited
                ? $"exit-code={process.ExitCode}"
                : "running";
        var output = processOutput[member];
        if (output is null || !output.IsCompletedSuccessfully)
            return $"NATS R3 member {member + 1} exited before cluster readiness ({state}).";

        var diagnostics = output.Result
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(IsDiagnosticLine)
            .OrderByDescending(IsPriorityDiagnosticLine)
            .Select(SanitizeDiagnosticLine)
            .Take(8)
            .ToArray();
        var suffix = diagnostics.Length == 0
            ? string.Empty
            : $" diagnostics={string.Join(" | ", diagnostics)}";
        return $"NATS R3 member {member + 1} exited before cluster readiness ({state}).{suffix}";
    }

    private static bool IsDiagnosticLine(string line) =>
        IsPriorityDiagnosticLine(line) ||
        line.Contains("tls", StringComparison.OrdinalIgnoreCase) ||
        line.Contains("resolver", StringComparison.OrdinalIgnoreCase) ||
        line.Contains("jetstream", StringComparison.OrdinalIgnoreCase);

    private static bool IsPriorityDiagnosticLine(string line) =>
        line.Contains("error", StringComparison.OrdinalIgnoreCase) ||
        line.Contains("fatal", StringComparison.OrdinalIgnoreCase) ||
        line.Contains("invalid", StringComparison.OrdinalIgnoreCase) ||
        line.Contains("failed", StringComparison.OrdinalIgnoreCase) ||
        line.Contains("panic", StringComparison.OrdinalIgnoreCase) ||
        line.Contains("parse", StringComparison.OrdinalIgnoreCase) ||
        line.Contains("address", StringComparison.OrdinalIgnoreCase) ||
        line.Contains("listen", StringComparison.OrdinalIgnoreCase) ||
        line.Contains("bind", StringComparison.OrdinalIgnoreCase);

    private static string SanitizeDiagnosticLine(string line)
    {
        line = Regex.Replace(
            line,
            @"-----BEGIN [^-]+-----.*?-----END [^-]+-----",
            "[redacted-secret-block]",
            RegexOptions.CultureInvariant);
        line = Regex.Replace(
            line,
            @"\b[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b",
            "[redacted-jwt]",
            RegexOptions.CultureInvariant);
        line = Regex.Replace(
            line,
            @"\b(?:SU|SA|SB|SO|SX)[A-Z0-9]{20,}\b",
            "[redacted-nkey-seed]",
            RegexOptions.CultureInvariant);
        return line.Replace("/tmp/ts-orch-nats-r3-l0c-", "<fixture-root>/", StringComparison.Ordinal);
    }

    private static async Task RetryNatsAsync(
        Func<Task> action,
        CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(30));
        NatsException? lastFailure = null;
        while (true)
        {
            try
            {
                await action();
                return;
            }
            catch (NatsException exception) when (!timeout.IsCancellationRequested)
            {
                lastFailure = exception;
                await Task.Delay(TimeSpan.FromMilliseconds(200));
                cancellationToken.ThrowIfCancellationRequested();
                if (timeout.IsCancellationRequested)
                {
                    var detail = lastFailure is null
                        ? "no NATS response"
                        : SanitizeDiagnosticLine(lastFailure.Message);
                    throw new TimeoutException(
                        $"NATS operation did not converge within 30 seconds; last failure: {detail}",
                        lastFailure);
                }
            }
        }
    }

    private static string WriteConfiguration(
        string root,
        int member,
        int clientPort,
        int routePort,
        int[] clientPorts,
        int[] routePorts,
        NatsControlR3L0cCertificate server,
        string operatorJwtFile,
        string globalAuthorityAccountPublicKey,
        string globalAuthorityAccountJwt,
        string globalDirectoryAccountPublicKey,
        string globalDirectoryAccountJwt,
        string regionalControlGruAccountPublicKey,
        string regionalControlGruAccountJwt,
        string regionalControlSfoAccountPublicKey,
        string regionalControlSfoAccountJwt,
        string systemAccountPublicKey,
        string systemAccountJwt,
        string wrongAccountPublicKey,
        string wrongAccountJwt,
        string caFile)
    {
        var path = Path.Combine(root, $"nats-{member + 1}.conf");
        var store = Path.Combine(root, $"store-{member + 1}");
        CreatePrivateDirectory(store);
        var routes = string.Join(", ", routePorts
            .Where((_, candidate) => candidate != member)
            .Select(route => $"\"nats-route://127.0.0.1:{route}\""));
        var contents = $$"""
            server_name: "r3-l0c-{{member + 1}}"
            host: "127.0.0.1"
            port: {{clientPort}}
            max_control_line: 65536
            operator: "{{operatorJwtFile}}"
            resolver: MEMORY
            resolver_preload: {
              {{globalAuthorityAccountPublicKey}}: "{{globalAuthorityAccountJwt}}"
              {{globalDirectoryAccountPublicKey}}: "{{globalDirectoryAccountJwt}}"
              {{regionalControlGruAccountPublicKey}}: "{{regionalControlGruAccountJwt}}"
              {{regionalControlSfoAccountPublicKey}}: "{{regionalControlSfoAccountJwt}}"
              {{systemAccountPublicKey}}: "{{systemAccountJwt}}"
              {{wrongAccountPublicKey}}: "{{wrongAccountJwt}}"
            }
            tls {
              cert_file: "{{server.CertificateFile}}"
              key_file: "{{server.KeyFile}}"
              ca_file: "{{caFile}}"
              verify: true
              timeout: 3
            }
            jetstream {
              domain: "ORCH_GRU"
              store_dir: "{{store}}"
            }
            cluster {
              name: "{{ClusterName}}"
              host: "127.0.0.1"
              port: {{routePort}}
              tls {
                cert_file: "{{server.CertificateFile}}"
                key_file: "{{server.KeyFile}}"
                ca_file: "{{caFile}}"
                verify: true
                timeout: 3
              }
              routes: [{{routes}}]
            }
            """;
        File.WriteAllText(path, contents);
        SetPrivateFile(path);
        return path;
    }

    private static FixtureIdentities CreateIdentities(string root, PkiMaterial pki)
    {
        var credentials = Path.Combine(root, "credentials");
        CreatePrivateDirectory(credentials);
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var operatorSeed = NKeys.CreateOperatorSeed();
        var globalAuthorityAccountSeed = NKeys.CreateAccountSeed();
        var globalDirectoryAccountSeed = NKeys.CreateAccountSeed();
        var regionalControlGruAccountSeed = NKeys.CreateAccountSeed();
        var regionalControlSfoAccountSeed = NKeys.CreateAccountSeed();
        var systemAccountSeed = NKeys.CreateAccountSeed();
        var wrongAccountSeed = NKeys.CreateAccountSeed();
        var operatorPublicKey = NKeys.PublicKeyFromSeed(operatorSeed);
        var globalAuthorityAccountPublicKey = NKeys.PublicKeyFromSeed(globalAuthorityAccountSeed);
        var globalDirectoryAccountPublicKey = NKeys.PublicKeyFromSeed(globalDirectoryAccountSeed);
        var regionalControlGruAccountPublicKey = NKeys.PublicKeyFromSeed(regionalControlGruAccountSeed);
        var regionalControlSfoAccountPublicKey = NKeys.PublicKeyFromSeed(regionalControlSfoAccountSeed);
        var systemAccountPublicKey = NKeys.PublicKeyFromSeed(systemAccountSeed);
        var wrongAccountPublicKey = NKeys.PublicKeyFromSeed(wrongAccountSeed);
        var operatorJwt = EncodeJwt(
            operatorSeed,
            operatorPublicKey,
            new Dictionary<string, object?>
            {
                ["iat"] = now,
                ["iss"] = operatorPublicKey,
                ["jti"] = Jti(operatorPublicKey, now, "operator"),
                ["name"] = "l0c-operator",
                ["nats"] = new Dictionary<string, object?>
                {
                    ["system_account"] = systemAccountPublicKey,
                },
                ["sub"] = operatorPublicKey,
                ["type"] = "operator",
            });
        var globalAuthorityAccountJwt = EncodeJwt(
            operatorSeed,
            operatorPublicKey,
            AccountClaims(
                operatorPublicKey,
                globalAuthorityAccountPublicKey,
                now,
                GlobalNatsAccountNames.GlobalAuthority,
                imports: Array.Empty<Dictionary<string, object?>>(),
                exports: Array.Empty<Dictionary<string, object?>>()));
        var globalDirectoryAccountJwt = EncodeJwt(
            operatorSeed,
            operatorPublicKey,
            AccountClaims(
                operatorPublicKey,
                globalDirectoryAccountPublicKey,
                now,
                GlobalNatsAccountNames.GlobalDirectory,
                imports: Array.Empty<Dictionary<string, object?>>(),
                exports: [ServiceExport(GlobalNatsTopology.CellDirectorySubject)]));
        var regionalControlGruAccountJwt = EncodeJwt(
            operatorSeed,
            operatorPublicKey,
            AccountClaims(
                operatorPublicKey,
                regionalControlGruAccountPublicKey,
                now,
                GlobalNatsAccountNames.RegionalControl(Cell),
                imports: Array.Empty<Dictionary<string, object?>>(),
                exports: Array.Empty<Dictionary<string, object?>>()));
        var regionalControlSfoAccountJwt = EncodeJwt(
            operatorSeed,
            operatorPublicKey,
            AccountClaims(
                operatorPublicKey,
                regionalControlSfoAccountPublicKey,
                now,
                GlobalNatsAccountNames.RegionalControl("sfo"),
                imports: [ServiceImport(
                    GlobalNatsTopology.CellDirectorySubject,
                    globalDirectoryAccountPublicKey)],
                exports: Array.Empty<Dictionary<string, object?>>()));
        var systemAccountJwt = EncodeJwt(
            operatorSeed,
            operatorPublicKey,
            AccountClaims(operatorPublicKey, systemAccountPublicKey, now, "system", enableJetStream: false));
        var wrongAccountJwt = EncodeJwt(
            operatorSeed,
            operatorPublicKey,
            AccountClaims(operatorPublicKey, wrongAccountPublicKey, now, "wrong-account", enableJetStream: false));
        var operatorJwtFile = WritePrivateFile(root, "credentials/operator.jwt", operatorJwt);

        var controller = CreateUser(
            credentials,
            pki,
            regionalControlGruAccountSeed,
            regionalControlGruAccountPublicKey,
            "controller-1",
            Role.Controller,
            1,
            now);
        var controllerTwo = CreateUser(
            credentials,
            pki,
            regionalControlGruAccountSeed,
            regionalControlGruAccountPublicKey,
            "controller-2",
            Role.Controller,
            2,
            now);
        var infrastructure = CreateUser(
            credentials,
            pki,
            regionalControlGruAccountSeed,
            regionalControlGruAccountPublicKey,
            "infrastructure",
            Role.Infrastructure,
            0,
            now);
        var globalDirectoryInfrastructure = CreateUser(
            credentials,
            pki,
            globalDirectoryAccountSeed,
            globalDirectoryAccountPublicKey,
            "global-directory-infrastructure",
            Role.GlobalDirectoryInfrastructure,
            0,
            now);
        var journalWriter = CreateUser(
            credentials,
            pki,
            regionalControlGruAccountSeed,
            regionalControlGruAccountPublicKey,
            "journal-writer",
            Role.JournalWriter,
            0,
            now);
        var cellDirectoryPublisher = CreateUser(
            credentials,
            pki,
            globalDirectoryAccountSeed,
            globalDirectoryAccountPublicKey,
            "cell-directory-publisher-sfo",
            Role.CellDirectoryPublisher,
            0,
            now);
        var cellDirectoryReader = CreateUser(
            credentials,
            pki,
            regionalControlSfoAccountSeed,
            regionalControlSfoAccountPublicKey,
            "cell-directory-reader-sfo",
            Role.CellDirectoryReader,
            0,
            now);
        var cellDirectoryService = CreateUser(
            credentials,
            pki,
            globalDirectoryAccountSeed,
            globalDirectoryAccountPublicKey,
            "cell-directory-service-gru",
            Role.CellDirectoryService,
            0,
            now);
        var operatorRead = CreateUser(
            credentials,
            pki,
            regionalControlGruAccountSeed,
            regionalControlGruAccountPublicKey,
            "operator-read",
            Role.Operator,
            0,
            now);
        var authority = CreateUser(
            credentials,
            pki,
            globalAuthorityAccountSeed,
            globalAuthorityAccountPublicKey,
            "global-authority",
            Role.GlobalAuthority,
            0,
            now);
        var wrongAccount = CreateUser(
            credentials,
            pki,
            wrongAccountSeed,
            wrongAccountPublicKey,
            "wrong-account",
            Role.WrongAccount,
            0,
            now);
        return new(
            operatorJwtFile,
            globalAuthorityAccountPublicKey,
            globalAuthorityAccountJwt,
            globalDirectoryAccountPublicKey,
            globalDirectoryAccountJwt,
            regionalControlGruAccountPublicKey,
            regionalControlGruAccountJwt,
            regionalControlSfoAccountPublicKey,
            regionalControlSfoAccountJwt,
            systemAccountPublicKey,
            systemAccountJwt,
            wrongAccountPublicKey,
            wrongAccountJwt,
            controller,
            controllerTwo,
            infrastructure,
            globalDirectoryInfrastructure,
            journalWriter,
            cellDirectoryPublisher,
            cellDirectoryReader,
            cellDirectoryService,
            authority,
            operatorRead,
            wrongAccount);
    }

    private static NatsControlR3L0cIdentity CreateUser(
        string root,
        PkiMaterial pki,
        string issuerSeed,
        string issuerPublicKey,
        string name,
        Role role,
        int controllerNumber,
        long issuedAt)
    {
        var seed = NKeys.CreateUserSeed();
        var publicKey = NKeys.PublicKeyFromSeed(seed);
        var certificate = pki.ClientCertificates[name];
        var permissions = Permissions(role, publicKey, controllerNumber);
        var jwt = EncodeJwt(
            issuerSeed,
            issuerPublicKey,
            UserClaims(issuerPublicKey, publicKey, name, permissions, issuedAt));
        var credentialsFile = WritePrivateFile(
            root,
            $"credentials/{name}.creds",
            $"-----BEGIN NATS USER JWT-----\n{jwt}\n------END NATS USER JWT------\n\n" +
            $"-----BEGIN USER NKEY SEED-----\n{seed}\n------END USER NKEY SEED------\n");
        var nkeyFile = WritePrivateFile(root, $"credentials/{name}.nk", $"{seed}\n{publicKey}\n");
        return new(
            name,
            publicKey,
            issuerPublicKey,
            credentialsFile,
            nkeyFile,
            certificate.CertificateFile,
            certificate.KeyFile,
            certificate.SpiffeId);
    }

    private static Dictionary<string, object?> AccountClaims(
        string issuer,
        string subject,
        long issuedAt,
        string name,
        bool enableJetStream = true,
        IReadOnlyList<Dictionary<string, object?>>? imports = null,
        IReadOnlyList<Dictionary<string, object?>>? exports = null)
    {
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
        if (imports is not null) nats["imports"] = imports;
        if (exports is not null) nats["exports"] = exports;
        return new()
        {
            ["iat"] = issuedAt,
            ["iss"] = issuer,
            ["jti"] = Jti(subject, issuedAt, name),
            ["name"] = name,
            ["nats"] = nats,
            ["sub"] = subject,
        };
    }

    private static Dictionary<string, object?> ServiceExport(string subject) => new()
    {
        ["subject"] = subject,
        ["type"] = "service",
        ["response_type"] = "Singleton",
    };

    private static Dictionary<string, object?> ServiceImport(
        string subject,
        string sourceAccount) => new()
        {
            ["account"] = sourceAccount,
            ["subject"] = subject,
            ["to"] = subject,
            ["type"] = "service",
        };

    private static Dictionary<string, object?> UserClaims(
        string issuer,
        string subject,
        string name,
        PermissionSet permissions,
        long issuedAt) => new()
        {
            ["iat"] = issuedAt,
            ["iss"] = issuer,
            ["jti"] = Jti(subject, issuedAt, name),
            ["name"] = name,
            ["nats"] = new Dictionary<string, object?>
            {
                ["data"] = -1,
                ["payload"] = -1,
                ["pub"] = new Dictionary<string, object?> { ["allow"] = permissions.Publish },
                ["sub"] = new Dictionary<string, object?> { ["allow"] = permissions.Subscribe },
                ["subs"] = -1,
                ["type"] = "user",
                ["version"] = 2,
            },
            ["sub"] = subject,
        };

    private static PermissionSet Permissions(Role role, string publicKey, int controllerNumber)
    {
        var root = NatsSubjectTaxonomy.RegionalRoot(Cell);
        var desired = NatsSubjectTaxonomy.RegionalFamilyPattern(
            Cell, NatsSubjectTaxonomy.DesiredFamilySegment);
        var observation = NatsSubjectTaxonomy.RegionalFamilyPattern(
            Cell, NatsSubjectTaxonomy.ObservationFamilySegment);
        var operation = NatsSubjectTaxonomy.RegionalFamilyPattern(
            Cell, NatsSubjectTaxonomy.OperationFamilySegment);
        var query = NatsSubjectTaxonomy.RegionalFamilyPattern(
            Cell, NatsSubjectTaxonomy.QueryFamilySegment);
        var journalCreate = NatsSubjectTaxonomy.OperationJournalCreateSubject(Cell);
        var journalUpdate = NatsSubjectTaxonomy.OperationJournalUpdateSubject(Cell);
        var runtimeLifecycleRead = NatsSubjectTaxonomy.RuntimeLifecycleJournalSubject(Cell, "read");
        var runtimeLifecycleWrite = NatsSubjectTaxonomy.RuntimeLifecycleJournalSubject(Cell, "write");
        return role switch
        {
            Role.Controller => new(
                [
                    desired,
                    observation,
                    operation,
                    query,
                    journalCreate,
                    journalUpdate,
                    runtimeLifecycleRead,
                    runtimeLifecycleWrite,
                    $"$JS.API.CONSUMER.INFO.CELL_SPEC.gitops_cell_spec_controller-{controllerNumber}",
                    $"$JS.API.CONSUMER.MSG.NEXT.CELL_SPEC.gitops_cell_spec_controller-{controllerNumber}",
                    $"$JS.ACK.CELL_SPEC.gitops_cell_spec_controller-{controllerNumber}.>",
                    "$JS.API.STREAM.INFO.KV_ORCH_DELIVERY",
                    "$JS.API.DIRECT.GET.KV_ORCH_DELIVERY",
                    "$KV.ORCH_DELIVERY.>",
                    // Membership heartbeat/watch surface — the same regional
                    // grants the production development cluster renders for a
                    // controller over the bounded ORCH_RUNTIME KV bucket — and
                    // the fenced authority lease key the coordinator CASes.
                    "$JS.API.STREAM.INFO.KV_ORCH_LEADERS",
                    "$JS.API.DIRECT.GET.KV_ORCH_LEADERS",
                    "$JS.API.DIRECT.GET.KV_ORCH_LEADERS.>",
                    "$KV.ORCH_LEADERS.>",
                    "$JS.API.STREAM.INFO.KV_ORCH_RUNTIME",
                    "$JS.API.DIRECT.GET.KV_ORCH_RUNTIME",
                    "$JS.API.DIRECT.GET.KV_ORCH_RUNTIME.>",
                    "$JS.API.CONSUMER.CREATE.KV_ORCH_RUNTIME.>",
                    "$JS.FC.KV_ORCH_RUNTIME.>",
                    "$KV.ORCH_RUNTIME.>",
                    "$JS.API.STREAM.INFO.OBJ_CELL_BUNDLES",
                    "$JS.API.STREAM.MSG.GET.OBJ_CELL_BUNDLES",
                    "$JS.API.CONSUMER.CREATE.OBJ_CELL_BUNDLES.>",
                    "$JS.API.CONSUMER.DELETE.OBJ_CELL_BUNDLES.>",
                    "$JS.FC.OBJ_CELL_BUNDLES.>",
                    "$O.CELL_BUNDLES.C.>",
                    "$O.CELL_BUNDLES.M.>",
                ],
                [
                    "_INBOX.>",
                    desired,
                    observation,
                    operation,
                    query,
                    $"{root}.command.journal.reply.{publicKey}.>",
                    $"{root}.command.runtime-lifecycle.reply.{publicKey}.>",
                    "$KV.ORCH_RUNTIME.>",
                ]),
            Role.Infrastructure => new(
                [
                    "$JS.API.STREAM.CREATE.CELL_SPEC",
                    "$JS.API.STREAM.UPDATE.CELL_SPEC",
                    "$JS.API.STREAM.INFO.CELL_SPEC",
                    "$JS.API.STREAM.CREATE.CELL_OPERATIONS",
                    "$JS.API.STREAM.UPDATE.CELL_OPERATIONS",
                    "$JS.API.STREAM.INFO.CELL_OPERATIONS",
                    "$JS.API.STREAM.CREATE.CELL_EVENTS",
                    "$JS.API.STREAM.UPDATE.CELL_EVENTS",
                    "$JS.API.STREAM.INFO.CELL_EVENTS",
                    "$JS.API.CONSUMER.CREATE.CELL_EVENTS.runtime_startup.>",
                    "$JS.API.CONSUMER.DURABLE.CREATE.CELL_EVENTS.runtime_startup.>",
                    "$JS.API.CONSUMER.INFO.CELL_EVENTS.runtime_startup",
                    "$JS.API.CONSUMER.CREATE.CELL_SPEC.gitops_cell_spec_controller-1.>",
                    "$JS.API.CONSUMER.DURABLE.CREATE.CELL_SPEC.gitops_cell_spec_controller-1.>",
                    "$JS.API.CONSUMER.INFO.CELL_SPEC.gitops_cell_spec_controller-1",
                    "$JS.API.STREAM.CREATE.KV_ORCH_LEADERS",
                    "$JS.API.STREAM.UPDATE.KV_ORCH_LEADERS",
                    "$JS.API.STREAM.INFO.KV_ORCH_LEADERS",
                    "$JS.API.STREAM.CREATE.KV_ORCH_RUNTIME",
                    "$JS.API.STREAM.UPDATE.KV_ORCH_RUNTIME",
                    "$JS.API.STREAM.INFO.KV_ORCH_RUNTIME",
                    "$JS.API.STREAM.CREATE.KV_ORCH_DELIVERY",
                    "$JS.API.STREAM.UPDATE.KV_ORCH_DELIVERY",
                    "$JS.API.STREAM.INFO.KV_ORCH_DELIVERY",
                    "$JS.API.STREAM.CREATE.KV_ORCH_OPERATIONS",
                    "$JS.API.STREAM.UPDATE.KV_ORCH_OPERATIONS",
                    "$JS.API.STREAM.INFO.KV_ORCH_OPERATIONS",
                    "$JS.API.STREAM.CREATE.KV_ORCH_OPERATION_PROOFS",
                    "$JS.API.STREAM.UPDATE.KV_ORCH_OPERATION_PROOFS",
                    "$JS.API.STREAM.INFO.KV_ORCH_OPERATION_PROOFS",
                    "$JS.API.STREAM.CREATE.KV_GLOBAL_CELLS",
                    "$JS.API.STREAM.UPDATE.KV_GLOBAL_CELLS",
                    "$JS.API.STREAM.INFO.KV_GLOBAL_CELLS",
                    "$JS.API.STREAM.CREATE.OBJ_CELL_BUNDLES",
                    "$JS.API.STREAM.UPDATE.OBJ_CELL_BUNDLES",
                    "$JS.API.STREAM.INFO.OBJ_CELL_BUNDLES",
                    "$JS.API.STREAM.CREATE.OBJ_ORCH_PROTOCOL_PACKAGE",
                    "$JS.API.STREAM.UPDATE.OBJ_ORCH_PROTOCOL_PACKAGE",
                    "$JS.API.STREAM.INFO.OBJ_ORCH_PROTOCOL_PACKAGE",
                    "$JS.API.STREAM.MSG.GET.OBJ_CELL_BUNDLES",
                    "$JS.API.STREAM.MSG.GET.OBJ_ORCH_PROTOCOL_PACKAGE",
                    "$JS.API.CONSUMER.CREATE.OBJ_CELL_BUNDLES.>",
                    "$JS.API.CONSUMER.CREATE.OBJ_ORCH_PROTOCOL_PACKAGE.>",
                    "$JS.API.CONSUMER.DELETE.OBJ_CELL_BUNDLES.>",
                    "$JS.API.CONSUMER.DELETE.OBJ_ORCH_PROTOCOL_PACKAGE.>",
                    "$JS.FC.OBJ_CELL_BUNDLES.>",
                    "$JS.FC.OBJ_ORCH_PROTOCOL_PACKAGE.>",
                    "$O.CELL_BUNDLES.C.>",
                    "$O.CELL_BUNDLES.M.>",
                    "$O.ORCH_PROTOCOL_PACKAGE.C.>",
                    "$O.ORCH_PROTOCOL_PACKAGE.M.>",
                ],
                [
                    "_INBOX.>",
                    "$O.CELL_BUNDLES.C.>",
                    "$O.CELL_BUNDLES.M.>",
                    "$O.ORCH_PROTOCOL_PACKAGE.C.>",
                    "$O.ORCH_PROTOCOL_PACKAGE.M.>",
                ]),
            Role.JournalWriter => new(
                [
                    "$KV.ORCH_OPERATIONS.>",
                    "$KV.ORCH_OPERATION_PROOFS.>",
                    $"{root}.command.journal.reply.>",
                    $"{root}.command.runtime-lifecycle.reply.>",
                    "$JS.API.STREAM.INFO.KV_ORCH_OPERATIONS",
                    "$JS.API.STREAM.INFO.KV_ORCH_OPERATION_PROOFS",
                    "$JS.API.DIRECT.GET.KV_ORCH_OPERATIONS",
                    "$JS.API.DIRECT.GET.KV_ORCH_OPERATION_PROOFS",
                    "$SRV.>",
                ],
                [
                    "_INBOX.>",
                    "$KV.ORCH_OPERATIONS.>",
                    "$KV.ORCH_OPERATION_PROOFS.>",
                    journalCreate,
                    journalUpdate,
                    runtimeLifecycleRead,
                    runtimeLifecycleWrite,
                    "$SRV.>",
                ]),
            Role.GlobalDirectoryInfrastructure => new(
                [
                    "$JS.API.STREAM.CREATE.KV_GLOBAL_CELLS",
                    "$JS.API.STREAM.UPDATE.KV_GLOBAL_CELLS",
                    "$JS.API.STREAM.INFO.KV_GLOBAL_CELLS",
                ],
                ["_INBOX.>"]),
            Role.CellDirectoryPublisher => From(
                GlobalNatsPermissions.Create("sfo", GlobalNatsRole.CellDirectoryPublisher)),
            Role.CellDirectoryReader => From(
                GlobalNatsPermissions.Create("sfo", GlobalNatsRole.CellDirectoryReader)),
            Role.CellDirectoryService => From(
                GlobalNatsPermissions.Create("gru", GlobalNatsRole.CellDirectoryService)),
            Role.GlobalAuthority => From(
                GlobalNatsPermissions.Create("gru", GlobalNatsRole.GlobalAuthority)),
            Role.Operator => new(
                [
                    NatsSubjectTaxonomy.ControllerStatusSubject(Cell),
                    NatsSubjectTaxonomy.ControllerMembersSubject(Cell),
                ],
                ["_INBOX.>"]),
            Role.WrongAccount => new([">"], ["_INBOX.>"]),
            _ => throw new ArgumentOutOfRangeException(nameof(role), role, "Unknown L0C role."),
        };
    }

    private static PermissionSet From(GlobalNatsPermissionPlan plan) =>
        new(plan.Publish, plan.Subscribe);

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
        // encoded payload. User claims below use the v2 nested nats.type/version
        // form and therefore sign the encoded header plus payload.
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

    private static PkiMaterial CreatePki(string root)
    {
        var pkiRoot = Path.Combine(root, "pki");
        CreatePrivateDirectory(pkiRoot);
        using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var caRequest = new CertificateRequest(
            "CN=TerraScale L0C ephemeral CA",
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
        var caFile = WriteCertificate(pkiRoot, "ca.pem", ca, caKey, privateKey: true);
        var servers = new NatsControlR3L0cCertificate[MemberCount];
        for (var member = 0; member < MemberCount; member++)
        {
            var spiffe = $"spiffe://terrascale.tech/cell/{Cell}/nats/server/{member + 1}";
            servers[member] = CreateLeaf(
                pkiRoot,
                $"server-{member + 1}",
                spiffe,
                ca,
                serverAuthentication: true,
                clientAuthentication: true,
                includeLoopbackNames: true);
        }
        var clients = new Dictionary<string, NatsControlR3L0cCertificate>(StringComparer.Ordinal);
        foreach (var name in new[]
                 {
                     "controller-1", "controller-2", "infrastructure", "journal-writer",
                     "global-directory-infrastructure",
                     "cell-directory-publisher-sfo", "cell-directory-reader-sfo",
                     "cell-directory-service-gru", "global-authority", "operator-read", "wrong-account"
                 })
        {
            clients[name] = CreateLeaf(
                pkiRoot,
                name,
                $"spiffe://terrascale.tech/cell/{Cell}/nats/client/{name}",
                ca,
                serverAuthentication: false,
                clientAuthentication: true,
                includeLoopbackNames: false);
        }
        return new(caFile, servers, clients);
    }

    private static NatsControlR3L0cCertificate CreateLeaf(
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
            spiffeId,
            withKey.NotAfter.ToUniversalTime(),
            withKey.Extensions.OfType<X509EnhancedKeyUsageExtension>().Single().EnhancedKeyUsages
                .Cast<Oid>()
                .Select(static oid => oid.Value!)
                .ToArray());
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
            throw new PlatformNotSupportedException("The real NATS L0C fixture requires Linux file permissions.");
        Directory.CreateDirectory(path, PrivateDirectoryMode);
    }

    private static void SetPrivateFile(string path)
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("The real NATS L0C fixture requires Linux file permissions.");
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

    private static void ValidateMember(int member)
    {
        if (member is < 0 or >= MemberCount)
            throw new ArgumentOutOfRangeException(nameof(member));
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
        throw new IOException("The ephemeral NATS fixture directory could not be removed.");
    }

    private static async Task TryDeleteAsync(string path)
    {
        try
        {
            await DeleteDirectoryWithRetryAsync(path);
        }
        catch
        {
        }
    }

    internal sealed class NatsControlR3L0cIdentity
    {
        internal NatsControlR3L0cIdentity(
            string name,
            string publicKey,
            string accountPublicKey,
            string credentialsFile,
            string nkeyFile,
            string certificateFile,
            string keyFile,
            string spiffeId)
        {
            Name = name;
            PublicKey = publicKey;
            AccountPublicKey = accountPublicKey;
            CredentialsFile = credentialsFile;
            NKeyFile = nkeyFile;
            CertificateFile = certificateFile;
            KeyFile = keyFile;
            SpiffeId = spiffeId;
        }

        internal string Name { get; }
        internal string PublicKey { get; }
        internal string AccountPublicKey { get; }
        internal string CredentialsFile { get; }
        internal string NKeyFile { get; }
        internal string CertificateFile { get; }
        internal string KeyFile { get; }
        internal string SpiffeId { get; }

        public override string ToString() => $"NATS identity {Name} ({PublicKey[..4]}…redacted)";
    }

    internal sealed record NatsControlR3L0cCertificate(
        string CertificateFile,
        string KeyFile,
        string SpiffeId,
        DateTime NotAfter,
        IReadOnlyList<string> EnhancedKeyUsages);

    private sealed record PkiMaterial(
        string CaFile,
        NatsControlR3L0cCertificate[] ServerCertificates,
        IReadOnlyDictionary<string, NatsControlR3L0cCertificate> ClientCertificates);

    private sealed record FixtureIdentities(
        string OperatorJwtFile,
        string GlobalAuthorityAccountPublicKey,
        string GlobalAuthorityAccountJwt,
        string GlobalDirectoryAccountPublicKey,
        string GlobalDirectoryAccountJwt,
        string RegionalControlGruAccountPublicKey,
        string RegionalControlGruAccountJwt,
        string RegionalControlSfoAccountPublicKey,
        string RegionalControlSfoAccountJwt,
        string SystemAccountPublicKey,
        string SystemAccountJwt,
        string WrongAccountPublicKey,
        string WrongAccountJwt,
        NatsControlR3L0cIdentity Controller,
        NatsControlR3L0cIdentity ControllerTwo,
        NatsControlR3L0cIdentity Infrastructure,
        NatsControlR3L0cIdentity GlobalDirectoryInfrastructure,
        NatsControlR3L0cIdentity JournalWriter,
        NatsControlR3L0cIdentity CellDirectoryPublisher,
        NatsControlR3L0cIdentity CellDirectoryReader,
        NatsControlR3L0cIdentity CellDirectoryService,
        NatsControlR3L0cIdentity Authority,
        NatsControlR3L0cIdentity Operator,
        NatsControlR3L0cIdentity WrongAccount);

    private sealed record PermissionSet(
        IReadOnlyList<string> Publish,
        IReadOnlyList<string> Subscribe);

    private enum Role
    {
        Controller,
        Infrastructure,
        GlobalDirectoryInfrastructure,
        JournalWriter,
        CellDirectoryPublisher,
        CellDirectoryReader,
        CellDirectoryService,
        GlobalAuthority,
        Operator,
        WrongAccount,
    }
}
