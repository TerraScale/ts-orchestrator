using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using NATS.Client.Core;
using NATS.Client.JetStream;
using NATS.Client.KeyValueStore;
using NATS.Net;
using TerraScale.Orchestrator.ControlPlane.Operations;
using TerraScale.Orchestrator.ControlPlane.Providers;
using TerraScale.Orchestrator.ControlPlane.Runtime;
using TerraScale.Orchestrator.Messaging;
using HostArchitecture = TerraScale.Orchestrator.Runtime.HostArchitecture;
using HostRuntimeDriver = TerraScale.Orchestrator.Runtime.RuntimeDriver;
using HostRuntimePlan = TerraScale.Orchestrator.Runtime.HostRuntimePlan;
using HostRole = TerraScale.Orchestrator.Runtime.AdmittedRole;

namespace TerraScale.Orchestrator.Tests;

// These integration tests each own one or more NATS servers. Running them alongside
// other tests in this module makes startup verification contend for the same bounded
// validation resources and intermittently time out during pre-deployment attestation.
[NotInParallel]
public sealed class NatsCreateNodeOperationJournalTests
{
    [Test]
    public async Task MutationServiceCancellationBeforeRegistrationDisposesItsReplySigner()
    {
        await using var server = await OneNodeJetStream.StartAsync();
        await using var writer = await server.ConnectAsAsync(port => new NatsOpts
        {
            Url = $"nats://127.0.0.1:{port}",
            RequestTimeout = TimeSpan.FromSeconds(1),
        });
        var topology = new NatsTopology("cleanup", 1);
        var operations = await writer.CreateJetStreamContext().CreateKeyValueStoreContext()
            .CreateOrUpdateStoreAsync(Rf1Operations(topology.Cell));
        var proofs = await writer.CreateJetStreamContext().CreateKeyValueStoreContext()
            .CreateOrUpdateStoreAsync(Rf1ProofConsumptions(topology.Cell));
        using var authorityKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var replyKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var replies = new NatsOperationJournalMutationReplySigner(replyKey);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        Func<Task> start = async () => _ = await NatsOperationJournalMutationService.StartAsync(
            writer,
            operations,
            proofs,
            topology,
            new NatsOperationJournalMutationAuthorityVerifier(authorityKey.ExportSubjectPublicKeyInfo()),
            new HashSet<string>(StringComparer.Ordinal) { "controller" },
            replies,
            cancellation.Token);
        await Assert.That(start).Throws<OperationCanceledException>();
        await Assert.That(() => replies.ExportPublicKey()).Throws<ObjectDisposedException>();

        Func<Task> ping = async () => _ = await writer.RequestAsync<string, string>(
            $"$SRV.PING.terrascale_orchestrator_journal_writer_{topology.Cell}", string.Empty);
        await Assert.That(ping).Throws<NatsNoRespondersException>();
    }

    [Test]
    public async Task JournalWriterStartupCancellationDisposesItsRetryingUnavailableClient()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"ts-orch-journal-writer-cancel-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        try
        {
            var nkey = Path.Combine(directory, "writer.nk");
            await File.WriteAllTextAsync(nkey, NATS.Client.Core.NKeys.CreateUserSeed());
            var options = new OrchestratorOptions(
                OrchestratorCommand.JournalWriter,
                "cleanup",
                $"nats://127.0.0.1:{port}",
                3,
                AuthoritativeJournal: new NatsAuthoritativeJournalConfiguration(
                    nkey,
                    new NatsTlsFiles("unused-ca.pem", "unused-cert.pem", "unused-key.pem"),
                    Array.Empty<byte>(),
                    "unused-reply.pem",
                    Array.Empty<byte>(),
                    new HashSet<string>(StringComparer.Ordinal) { "controller" }));
            using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
            var startup = NatsJournalWriterRuntime.StartAsync(options, cancellation.Token);

            await Assert.That(async () => await startup.WaitAsync(TimeSpan.FromSeconds(2)))
                .Throws<OperationCanceledException>();
            await Assert.That(startup.IsCompleted).IsTrue();
        }
        finally
        {
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }

    private static CreateNodeOperationJournalEntry Entry()
    {
        var now = DateTimeOffset.UtcNow;
        var binding = new CreateNodeReceiptBinding("operation-1", "tenant-1", "node-request-1", "idempotency-1", "create-1",
            "gru", "compartment-1", 1, 1, "template-1", "placement-1", "bootstrap-1", 1, "authorization-1", "provider-1");
        using var receiptKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var recoveryKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return new(0, "fingerprint-1", binding,
            new CreateNodeHandoffReceiptSigner("receipt", receiptKey).Sign(binding, now, now.AddMinutes(5)),
            new CreateNodeRecoveryLookupSigner("recovery", recoveryKey).Sign(binding, now, now.AddDays(1)),
            CreateNodeJournalStage.Prepared, null, 0, null);
    }

    private static RuntimeLifecycleOperationRequest RuntimeRequest(string cell)
    {
        var plan = HostRuntimePlan.Create(HostRole.CustomerDashboard, HostRuntimeDriver.OciContainer,
            new TerraScale.Orchestrator.Runtime.RuntimeAllocationId("dashboard-a"),
            new TerraScale.Orchestrator.Runtime.ArtifactDigest(RuntimeLifecycleFingerprint.Hash("artifact")), HostArchitecture.Arm64);
        return new(new(cell), new("node-a"), new(7), new(RuntimeLifecycleFingerprint.Hash("convergence")), plan,
            LifecycleAction.Converge, new(7), new(RuntimeLifecycleFingerprint.Hash("authorization")),
            new(new(RuntimeLifecycleFingerprint.Hash("deadline")), 9));
    }

    private static async Task<bool> TryUpdateAsync(INatsKVStore store, string key, string value, ulong revision)
    {
        try
        {
            await store.UpdateAsync(key, value, revision);
            return true;
        }
        catch (NatsKVWrongLastRevisionException)
        {
            return false;
        }
    }

    private static async Task<NatsOperationJournalMutationReply> RequestPrivateAsync<TRequest>(
        NatsClient client,
        NatsTopology topology,
        string callerIdentity,
        string subject,
        TRequest request)
    {
        var reply = topology.OperationJournalReplySubject(callerIdentity, Guid.NewGuid().ToString("N"));
        using var responseTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        await using var subscription = await client.Connection.SubscribeCoreAsync<NatsOperationJournalMutationReply>(
            reply,
            opts: new NatsSubOpts { MaxMsgs = 1, Timeout = TimeSpan.FromSeconds(2) },
            cancellationToken: responseTimeout.Token);
        await client.PingAsync(responseTimeout.Token);
        await client.PublishAsync(subject, request, replyTo: reply, cancellationToken: responseTimeout.Token);
        return (await subscription.Msgs.ReadAsync(responseTimeout.Token)).Data
            ?? throw new InvalidOperationException("Private journal response was empty.");
    }

    private static async Task<NatsRuntimeLifecycleJournalReply> RequestRuntimePrivateAsync<TRequest>(
        NatsClient client,
        string cell,
        string callerIdentity,
        string subject,
        TRequest request)
        where TRequest : INatsOperationJournalMutationRequest
    {
        var reply = RuntimeLifecycleNatsProtocol.ReplySubject(cell, callerIdentity, Guid.NewGuid().ToString("N"));
        using var responseTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        await using var subscription = await client.Connection.SubscribeCoreAsync<NatsRuntimeLifecycleJournalReply>(
            reply,
            opts: new NatsSubOpts { MaxMsgs = 1, Timeout = TimeSpan.FromSeconds(2) },
            cancellationToken: responseTimeout.Token);
        await client.PingAsync(responseTimeout.Token);
        await client.PublishAsync(subject, request, replyTo: reply, cancellationToken: responseTimeout.Token);
        return (await subscription.Msgs.ReadAsync(responseTimeout.Token)).Data
            ?? throw new InvalidOperationException("Private runtime journal response was empty.");
    }

    // TODO(rehome-agent): the credentialed R3 journal-writer, invocation-capability,
    // concurrent-controller, protocol-package-corruption, and controller-rejection tests were
    // removed with the production Development/ lab fixtures (they minted per-controller NKey
    // and mTLS identities through DevelopmentNatsSecurity); rehome them onto a test-owned NATS
    // identity fixture to restore that coverage.

    private sealed class RetriableLeaseOwner(LocalNatsServerLease.Handle lease) : IAsyncDisposable
    {
        private int attempts;

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Increment(ref attempts) == 1)
                throw new IOException("private root remains");
            await lease.ReleaseIfCleanAsync(new LocalNatsServerLease.Cleanup());
            LocalNatsServerLease.CompleteRetention(this);
        }
    }

    private static async Task<string> SubscribeDeniedAsync(int port, string seedFile, string subject)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, port, timeout.Token);
        await using var stream = tcp.GetStream();
        using var reader = new StreamReader(stream, System.Text.Encoding.UTF8, leaveOpen: true);
        await using var writer = new StreamWriter(stream, new System.Text.UTF8Encoding(false), leaveOpen: true)
        {
            NewLine = "\r\n",
            AutoFlush = true,
        };
        var info = await reader.ReadLineAsync(timeout.Token)
            ?? throw new InvalidOperationException("NATS server did not send its connection info.");
        using var infoDocument = JsonDocument.Parse(info["INFO ".Length..]);
        var nonce = infoDocument.RootElement.GetProperty("nonce").GetString()
            ?? throw new InvalidOperationException("NATS server did not provide an NKey nonce.");
        var seed = File.ReadLines(seedFile).First(line => !string.IsNullOrWhiteSpace(line)).Trim();
        using var pair = NATS.Client.Core.NKeys.FromSeed(seed);
        var connect = JsonSerializer.Serialize(new
        {
            nkey = NATS.Client.Core.NKeys.PublicKeyFromSeed(seed),
            sig = Convert.ToBase64String(pair.Sign(System.Text.Encoding.UTF8.GetBytes(nonce))),
        });
        await writer.WriteLineAsync($"CONNECT {connect}");
        await writer.WriteLineAsync($"SUB {subject} 1");

        while (true)
        {
            var response = await reader.ReadLineAsync(timeout.Token)
                ?? throw new InvalidOperationException("NATS server closed before reporting the subscription result.");
            if (!response.StartsWith("+OK", StringComparison.Ordinal))
            {
                return response;
            }
        }
    }

    private static async Task<string> PublishDeniedAsync(int port, string seedFile, string subject, string payload)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, port, timeout.Token);
        await using var stream = tcp.GetStream();
        using var reader = new StreamReader(stream, System.Text.Encoding.UTF8, leaveOpen: true);
        await using var writer = new StreamWriter(stream, new System.Text.UTF8Encoding(false), leaveOpen: true)
        {
            NewLine = "\r\n",
            AutoFlush = true,
        };
        var info = await reader.ReadLineAsync(timeout.Token)
            ?? throw new InvalidOperationException("NATS server did not send its connection info.");
        using var infoDocument = JsonDocument.Parse(info["INFO ".Length..]);
        var nonce = infoDocument.RootElement.GetProperty("nonce").GetString()
            ?? throw new InvalidOperationException("NATS server did not provide an NKey nonce.");
        var seed = File.ReadLines(seedFile).First(line => !string.IsNullOrWhiteSpace(line)).Trim();
        using var pair = NATS.Client.Core.NKeys.FromSeed(seed);
        await writer.WriteLineAsync($"CONNECT {JsonSerializer.Serialize(new { nkey = NATS.Client.Core.NKeys.PublicKeyFromSeed(seed), sig = Convert.ToBase64String(pair.Sign(System.Text.Encoding.UTF8.GetBytes(nonce))) })}");
        await writer.WriteLineAsync($"PUB {subject} {System.Text.Encoding.UTF8.GetByteCount(payload)}\r\n{payload}");
        while (true)
        {
            var response = await reader.ReadLineAsync(timeout.Token)
                ?? throw new InvalidOperationException("NATS server closed before reporting the publish result.");
            if (response.StartsWith("-ERR", StringComparison.Ordinal)) return response;
        }
    }

    private static NatsOperationJournalMutationReplySigner CreateReplySigner(byte[] privateKey)
    {
        var key = ECDsa.Create();
        key.ImportPkcs8PrivateKey(privateKey, out _);
        return new(key);
    }

    private static async Task EventuallyAsync(Func<Task> action)
    {
        for (var attempt = 0; ; attempt++)
        {
            try
            {
                await action();
                return;
            }
            catch (NatsJSApiException) when (attempt < 49)
            {
                await Task.Delay(100);
            }
            catch (NatsJSApiNoResponseException) when (attempt < 49)
            {
                await Task.Delay(100);
            }
        }
    }

    private static async Task<RegionalRuntimeMembershipHealth> WaitForMembershipAsync(
        NatsRuntime runtime,
        Func<RegionalRuntimeMembershipHealth, bool> predicate,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        var elapsed = Stopwatch.StartNew();
        while (true)
        {
            var health = runtime.MembershipHealth;
            if (predicate(health)) return health;
            if (elapsed.Elapsed >= timeout)
                throw new TimeoutException("Regional runtime membership did not reach the expected health state.");
            await Task.Delay(50, cancellationToken);
        }
    }

    private static NatsKVConfig Rf1Operations(string cell = "journal") => new("ORCH_OPERATIONS")
    {
        Description = $"Authoritative encrypted regional operation journal for {cell}",
        History = 2,
        MaxValueSize = 16 * 1024,
        MaxBytes = 256 * 1024 * 1024,
        NumberOfReplicas = 1,
    };

    private static NatsKVConfig Rf1ProofConsumptions(string cell = "journal") => new("ORCH_OPERATION_PROOFS")
    {
        Description = $"Expiry-bounded single-use operation journal authority proofs for {cell}",
        History = 1,
        MaxAge = TimeSpan.FromMinutes(5),
        MaxValueSize = 256,
        MaxBytes = 8 * 1024 * 1024,
        NumberOfReplicas = 1,
    };

    private static RegionalAuthoritySnapshot Authority(long epoch, long revision)
    {
        var now = DateTimeOffset.UtcNow;
        return new("leader", true, epoch, revision, now.AddSeconds(15), now, null);
    }

    private static RegionalRuntimeMembershipSnapshot Membership(string cell)
    {
        var now = DateTimeOffset.UtcNow;
        using var identity = RegionalRuntimeMembershipIdentity.Create();
        var member = Sign(new RegionalRuntimeMember(
            1,
            cell,
            $"orchestrator-control-{cell}",
            "controller-1",
            Guid.NewGuid().ToString("N"),
            "test-build",
            ["authority", "regional-membership", "service-discovery"],
            now.AddMinutes(-1),
            now,
            now.Add(RegionalRuntimeMembership.LeaseDuration),
            "leader",
            true,
            7,
            11), identity);
        var health = RegionalRuntimeMembershipHealth.Evaluate(cell, 3, [member], 0, now);
        return new(2, cell, now, health, [member]);
    }

    private static RegionalRuntimeMember Sign(
        RegionalRuntimeMember member,
        RegionalRuntimeMembershipIdentity identity) =>
        member with
        {
            IdentityKeyId = identity.KeyId,
            IdentityPublicKey = identity.PublicKey,
            IdentitySignature = identity.Sign(member),
        };

    private static async Task<GlobalCellDirectorySnapshot> WaitForDirectoryAsync(
        GlobalCellDirectoryRuntime runtime,
        int activeCells,
        TimeSpan timeout,
        Func<GlobalCellDirectorySnapshot, bool>? predicate = null)
    {
        var started = Stopwatch.StartNew();
        while (started.Elapsed < timeout)
        {
            var snapshot = runtime.Snapshot;
            if (snapshot.ActiveCells == activeCells && (predicate?.Invoke(snapshot) ?? true))
                return snapshot;
            await Task.Delay(50);
        }
        throw new TimeoutException($"The global cell directory did not converge to {activeCells} active cells.");
    }

    private sealed class OneNodeJetStream : IAsyncDisposable
    {
        private readonly string directory;
        private readonly string configuration;
        private readonly int port;
        private readonly Func<int, NatsOpts>? clientOptions;
        private readonly ContainerizedNatsCluster containerCluster;
        private readonly LocalNatsServerLease.Handle lease;
        private Process? process;
        private NatsClient? client;
        private Task? processOutput;
        private int disposed;

        public int Port => port;

        private OneNodeJetStream(
            string directory,
            string configuration,
            int port,
            Func<int, NatsOpts>? clientOptions,
            ContainerizedNatsCluster containerCluster,
            LocalNatsServerLease.Handle lease)
        {
            this.directory = directory;
            this.configuration = configuration;
            this.port = port;
            this.clientOptions = clientOptions;
            this.containerCluster = containerCluster;
            this.lease = lease;
        }

        public static async Task<OneNodeJetStream> StartAsync(
            string? authorization = null,
            Func<int, NatsOpts>? clientOptions = null)
        {
            var lease = await LocalNatsServerLease.AcquireAsync();
            var directory = Path.Combine(Path.GetTempPath(), $"ts-orch-create-node-journal-{Guid.NewGuid():N}");
            OneNodeJetStream? server = null;
            try
            {
                Directory.CreateDirectory(directory);
                var listener = new TcpListener(IPAddress.Loopback, 0);
                listener.Start();
                var port = ((IPEndPoint)listener.LocalEndpoint).Port;
                listener.Stop();
                var configuration = Path.Combine(directory, "nats.conf");
                await File.WriteAllTextAsync(configuration, $"host: 127.0.0.1\nport: {port}\n{authorization}\njetstream {{ store_dir: \"{Path.Combine(directory, "store")}\" }}\n");
                var containerCluster = await ContainerizedNatsCluster.CreateAsync(directory);
                server = new OneNodeJetStream(directory, configuration, port, clientOptions, containerCluster, lease);
                await server.ConnectAsync();
                return server;
            }
            catch (Exception startupFailure)
            {
                if (server is not null)
                {
                    try
                    {
                        await server.DisposeAsync();
                    }
                    catch (Exception cleanupFailure)
                    {
                        throw new AggregateException(startupFailure, cleanupFailure);
                    }
                }
                else
                {
                    var owner = new LocalNatsServerLease.DirectoryCleanupOwner(directory, lease);
                    try
                    {
                        await owner.DisposeAsync();
                    }
                    catch (Exception cleanupFailure)
                    {
                        throw new AggregateException(startupFailure, cleanupFailure);
                    }
                }
                throw;
            }
        }

        public async Task<INatsKVStore> OpenAsync(NatsKVConfig configuration)
        {
            var jetStream = client!.CreateJetStreamContext();
            return await jetStream.CreateKeyValueStoreContext().CreateOrUpdateStoreAsync(configuration);
        }

        public async ValueTask<INatsKVStore> OpenAuthoritativeAsync(NatsKVConfig configuration) =>
            await NatsOperationJournalStore.OpenAsync(
                client!.CreateJetStreamContext().CreateKeyValueStoreContext(),
                configuration,
                default);

        public async Task RequestAsync(string subject, string payload) =>
            _ = await client!.RequestAsync<string, string>(subject, payload);

        public async Task<NatsClient> ConnectAsAsync(Func<int, NatsOpts> options)
        {
            var additional = new NatsClient(options(port));
            try
            {
                await additional.ConnectAsync();
                return additional;
            }
            catch
            {
                await additional.DisposeAsync();
                throw;
            }
        }

        public async Task RestartAsync()
        {
            if (client is not null) await client.DisposeAsync();
            client = null;
            if (process is not null)
            {
                await containerCluster.StopAsync(process);
                process.Dispose();
                process = null;
            }
            if (processOutput is not null)
            {
                await processOutput.WaitAsync(TimeSpan.FromSeconds(1));
                processOutput = null;
            }
            await ConnectAsync();
        }

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.CompareExchange(ref disposed, 1, 0) != 0) return;
            var cleanup = new LocalNatsServerLease.Cleanup();
            try
            {
                if (client is not null &&
                    await cleanup.AttemptAsync(() => client.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5))))
                    client = null;
                if (process is not null)
                {
                    if (await cleanup.AttemptAsync(() => containerCluster.StopAsync(process)) &&
                        cleanup.Attempt(process.Dispose))
                        process = null;
                }
                if (processOutput is not null &&
                    await cleanup.AttemptAsync(() => processOutput.WaitAsync(TimeSpan.FromSeconds(1))))
                    processOutput = null;
                await cleanup.AttemptAsync(() => containerCluster.DisposeAsync().AsTask());
                cleanup.Attempt(() =>
                {
                    if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
                });
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

        private async Task ConnectAsync()
        {
            process = containerCluster.Start(configuration);
            processOutput = Task.WhenAll(
                process.StandardOutput.ReadToEndAsync(),
                process.StandardError.ReadToEndAsync());
            for (var attempt = 0; attempt < 50; attempt++)
            {
                client = new NatsClient(clientOptions?.Invoke(port) ?? new NatsOpts
                {
                    Url = $"nats://127.0.0.1:{port}",
                    ConnectTimeout = TimeSpan.FromSeconds(1),
                });
                try
                {
                    await client.ConnectAsync();
                    return;
                }
                catch (NatsException) when (attempt < 49)
                {
                    await client.DisposeAsync();
                    client = null;
                    await Task.Delay(50);
                }
            }
            throw new InvalidOperationException("The containerized NATS server did not accept a local JetStream connection.");
        }
    }

    private sealed class ThreeNodeJetStream : IAsyncDisposable
    {
        private readonly string directory;
        private readonly int[] ports;
        private readonly Process?[] processes;
        private readonly Task?[] processOutput;
        private readonly ContainerizedNatsCluster containerCluster;
        private readonly LocalNatsServerLease.Handle lease;
        private int disposed;

        private ThreeNodeJetStream(
            string directory,
            int[] ports,
            Process?[] processes,
            Task?[] processOutput,
            ContainerizedNatsCluster containerCluster,
            LocalNatsServerLease.Handle lease)
        {
            this.directory = directory;
            this.ports = ports;
            this.processes = processes;
            this.processOutput = processOutput;
            this.containerCluster = containerCluster;
            this.lease = lease;
        }

        public int Port => ports[0];

        public static async Task<ThreeNodeJetStream> StartAsync(
            string authorization,
            string readinessNkeyFile,
            Func<int, NatsOpts>? readinessOptions = null,
            string? transportConfiguration = null,
            IEnumerable<string>? readOnlyRoots = null)
        {
            var lease = await LocalNatsServerLease.AcquireAsync();
            var directory = Path.Combine(Path.GetTempPath(), $"ts-orch-r3-journal-{Guid.NewGuid():N}");
            ThreeNodeJetStream? server = null;
            var processes = new Process?[3];
            var processOutput = new Task?[3];
            try
            {
                Directory.CreateDirectory(directory);
                var clientPorts = Enumerable.Range(0, 3).Select(_ => FreePort()).ToArray();
                var routePorts = Enumerable.Range(0, 3).Select(_ => FreePort()).ToArray();
                var configurations = clientPorts.Select((port, index) => Path.Combine(directory, $"nats-{index}.conf")).ToArray();
                for (var index = 0; index < 3; index++)
                {
                    var routes = string.Join(", ", routePorts.Where((_, candidate) => candidate != index)
                        .Select(route => $"\"nats-route://127.0.0.1:{route}\""));
                    await File.WriteAllTextAsync(configurations[index], $$"""
                        server_name: "journal-{{index}}"
                        host: "127.0.0.1"
                        port: {{clientPorts[index]}}
                        {{authorization}}
                        {{transportConfiguration}}
                        jetstream { store_dir: "{{Path.Combine(directory, $"store-{index}")}}" }
                        cluster {
                          name: "journal-r3"
                          host: "127.0.0.1"
                          port: {{routePorts[index]}}
                          routes: [{{routes}}]
                        }
                        """);
                }

                var containerCluster = await ContainerizedNatsCluster.CreateAsync(
                    directory,
                    readOnlyRoots);
                server = new ThreeNodeJetStream(directory, clientPorts, processes, processOutput, containerCluster, lease);
                for (var index = 0; index < configurations.Length; index++)
                {
                    processes[index] = containerCluster.Start(configurations[index]);
                    processOutput[index] = Task.WhenAll(
                        processes[index]!.StandardOutput.ReadToEndAsync(),
                        processes[index]!.StandardError.ReadToEndAsync());
                }
                // Rootless Podman must create the pod network and start three TLS
                // servers before the first connection can complete. Keep this
                // bounded, but allow materially more time than a host process.
                for (var attempt = 0; attempt < 150; attempt++)
                {
                    try
                    {
                        await using var client = await server.ConnectAsAsync(readinessOptions ?? (port => new NatsOpts
                        {
                            Url = $"nats://127.0.0.1:{port}",
                            ConnectTimeout = TimeSpan.FromSeconds(1),
                            AuthOpts = new NatsAuthOpts { NKeyFile = readinessNkeyFile },
                        }));
                        return server;
                    }
                    catch (NatsException) when (attempt < 149)
                    {
                        await Task.Delay(100);
                    }
                }
                throw new InvalidOperationException("The three-node containerized NATS cluster did not accept a local JetStream connection.");
            }
            catch (Exception startupFailure)
            {
                if (server is not null)
                {
                    try
                    {
                        await server.DisposeAsync();
                    }
                    catch (Exception cleanupFailure)
                    {
                        throw new AggregateException(startupFailure, cleanupFailure);
                    }
                }
                else
                {
                    var owner = new LocalNatsServerLease.DirectoryCleanupOwner(directory, lease);
                    try
                    {
                        await owner.DisposeAsync();
                    }
                    catch (Exception cleanupFailure)
                    {
                        throw new AggregateException(startupFailure, cleanupFailure);
                    }
                }
                throw;
            }
        }

        public async Task<NatsClient> ConnectAsAsync(Func<int, NatsOpts> options)
        {
            var client = new NatsClient(options(Port));
            try
            {
                await client.ConnectAsync();
                return client;
            }
            catch
            {
                await client.DisposeAsync();
                throw;
            }
        }

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.CompareExchange(ref disposed, 1, 0) != 0) return;
            var cleanup = new LocalNatsServerLease.Cleanup();
            try
            {
                for (var index = 0; index < processes.Length; index++)
                {
                    var process = processes[index];
                    if (process is null) continue;
                    if (await cleanup.AttemptAsync(() => containerCluster.StopAsync(process)) &&
                        cleanup.Attempt(process.Dispose))
                        processes[index] = null;
                }
                for (var index = 0; index < processOutput.Length; index++)
                {
                    var output = processOutput[index];
                    if (output is not null &&
                        await cleanup.AttemptAsync(() => output.WaitAsync(TimeSpan.FromSeconds(1))))
                        processOutput[index] = null;
                }
                await cleanup.AttemptAsync(() => containerCluster.DisposeAsync().AsTask());
                cleanup.Attempt(() =>
                {
                    if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
                });
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

        private static int FreePort()
        {
            using var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            return ((IPEndPoint)listener.LocalEndpoint).Port;
        }
    }
}
