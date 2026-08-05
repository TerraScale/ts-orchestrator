using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using NATS.Client.Core;
using NATS.Client.JetStream;
using NATS.Client.KeyValueStore;
using NATS.Net;
using TerraScale.Orchestrator.Development;
using TerraScale.Orchestrator.ControlPlane.Operations;
using TerraScale.Orchestrator.ControlPlane.Providers;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

public sealed class NatsCreateNodeOperationJournalTests
{
    [Test]
    public async Task OneNodeJetStreamPersistsCasButRejectsJournalMutationWhenRf1IsNotR3()
    {
        await using var server = await OneNodeJetStream.StartAsync();
        var topology = new NatsTopology("journal", 1);
        var rf1Operations = Rf1Operations();
        var store = await server.OpenAsync(rf1Operations);
        using var invocationKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CreateNodeAuthoritativeInvocationCapabilitySigner("invocation", invocationKey);
        var status = await store.GetStatusAsync();
        await Assert.That(status.Info.Config.NumReplicas).IsEqualTo(1);
        await Assert.That(status.Info.Config.MaxAge).IsEqualTo(TimeSpan.Zero);
        var key = "operation.cas-journal";
        var revision = await store.CreateAsync(key, "ProviderCallStarted");
        await Assert.That(await TryUpdateAsync(store, key, "ProviderCallStarted;first", revision)).IsTrue();
        await Assert.That(await TryUpdateAsync(store, key, "ProviderCallStarted;second", revision)).IsFalse();

        var beforeRestart = await store.GetEntryAsync<string>(key);
        beforeRestart.EnsureSuccess();

        await server.RestartAsync();
        store = await server.OpenAsync(rf1Operations);
        var reloaded = await store.GetEntryAsync<string>(key);
        reloaded.EnsureSuccess();
        await Assert.That(reloaded.Value).IsEqualTo("ProviderCallStarted;first");
        await Assert.That(reloaded.Revision).IsEqualTo(beforeRestart.Revision);

        Func<Task> openAuthoritative = async () => { await server.OpenAuthoritativeAsync(topology.Operations); };
        await Assert.That(openAuthoritative).Throws<InvalidOperationException>();
        var afterRejectedOpen = await store.GetEntryAsync<string>(key);
        afterRejectedOpen.EnsureSuccess();
        await Assert.That(afterRejectedOpen.Revision).IsEqualTo(reloaded.Revision);

        var journal = new NatsCreateNodeOperationJournal(store,
            new CreateNodeJournalEncryptionKeyRing("key", new Dictionary<string, byte[]> { ["key"] = RandomNumberGenerator.GetBytes(32) }), signer);
        await Assert.That(() => journal.CompareExchangeAsync(null, Entry(), default).AsTask())
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task MutationRequiresActualR3ConfigurationAndHealthyInjectedKeyService()
    {
        await using var server = await OneNodeJetStream.StartAsync();
        var store = await server.OpenAsync(Rf1Operations());
        using var invocationKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CreateNodeAuthoritativeInvocationCapabilitySigner("invocation", invocationKey);
        var key = RandomNumberGenerator.GetBytes(32);

        var healthy = false;
        var journal = new NatsCreateNodeOperationJournal(store,
            new CreateNodeJournalEncryptionKeyRing("key", new Dictionary<string, byte[]> { ["key"] = key }, () => healthy), signer);
        await Assert.That(() => journal.CompareExchangeAsync(null, Entry(), default).AsTask())
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task DedicatedOperationKvNeverExpiresTombstonesAndIsR3Configured()
    {
        var operations = new NatsTopology("gru", 3).Operations;

        await Assert.That(new NatsTopology("gru", 1).Operations.NumberOfReplicas).IsEqualTo(3);

        await Assert.That(operations.Bucket).IsEqualTo("ORCH_OPERATIONS");
        await Assert.That(operations.NumberOfReplicas).IsEqualTo(3);
        await Assert.That(operations.History).IsEqualTo(2);
        await Assert.That(operations.MaxAge).IsEqualTo(TimeSpan.Zero);
        await Assert.That(operations.MaxValueSize).IsEqualTo(16 * 1024);
        await Assert.That(operations.MaxBytes).IsEqualTo(256 * 1024 * 1024);
    }

    [Test]
    public async Task ProvisioningUsesTheCompleteImmutableKvStreamConfiguration()
    {
        var stream = NatsOperationJournalStore.CanonicalStream(new NatsTopology("gru", 3).Operations);

        await Assert.That(stream.Name).IsEqualTo("KV_ORCH_OPERATIONS");
        await Assert.That(stream.Subjects).IsEquivalentTo(["$KV.ORCH_OPERATIONS.>"]);
        await Assert.That(stream.SubjectTransform).IsNull();
        await Assert.That(stream.Retention).IsEqualTo(NATS.Client.JetStream.Models.StreamConfigRetention.Limits);
        await Assert.That(stream.MaxConsumers).IsEqualTo(-1);
        await Assert.That(stream.MaxMsgs).IsEqualTo(-1);
        await Assert.That(stream.MaxMsgsPerSubject).IsEqualTo(2);
        await Assert.That(stream.MaxBytes).IsEqualTo(256 * 1024 * 1024);
        await Assert.That(stream.MaxAge).IsEqualTo(TimeSpan.Zero);
        await Assert.That(stream.MaxMsgSize).IsEqualTo(16 * 1024);
        await Assert.That(stream.Storage).IsEqualTo(NATS.Client.JetStream.Models.StreamConfigStorage.File);
        await Assert.That(stream.Compression).IsEqualTo(NATS.Client.JetStream.Models.StreamConfigCompression.None);
        await Assert.That(stream.NumReplicas).IsEqualTo(3);
        await Assert.That(stream.NoAck).IsFalse();
        await Assert.That(stream.TemplateOwner).IsNull();
        await Assert.That(stream.Discard).IsEqualTo(NATS.Client.JetStream.Models.StreamConfigDiscard.New);
        await Assert.That(stream.DuplicateWindow).IsEqualTo(TimeSpan.FromMinutes(2));
        await Assert.That(stream.Placement).IsNull();
        await Assert.That(stream.Sealed).IsFalse();
        await Assert.That(stream.DenyDelete).IsTrue();
        await Assert.That(stream.DenyPurge).IsTrue();
        await Assert.That(stream.AllowRollupHdrs).IsTrue();
        await Assert.That(stream.AllowDirect).IsTrue();
        await Assert.That(stream.Mirror).IsNull();
        await Assert.That(stream.Sources).IsNull();
        await Assert.That(stream.MirrorDirect).IsFalse();
        await Assert.That(stream.Republish).IsNull();
        await Assert.That(stream.DiscardNewPerSubject).IsFalse();
        await Assert.That(stream.AllowMsgTTL).IsFalse();
        await Assert.That(stream.SubjectDeleteMarkerTTL).IsEqualTo(TimeSpan.Zero);
        await Assert.That(stream.AllowMsgCounter).IsFalse();
        await Assert.That(stream.AllowMsgSchedules).IsFalse();
        await Assert.That(stream.AllowAtomicPublish).IsFalse();
        await Assert.That(stream.PersistMode).IsNull();
        await Assert.That(stream.Metadata).IsNull();
    }

    [Test]
    public async Task CredentialedDevelopmentControllerCannotDeleteOrPurgeOperationStream()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        var securityDirectory = Path.Combine(Path.GetTempPath(), $"ts-orch-nats-security-{Guid.NewGuid():N}");
        try
        {
            var topology = DevelopmentTopology.CreateRegional();
            var cell = topology.Cells.Single(candidate => candidate.Cell == "gru");
            var security = DevelopmentNatsSecurity.Create(topology, securityDirectory);
            var controller = security.Cell(cell.Cell).Controllers.Single().Value;
            await using var server = await OneNodeJetStream.StartAsync(
                NatsDevelopmentCluster.ControlAuthorization(cell, security.Cell(cell.Cell)),
                port => new NatsOpts
                {
                    Url = $"nats://127.0.0.1:{port}",
                    ConnectTimeout = TimeSpan.FromSeconds(1),
                    RequestTimeout = TimeSpan.FromSeconds(1),
                    AuthOpts = new NatsAuthOpts { NKeyFile = controller.SeedFile },
                });

            foreach (var subject in new[]
                     {
                         "$JS.API.STREAM.MSG.DELETE.KV_ORCH_OPERATIONS",
                         "$JS.API.STREAM.PURGE.KV_ORCH_OPERATIONS",
                     })
            {
                Func<Task> publish = async () =>
                    await server.RequestAsync(subject, "{}");
                await Assert.That(publish).Throws<NatsException>();
            }
        }
        finally
        {
            if (Directory.Exists(securityDirectory)) Directory.Delete(securityDirectory, recursive: true);
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

    private static NatsKVConfig Rf1Operations() => new("ORCH_OPERATIONS")
    {
        Description = "one-node RF1 evidence only",
        History = 2,
        MaxValueSize = 16 * 1024,
        MaxBytes = 256 * 1024 * 1024,
        NumberOfReplicas = 1,
    };

    private sealed class OneNodeJetStream : IAsyncDisposable
    {
        private readonly string directory;
        private readonly string configuration;
        private readonly int port;
        private readonly Func<int, NatsOpts>? clientOptions;
        private Process? process;
        private NatsClient? client;

        private OneNodeJetStream(
            string directory,
            string configuration,
            int port,
            Func<int, NatsOpts>? clientOptions)
        {
            this.directory = directory;
            this.configuration = configuration;
            this.port = port;
            this.clientOptions = clientOptions;
        }

        public static async Task<OneNodeJetStream> StartAsync(
            string? authorization = null,
            Func<int, NatsOpts>? clientOptions = null)
        {
            var directory = Path.Combine(Path.GetTempPath(), $"ts-orch-create-node-journal-{Guid.NewGuid():N}");
            Directory.CreateDirectory(directory);
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();
            var configuration = Path.Combine(directory, "nats.conf");
            await File.WriteAllTextAsync(configuration, $"port: {port}\n{authorization}\njetstream {{ store_dir: \"{Path.Combine(directory, "store")}\" }}\n");
            var server = new OneNodeJetStream(directory, configuration, port, clientOptions);
            await server.ConnectAsync();
            return server;
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

        public async Task RestartAsync()
        {
            if (client is not null) await client.DisposeAsync();
            client = null;
            if (process is not null)
            {
                process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync();
                process.Dispose();
                process = null;
            }
            await ConnectAsync();
        }

        public async ValueTask DisposeAsync()
        {
            if (client is not null) await client.DisposeAsync();
            if (process is not null)
            {
                if (!process.HasExited) process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync();
                process.Dispose();
            }
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }

        private async Task ConnectAsync()
        {
            process = Process.Start(new ProcessStartInfo("nats-server", $"-c {configuration}")
            {
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                UseShellExecute = false,
            }) ?? throw new InvalidOperationException("nats-server did not start.");
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
            throw new InvalidOperationException("nats-server did not accept a local JetStream connection.");
        }
    }
}
