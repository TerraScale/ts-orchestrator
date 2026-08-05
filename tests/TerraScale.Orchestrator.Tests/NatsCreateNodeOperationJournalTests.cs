using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using NATS.Client.Core;
using NATS.Client.JetStream;
using NATS.Client.KeyValueStore;
using NATS.Net;
using TerraScale.Orchestrator.ControlPlane.Operations;
using TerraScale.Orchestrator.ControlPlane.Providers;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

public sealed class NatsCreateNodeOperationJournalTests
{
    [Test]
    public async Task OneNodeJetStreamPersistsEncryptedCasJournalButDoesNotClaimR3()
    {
        await using var server = await OneNodeJetStream.StartAsync();
        var topology = new NatsTopology("journal", 1);
        var store = await server.OpenAsync(topology.Operations);
        using var invocationKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CreateNodeAuthoritativeInvocationCapabilitySigner("invocation", invocationKey);
        var oldKey = RandomNumberGenerator.GetBytes(32);
        var newKey = RandomNumberGenerator.GetBytes(32);
        var oldOnly = new CreateNodeJournalEncryptionKeyRing("old", new Dictionary<string, byte[]> { ["old"] = oldKey });
        var journal = new NatsCreateNodeOperationJournal(store, 3, oldOnly, signer);
        var prepared = Entry();

        await Assert.That(await journal.CompareExchangeAsync(null, prepared, default)).IsTrue();
        var beforeRestart = (await journal.ReadAsync(prepared.Binding.OperationId, default))!;
        await Assert.That(beforeRestart.Version).IsGreaterThan(0);

        await server.RestartAsync();
        store = await server.OpenAsync(topology.Operations);
        var rotated = new CreateNodeJournalEncryptionKeyRing("new", new Dictionary<string, byte[]>
        {
            ["old"] = oldKey,
            ["new"] = newKey,
        });
        journal = new NatsCreateNodeOperationJournal(store, 3, rotated, signer);
        var reloaded = (await journal.ReadAsync(prepared.Binding.OperationId, default))!;
        await Assert.That(reloaded.Version).IsEqualTo(beforeRestart.Version);
        var onlyNew = new CreateNodeJournalEncryptionKeyRing("new", new Dictionary<string, byte[]> { ["new"] = newKey });
        await Assert.That(() => new NatsCreateNodeOperationJournal(store, 3, onlyNew, signer)
                .ReadAsync(prepared.Binding.OperationId, default).AsTask())
            .Throws<InvalidDataException>();

        var started = Started(reloaded);
        await Assert.That(await journal.CompareExchangeAsync(reloaded, started, default)).IsTrue();
        var checkpoint = (await journal.ReadAsync(prepared.Binding.OperationId, default))!;

        var capability = await journal.MintInvocationCapabilityAsync(checkpoint, DateTimeOffset.UtcNow, default);
        var stale = capability with { JournalVersion = capability.JournalVersion + 1 };
        await Assert.That(await journal.TryConsumeInvocationCapabilityAsync(stale, checkpoint.Binding, DateTimeOffset.UtcNow, default)).IsFalse();
        var consumed = await Task.WhenAll(
            journal.TryConsumeInvocationCapabilityAsync(capability, checkpoint.Binding, DateTimeOffset.UtcNow, default).AsTask(),
            journal.TryConsumeInvocationCapabilityAsync(capability, checkpoint.Binding, DateTimeOffset.UtcNow, default).AsTask());
        await Assert.That(consumed.Count(result => result)).IsEqualTo(1);

        var encrypted = await store.GetEntryAsync<string>(OperationKey(prepared.Binding.OperationId));
        encrypted.EnsureSuccess();
        const string ciphertext = "\"Ciphertext\":\"";
        var offset = encrypted.Value!.IndexOf(ciphertext, StringComparison.Ordinal) + ciphertext.Length;
        var tampered = encrypted.Value[..offset] +
            (encrypted.Value[offset] == 'A' ? 'B' : 'A') + encrypted.Value[(offset + 1)..];
        await store.UpdateAsync(OperationKey(prepared.Binding.OperationId), tampered, encrypted.Revision);
        await Assert.That(() => journal.ReadAsync(prepared.Binding.OperationId, default).AsTask())
            .Throws<InvalidDataException>();
    }

    [Test]
    public async Task MutationRequiresR3AndHealthyInjectedKeyService()
    {
        await using var server = await OneNodeJetStream.StartAsync();
        var store = await server.OpenAsync(new NatsTopology("gate", 1).Operations);
        using var invocationKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CreateNodeAuthoritativeInvocationCapabilitySigner("invocation", invocationKey);
        var key = RandomNumberGenerator.GetBytes(32);

        await Assert.That(() => new NatsCreateNodeOperationJournal(store, 1,
                new CreateNodeJournalEncryptionKeyRing("key", new Dictionary<string, byte[]> { ["key"] = key }), signer))
            .Throws<InvalidOperationException>();
        var healthy = false;
        var journal = new NatsCreateNodeOperationJournal(store, 3,
            new CreateNodeJournalEncryptionKeyRing("key", new Dictionary<string, byte[]> { ["key"] = key }, () => healthy), signer);
        await Assert.That(() => journal.CompareExchangeAsync(null, Entry(), default).AsTask())
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task DedicatedOperationKvIsBoundedRetainedAndR3Configured()
    {
        var operations = new NatsTopology("gru", 3).Operations;

        await Assert.That(operations.Bucket).IsEqualTo("ORCH_OPERATIONS");
        await Assert.That(operations.NumberOfReplicas).IsEqualTo(3);
        await Assert.That(operations.History).IsEqualTo(2);
        await Assert.That(operations.MaxAge).IsEqualTo(TimeSpan.FromDays(7));
        await Assert.That(operations.MaxValueSize).IsEqualTo(16 * 1024);
        await Assert.That(operations.MaxBytes).IsEqualTo(256 * 1024 * 1024);
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

    private static CreateNodeOperationJournalEntry Started(CreateNodeOperationJournalEntry entry)
    {
        var now = DateTimeOffset.UtcNow;
        return entry with
        {
            Stage = CreateNodeJournalStage.ProviderCallStarted,
            ProviderCallStartedAt = now,
            ProviderAttempts = 1,
            InvocationLeaseOwner = "owner-1",
            InvocationLeaseToken = "token-1",
            InvocationCapabilityNonce = "nonce-1",
            InvocationLeaseExpiresAt = now.AddMinutes(1),
        };
    }

    private static string OperationKey(string operationId) => "operation." + Convert.ToHexStringLower(
        SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(operationId)));

    private sealed class OneNodeJetStream : IAsyncDisposable
    {
        private readonly string directory;
        private readonly string configuration;
        private readonly int port;
        private Process? process;
        private NatsClient? client;

        private OneNodeJetStream(string directory, string configuration, int port)
        {
            this.directory = directory;
            this.configuration = configuration;
            this.port = port;
        }

        public static async Task<OneNodeJetStream> StartAsync()
        {
            var directory = Path.Combine(Path.GetTempPath(), $"ts-orch-create-node-journal-{Guid.NewGuid():N}");
            Directory.CreateDirectory(directory);
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();
            var configuration = Path.Combine(directory, "nats.conf");
            await File.WriteAllTextAsync(configuration, $"port: {port}\njetstream {{ store_dir: \"{Path.Combine(directory, "store")}\" }}\n");
            var server = new OneNodeJetStream(directory, configuration, port);
            await server.ConnectAsync();
            return server;
        }

        public async Task<INatsKVStore> OpenAsync(NatsKVConfig configuration)
        {
            var jetStream = client!.CreateJetStreamContext();
            return await jetStream.CreateKeyValueStoreContext().CreateOrUpdateStoreAsync(configuration);
        }

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
                client = new NatsClient(new NatsOpts { Url = $"nats://127.0.0.1:{port}", ConnectTimeout = TimeSpan.FromSeconds(1) });
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
