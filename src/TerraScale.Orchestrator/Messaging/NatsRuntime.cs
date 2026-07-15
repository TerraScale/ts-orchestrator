using NATS.Client.Core;
using NATS.Client.JetStream;
using NATS.Client.KeyValueStore;
using NATS.Client.ObjectStore;
using NATS.Client.Services;
using NATS.Net;

namespace TerraScale.Orchestrator.Messaging;

public sealed class NatsRuntime : IAsyncDisposable
{
    private static readonly byte[] ProtocolPackage = """
        {"name":"terrascale-orchestrator","protocol":1}
        """u8.ToArray();

    private readonly NatsClient client;
    private readonly RuntimeRegistration registration;
    private readonly INatsSvcServer service;

    private NatsRuntime(NatsClient client, INatsSvcServer service, RuntimeRegistration registration)
    {
        this.client = client;
        this.service = service;
        this.registration = registration;
    }

    public static async Task<NatsRuntime> StartAsync(
        OrchestratorOptions options,
        CancellationToken cancellationToken)
    {
        var topology = new NatsTopology(options.Cell, options.Replicas);
        var client = new NatsClient(new NatsOpts
        {
            Url = options.NatsUrl,
            RetryOnInitialConnect = false
        });

        RuntimeRegistration? registration = null;
        try
        {
            await client.ConnectAsync();
            var state = await ReconcileStateAsync(client, topology, cancellationToken);
            await VerifyProtocolPackageAsync(state.Bundles, topology, cancellationToken);
            registration = await RuntimeRegistration.CreateAsync(state.Runtime, cancellationToken);
            await VerifyDurableMessagingAsync(client, state.StartupConsumer, topology, cancellationToken);

            var services = client.CreateServicesContext();
            var service = await services.AddServiceAsync(
                new NatsSvcConfig("terrascale_orchestrator", "1.0.0")
                {
                    Description = "TerraScale regional control service",
                    Metadata = new Dictionary<string, string> { ["cell"] = options.Cell }
                },
                cancellationToken);

            await service.AddEndpointAsync<string>(
                message => message.ReplyAsync("ready", cancellationToken: cancellationToken),
                name: "health",
                subject: topology.HealthSubject,
                cancellationToken: cancellationToken);

            var health = await client.RequestAsync<string, string>(
                topology.HealthSubject,
                "health",
                cancellationToken: cancellationToken);
            if (health.Data is not "ready")
            {
                throw new InvalidOperationException("NATS health service returned an invalid response.");
            }

            return new(client, service, registration);
        }
        catch
        {
            if (registration is not null)
            {
                await registration.DisposeAsync();
            }

            await client.DisposeAsync();
            throw;
        }
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            await service.DisposeAsync();
        }
        finally
        {
            try
            {
                await registration.DisposeAsync();
            }
            finally
            {
                await client.DisposeAsync();
            }
        }
    }

    private static async Task<RuntimeState> ReconcileStateAsync(
        NatsClient client,
        NatsTopology topology,
        CancellationToken cancellationToken)
    {
        var jetStream = client.CreateJetStreamContext();
        foreach (var stream in topology.Streams)
        {
            await jetStream.CreateOrUpdateStreamAsync(stream, cancellationToken);
        }

        var keyValue = jetStream.CreateKeyValueStoreContext();
        await keyValue.CreateOrUpdateStoreAsync(topology.Leaders, cancellationToken);
        var runtime = await keyValue.CreateOrUpdateStoreAsync(topology.Runtime, cancellationToken);

        var objects = jetStream.CreateObjectStoreContext();
        INatsObjStore bundles;
        try
        {
            bundles = await objects.GetObjectStoreAsync(topology.Bundles.Bucket, cancellationToken);
        }
        catch (NatsJSApiException exception) when (exception.Error.Code == 404)
        {
            bundles = await objects.CreateObjectStoreAsync(topology.Bundles, cancellationToken);
        }

        var startupConsumer = await jetStream.CreateOrUpdateConsumerAsync(
            "CELL_EVENTS",
            topology.StartupConsumer,
            cancellationToken);
        return new(startupConsumer, runtime, bundles);
    }

    private static async Task VerifyProtocolPackageAsync(
        INatsObjStore bundles,
        NatsTopology topology,
        CancellationToken cancellationToken)
    {
        await bundles.PutAsync(topology.ProtocolObject, ProtocolPackage, cancellationToken);
        var stored = await bundles.GetBytesAsync(topology.ProtocolObject, cancellationToken);
        if (!stored.AsSpan().SequenceEqual(ProtocolPackage))
        {
            throw new InvalidOperationException("NATS protocol package failed its integrity check.");
        }
    }

    private static async Task VerifyDurableMessagingAsync(
        NatsClient client,
        INatsJSConsumer consumer,
        NatsTopology topology,
        CancellationToken cancellationToken)
    {
        var eventId = Guid.NewGuid().ToString("N");
        var headers = new NatsHeaders
        {
            ["TS-Protocol-Version"] = "1",
            ["TS-Cell"] = topology.Cell,
            ["TS-Correlation-Id"] = eventId
        };
        var jetStream = client.CreateJetStreamContext();
        var acknowledgement = await jetStream.PublishAsync(
            topology.StartupSubject,
            eventId,
            opts: new NatsJSPubOpts
            {
                MsgId = eventId,
                ExpectedStream = "CELL_EVENTS",
                RetryAttempts = 3,
                RetryWaitBetweenAttempts = TimeSpan.FromMilliseconds(250)
            },
            headers: headers,
            cancellationToken: cancellationToken);
        acknowledgement.EnsureSuccess();

        var message = await consumer.NextAsync<string>(
            opts: new NatsJSNextOpts { Expires = TimeSpan.FromSeconds(5) },
            cancellationToken: cancellationToken)
            ?? throw new InvalidOperationException("Durable NATS startup event was not delivered.");

        if (string.IsNullOrWhiteSpace(message.Data) ||
            !HeaderEquals(message.Headers, "TS-Protocol-Version", "1") ||
            !HeaderEquals(message.Headers, "TS-Cell", topology.Cell) ||
            !HeaderEquals(message.Headers, "TS-Correlation-Id", message.Data))
        {
            throw new InvalidOperationException("Durable NATS startup event metadata was invalid.");
        }

        await message.AckAsync(cancellationToken: cancellationToken);
    }

    private static bool HeaderEquals(NatsHeaders? headers, string name, string expected) =>
        headers is not null &&
        headers.TryGetLastValue(name, out var value) &&
        string.Equals(value, expected, StringComparison.Ordinal);

    private sealed record RuntimeState(
        INatsJSConsumer StartupConsumer,
        INatsKVStore Runtime,
        INatsObjStore Bundles);

    private sealed class RuntimeRegistration : IAsyncDisposable
    {
        private readonly string key;
        private readonly INatsKVStore store;
        private ulong revision;

        private RuntimeRegistration(INatsKVStore store, string key, ulong revision)
        {
            this.store = store;
            this.key = key;
            this.revision = revision;
        }

        public static async Task<RuntimeRegistration> CreateAsync(
            INatsKVStore store,
            CancellationToken cancellationToken)
        {
            var key = $"instance.{Guid.NewGuid():N}";
            var revision = await store.CreateAsync(key, "starting", cancellationToken: cancellationToken);
            var registration = new RuntimeRegistration(store, key, revision);

            try
            {
                await using var watcher = store.WatchAsync<string>(key, cancellationToken: cancellationToken)
                    .GetAsyncEnumerator(cancellationToken);
                await registration.ExpectAsync(watcher, "starting", revision);

                revision = await store.UpdateAsync(key, "ready", revision, cancellationToken: cancellationToken);
                registration.revision = revision;
                await registration.ExpectAsync(watcher, "ready", revision);
                return registration;
            }
            catch
            {
                await registration.DisposeAsync();
                throw;
            }
        }

        public async ValueTask DisposeAsync()
        {
            await store.DeleteAsync(key, new NatsKVDeleteOpts { Revision = revision });
        }

        private async Task ExpectAsync(
            IAsyncEnumerator<NatsKVEntry<string>> watcher,
            string expectedValue,
            ulong expectedRevision)
        {
            if (!await watcher.MoveNextAsync())
            {
                throw new InvalidOperationException("NATS runtime registration watcher ended unexpectedly.");
            }

            var entry = watcher.Current;
            entry.EnsureSuccess();
            if (entry.Key != key || entry.Value != expectedValue || entry.Revision != expectedRevision)
            {
                throw new InvalidOperationException("NATS runtime registration watcher returned invalid state.");
            }
        }
    }
}
