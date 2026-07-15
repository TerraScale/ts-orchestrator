using NATS.Client.Core;
using NATS.Client.JetStream;
using NATS.Client.ObjectStore;
using NATS.Client.Services;
using NATS.Net;

namespace TerraScale.Orchestrator.Messaging;

public sealed class NatsRuntime : IAsyncDisposable
{
    private readonly NatsClient client;
    private readonly INatsSvcServer service;

    private NatsRuntime(NatsClient client, INatsSvcServer service)
    {
        this.client = client;
        this.service = service;
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

        try
        {
            await client.ConnectAsync();
            var startupConsumer = await ReconcileStateAsync(client, topology, cancellationToken);
            await VerifyDurableMessagingAsync(client, startupConsumer, topology, cancellationToken);

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

            return new(client, service);
        }
        catch
        {
            await client.DisposeAsync();
            throw;
        }
    }

    public async ValueTask DisposeAsync()
    {
        await service.DisposeAsync();
        await client.DisposeAsync();
    }

    private static async Task<INatsJSConsumer> ReconcileStateAsync(
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

        var objects = jetStream.CreateObjectStoreContext();
        try
        {
            await objects.GetObjectStoreAsync(topology.Bundles.Bucket, cancellationToken);
        }
        catch (NatsJSApiException exception) when (exception.Error.Code == 404)
        {
            await objects.CreateObjectStoreAsync(topology.Bundles, cancellationToken);
        }

        return await jetStream.CreateOrUpdateConsumerAsync(
            "CELL_EVENTS",
            topology.StartupConsumer,
            cancellationToken);
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
}
