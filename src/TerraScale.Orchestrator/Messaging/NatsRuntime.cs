using NATS.Client.Core;
using NATS.Client.JetStream;
using NATS.Client.KeyValueStore;
using NATS.Client.ObjectStore;
using NATS.Client.Services;
using NATS.Net;
using System.Text.Json;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Operations;

namespace TerraScale.Orchestrator.Messaging;

public sealed class NatsRuntime : IAsyncDisposable
{
    private static readonly byte[] ProtocolPackage = """
        {"name":"terrascale-orchestrator","protocol":1}
        """u8.ToArray();

    private readonly NatsClient client;
    private readonly RuntimeRegistration registration;
    private readonly RegionalAuthorityCoordinator authority;
    private readonly INatsSvcServer service;

    private NatsRuntime(
        NatsClient client,
        INatsSvcServer service,
        RuntimeRegistration registration,
        RegionalAuthorityCoordinator authority,
        NativeGitOpsCellAcceptanceJournal nativeGitOpsCellAcceptances)
    {
        this.client = client;
        this.service = service;
        this.registration = registration;
        this.authority = authority;
        NativeGitOpsCellAcceptances = nativeGitOpsCellAcceptances;
    }

    public Task Completion => authority.Completion;
    internal NativeGitOpsCellAcceptanceJournal NativeGitOpsCellAcceptances { get; }
    internal RegionalAuthoritySnapshot AuthoritySnapshot => authority.Snapshot;

    public static async Task<NatsRuntime> StartAsync(
        OrchestratorOptions options,
        CancellationToken cancellationToken)
    {
        var topology = new NatsTopology(options.Cell, options.Replicas, options.Instance);
        var clientOptions = new NatsOpts
        {
            Url = options.NatsUrl,
            RetryOnInitialConnect = true,
            RequestTimeout = TimeSpan.FromSeconds(15)
        };
        if (options.NatsNKeyFile is not null)
        {
            clientOptions = clientOptions with
            {
                AuthOpts = new NatsAuthOpts { NKeyFile = options.NatsNKeyFile }
            };
        }
        if (options.NatsTls is not null)
        {
            clientOptions = clientOptions with
            {
                TlsOpts = new NatsTlsOpts
                {
                    Mode = TlsMode.Require,
                    CaFile = options.NatsTls.CaFile,
                    CertFile = options.NatsTls.CertificateFile,
                    KeyFile = options.NatsTls.KeyFile
                }
            };
        }
        var client = new NatsClient(clientOptions);

        RuntimeRegistration? registration = null;
        RegionalAuthorityCoordinator? authority = null;
        try
        {
            await client.ConnectAsync();
            if (options.NatsNKeyFile is not null || options.NatsTls is not null)
            {
                await VerifyAnonymousDeniedAsync(options.NatsUrl, options.NatsTls, cancellationToken);
            }
            var state = await ReconcileStateWithRetryAsync(client, topology, cancellationToken);
            await VerifyProtocolPackageAsync(state.Bundles, topology, cancellationToken);
            registration = await RuntimeRegistration.CreateAsync(state.Runtime, cancellationToken);
            await VerifyDurableMessagingAsync(client, state.StartupConsumer, topology, cancellationToken);
            authority = await RegionalAuthorityCoordinator.StartAsync(
                state.Leaders,
                options.Cell,
                options.Instance,
                cancellationToken);

            var services = client.CreateServicesContext();
            var service = await services.AddServiceAsync(
                new NatsSvcConfig(topology.ServiceName, "1.0.0")
                {
                    Description = "TerraScale regional control service",
                    Metadata = new Dictionary<string, string>
                    {
                        ["cell"] = options.Cell,
                        ["instance"] = options.Instance
                    },
                    QueueGroup = topology.ServiceQueueGroup
                },
                cancellationToken);

            await service.AddEndpointAsync<string>(
                message => message.ReplyAsync(
                    authority.Snapshot.Ready ? "ready" : "not-ready",
                    cancellationToken: cancellationToken),
                name: "health",
                subject: topology.HealthSubject,
                metadata: new Dictionary<string, string> { ["protocol"] = "1" },
                cancellationToken: cancellationToken);

            await service.AddEndpointAsync<string>(
                message => message.ReplyAsync(
                    authority.Snapshot.Ready ? "ready" : "not-ready",
                    cancellationToken: cancellationToken),
                name: "instance_health",
                subject: topology.InstanceHealthSubject,
                metadata: new Dictionary<string, string>
                {
                    ["protocol"] = "1",
                    ["instance"] = options.Instance
                },
                cancellationToken: cancellationToken);

            var startedAt = DateTimeOffset.UtcNow;
            var capabilities = new List<string>
            {
                "authority",
                "authority-election",
                "delivery",
                "messaging",
                "observability",
                "operator-read",
                "provider-ownership",
                "reconciliation",
                "runtime",
                "scheduler",
                "security",
                "storage",
                "terrabase"
            };
            if (options.NatsNKeyFile is not null)
            {
                capabilities.Add("nats-nkey-authenticated");
            }
            if (options.NatsTls is not null)
            {
                capabilities.Add("nats-mtls");
            }
            capabilities.Sort(StringComparer.Ordinal);
            await service.AddEndpointAsync<string>(
                message =>
                {
                    var authoritySnapshot = authority.Snapshot;
                    return message.ReplyAsync(
                        JsonSerializer.Serialize(
                            new RegionalControllerStatus(
                                2,
                                options.Cell,
                                options.Instance,
                                options.Replicas,
                                authoritySnapshot.Ready,
                                startedAt,
                                DateTimeOffset.UtcNow,
                                BuildVersion.Current.DisplayName,
                                capabilities,
                                authoritySnapshot.State,
                                authoritySnapshot.IsLeader,
                                authoritySnapshot.Epoch,
                                authoritySnapshot.KvRevision,
                                authoritySnapshot.LeaseExpiresAt),
                            RegionalControllerStatusJsonContext.Default.RegionalControllerStatus),
                        cancellationToken: cancellationToken);
                },
                name: "status",
                subject: topology.StatusSubject,
                metadata: new Dictionary<string, string> { ["protocol"] = "1", ["readOnly"] = "true" },
                cancellationToken: cancellationToken);

            await VerifyServiceAsync(client, topology, cancellationToken);

            var deliveryLedger = new NatsForgejoDeliveryLedger(state.Delivery);
            var bundles = new NatsDeliveryObjectStore(state.Bundles);
            return new(
                client,
                service,
                registration,
                authority,
                new(deliveryLedger, bundles));
        }
        catch
        {
            if (authority is not null)
            {
                await authority.DisposeAsync();
            }
            if (registration is not null)
            {
                await registration.DisposeAsync();
            }

            await client.DisposeAsync();
            throw;
        }
    }

    private static async Task<RuntimeState> ReconcileStateWithRetryAsync(
        NatsClient client,
        NatsTopology topology,
        CancellationToken cancellationToken)
    {
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                return await ReconcileStateAsync(client, topology, cancellationToken);
            }
            catch (Exception exception) when (
                attempt < 5 &&
                exception is NatsJSApiNoResponseException or NatsJSTimeoutException or NatsJSConnectionException)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(500 * attempt), cancellationToken);
            }
        }
    }

    internal static async Task VerifyAnonymousDeniedAsync(
        string url,
        NatsTlsFiles? tls,
        CancellationToken cancellationToken)
    {
        var options = new NatsOpts
        {
            Url = url,
            RetryOnInitialConnect = false,
            ConnectTimeout = TimeSpan.FromSeconds(3),
            RequestTimeout = TimeSpan.FromSeconds(3)
        };
        if (tls is not null)
            options = options with
            {
                TlsOpts = new NatsTlsOpts
                {
                    Mode = TlsMode.Require,
                    CaFile = tls.CaFile,
                    CertFile = tls.CertificateFile,
                    KeyFile = tls.KeyFile,
                },
            };
        await using var anonymous = new NatsClient(options);
        try
        {
            await anonymous.ConnectAsync();
        }
        catch (NatsException)
        {
            return;
        }
        throw new InvalidOperationException(
            "Control NATS accepted an anonymous client while NKey authentication was required.");
    }

    private static async Task VerifyServiceAsync(
        NatsClient client,
        NatsTopology topology,
        CancellationToken cancellationToken)
    {
        var health = await client.RequestAsync<string, string>(
            topology.InstanceHealthSubject,
            "health",
            cancellationToken: cancellationToken);
        if (health.Data is not "ready")
        {
            throw new InvalidOperationException("NATS health service returned an invalid response.");
        }

        var info = await client.RequestAsync<string, string>(
            $"$SRV.INFO.{topology.ServiceName}",
            string.Empty,
            cancellationToken: cancellationToken);
        if (!HasExpectedEndpoint(info.Data, topology))
        {
            throw new InvalidOperationException("NATS service discovery returned invalid endpoint metadata.");
        }

        var statusResponse = await client.RequestAsync<string, string>(
            topology.StatusSubject,
            "status",
            cancellationToken: cancellationToken);
        var status = JsonSerializer.Deserialize(
            statusResponse.Data ?? throw new InvalidOperationException("NATS status service returned no response."),
            RegionalControllerStatusJsonContext.Default.RegionalControllerStatus)
            ?? throw new InvalidOperationException("NATS status service returned no response.");
        status.Validate(topology.Cell);
    }

    private static bool HasExpectedEndpoint(
        string? response,
        NatsTopology topology)
    {
        if (string.IsNullOrWhiteSpace(response))
        {
            return false;
        }

        using var document = JsonDocument.Parse(response);
        var root = document.RootElement;
        if (!root.TryGetProperty("name", out var name) || name.GetString() != topology.ServiceName ||
            !root.TryGetProperty("endpoints", out var endpoints))
        {
            return false;
        }

        return endpoints.EnumerateArray().Any(endpoint =>
            endpoint.TryGetProperty("name", out var endpointName) && endpointName.GetString() == "health" &&
            endpoint.TryGetProperty("subject", out var subject) && subject.GetString() == topology.HealthSubject &&
            endpoint.TryGetProperty("queue_group", out var queue) && queue.GetString() == topology.ServiceQueueGroup);
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
                await authority.DisposeAsync();
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
        var leaders = await keyValue.CreateOrUpdateStoreAsync(topology.Leaders, cancellationToken);
        var runtime = await keyValue.CreateOrUpdateStoreAsync(topology.Runtime, cancellationToken);
        var delivery = await keyValue.CreateOrUpdateStoreAsync(topology.Delivery, cancellationToken);

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
        return new(startupConsumer, leaders, runtime, delivery, bundles);
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
        INatsKVStore Leaders,
        INatsKVStore Runtime,
        INatsKVStore Delivery,
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
