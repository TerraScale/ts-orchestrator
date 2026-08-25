using NATS.Client.Core;
using NATS.Client.JetStream;
using NATS.Client.KeyValueStore;
using NATS.Client.ObjectStore;
using NATS.Client.Services;
using NATS.Net;
using System.Text;
using System.Text.Json;
using TerraScale.Orchestrator.Operations;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Protocol;

namespace TerraScale.Orchestrator.Messaging;

public sealed class NatsRuntime : IAsyncDisposable
{
    private readonly NatsClient client;
    private readonly RegionalRuntimeMembership membership;
    private readonly RegionalAuthorityCoordinator authority;
    private readonly INatsSvcServer service;
    private readonly INatsJSConsumer? cellSpecConsumer;
    private readonly INatsKVStore? delivery;
    private readonly INatsObjStore? bundles;
    private readonly NatsTopology topology;
    private readonly DirectDeliveryService? directDelivery;

    private NatsRuntime(
        NatsClient client,
        INatsSvcServer service,
        RegionalRuntimeMembership membership,
        RegionalAuthorityCoordinator authority,
        INatsJSConsumer? cellSpecConsumer,
        INatsKVStore? delivery,
        INatsObjStore? bundles,
        NatsTopology topology,
        DirectDeliveryService? directDelivery)
    {
        this.client = client;
        this.service = service;
        this.membership = membership;
        this.authority = authority;
        this.cellSpecConsumer = cellSpecConsumer;
        this.delivery = delivery;
        this.bundles = bundles;
        this.topology = topology;
        this.directDelivery = directDelivery;
    }

    public Task Completion => Task.WhenAny(authority.Completion, membership.Completion).Unwrap();
    internal RegionalAuthoritySnapshot AuthoritySnapshot => authority.Snapshot;
    internal RegionalRuntimeMembershipSnapshot MembershipSnapshot => membership.Snapshot;
    internal RegionalRuntimeMembershipHealth MembershipHealth => membership.Health;
    internal string Cell => topology.Cell;
    internal DirectDeliveryService? DirectDelivery => directDelivery;

    internal NativeGitOpsCellNatsConsumer CreateNativeGitOpsConsumer()
    {
        var ledger = new NatsForgejoDeliveryLedger(delivery
            ?? throw new InvalidOperationException("Native GitOps delivery storage is not configured."));
        var objects = new NatsDeliveryObjectStore(bundles
            ?? throw new InvalidOperationException("Native GitOps bundle storage is not configured."));
        return new NativeGitOpsCellNatsConsumer(
            cellSpecConsumer ?? throw new InvalidOperationException("Native GitOps consumer is not configured."),
            new NativeGitOpsCellInbox(new NativeGitOpsCellAcceptanceJournal(ledger, objects)),
            topology);
    }

    internal NativeGitOpsCellConvergenceJournal CreateNativeGitOpsConvergenceJournal() =>
        new(new NatsForgejoDeliveryLedger(delivery
            ?? throw new InvalidOperationException("Native GitOps delivery storage is not configured.")));

    internal NativeGitOpsCellPublisher CreateNativeGitOpsPublisher() =>
        new(new NatsNativeGitOpsCellTransport(client));

    public static async Task<NatsRuntime> StartAsync(
        OrchestratorOptions options,
        CancellationToken cancellationToken,
        Protocol.ICommandSignatureVerifier? commandSignatureVerifier = null,
        Delivery.DirectDeliveryDeploymentMode deploymentMode = Delivery.DirectDeliveryDeploymentMode.Development,
        bool registersDirectDeliveryEndpoint = true,
        DirectDeliveryAdmittedTargets? admittedDeliveryTargets = null,
        Protocol.ICommandSignatureVerifier? ciArtifactSignatures = null)
    {
        if (options.Command is not (OrchestratorCommand.Run or OrchestratorCommand.Check))
            throw new InvalidOperationException("Only controller run/check roles can start the regional controller runtime.");
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
                AuthOpts = new NatsAuthOpts { NKeyFile = options.NatsNKeyFile },
                InboxPrefix = $"ts.orch.v1.{options.Cell}.internal.reply.{NatsCredentialFile.PublicKey(options.NatsNKeyFile)}"
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

        RegionalRuntimeMembership? membership = null;
        RegionalAuthorityCoordinator? authority = null;
        try
        {
            await client.ConnectAsync();
            if (options.NatsNKeyFile is not null || options.NatsTls is not null)
            {
                await VerifyAnonymousDeniedAsync(options.NatsUrl, options.NatsTls, cancellationToken);
            }
            var nativeGitOpsEnabled = NativeGitOpsRuntime.IsEnabled(
                options.GlobalNats is not null &&
                    GlobalNatsConfiguration.IsLegacyAuthorityAliasAllowed(options.Cell),
                options.CommandIdentity?.TrustKeyFiles.Count > 0);
            var state = await OpenStateWithRetryAsync(
                client, topology, nativeGitOpsEnabled, cancellationToken);
            await VerifyProtocolPackageAsync(state.ProtocolPackage, topology, cancellationToken);
            await VerifyDurableMessagingAsync(client, state.StartupConsumer, topology, cancellationToken);
            authority = await RegionalAuthorityCoordinator.StartAsync(
                state.Leaders,
                options.Cell,
                options.Instance,
                cancellationToken);

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
                "regional-membership",
                "runtime",
                "scheduler",
                "security",
                "service-discovery",
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
            membership = await RegionalRuntimeMembership.StartAsync(
                state.Runtime,
                topology,
                BuildVersion.Current.DisplayName,
                capabilities,
                startedAt,
                () => authority.Snapshot,
                cancellationToken);

            DirectDeliveryService? directDelivery = null;
            if (state.Delivery is not null)
            {
                var ledger = new NatsForgejoDeliveryLedger(state.Delivery);
                // Production mode fails closed here without the evidence verifier or the
                // configured admitted-target allow-list, mirroring the signed-command rule.
                // The evidence verifier is the CI artifact role's trust root, supplied
                // explicitly by composition; this runtime performs no fallback of its own —
                // a composition that wants the shared command identity for development
                // passes it explicitly, and production never does.
                var adapters = DirectDeliveryRuntimeAdapterSet.Create(
                    ledger,
                    deploymentMode,
                    () => authority.Snapshot.Ready && authority.Snapshot.IsLeader,
                    request =>
                    {
                        var current = authority.Snapshot;
                        return current.Ready && current.IsLeader &&
                            current.KvRevision == request.AuthorityGeneration &&
                            current.Epoch == request.WriterEpoch;
                    },
                    admittedDeliveryTargets,
                    ciArtifactSignatures as IRepositoryCiArtifactSignatureVerifier);
                directDelivery = new DirectDeliveryService(
                    adapters.Authorizer,
                    adapters.Provenance,
                    adapters.TargetResolver,
                    adapters.Journal,
                    adapters.ArtifactBuilder,
                    auditIdFactory: static () => $"audit-{Guid.NewGuid():N}",
                    authorityIsCurrent: request =>
                    {
                        var current = authority.Snapshot;
                        return current.Ready && current.IsLeader &&
                            current.KvRevision == request.AuthorityGeneration &&
                            current.Epoch == request.WriterEpoch;
                    });
            }

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

            if (directDelivery is not null)
            {
                // The direct-delivery mutation endpoint is only as strong as its admission seam:
                // fail closed at startup in run mode without a signed-command verifier instead of
                // ever accepting an unsigned production mutation. The startup plan owns the
                // decision (Run-only); this runtime never re-derives it from options.
                if (registersDirectDeliveryEndpoint && commandSignatureVerifier is null)
                    throw new InvalidOperationException(
                        "The direct delivery mutation endpoint requires a configured command identity verifier.");
                if (registersDirectDeliveryEndpoint && commandSignatureVerifier is not null)
                {
                    var handoffDelivery = new TerraScale.Orchestrator.Delivery.DeployHandoff.DeployHandoffDeliveryRuntime(directDelivery);
                    await service.AddEndpointAsync<string>(
                        async message =>
                        {
                            // Exactly two payload kinds are admitted behind the one signed seam:
                            // the canonical DeliveryRequest and the Deploy handoff manifest. The
                            // runtime binds a handoff execution to the live authority lease it
                            // owns; a direct request carries and is fenced by its own claims.
                            var lease = authority.Snapshot;
                            var admission = DirectDeliveryCommandIngress.Decode(
                                Encoding.UTF8.GetBytes(message.Data ?? string.Empty),
                                Flatten(message.Headers),
                                options.Cell,
                                DateTimeOffset.UtcNow,
                                TimeSpan.FromMinutes(5),
                                commandSignatureVerifier,
                                lease.KvRevision,
                                lease.Epoch);
                            var receipt = admission.Kind switch
                            {
                                DirectDeliveryCommandPayloadKind.DeliveryRequest when admission.Request is { } request =>
                                    await directDelivery.DeliverAsync(request, cancellationToken)
                                        .ConfigureAwait(false),
                                DirectDeliveryCommandPayloadKind.DeployHandoffManifest when admission.Handoff is
                                    { IsAdmittedForTargetMutation: true } mapping =>
                                    await handoffDelivery.DeliverMappedAsync(
                                        mapping, lease.KvRevision, lease.Epoch, admission.Attempt, cancellationToken)
                                        .ConfigureAwait(false),
                                _ => DirectDeliveryCommandIngress.RefusalReceipt(admission),
                            };
                            await message.ReplyAsync(
                                DeliveryWireCodec.SerializeReceipt(receipt),
                                cancellationToken: cancellationToken).ConfigureAwait(false);
                        },
                        name: "direct_delivery",
                        subject: topology.DirectDeliverySubject,
                        metadata: new Dictionary<string, string>
                        {
                            ["protocol"] = DeliveryRequest.CurrentSchemaVersion.ToString(),
                            ["mutation"] = "direct",
                            ["admission"] = "signed-envelope",
                        },
                        cancellationToken: cancellationToken);
                }
            }

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

            await service.AddEndpointAsync<string>(
                message => message.ReplyAsync(
                    JsonSerializer.Serialize(
                        membership.Snapshot,
                        RegionalRuntimeMembershipJsonContext.Default.RegionalRuntimeMembershipSnapshot),
                    cancellationToken: cancellationToken),
                name: "members",
                subject: topology.MembersSubject,
                metadata: new Dictionary<string, string>
                {
                    ["protocol"] = "1",
                    ["readOnly"] = "true",
                    ["source"] = topology.Runtime.Bucket
                },
                cancellationToken: cancellationToken);

            await VerifyServiceAsync(client, topology, cancellationToken);

            return new(
                client,
                service,
                membership,
                authority,
                state.CellSpecConsumer,
                state.Delivery,
                state.Bundles,
                topology,
                directDelivery);
        }
        catch
        {
            if (authority is not null)
            {
                await authority.DisposeAsync();
            }
            if (membership is not null)
            {
                await membership.DisposeAsync();
            }
            await client.DisposeAsync();
            throw;
        }
    }

    private static async Task<RuntimeState> OpenStateWithRetryAsync(
        NatsClient client,
        NatsTopology topology,
        bool nativeGitOpsEnabled,
        CancellationToken cancellationToken)
    {
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                return await OpenStateAsync(client, topology, nativeGitOpsEnabled, cancellationToken);
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
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                await VerifyServiceOnceAsync(client, topology, cancellationToken);
                return;
            }
            catch (Exception exception) when (attempt < 5 &&
                (exception is NatsNoReplyException ||
                 exception is InvalidOperationException { Message: "NATS health service returned an invalid response." }))
            {
                await Task.Delay(TimeSpan.FromMilliseconds(100 * attempt), cancellationToken);
            }
        }
    }

    private static async Task VerifyServiceOnceAsync(
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

        var membersResponse = await client.RequestAsync<string, string>(
            topology.MembersSubject,
            "members",
            cancellationToken: cancellationToken);
        var members = JsonSerializer.Deserialize(
            membersResponse.Data ?? throw new InvalidOperationException("NATS membership service returned no response."),
            RegionalRuntimeMembershipJsonContext.Default.RegionalRuntimeMembershipSnapshot)
            ?? throw new InvalidOperationException("NATS membership service returned no response.");
        members.Validate(topology.Cell);
    }

    private static bool HasExpectedEndpoint(
        string? response,
        NatsTopology topology)
    {
        if (string.IsNullOrWhiteSpace(response))
        {
            return false;
        }

        var root = JsonElement.Parse(response);
        if (!root.TryGetProperty("name", out var name) || name.GetString() != topology.ServiceName ||
            !root.TryGetProperty("endpoints", out var endpoints))
        {
            return false;
        }

        var discovered = endpoints.EnumerateArray().ToArray();
        var hasHealth = discovered.Any(endpoint =>
            endpoint.TryGetProperty("name", out var endpointName) && endpointName.GetString() == "health" &&
            endpoint.TryGetProperty("subject", out var subject) && subject.GetString() == topology.HealthSubject &&
            endpoint.TryGetProperty("queue_group", out var queue) && queue.GetString() == topology.ServiceQueueGroup);
        var hasMembers = discovered.Any(endpoint =>
            endpoint.TryGetProperty("name", out var endpointName) && endpointName.GetString() == "members" &&
            endpoint.TryGetProperty("subject", out var subject) && subject.GetString() == topology.MembersSubject &&
            endpoint.TryGetProperty("queue_group", out var queue) && queue.GetString() == topology.ServiceQueueGroup);
        return hasHealth && hasMembers;
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
                    await membership.DisposeAsync();
                }
                finally
                {
                    await client.DisposeAsync();
                }
            }
        }
    }

    private static async Task<RuntimeState> OpenStateAsync(
        NatsClient client,
        NatsTopology topology,
        bool nativeGitOpsEnabled,
        CancellationToken cancellationToken)
    {
        var jetStream = client.CreateJetStreamContext();
        foreach (var expected in topology.Streams)
        {
            if (expected.Name is not { } streamName)
                throw new InvalidOperationException("The infrastructure-provisioned NATS stream has no name.");
            var stream = await jetStream.GetStreamAsync(streamName, cancellationToken: cancellationToken);
            NatsOperationJournalStore.ValidateExactStreamConfiguration(stream.Info.Config, expected);
        }

        var keyValue = jetStream.CreateKeyValueStoreContext();
        var leaders = await OpenKeyValueAsync(keyValue, topology.Leaders, cancellationToken);
        var runtime = await OpenKeyValueAsync(keyValue, topology.Runtime, cancellationToken);
        var objects = jetStream.CreateObjectStoreContext();
        var protocolPackage = await objects.GetObjectStoreAsync(topology.ProtocolPackage.Bucket, cancellationToken);
        NatsOperationJournalStore.ValidateExactObjectConfiguration(
            (await protocolPackage.GetStatusAsync(cancellationToken)).Info.Config, topology.ProtocolPackage);

        var startupConsumer = await OpenExactConsumerAsync(
            jetStream, "CELL_EVENTS", topology.StartupConsumer, cancellationToken);
        INatsKVStore? delivery = null;
        INatsObjStore? bundles = null;
        INatsJSConsumer? cellSpecConsumer = null;
        delivery = await OpenKeyValueAsync(keyValue, topology.Delivery, cancellationToken);
        if (nativeGitOpsEnabled)
        {
            bundles = await objects.GetObjectStoreAsync(topology.Bundles.Bucket, cancellationToken);
            NatsOperationJournalStore.ValidateExactObjectConfiguration(
                (await bundles.GetStatusAsync(cancellationToken)).Info.Config, topology.Bundles);
            cellSpecConsumer = await OpenExactConsumerAsync(
                jetStream, "CELL_SPEC", topology.CellSpecConsumer, cancellationToken);
        }
        return new(startupConsumer, cellSpecConsumer, leaders, runtime, delivery, bundles, protocolPackage);
    }

    private static async Task<INatsKVStore> OpenKeyValueAsync(
        INatsKVContext keyValue,
        NatsKVConfig expected,
        CancellationToken cancellationToken)
    {
        var store = await keyValue.GetStoreAsync(expected.Bucket, cancellationToken);
        NatsOperationJournalStore.ValidatePlainTopologyKeyValueConfiguration(
            (await store.GetStatusAsync(cancellationToken)).Info.Config,
            expected);
        return store;
    }

    private static async Task<INatsJSConsumer> OpenExactConsumerAsync(
        INatsJSContext jetStream,
        string stream,
        NATS.Client.JetStream.Models.ConsumerConfig expected,
        CancellationToken cancellationToken)
    {
        if (expected.Name is not { } consumerName)
            throw new InvalidOperationException("The infrastructure-provisioned NATS consumer has no name.");
        var consumer = await jetStream.GetConsumerAsync(stream, consumerName, cancellationToken);
        await consumer.RefreshAsync(cancellationToken);
        if (!CiRunnerConsumerReconciler.Matches(consumer.Info, expected, stream))
            throw new InvalidOperationException("The infrastructure-provisioned NATS consumer does not match its closed profile.");
        return consumer;
    }

    private static async Task VerifyProtocolPackageAsync(
        INatsObjStore bundles,
        NatsTopology topology,
        CancellationToken cancellationToken)
    {
        var stored = await bundles.GetBytesAsync(topology.ProtocolObject, cancellationToken);
        if (!stored.AsSpan().SequenceEqual(NatsProtocolPackage.Bytes))
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

        // NextAsync creates a new reply subscription per pull. With an R3 consumer,
        // its leader can deliver before interest for that reply subject has converged
        // to the leader. Keep one subscription and allow its pull loop to recover
        // from that transient reply loss; the five-second verification bound and
        // the acknowledgement and metadata checks remain unchanged.
        using var deliveryTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deliveryTimeout.CancelAfter(TimeSpan.FromSeconds(5));
        await using var deliveries = consumer.ConsumeAsync<string>(
                opts: new NatsJSConsumeOpts
                {
                    MaxMsgs = 1,
                    Expires = TimeSpan.FromSeconds(1)
                },
                cancellationToken: deliveryTimeout.Token)
            .GetAsyncEnumerator(deliveryTimeout.Token);
        INatsJSMsg<string>? message;
        try
        {
            message = await deliveries.MoveNextAsync()
                ? deliveries.Current
                : null;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            message = null;
        }

        if (message is null)
        {
            throw new InvalidOperationException("Durable NATS startup event was not delivered.");
        }

        // PublishAsync already proved this runtime's event is durable. The canonical
        // consumer is intentionally shared by all controllers, so requiring this
        // pull to return eventId could steal a peer's event and leave both runtimes
        // waiting for redelivery. A self-consistent event for this cell instead
        // proves the shared delivery-and-ack path without changing its ownership.
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

    private static List<KeyValuePair<string, string>> Flatten(NatsHeaders? headers)
    {
        var flattened = new List<KeyValuePair<string, string>>();
        if (headers is null) return flattened;
        foreach (var (key, values) in headers)
        foreach (var value in values)
            flattened.Add(new KeyValuePair<string, string>(key, value ?? string.Empty));
        return flattened;
    }

    private sealed record RuntimeState(
        INatsJSConsumer StartupConsumer,
        INatsJSConsumer? CellSpecConsumer,
        INatsKVStore Leaders,
        INatsKVStore Runtime,
        INatsKVStore? Delivery,
        INatsObjStore? Bundles,
        INatsObjStore ProtocolPackage);

}
