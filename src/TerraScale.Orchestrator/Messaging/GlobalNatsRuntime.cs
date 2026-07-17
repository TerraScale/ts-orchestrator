using NATS.Client.Core;
using NATS.Client.JetStream;
using NATS.Client.KeyValueStore;
using NATS.Client.ObjectStore;
using NATS.Net;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Messaging;

internal sealed class GlobalNatsRuntime : IAsyncDisposable
{
    private readonly NatsClient client;
    private readonly RegionalAuthorityCoordinator authority;
    private readonly ForgejoCiEventConsumer ciEvents;

    private GlobalNatsRuntime(
        NatsClient client,
        RegionalAuthorityCoordinator authority,
        ForgejoCiEventConsumer ciEvents,
        ForgejoWebhookJournal forgejoWebhooks,
        ForgejoSourceJournal forgejoSources,
        NativeGitOpsSourceJournal nativeGitOpsSources,
        RepositoryCiPromotionJournal promotions,
        RepositoryCiCandidateJournal candidates)
    {
        this.client = client;
        this.authority = authority;
        this.ciEvents = ciEvents;
        ForgejoWebhooks = forgejoWebhooks;
        ForgejoSources = forgejoSources;
        NativeGitOpsSources = nativeGitOpsSources;
        Promotions = promotions;
        Candidates = candidates;
    }

    public Task Completion => Task.WhenAny(authority.Completion, ciEvents.Completion).Unwrap();
    public ForgejoWebhookJournal ForgejoWebhooks { get; }
    public ForgejoSourceJournal ForgejoSources { get; }
    public NativeGitOpsSourceJournal NativeGitOpsSources { get; }
    public RepositoryCiPromotionJournal Promotions { get; }
    public RepositoryCiCandidateJournal Candidates { get; }
    public RegionalAuthoritySnapshot AuthoritySnapshot => authority.Snapshot;

    public static async Task<GlobalNatsRuntime> StartAsync(
        GlobalNatsConfiguration configuration,
        string instance,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        var topology = new GlobalNatsTopology(3);
        var client = new NatsClient(new NatsOpts
        {
            Url = configuration.Url,
            RetryOnInitialConnect = true,
            RequestTimeout = TimeSpan.FromSeconds(15),
            AuthOpts = new NatsAuthOpts { NKeyFile = configuration.NKeyFile },
            TlsOpts = new NatsTlsOpts
            {
                Mode = TlsMode.Require,
                CaFile = configuration.Tls.CaFile,
                CertFile = configuration.Tls.CertificateFile,
                KeyFile = configuration.Tls.KeyFile,
            },
        });

        RegionalAuthorityCoordinator? authority = null;
        try
        {
            await client.ConnectAsync();
            await NatsRuntime.VerifyAnonymousDeniedAsync(configuration.Url, configuration.Tls, cancellationToken);
            var state = await ReconcileStateWithRetryAsync(client, topology, cancellationToken);
            authority = await RegionalAuthorityCoordinator.StartGlobalAsync(
                state.Leaders,
                instance,
                cancellationToken);
            if (!authority.Snapshot.Ready)
                throw new InvalidOperationException("Global authority did not reach a ready leader or follower state.");
            var ledger = new NatsForgejoDeliveryLedger(state.Releases);
            var objects = new NatsNativeGitOpsManifestStore(state.Bundles);
            var triggerJournal = new ForgejoCiTriggerJournal(ledger);
            var ciEvents = ForgejoCiEventConsumer.Start(
                state.CiConsumer,
                new(triggerJournal, () => authority.Snapshot),
                () => authority.Snapshot);
            return new(
                client,
                authority,
                ciEvents,
                new(ledger, new NatsForgejoEventPublisher(client)),
                new(ledger),
                new(ledger, objects),
                new(ledger),
                new(ledger, objects));
        }
        catch
        {
            if (authority is not null) await authority.DisposeAsync();
            await client.DisposeAsync();
            throw;
        }
    }

    private static async Task<GlobalState> ReconcileStateWithRetryAsync(
        NatsClient client,
        GlobalNatsTopology topology,
        CancellationToken cancellationToken)
    {
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                var jetStream = client.CreateJetStreamContext();
                foreach (var stream in topology.Streams)
                    await jetStream.CreateOrUpdateStreamAsync(stream, cancellationToken);
                var keyValue = jetStream.CreateKeyValueStoreContext();
                var leaders = await keyValue.CreateOrUpdateStoreAsync(topology.Leaders, cancellationToken);
                var releases = await keyValue.CreateOrUpdateStoreAsync(topology.Releases, cancellationToken);
                var objectStore = jetStream.CreateObjectStoreContext();
                INatsObjStore bundles;
                try
                {
                    bundles = await objectStore.GetObjectStoreAsync(topology.Bundles.Bucket, cancellationToken);
                }
                catch (NatsJSApiException exception) when (exception.Error.Code == 404)
                {
                    bundles = await objectStore.CreateObjectStoreAsync(topology.Bundles, cancellationToken);
                }
                var ciConsumer = await jetStream.CreateOrUpdateConsumerAsync(
                    GlobalNatsTopology.CiStream,
                    topology.CiConsumer,
                    cancellationToken);
                return new(leaders, releases, bundles, ciConsumer);
            }
            catch (Exception exception) when (
                attempt < 5 &&
                exception is NatsJSApiNoResponseException or NatsJSTimeoutException or NatsJSConnectionException)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(500 * attempt), cancellationToken);
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            await ciEvents.DisposeAsync();
        }
        finally
        {
            try
            {
                await authority.DisposeAsync();
            }
            finally
            {
                await client.DisposeAsync();
            }
        }
    }

    private sealed record GlobalState(
        INatsKVStore Leaders,
        INatsKVStore Releases,
        INatsObjStore Bundles,
        INatsJSConsumer CiConsumer);
}
