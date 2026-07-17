using NATS.Client.Core;
using NATS.Client.JetStream;
using NATS.Client.KeyValueStore;
using NATS.Net;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Messaging;

internal sealed class GlobalNatsRuntime : IAsyncDisposable
{
    private readonly NatsClient client;
    private readonly RegionalAuthorityCoordinator authority;

    private GlobalNatsRuntime(
        NatsClient client,
        RegionalAuthorityCoordinator authority,
        RepositoryCiPromotionJournal promotions)
    {
        this.client = client;
        this.authority = authority;
        Promotions = promotions;
    }

    public Task Completion => authority.Completion;
    public RepositoryCiPromotionJournal Promotions { get; }
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
            return new(client, authority, new(new NatsForgejoDeliveryLedger(state.Releases)));
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
                return new(leaders, releases);
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
            await authority.DisposeAsync();
        }
        finally
        {
            await client.DisposeAsync();
        }
    }

    private sealed record GlobalState(INatsKVStore Leaders, INatsKVStore Releases);
}
