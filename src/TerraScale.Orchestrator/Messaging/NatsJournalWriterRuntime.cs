using NATS.Client.Core;
using NATS.Net;

namespace TerraScale.Orchestrator.Messaging;

/// <summary>
/// Isolated journal-writer process role. Its configuration is intentionally
/// unavailable to the regional controller runtime.
/// </summary>
public sealed class NatsJournalWriterRuntime : IAsyncDisposable
{
    private readonly NatsClient client;
    private readonly NatsOperationJournalMutationService mutations;

    private NatsJournalWriterRuntime(NatsClient client, NatsOperationJournalMutationService mutations)
    {
        this.client = client;
        this.mutations = mutations;
    }

    public Task Completion { get; } = Task.Delay(Timeout.InfiniteTimeSpan);

    public static async Task<NatsJournalWriterRuntime> StartAsync(
        OrchestratorOptions options,
        CancellationToken cancellationToken)
    {
        if (options.Command != OrchestratorCommand.JournalWriter || options.AuthoritativeJournal is not { } journal)
            throw new InvalidOperationException("The isolated journal-writer role requires complete writer credentials.");
        var client = new NatsClient(new NatsOpts
        {
            Url = options.NatsUrl,
            RetryOnInitialConnect = true,
            RequestTimeout = TimeSpan.FromSeconds(15),
            AuthOpts = new NatsAuthOpts { NKeyFile = journal.NKeyFile },
            TlsOpts = new NatsTlsOpts
            {
                Mode = TlsMode.Require,
                CaFile = journal.Tls.CaFile,
                CertFile = journal.Tls.CertificateFile,
                KeyFile = journal.Tls.KeyFile,
            },
        });
        try
        {
            await client.ConnectAsync().AsTask().WaitAsync(cancellationToken);
            var topology = new NatsTopology(options.Cell, options.Replicas, options.Instance);
            var keyValue = client.CreateJetStreamContext().CreateKeyValueStoreContext();
            var operations = await NatsOperationJournalStore.OpenAsync(keyValue, topology.Operations, cancellationToken, client);
            var proofs = await NatsOperationJournalStore.OpenAsync(keyValue, topology.OperationProofConsumptions, cancellationToken, client);
            var mutations = await NatsOperationJournalMutationService.StartAsync(
                client,
                operations,
                proofs,
                topology,
                new NatsOperationJournalMutationAuthorityVerifier(journal.AuthorityPublicKey),
                journal.EligibleControllerIdentities,
                NatsOperationJournalMutationReplySigner.Load(journal.ReplySigningKeyFile),
                cancellationToken,
                enableRuntimeLifecycleProtocol: true);
            return new(client, mutations);
        }
        catch
        {
            await client.DisposeAsync();
            throw;
        }
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            await mutations.DisposeAsync();
        }
        finally
        {
            await client.DisposeAsync();
        }
    }
}

