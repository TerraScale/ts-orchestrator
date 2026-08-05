using NATS.Client.Core;
using NATS.Net;

namespace TerraScale.Orchestrator.Messaging;

/// <summary>Runs before controllers start, using the separate infrastructure NATS identity.</summary>
internal static class NatsOperationJournalProvisioner
{
    internal static async Task ProvisionAsync(
        OrchestratorOptions options,
        CancellationToken cancellationToken)
    {
        var nkeyFile = options.InfrastructureNatsNKeyFile
            ?? throw new InvalidOperationException("The infrastructure NATS identity is required to provision ORCH_OPERATIONS.");
        var tls = options.InfrastructureNatsTls
            ?? throw new InvalidOperationException("Infrastructure mTLS is required to provision ORCH_OPERATIONS.");
        await using var client = new NatsClient(new NatsOpts
        {
            Url = options.NatsUrl,
            RetryOnInitialConnect = false,
            RequestTimeout = TimeSpan.FromSeconds(15),
            AuthOpts = new NatsAuthOpts { NKeyFile = nkeyFile },
            TlsOpts = new NatsTlsOpts
            {
                Mode = TlsMode.Require,
                CaFile = tls.CaFile,
                CertFile = tls.CertificateFile,
                KeyFile = tls.KeyFile,
            },
        });
        await client.ConnectAsync();
        cancellationToken.ThrowIfCancellationRequested();
        var jetStream = client.CreateJetStreamContext();
        var topology = new NatsTopology(options.Cell, 3, options.Instance);
        await NatsOperationJournalStore.ProvisionAsync(
            jetStream,
            jetStream.CreateKeyValueStoreContext(),
            topology.Operations,
            cancellationToken);
    }
}
