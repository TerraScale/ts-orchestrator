using NATS.Client.Core;
using NATS.Client.ObjectStore;
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
        var topology = new NatsTopology(options.Cell, options.Replicas, options.Instance);
        await ProvisionTopologyAsync(client, topology, cancellationToken);
    }

    internal static async Task ProvisionTopologyAsync(
        NatsClient client,
        NatsTopology topology,
        CancellationToken cancellationToken)
    {
        await ProvisionControllerTopologyAsync(client, topology, cancellationToken);
        var jetStream = client.CreateJetStreamContext();
        var keyValue = jetStream.CreateKeyValueStoreContext();
        await NatsOperationJournalStore.ProvisionAsync(
            client,
            jetStream,
            keyValue,
            topology.Operations,
            cancellationToken);
        await NatsOperationJournalStore.ProvisionAsync(
            client,
            jetStream,
            keyValue,
            topology.OperationProofConsumptions,
            cancellationToken);
    }

    internal static async Task ProvisionControllerTopologyAsync(
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
        await keyValue.CreateOrUpdateStoreAsync(topology.Runtime, cancellationToken);
        await keyValue.CreateOrUpdateStoreAsync(topology.Delivery, cancellationToken);
        var objects = jetStream.CreateObjectStoreContext();
        INatsObjStore bundles;
        try
        {
            bundles = await objects.GetObjectStoreAsync(topology.Bundles.Bucket, cancellationToken);
        }
        catch (NATS.Client.JetStream.NatsJSApiException exception) when (exception.Error.Code == 404)
        {
            bundles = await objects.CreateObjectStoreAsync(topology.Bundles, cancellationToken);
        }

        byte[] stored;
        try
        {
            stored = await bundles.GetBytesAsync(topology.ProtocolObject, cancellationToken);
        }
        catch (NatsObjNotFoundException)
        {
            await bundles.PutAsync(topology.ProtocolObject, NatsProtocolPackage.Bytes, cancellationToken);
            stored = await bundles.GetBytesAsync(topology.ProtocolObject, cancellationToken);
        }
        if (!stored.AsSpan().SequenceEqual(NatsProtocolPackage.Bytes))
        {
            throw new InvalidOperationException("NATS protocol package failed its integrity check.");
        }
    }
}
