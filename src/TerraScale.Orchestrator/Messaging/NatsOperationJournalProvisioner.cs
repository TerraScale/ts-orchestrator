using NATS.Client.Core;
using NATS.Client.ObjectStore;
using NATS.Net;

namespace TerraScale.Orchestrator.Messaging;

/// <summary>Runs before controllers start, using the separate infrastructure NATS identity.</summary>
internal static class NatsOperationJournalProvisioner
{
    internal static async Task ProvisionAsync(
        OrchestratorOptions options,
        CancellationToken cancellationToken) =>
        await ProvisionAsync(options, includeAuthoritativeJournal: true, cancellationToken);

    internal static async Task ProvisionControllerAsync(
        OrchestratorOptions options,
        CancellationToken cancellationToken) =>
        await ProvisionAsync(options, includeAuthoritativeJournal: false, cancellationToken);

    private static async Task ProvisionAsync(
        OrchestratorOptions options,
        bool includeAuthoritativeJournal,
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
        if (includeAuthoritativeJournal)
            await ProvisionTopologyAsync(client, topology, cancellationToken);
        else
            await ProvisionControllerTopologyAsync(client, topology, cancellationToken);
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
        await OpenOrCreateAndValidateObjectStoreAsync(objects, topology.Bundles, cancellationToken);
        var protocolPackage = await OpenOrCreateAndValidateObjectStoreAsync(
            objects, topology.ProtocolPackage, cancellationToken);

        byte[] stored;
        try
        {
            stored = await protocolPackage.GetBytesAsync(topology.ProtocolObject, cancellationToken);
        }
        catch (NatsObjNotFoundException)
        {
            await protocolPackage.PutAsync(topology.ProtocolObject, NatsProtocolPackage.Bytes, cancellationToken);
            stored = await protocolPackage.GetBytesAsync(topology.ProtocolObject, cancellationToken);
        }
        if (!stored.AsSpan().SequenceEqual(NatsProtocolPackage.Bytes))
        {
            throw new InvalidOperationException("NATS protocol package failed its integrity check.");
        }

        await CreateOrUpdateAndValidateConsumerAsync(
            jetStream, "CELL_EVENTS", topology.StartupConsumer, cancellationToken);
        await CreateOrUpdateAndValidateConsumerAsync(
            jetStream, "CELL_SPEC", topology.CellSpecConsumer, cancellationToken);
    }

    private static async Task CreateOrUpdateAndValidateConsumerAsync(
        NATS.Client.JetStream.INatsJSContext jetStream,
        string stream,
        NATS.Client.JetStream.Models.ConsumerConfig configuration,
        CancellationToken cancellationToken)
    {
        var consumer = await jetStream.CreateOrUpdateConsumerAsync(stream, configuration, cancellationToken);
        await consumer.RefreshAsync(cancellationToken);
        if (!CiRunnerConsumerReconciler.Matches(consumer.Info, configuration, stream))
            throw new InvalidOperationException("An infrastructure-provisioned NATS consumer does not match its closed profile.");
    }

    private static async Task<INatsObjStore> OpenOrCreateAndValidateObjectStoreAsync(
        INatsObjContext objects,
        NatsObjConfig configuration,
        CancellationToken cancellationToken)
    {
        INatsObjStore store;
        try
        {
            store = await objects.GetObjectStoreAsync(configuration.Bucket, cancellationToken);
        }
        catch (NATS.Client.JetStream.NatsJSApiException exception) when (exception.Error.Code == 404)
        {
            store = await objects.CreateObjectStoreAsync(configuration, cancellationToken);
        }
        NatsOperationJournalStore.ValidateExactObjectConfiguration(
            (await store.GetStatusAsync(cancellationToken)).Info.Config, configuration);
        return store;
    }
}
