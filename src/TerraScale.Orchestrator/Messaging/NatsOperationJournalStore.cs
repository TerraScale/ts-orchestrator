using NATS.Client.JetStream.Models;
using NATS.Client.KeyValueStore;

namespace TerraScale.Orchestrator.Messaging;

/// <summary>Infrastructure provisions this bucket; controller identities only open and validate it.</summary>
internal static class NatsOperationJournalStore
{
    internal static async Task<INatsKVStore> ProvisionAsync(
        INatsKVContext keyValue,
        NatsKVConfig configuration,
        CancellationToken cancellationToken)
    {
        ValidateExpected(configuration);
        var store = await keyValue.CreateOrUpdateStoreAsync(configuration, cancellationToken);
        await ValidateAsync(store, configuration, cancellationToken);
        return store;
    }

    internal static async Task<INatsKVStore> OpenAsync(
        INatsKVContext keyValue,
        NatsKVConfig configuration,
        CancellationToken cancellationToken)
    {
        ValidateExpected(configuration);
        var store = await keyValue.GetStoreAsync(configuration.Bucket, cancellationToken);
        await ValidateAsync(store, configuration, cancellationToken);
        return store;
    }

    internal static async Task ValidateAsync(
        INatsKVStore store,
        NatsKVConfig configuration,
        CancellationToken cancellationToken)
    {
        ValidateExpected(configuration);
        var status = await store.GetStatusAsync(cancellationToken);
        var actual = status.Info.Config;
        if (status.Bucket != configuration.Bucket || actual.NumReplicas != 3 ||
            actual.MaxAge != configuration.MaxAge || actual.MaxBytes != configuration.MaxBytes ||
            actual.MaxMsgSize != configuration.MaxValueSize || actual.MaxMsgsPerSubject != configuration.History ||
            actual.Storage != StreamConfigStorage.File || actual.Discard != StreamConfigDiscard.New)
            throw new InvalidOperationException("ORCH_OPERATIONS is absent or does not have its immutable authoritative R3 configuration.");
    }

    private static void ValidateExpected(NatsKVConfig configuration)
    {
        if (configuration.Bucket != "ORCH_OPERATIONS" || configuration.NumberOfReplicas != 3 ||
            configuration.History != 2 || configuration.MaxAge != TimeSpan.Zero ||
            configuration.MaxValueSize != 16 * 1024 || configuration.MaxBytes != 256 * 1024 * 1024 ||
            configuration.Storage != NatsKVStorageType.File)
            throw new ArgumentException("The authoritative CreateNode journal configuration must be exact R3.", nameof(configuration));
    }
}
