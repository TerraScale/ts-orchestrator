using NATS.Client.JetStream.Models;
using NATS.Client.KeyValueStore;
using NATS.Client.JetStream;
using NATS.Net;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace TerraScale.Orchestrator.Messaging;

/// <summary>Infrastructure provisions this bucket; controller identities only open and validate it.</summary>
internal static class NatsOperationJournalStore
{
    internal static async Task<INatsKVStore> ProvisionAsync(
        NatsClient client,
        INatsJSContext jetStream,
        INatsKVContext keyValue,
        NatsKVConfig configuration,
        CancellationToken cancellationToken)
    {
        ValidateExpected(configuration);
        await jetStream.CreateOrUpdateStreamAsync(CanonicalStream(configuration), cancellationToken);
        await SetBatchPublishDisabledAsync(client, configuration, cancellationToken);
        var store = await keyValue.GetStoreAsync(configuration.Bucket, cancellationToken);
        await ValidateAsync(store, configuration, client, cancellationToken);
        return store;
    }

    internal static async Task<INatsKVStore> OpenAsync(
        INatsKVContext keyValue,
        NatsKVConfig configuration,
        CancellationToken cancellationToken,
        NatsClient? client = null)
    {
        ValidateExpected(configuration);
        var store = await keyValue.GetStoreAsync(configuration.Bucket, cancellationToken);
        await ValidateAsync(store, configuration, client, cancellationToken);
        return store;
    }

    internal static async Task ValidateAsync(
        INatsKVStore store,
        NatsKVConfig configuration,
        CancellationToken cancellationToken) =>
        await ValidateAsync(store, configuration, null, cancellationToken);

    private static async Task ValidateAsync(
        INatsKVStore store,
        NatsKVConfig configuration,
        NatsClient? client,
        CancellationToken cancellationToken)
    {
        ValidateExpected(configuration);
        var status = await store.GetStatusAsync(cancellationToken);
        if (status.Bucket != configuration.Bucket)
            throw new InvalidOperationException("ORCH_OPERATIONS is absent or does not have its immutable authoritative R3 configuration.");
        ValidateConfiguration(status.Info.Config, configuration);
        if (client is not null)
            await ValidateBatchPublishDisabledAsync(client, configuration, cancellationToken);
    }

    internal static void ValidateConfiguration(StreamConfig actual, NatsKVConfig configuration)
    {
        ArgumentNullException.ThrowIfNull(actual);
        ValidateExpected(configuration);
        var expected = CanonicalStream(configuration);
        var actualSubjects = actual.Subjects;
        var expectedSubjects = expected.Subjects;
        var actualSources = actual.Sources;
        var metadata = actual.Metadata;
        if (actual.Name != expected.Name ||
            actual.Description != expected.Description ||
            actualSubjects is null || expectedSubjects is null ||
            !actualSubjects.Order(StringComparer.Ordinal).SequenceEqual(expectedSubjects.Order(StringComparer.Ordinal)) ||
            actual.SubjectTransform is not null || actual.Retention != expected.Retention ||
            actual.MaxConsumers != expected.MaxConsumers || actual.MaxMsgs != expected.MaxMsgs ||
            actual.MaxMsgsPerSubject != expected.MaxMsgsPerSubject || actual.MaxBytes != expected.MaxBytes ||
            actual.MaxAge != expected.MaxAge || actual.MaxMsgSize != expected.MaxMsgSize ||
            actual.Storage != expected.Storage || actual.Compression != expected.Compression ||
            actual.NumReplicas != expected.NumReplicas || actual.NoAck != expected.NoAck ||
            actual.TemplateOwner is not null || actual.Discard != expected.Discard ||
            actual.DuplicateWindow != expected.DuplicateWindow || actual.Placement is not null ||
            actual.Mirror is not null || actualSources?.Count > 0 || actual.Sealed != expected.Sealed ||
            actual.DenyDelete != expected.DenyDelete || actual.DenyPurge != expected.DenyPurge ||
            actual.AllowRollupHdrs != expected.AllowRollupHdrs || actual.AllowDirect != expected.AllowDirect ||
            actual.MirrorDirect != expected.MirrorDirect || actual.Republish is not null ||
            actual.DiscardNewPerSubject != expected.DiscardNewPerSubject ||
            actual.AllowMsgTTL != expected.AllowMsgTTL ||
            actual.SubjectDeleteMarkerTTL != expected.SubjectDeleteMarkerTTL ||
            actual.AllowMsgCounter != expected.AllowMsgCounter ||
            actual.AllowMsgSchedules != expected.AllowMsgSchedules ||
            actual.AllowAtomicPublish != expected.AllowAtomicPublish || actual.PersistMode is not null ||
            (metadata is not null && metadata.Keys.Any(key => !key.StartsWith("_nats.", StringComparison.Ordinal))))
            throw new InvalidOperationException("ORCH_OPERATIONS is absent or does not have its immutable authoritative R3 configuration.");
    }

    internal static StreamConfig CanonicalStream(NatsKVConfig configuration) => new(
        $"KV_{configuration.Bucket}",
        [$"$KV.{configuration.Bucket}.>"])
    {
        Description = configuration.Description,
        Retention = StreamConfigRetention.Limits,
        MaxConsumers = -1,
        MaxMsgs = -1,
        MaxMsgsPerSubject = configuration.History,
        MaxBytes = configuration.MaxBytes,
        MaxAge = configuration.MaxAge,
        MaxMsgSize = configuration.MaxValueSize,
        Storage = StreamConfigStorage.File,
        Compression = StreamConfigCompression.None,
        NumReplicas = configuration.NumberOfReplicas,
        NoAck = false,
        Discard = StreamConfigDiscard.New,
        DuplicateWindow = TimeSpan.FromMinutes(2),
        Sealed = false,
        DenyDelete = true,
        DenyPurge = true,
        // CAS uses Nats-Expected-Last-Subject-Sequence, not rollups. Refuse any
        // Nats-Rollup header so a writer cannot erase retained operation history.
        AllowRollupHdrs = false,
        AllowDirect = true,
        MirrorDirect = false,
        DiscardNewPerSubject = false,
        AllowMsgTTL = false,
        SubjectDeleteMarkerTTL = TimeSpan.Zero,
        AllowMsgCounter = false,
        AllowMsgSchedules = false,
        AllowAtomicPublish = false,
    };

    private static async Task SetBatchPublishDisabledAsync(
        NatsClient client,
        NatsKVConfig configuration,
        CancellationToken cancellationToken)
    {
        var config = JsonNode.Parse(JsonSerializer.Serialize(CanonicalStream(configuration)))?.AsObject()
            ?? throw new InvalidOperationException("Unable to serialize the operation journal stream configuration.");
        // NATS.Net 2.7 does not surface the NATS 2.14 allow_batch_publish field.
        // Send it over the JetStream API explicitly so the server receives a hard false.
        config["allow_batch_publish"] = false;
        var response = await client.RequestAsync<string, string>(
            $"$JS.API.STREAM.UPDATE.KV_{configuration.Bucket}",
            JsonSerializer.Serialize(new JsonObject { ["config"] = config }),
            cancellationToken: cancellationToken);
        response.EnsureSuccess();
        using var document = JsonDocument.Parse(response.Data ?? throw new InvalidOperationException("JetStream returned no stream update response."));
        ThrowIfJetStreamError(document.RootElement);
        ValidateBatchPublish(document.RootElement);
    }

    private static async Task ValidateBatchPublishDisabledAsync(
        NatsClient client,
        NatsKVConfig configuration,
        CancellationToken cancellationToken)
    {
        var response = await client.RequestAsync<string, string>(
            $"$JS.API.STREAM.INFO.KV_{configuration.Bucket}",
            string.Empty,
            cancellationToken: cancellationToken);
        response.EnsureSuccess();
        using var document = JsonDocument.Parse(response.Data ?? throw new InvalidOperationException("JetStream returned no stream information response."));
        ThrowIfJetStreamError(document.RootElement);
        ValidateBatchPublish(document.RootElement);
    }

    internal static void ValidateBatchPublish(JsonElement response)
    {
        if (!response.TryGetProperty("config", out var config) ||
            !config.TryGetProperty("allow_batch_publish", out var enabled) || enabled.ValueKind != JsonValueKind.False)
            throw new InvalidOperationException("ORCH_OPERATIONS must set allow_batch_publish to false.");
    }

    private static void ThrowIfJetStreamError(JsonElement response)
    {
        if (response.TryGetProperty("error", out var error))
            throw new InvalidOperationException($"JetStream operation journal stream mutation failed: {error}");
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
