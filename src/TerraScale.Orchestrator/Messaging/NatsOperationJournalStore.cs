using NATS.Client.JetStream.Models;
using NATS.Client.KeyValueStore;
using NATS.Client.JetStream;
using NATS.Client.ObjectStore;
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
            throw new InvalidOperationException("The authoritative CreateNode journal store is absent or does not have its immutable R3 configuration.");
        ValidateConfiguration(status.Info.Config, configuration);
        if (client is not null)
            await ValidateBatchPublishDisabledAsync(client, configuration, cancellationToken);
    }

    internal static void ValidateConfiguration(StreamConfig actual, NatsKVConfig configuration)
    {
        ArgumentNullException.ThrowIfNull(actual);
        ValidateExpected(configuration);
        ValidateExactStreamConfiguration(actual, CanonicalStream(configuration));
    }

    internal static void ValidateExactStreamConfiguration(StreamConfig actual, StreamConfig expected)
    {
        ArgumentNullException.ThrowIfNull(actual);
        ArgumentNullException.ThrowIfNull(expected);
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
            throw new InvalidOperationException("The authoritative CreateNode journal store is absent or does not have its immutable R3 configuration.");
    }

    internal static void ValidateExactObjectConfiguration(StreamConfig actual, NatsObjConfig configuration)
    {
        ValidateExactStreamConfiguration(actual, new StreamConfig($"OBJ_{configuration.Bucket}",
            [$"$O.{configuration.Bucket}.C.>", $"$O.{configuration.Bucket}.M.>"])
        {
            Description = configuration.Description,
            Retention = StreamConfigRetention.Limits,
            MaxConsumers = -1,
            MaxMsgs = -1,
            MaxMsgsPerSubject = -1,
            MaxBytes = configuration.MaxBytes ?? -1,
            MaxAge = TimeSpan.Zero,
            MaxMsgSize = -1,
            Storage = StreamConfigStorage.File,
            Compression = StreamConfigCompression.None,
            NumReplicas = configuration.NumberOfReplicas,
            NoAck = false,
            Discard = StreamConfigDiscard.New,
            DuplicateWindow = TimeSpan.FromMinutes(2),
            Sealed = false,
            DenyDelete = false,
            DenyPurge = false,
            AllowRollupHdrs = true,
            AllowDirect = true,
            MirrorDirect = false,
            DiscardNewPerSubject = false,
            AllowMsgTTL = false,
            SubjectDeleteMarkerTTL = TimeSpan.Zero,
            AllowMsgCounter = false,
            AllowMsgSchedules = false,
            AllowAtomicPublish = false,
        });
        if (actual.Metadata is null || !HasExpectedNatsMetadata(actual.Metadata))
            throw new InvalidOperationException("The regional object store configuration carries unexpected metadata.");
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

    internal static StreamConfig CanonicalKeyValueStream(NatsKVConfig configuration) => new(
        $"KV_{configuration.Bucket}",
        [$"$KV.{configuration.Bucket}.>"])
    {
        Description = configuration.Description,
        Retention = StreamConfigRetention.Limits,
        MaxConsumers = -1,
        MaxMsgs = -1,
        MaxMsgsPerSubject = configuration.History > 0 ? configuration.History : 1,
        MaxBytes = configuration.MaxBytes == 0 ? -1 : configuration.MaxBytes,
        MaxAge = configuration.MaxAge,
        MaxMsgSize = configuration.MaxValueSize == 0 ? -1 : configuration.MaxValueSize,
        Storage = configuration.Storage == NatsKVStorageType.Memory
            ? StreamConfigStorage.Memory
            : StreamConfigStorage.File,
        Compression = configuration.Compression
            ? StreamConfigCompression.S2
            : StreamConfigCompression.None,
        NumReplicas = configuration.NumberOfReplicas > 0 ? configuration.NumberOfReplicas : 1,
        NoAck = false,
        Discard = StreamConfigDiscard.New,
        DuplicateWindow = TimeSpan.FromMinutes(2),
        Sealed = false,
        DenyDelete = true,
        DenyPurge = false,
        AllowRollupHdrs = true,
        AllowDirect = true,
        MirrorDirect = false,
        DiscardNewPerSubject = false,
        AllowMsgTTL = configuration.LimitMarkerTTL > TimeSpan.Zero,
        SubjectDeleteMarkerTTL = configuration.LimitMarkerTTL,
        AllowMsgCounter = false,
        AllowMsgSchedules = false,
        AllowAtomicPublish = false,
    };

    internal static void ValidatePlainTopologyKeyValueConfiguration(
        StreamConfig actual,
        NatsKVConfig configuration)
    {
        if (configuration.Bucket is not ("ORCH_LEADERS" or "ORCH_RUNTIME" or "ORCH_DELIVERY") ||
            configuration.Republish is not null || configuration.Placement is not null ||
            configuration.Mirror is not null || configuration.Sources is { Count: > 0 } ||
            configuration.Metadata is { Count: > 0 })
            throw new ArgumentException("The regional topology KV configuration must be closed.", nameof(configuration));
        ValidateExactStreamConfiguration(actual, CanonicalKeyValueStream(configuration));
        if (actual.Metadata is not null && !HasExpectedNatsMetadata(actual.Metadata))
            throw new InvalidOperationException("The regional topology KV configuration carries unexpected metadata.");
    }

    private static bool HasExpectedNatsMetadata(IDictionary<string, string> metadata) =>
        metadata.Count == 3 &&
        metadata.TryGetValue("_nats.level", out var level) && IsNonnegativeInteger(level) &&
        metadata.TryGetValue("_nats.req.level", out var requestedLevel) && IsNonnegativeInteger(requestedLevel) &&
        metadata.TryGetValue("_nats.ver", out var version) &&
        Version.TryParse(version, out var parsedVersion) && parsedVersion.Build >= 0;

    private static bool IsNonnegativeInteger(string value) =>
        int.TryParse(value, System.Globalization.NumberStyles.None,
            System.Globalization.CultureInfo.InvariantCulture, out var parsed) && parsed >= 0;

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
            JsonSerializer.Serialize(config),
            cancellationToken: cancellationToken);
        response.EnsureSuccess();
        var root = JsonElement.Parse(response.Data ?? throw new InvalidOperationException("JetStream returned no stream update response."));
        ThrowIfJetStreamError(root);
        ValidateBatchPublish(root);
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
        var root = JsonElement.Parse(response.Data ?? throw new InvalidOperationException("JetStream returned no stream information response."));
        ThrowIfJetStreamError(root);
        ValidateBatchPublish(root);
    }

    internal static void ValidateBatchPublish(JsonElement response)
    {
        if (!response.TryGetProperty("config", out var config) ||
            !config.TryGetProperty("allow_batch_publish", out var enabled) || enabled.ValueKind != JsonValueKind.False)
            throw new InvalidOperationException("Authoritative CreateNode journal stores must set allow_batch_publish to false.");
    }

    private static void ThrowIfJetStreamError(JsonElement response)
    {
        if (response.TryGetProperty("error", out var error))
            throw new InvalidOperationException($"JetStream operation journal stream mutation failed: {error}");
    }

    private static void ValidateExpected(NatsKVConfig configuration)
    {
        var isOperationJournal = configuration.Bucket == "ORCH_OPERATIONS" &&
            configuration.History == 2 && configuration.MaxAge == TimeSpan.Zero &&
            configuration.MaxValueSize == 16 * 1024 && configuration.MaxBytes == 256 * 1024 * 1024;
        var isProofConsumption = configuration.Bucket == "ORCH_OPERATION_PROOFS" &&
            configuration.History == 1 && configuration.MaxAge == TimeSpan.FromMinutes(5) &&
            configuration.MaxValueSize == 256 && configuration.MaxBytes == 8 * 1024 * 1024;
        if ((isOperationJournal || isProofConsumption) && configuration.NumberOfReplicas == 3 &&
            configuration.Storage == NatsKVStorageType.File)
            return;
        throw new ArgumentException("The authoritative CreateNode journal store configuration must be exact R3.", nameof(configuration));
    }
}
