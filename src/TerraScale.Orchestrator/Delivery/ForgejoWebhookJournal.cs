using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using NATS.Client.KeyValueStore;

namespace TerraScale.Orchestrator.Delivery;

public enum ForgejoWebhookJournalDisposition
{
    Unspecified,
    Accepted,
    Duplicate,
    DeliveryCollision,
    PayloadReplay,
}

public sealed class ForgejoWebhookJournalReceipt
{
    internal ForgejoWebhookJournalReceipt(ForgejoWebhookJournalDisposition disposition) => Disposition = disposition;

    public ForgejoWebhookJournalDisposition Disposition { get; }
    public bool CanAcknowledge => Disposition is ForgejoWebhookJournalDisposition.Accepted or ForgejoWebhookJournalDisposition.Duplicate;
}

/// <summary>Durably reserves both Forgejo delivery and signed-payload identities before acknowledgement.</summary>
public sealed class ForgejoWebhookJournal
{
    private const int MaximumConflictRetries = 8;
    private readonly IForgejoDeliveryLedger ledger;
    private readonly IForgejoEventPublisher publisher;

    internal ForgejoWebhookJournal(IForgejoDeliveryLedger ledger) : this(ledger, NullForgejoEventPublisher.Instance) { }

    internal ForgejoWebhookJournal(IForgejoDeliveryLedger ledger, IForgejoEventPublisher publisher)
    {
        this.ledger = ledger;
        this.publisher = publisher;
    }

    public async Task<ForgejoWebhookJournalReceipt> AcceptAsync(
        ForgejoWebhookEnvelope envelope,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        var pending = ForgejoWebhookJournalDocument.From(envelope);
        var payload = await EnsureAsync(PayloadIndex(envelope), pending, cancellationToken);
        if (!payload.Matches) return new(ForgejoWebhookJournalDisposition.PayloadReplay);

        var delivery = await EnsureAsync(DeliveryIndex(envelope), pending, cancellationToken);
        if (!delivery.Matches) return new(ForgejoWebhookJournalDisposition.DeliveryCollision);

        var wasComplete = delivery.Document!.State == ForgejoWebhookJournalState.Accepted &&
                          payload.Document!.State == ForgejoWebhookJournalState.Accepted;
        if (!wasComplete) await publisher.PublishAsync(envelope, cancellationToken);
        await MarkAcceptedAsync(PayloadIndex(envelope), payload, cancellationToken);
        await MarkAcceptedAsync(DeliveryIndex(envelope), delivery, cancellationToken);
        return new(wasComplete
            ? ForgejoWebhookJournalDisposition.Duplicate
            : ForgejoWebhookJournalDisposition.Accepted);
    }

    private async Task<IndexReservation> EnsureAsync(
        string key,
        ForgejoWebhookJournalDocument proposed,
        CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < MaximumConflictRetries; attempt++)
        {
            var current = await ledger.GetAsync(key, cancellationToken);
            if (current is not null) return Read(current, proposed);
            try
            {
                var created = await ledger.CreateAsync(
                    key,
                    Serialize(proposed),
                    cancellationToken);
                return new(true, proposed, created.Revision);
            }
            catch (ForgejoDeliveryLedgerConflictException)
            {
            }
        }
        throw new InvalidOperationException("The Forgejo webhook journal could not resolve an index reservation.");
    }

    private async Task MarkAcceptedAsync(
        string key,
        IndexReservation reservation,
        CancellationToken cancellationToken)
    {
        var current = reservation;
        for (var attempt = 0; attempt < MaximumConflictRetries; attempt++)
        {
            if (current.Document!.State == ForgejoWebhookJournalState.Accepted) return;
            try
            {
                await ledger.UpdateAsync(
                    key,
                    Serialize(current.Document with { State = ForgejoWebhookJournalState.Accepted }),
                    current.Revision,
                    cancellationToken);
                return;
            }
            catch (ForgejoDeliveryLedgerConflictException)
            {
                var observed = await ledger.GetAsync(key, cancellationToken)
                    ?? throw new InvalidDataException("A reserved Forgejo webhook journal index disappeared.");
                current = Read(observed, reservation.Document!);
                if (!current.Matches)
                    throw new InvalidDataException("A reserved Forgejo webhook journal index changed identity.");
            }
        }
        throw new InvalidOperationException("The Forgejo webhook journal could not commit an index reservation.");
    }

    private static IndexReservation Read(
        ForgejoDeliveryLedgerEntry entry,
        ForgejoWebhookJournalDocument expected)
    {
        ForgejoWebhookJournalDocument document;
        try
        {
            document = JsonSerializer.Deserialize(
                entry.Value,
                ForgejoWebhookJournalJsonContext.Default.ForgejoWebhookJournalDocument)
                ?? throw new JsonException();
            document.Validate();
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("A Forgejo webhook journal record is invalid.", exception);
        }
        return new(document.Matches(expected), document, entry.Revision);
    }

    private static string Serialize(ForgejoWebhookJournalDocument document) => JsonSerializer.Serialize(
        document,
        ForgejoWebhookJournalJsonContext.Default.ForgejoWebhookJournalDocument);

    private static string DeliveryIndex(ForgejoWebhookEnvelope envelope) =>
        $"delivery.{Hash(envelope.DeliveryKey)}";

    private static string PayloadIndex(ForgejoWebhookEnvelope envelope) =>
        $"payload.{envelope.PayloadSha256}";

    private static string Hash(string value) => Convert.ToHexStringLower(
        SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private sealed record IndexReservation(
        bool Matches,
        ForgejoWebhookJournalDocument? Document,
        ulong Revision);

    private sealed class NullForgejoEventPublisher : IForgejoEventPublisher
    {
        internal static readonly NullForgejoEventPublisher Instance = new();

        public Task PublishAsync(ForgejoWebhookEnvelope envelope, CancellationToken cancellationToken) =>
            Task.CompletedTask;
    }
}

internal enum ForgejoWebhookJournalState
{
    Unspecified,
    Pending,
    Accepted,
}

internal sealed record ForgejoWebhookJournalDocument(
    int SchemaVersion,
    ForgejoWebhookJournalState State,
    Guid DeliveryId,
    ForgejoWebhookKind Kind,
    string Action,
    string Repository,
    string SourceRepository,
    string BaseRevision,
    string Revision,
    string SourceRef,
    string? TargetRef,
    long? PullRequestNumber,
    bool IsDeletion,
    string PayloadSha256,
    string DeliveryKey,
    string DedupeKey)
{
    internal static ForgejoWebhookJournalDocument From(ForgejoWebhookEnvelope envelope) => new(
        1,
        ForgejoWebhookJournalState.Pending,
        envelope.DeliveryId,
        envelope.Kind,
        envelope.Action,
        envelope.Repository,
        envelope.SourceRepository,
        envelope.BaseRevision,
        envelope.Revision,
        envelope.SourceRef,
        envelope.TargetRef,
        envelope.PullRequestNumber,
        envelope.IsDeletion,
        envelope.PayloadSha256,
        envelope.DeliveryKey,
        envelope.DedupeKey);

    internal bool Matches(ForgejoWebhookJournalDocument other) =>
        this with { State = other.State } == other;

    internal void Validate()
    {
        if (SchemaVersion != 1 || State is not (ForgejoWebhookJournalState.Pending or ForgejoWebhookJournalState.Accepted) ||
            DeliveryId == Guid.Empty || Kind is not (ForgejoWebhookKind.Push or ForgejoWebhookKind.PullRequest) ||
            string.IsNullOrWhiteSpace(Action) || string.IsNullOrWhiteSpace(Repository) ||
            string.IsNullOrWhiteSpace(SourceRepository) || BaseRevision.Length is not (40 or 64) ||
            Revision.Length is not (40 or 64) ||
            !BaseRevision.All(IsHex) || !Revision.All(IsHex) ||
            string.IsNullOrWhiteSpace(SourceRef) || PayloadSha256.Length != 64 ||
            !PayloadSha256.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f') ||
            DeliveryKey != $"forgejo-delivery:{Repository}:{DeliveryId:D}" ||
            DedupeKey != $"forgejo-payload:{Repository}:{PayloadSha256}" ||
            Kind == ForgejoWebhookKind.Push &&
            (TargetRef is not null || PullRequestNumber is not null || SourceRepository != Repository) ||
            Kind == ForgejoWebhookKind.PullRequest &&
            (string.IsNullOrWhiteSpace(TargetRef) || PullRequestNumber is null or <= 0 || IsDeletion))
            throw new InvalidDataException("A Forgejo webhook journal record is invalid.");
    }

    private static bool IsHex(char value) => value is
        >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F';
}

internal sealed record ForgejoDeliveryLedgerEntry(string Value, ulong Revision);

internal interface IForgejoDeliveryLedger
{
    Task<ForgejoDeliveryLedgerEntry?> GetAsync(string key, CancellationToken cancellationToken);
    Task<ForgejoDeliveryLedgerEntry> CreateAsync(string key, string value, CancellationToken cancellationToken);
    Task<ForgejoDeliveryLedgerEntry> UpdateAsync(string key, string value, ulong revision, CancellationToken cancellationToken);
}

internal interface IForgejoDeliveryRetentionLedger
{
    IAsyncEnumerable<string> ListKeysAsync(string filter, CancellationToken cancellationToken);
    Task DeleteAsync(string key, ulong revision, CancellationToken cancellationToken);
}

internal sealed class ForgejoDeliveryLedgerConflictException(Exception innerException)
    : Exception("The Forgejo delivery ledger changed concurrently.", innerException);

internal sealed class NatsForgejoDeliveryLedger(INatsKVStore store) :
    IForgejoDeliveryLedger,
    IForgejoDeliveryRetentionLedger
{
    public async Task<ForgejoDeliveryLedgerEntry?> GetAsync(string key, CancellationToken cancellationToken)
    {
        try
        {
            var entry = await store.GetEntryAsync<string>(key, cancellationToken: cancellationToken);
            entry.EnsureSuccess();
            return new(
                entry.Value ?? throw new InvalidDataException("A Forgejo webhook journal record is empty."),
                entry.Revision);
        }
        catch (NatsKVKeyNotFoundException)
        {
            return null;
        }
    }

    public async Task<ForgejoDeliveryLedgerEntry> CreateAsync(
        string key,
        string value,
        CancellationToken cancellationToken)
    {
        try
        {
            var revision = await store.CreateAsync(key, value, cancellationToken: cancellationToken);
            return new(value, revision);
        }
        catch (NatsKVCreateException exception)
        {
            throw new ForgejoDeliveryLedgerConflictException(exception);
        }
    }

    public async Task<ForgejoDeliveryLedgerEntry> UpdateAsync(
        string key,
        string value,
        ulong revision,
        CancellationToken cancellationToken)
    {
        try
        {
            var updated = await store.UpdateAsync(key, value, revision, cancellationToken: cancellationToken);
            return new(value, updated);
        }
        catch (NatsKVWrongLastRevisionException exception)
        {
            throw new ForgejoDeliveryLedgerConflictException(exception);
        }
    }

    public async IAsyncEnumerable<string> ListKeysAsync(
        string filter,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await foreach (var key in store.GetKeysAsync(
            [filter],
            new NatsKVWatchOpts { IgnoreDeletes = true },
            cancellationToken))
            yield return key;
    }

    public async Task DeleteAsync(
        string key,
        ulong revision,
        CancellationToken cancellationToken)
    {
        try
        {
            await store.DeleteAsync(key, new NatsKVDeleteOpts { Revision = revision }, cancellationToken);
        }
        catch (NatsKVWrongLastRevisionException exception)
        {
            throw new ForgejoDeliveryLedgerConflictException(exception);
        }
    }
}

[JsonSerializable(typeof(ForgejoWebhookJournalDocument))]
internal sealed partial class ForgejoWebhookJournalJsonContext : JsonSerializerContext;
