using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using TerraScale.Orchestrator.ControlPlane.Delivery;

namespace TerraScale.Orchestrator.Delivery;

public enum PublicAlphaReleaseReceiptJournalDisposition
{
    Unspecified,
    Recorded,
    Duplicate,
    Contention,
}

public sealed class PublicAlphaReleaseReceiptJournalResult
{
    internal PublicAlphaReleaseReceiptJournalResult(PublicAlphaReleaseReceiptJournalDisposition disposition) =>
        Disposition = disposition;

    public PublicAlphaReleaseReceiptJournalDisposition Disposition { get; }
}

/// <summary>Durably appends digest-bound Public Alpha release evidence and decisions.</summary>
public sealed class PublicAlphaReleaseReceiptJournal
{
    private const int MaximumConflictRetries = 8;
    private readonly IForgejoDeliveryLedger ledger;

    internal PublicAlphaReleaseReceiptJournal(IForgejoDeliveryLedger ledger) => this.ledger = ledger;

    public async Task<PublicAlphaReleaseReceipt?> ReadAsync(
        string releaseId,
        CancellationToken cancellationToken = default)
    {
        if (!Required(releaseId)) throw new ArgumentException("A release identity is required.", nameof(releaseId));
        var entry = await ledger.GetAsync(Index(releaseId), cancellationToken);
        if (entry is null) return null;
        var receipt = Read(entry.Value);
        if (!string.Equals(receipt.ReleaseId, releaseId, StringComparison.Ordinal))
            throw new InvalidDataException("A Public Alpha release receipt index changed identity.");
        return receipt;
    }

    public async Task<PublicAlphaReleaseReceiptJournalResult> AppendAsync(
        PublicAlphaReleaseReceipt receipt,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        var proposed = PublicAlphaReleaseReceiptJournalDocument.From(receipt);
        proposed.Validate();
        var key = Index(receipt.ReleaseId);

        for (var attempt = 0; attempt < MaximumConflictRetries; attempt++)
        {
            var current = await ledger.GetAsync(key, cancellationToken);
            if (current is null)
            {
                try
                {
                    await ledger.CreateAsync(key, Serialize(proposed), cancellationToken);
                    return new(PublicAlphaReleaseReceiptJournalDisposition.Recorded);
                }
                catch (ForgejoDeliveryLedgerConflictException)
                {
                    continue;
                }
            }

            var observed = ReadDocument(current.Value);
            if (!observed.SameIdentity(proposed))
                throw new InvalidDataException("A Public Alpha release receipt changed release identity.");

            var merged = observed.Merge(proposed);
            if (merged == observed)
                return new(PublicAlphaReleaseReceiptJournalDisposition.Duplicate);

            try
            {
                await ledger.UpdateAsync(key, Serialize(merged), current.Revision, cancellationToken);
                return new(PublicAlphaReleaseReceiptJournalDisposition.Recorded);
            }
            catch (ForgejoDeliveryLedgerConflictException)
            {
            }
        }

        return new(PublicAlphaReleaseReceiptJournalDisposition.Contention);
    }

    private static PublicAlphaReleaseReceipt Read(string value) => ReadDocument(value).ToReceipt();

    private static PublicAlphaReleaseReceiptJournalDocument ReadDocument(string value)
    {
        try
        {
            var document = JsonSerializer.Deserialize(
                value,
                PublicAlphaReleaseReceiptJournalJsonContext.Default.PublicAlphaReleaseReceiptJournalDocument)
                ?? throw new JsonException();
            document.Validate();
            return document;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("A Public Alpha release receipt record is invalid.", exception);
        }
    }

    private static string Serialize(PublicAlphaReleaseReceiptJournalDocument document) => JsonSerializer.Serialize(
        document,
        PublicAlphaReleaseReceiptJournalJsonContext.Default.PublicAlphaReleaseReceiptJournalDocument);

    private static string Index(string releaseId) => $"public-alpha-release.{Convert.ToHexStringLower(
        SHA256.HashData(Encoding.UTF8.GetBytes(releaseId)))}";

    private static bool Required(string? value) =>
        value is { Length: <= 256 } && !string.IsNullOrWhiteSpace(value);
}

internal sealed record PublicAlphaReleaseReceiptJournalDocument(
    int SchemaVersion,
    string ReleaseId,
    string SourceRevision,
    string CandidateDigest,
    string PreviousQualifiedDigest,
    string ConfigurationRevision,
    string MigrationSetDigest,
    string PreviousQualifiedConfigurationRevision,
    string PreviousQualifiedMigrationSetDigest,
    DateTimeOffset CreatedAt,
    PublicAlphaReceiptEvidenceLink[] EvidenceLinks,
    PublicAlphaReceiptEvent[] Events,
    string Digest)
{
    internal static PublicAlphaReleaseReceiptJournalDocument From(PublicAlphaReleaseReceipt receipt) => new(
        1,
        receipt.ReleaseId,
        receipt.SourceRevision,
        receipt.CandidateDigest,
        receipt.PreviousQualifiedDigest,
        receipt.ConfigurationRevision,
        receipt.MigrationSetDigest,
        receipt.PreviousQualifiedConfigurationRevision,
        receipt.PreviousQualifiedMigrationSetDigest,
        receipt.CreatedAt,
        receipt.EvidenceLinks.ToArray(),
        receipt.Events.ToArray(),
        receipt.Digest);

    internal bool SameIdentity(PublicAlphaReleaseReceiptJournalDocument other) =>
        ReleaseId == other.ReleaseId && SourceRevision == other.SourceRevision &&
        CandidateDigest == other.CandidateDigest && PreviousQualifiedDigest == other.PreviousQualifiedDigest &&
        ConfigurationRevision == other.ConfigurationRevision && MigrationSetDigest == other.MigrationSetDigest &&
        PreviousQualifiedConfigurationRevision == other.PreviousQualifiedConfigurationRevision &&
        PreviousQualifiedMigrationSetDigest == other.PreviousQualifiedMigrationSetDigest &&
        CreatedAt == other.CreatedAt;

    internal PublicAlphaReleaseReceiptJournalDocument Merge(PublicAlphaReleaseReceiptJournalDocument proposed)
    {
        var links = EvidenceLinks.Concat(proposed.EvidenceLinks).Distinct().ToArray();
        // A retried operation may carry a fresh observation timestamp. Treat the
        // decision identity as the idempotency key so a replay cannot append a
        // second logical activation/rollback event merely because its clock moved.
        var events = Events.Concat(proposed.Events)
            .GroupBy(static item => (item.Decision, item.Actor, item.GlobalDigest))
            .Select(static group => group.First())
            .ToArray();
        if (links.Length == EvidenceLinks.Length && events.Length == Events.Length) return this;
        return From(ToReceipt(links, events));
    }

    internal PublicAlphaReleaseReceipt ToReceipt() => ToReceipt(EvidenceLinks, Events);

    internal void Validate()
    {
        if (SchemaVersion != 1 || !SafeLabel(ReleaseId) || !ObjectId(SourceRevision) ||
            !DigestValue(CandidateDigest) || !DigestValue(PreviousQualifiedDigest) ||
            CandidateDigest == PreviousQualifiedDigest || !SafeLabel(ConfigurationRevision) ||
            !DigestValue(MigrationSetDigest) || !SafeLabel(PreviousQualifiedConfigurationRevision) ||
            !DigestValue(PreviousQualifiedMigrationSetDigest) || CreatedAt == default ||
            EvidenceLinks is null or { Length: > 512 } || Events is null or { Length: > 512 } ||
            EvidenceLinks.Any(static link => link is null || !SafeLabel(link.Kind) || !DigestValue(link.Digest)) ||
            Events.Any(item => item is null || !SafeLabel(item.Decision) || !SafeLabel(item.Actor) ||
                item.RecordedAt == default || item.RecordedAt < CreatedAt || !DigestValue(item.GlobalDigest) ||
                !ValidEvent(item)) ||
            EvidenceLinks.Distinct().Count() != EvidenceLinks.Length ||
            Events.Distinct().Count() != Events.Length || !DigestValue(Digest))
            throw new InvalidDataException("A Public Alpha release receipt record is invalid.");

        var receipt = ToReceipt();
        if (!string.Equals(receipt.Digest, Digest, StringComparison.Ordinal))
            throw new InvalidDataException("A Public Alpha release receipt digest is invalid.");
    }

    private PublicAlphaReleaseReceipt ToReceipt(
        IReadOnlyList<PublicAlphaReceiptEvidenceLink> links,
        IReadOnlyList<PublicAlphaReceiptEvent> events) => new(
        new(ReleaseId, SourceRevision, CandidateDigest, PreviousQualifiedDigest, ConfigurationRevision,
            MigrationSetDigest, PreviousQualifiedConfigurationRevision, PreviousQualifiedMigrationSetDigest, CreatedAt),
        links,
        events);

    private static bool Required(string? value) =>
        value is { Length: <= 256 } && !string.IsNullOrWhiteSpace(value);

    private static bool SafeLabel(string? value) => Required(value) &&
        !value!.Contains('\n', StringComparison.Ordinal) && !value.Contains('\r', StringComparison.Ordinal) &&
        !new[]
        {
            "authorization:", "bearer ", "password=", "password:", "secret=", "secret:",
            "token=", "token:", "query=", "-----BEGIN",
        }.Any(marker => value.Contains(marker, StringComparison.OrdinalIgnoreCase));

    private static bool ObjectId(string? value) => value is { Length: 40 or 64 } &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static bool DigestValue(string? value) =>
        PublicAlphaDigest.IsValid(value);

    private bool ValidEvent(PublicAlphaReceiptEvent item) => item.Decision switch
    {
        "activate" or "verified" => item.GlobalDigest == CandidateDigest,
        "rollback" => item.GlobalDigest == PreviousQualifiedDigest,
        "converge" => item.GlobalDigest is not null &&
            (item.GlobalDigest == CandidateDigest || item.GlobalDigest == PreviousQualifiedDigest),
        _ => false,
    };
}

[JsonSerializable(typeof(PublicAlphaReleaseReceiptJournalDocument))]
internal sealed partial class PublicAlphaReleaseReceiptJournalJsonContext : JsonSerializerContext;
