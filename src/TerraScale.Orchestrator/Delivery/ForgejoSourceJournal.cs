using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace TerraScale.Orchestrator.Delivery;

public enum ForgejoSourceJournalDisposition
{
    Unspecified,
    Recorded,
    Duplicate,
    StaleAuthority,
    StaleSequence,
    IdentityConflict,
    UnprotectedBranch,
}

public sealed class ForgejoSourceJournalReceipt
{
    internal ForgejoSourceJournalReceipt(ForgejoSourceJournalDisposition disposition) =>
        Disposition = disposition;

    public ForgejoSourceJournalDisposition Disposition { get; }
}

/// <summary>Fences durable branch observations by regional authority epoch and poll sequence.</summary>
public sealed class ForgejoSourceJournal
{
    private const int MaximumConflictRetries = 8;
    private readonly IForgejoDeliveryLedger ledger;

    internal ForgejoSourceJournal(IForgejoDeliveryLedger ledger) => this.ledger = ledger;

    public async Task<ForgejoSourceJournalReceipt> ObserveAsync(
        ForgejoBranchObservation observation,
        long authorityEpoch,
        long pollSequence,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(observation);
        if (authorityEpoch <= 0) throw new ArgumentOutOfRangeException(nameof(authorityEpoch));
        if (pollSequence <= 0) throw new ArgumentOutOfRangeException(nameof(pollSequence));
        if (!observation.Protected)
            return new(ForgejoSourceJournalDisposition.UnprotectedBranch);

        var proposed = ForgejoSourceJournalDocument.From(observation, authorityEpoch, pollSequence);
        proposed.Validate();
        var key = Index(proposed.SourceKey);
        for (var attempt = 0; attempt < MaximumConflictRetries; attempt++)
        {
            var current = await ledger.GetAsync(key, cancellationToken);
            if (current is null)
            {
                try
                {
                    await ledger.CreateAsync(key, Serialize(proposed), cancellationToken);
                    return new(ForgejoSourceJournalDisposition.Recorded);
                }
                catch (ForgejoDeliveryLedgerConflictException)
                {
                    continue;
                }
            }

            var observed = Read(current);
            if (observed.SourceKey != proposed.SourceKey)
                throw new InvalidDataException("A Forgejo source journal index changed identity.");
            if (authorityEpoch < observed.AuthorityEpoch)
                return new(ForgejoSourceJournalDisposition.StaleAuthority);
            if (authorityEpoch == observed.AuthorityEpoch && pollSequence < observed.PollSequence)
                return new(ForgejoSourceJournalDisposition.StaleSequence);
            if (authorityEpoch == observed.AuthorityEpoch && pollSequence == observed.PollSequence)
                return new(observed.SameSource(proposed)
                    ? ForgejoSourceJournalDisposition.Duplicate
                    : ForgejoSourceJournalDisposition.IdentityConflict);

            try
            {
                await ledger.UpdateAsync(key, Serialize(proposed), current.Revision, cancellationToken);
                return new(ForgejoSourceJournalDisposition.Recorded);
            }
            catch (ForgejoDeliveryLedgerConflictException)
            {
            }
        }

        throw new InvalidOperationException("The Forgejo source journal could not resolve a concurrent observation.");
    }

    private static ForgejoSourceJournalDocument Read(ForgejoDeliveryLedgerEntry entry)
    {
        try
        {
            var document = JsonSerializer.Deserialize(
                entry.Value,
                ForgejoSourceJournalJsonContext.Default.ForgejoSourceJournalDocument)
                ?? throw new JsonException();
            document.Validate();
            return document;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("A Forgejo source journal record is invalid.", exception);
        }
    }

    private static string Serialize(ForgejoSourceJournalDocument document) => JsonSerializer.Serialize(
        document,
        ForgejoSourceJournalJsonContext.Default.ForgejoSourceJournalDocument);

    private static string Index(string sourceKey) => $"source.{Convert.ToHexStringLower(
        SHA256.HashData(Encoding.UTF8.GetBytes(sourceKey)))}";
}

internal sealed record ForgejoSourceJournalDocument(
    int SchemaVersion,
    string SourceKey,
    string Repository,
    string Branch,
    string Commit,
    string Tree,
    bool SignatureVerified,
    bool Protected,
    long AuthorityEpoch,
    long PollSequence)
{
    internal static ForgejoSourceJournalDocument From(
        ForgejoBranchObservation observation,
        long authorityEpoch,
        long pollSequence) => new(
            1,
            $"forgejo-source:{observation.Revision.Repository}:{observation.Branch}",
            observation.Revision.Repository,
            observation.Branch,
            observation.Revision.Commit,
            observation.Revision.Tree,
            observation.Revision.SignatureVerified,
            observation.Protected,
            authorityEpoch,
            pollSequence);

    internal bool SameSource(ForgejoSourceJournalDocument other) =>
        Repository == other.Repository && Branch == other.Branch &&
        StringComparer.OrdinalIgnoreCase.Equals(Commit, other.Commit) &&
        StringComparer.OrdinalIgnoreCase.Equals(Tree, other.Tree) &&
        SignatureVerified == other.SignatureVerified && Protected == other.Protected;

    internal void Validate()
    {
        if (SchemaVersion != 1 || !ForgejoWebhookVerifier.IsRepository(Repository) ||
            Branch is not ("develop" or "main") || !Protected ||
            !IsObjectId(Commit) || Commit.All(static value => value == '0') ||
            !IsObjectId(Tree) || Tree.All(static value => value == '0') ||
            AuthorityEpoch <= 0 || PollSequence <= 0 ||
            SourceKey != $"forgejo-source:{Repository}:{Branch}")
            throw new InvalidDataException("A Forgejo source journal record is invalid.");
    }

    private static bool IsObjectId(string value) => value.Length is 40 or 64 &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F');
}

[JsonSerializable(typeof(ForgejoSourceJournalDocument))]
internal sealed partial class ForgejoSourceJournalJsonContext : JsonSerializerContext;

