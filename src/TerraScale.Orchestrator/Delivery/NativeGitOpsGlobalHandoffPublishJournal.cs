using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace TerraScale.Orchestrator.Delivery;

internal enum NativeGitOpsGlobalHandoffPublishJournalDisposition
{
    Unspecified,
    Recorded,
    Duplicate,
    StaleAuthority,
    StaleSourceRevision,
    StaleGeneration,
    HandoffConflict,
    PreparedHandoffConflict,
    StreamSequenceConflict,
    ConcurrentUpdate,
}

internal sealed record NativeGitOpsGlobalPublishedCell(
    string Cell,
    string WireSha256,
    ulong StreamSequence);

internal sealed record NativeGitOpsGlobalHandoffPublishSnapshot(
    string Repository,
    string Branch,
    ulong SourceJournalRevision,
    long AuthorityEpoch,
    long Generation,
    string GlobalPlanDigest,
    string HandoffDigest,
    ulong SignedHandoffJournalRevision,
    int RequiredCellCount,
    IReadOnlyList<NativeGitOpsGlobalPublishedCell> Cells,
    ulong JournalRevision)
{
    internal bool IsComplete => Cells.Count == RequiredCellCount;
}

internal sealed record NativeGitOpsGlobalHandoffPublishJournalReceipt(
    NativeGitOpsGlobalHandoffPublishJournalDisposition Disposition,
    NativeGitOpsGlobalHandoffPublishSnapshot? Snapshot);

/// <summary>
/// CAS-journals each exact GLOBAL_SPEC storage acknowledgement. Restarts can therefore skip cells
/// already stored for the current signed handoff and resume only the missing sequential suffix.
/// </summary>
internal sealed class NativeGitOpsGlobalHandoffPublishJournal(IForgejoDeliveryLedger ledger)
{
    internal const int MaximumRecordBytes = 16 * 1024;

    internal async Task<NativeGitOpsGlobalHandoffPublishSnapshot?> ReadAsync(
        string repository,
        string branch,
        CancellationToken cancellationToken = default)
    {
        ValidateSource(repository, branch);
        var entry = await ledger.GetAsync(Index(repository, branch), cancellationToken);
        if (entry is null) return null;
        var document = Deserialize(entry.Value);
        if (document.Repository != repository || document.Branch != branch)
            throw new InvalidDataException("A native GitOps global publish journal changed source identity.");
        return document.Snapshot(entry.Revision);
    }

    internal async Task<NativeGitOpsGlobalHandoffPublishJournalReceipt> RecordAsync(
        NativeGitOpsPreparedHandoff handoff,
        NativeGitOpsGlobalCellPublishReceipt publication,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(handoff);
        ArgumentNullException.ThrowIfNull(publication);
        ArgumentNullException.ThrowIfNull(authorityStillValid);
        NativeGitOpsGlobalHandoffPublisher.Validate(handoff);
        var prepared = handoff.Cells.SingleOrDefault(cell => cell.Cell == publication.Cell)
            ?? throw new InvalidDataException("The global publication cell is not part of the signed handoff.");
        if (!publication.IsDurable || publication.Disposition is not (
                NativeGitOpsGlobalCellPublishDisposition.Published or
                NativeGitOpsGlobalCellPublishDisposition.Duplicate) ||
            publication.WireSha256 != prepared.WireSha256)
            throw new InvalidDataException("The global publication is not a current durable acknowledgement.");

        var key = Index(handoff.Repository, handoff.Branch);
        var entry = await ledger.GetAsync(key, cancellationToken);
        NativeGitOpsGlobalHandoffPublishDocument proposed;
        if (entry is null)
        {
            proposed = NativeGitOpsGlobalHandoffPublishDocument.From(handoff, publication);
        }
        else
        {
            var current = Deserialize(entry.Value);
            if (current.Repository != handoff.Repository || current.Branch != handoff.Branch)
                throw new InvalidDataException("A native GitOps global publish journal changed source identity.");
            var disposition = Compare(current.Snapshot(entry.Revision), handoff);
            if (disposition is not null)
                return new(disposition.Value, current.Snapshot(entry.Revision));
            if (current.SamePreparedHandoff(handoff))
            {
                var existing = current.Cells.SingleOrDefault(cell => cell.Cell == publication.Cell);
                if (existing is not null)
                {
                    return new(
                        existing.WireSha256 == publication.WireSha256 &&
                        existing.StreamSequence == publication.StreamSequence
                            ? NativeGitOpsGlobalHandoffPublishJournalDisposition.Duplicate
                            : NativeGitOpsGlobalHandoffPublishJournalDisposition.StreamSequenceConflict,
                        current.Snapshot(entry.Revision));
                }
                proposed = current.Add(publication);
            }
            else
            {
                proposed = NativeGitOpsGlobalHandoffPublishDocument.From(handoff, publication);
            }
        }
        if (!authorityStillValid())
            return new(
                NativeGitOpsGlobalHandoffPublishJournalDisposition.StaleAuthority,
                entry is null ? null : Deserialize(entry.Value).Snapshot(entry.Revision));

        var value = Serialize(proposed);
        try
        {
            var committed = entry is null
                ? await ledger.CreateAsync(key, value, cancellationToken)
                : await ledger.UpdateAsync(key, value, entry.Revision, cancellationToken);
            return new(
                NativeGitOpsGlobalHandoffPublishJournalDisposition.Recorded,
                proposed.Snapshot(committed.Revision));
        }
        catch (ForgejoDeliveryLedgerConflictException)
        {
            var winner = await ledger.GetAsync(key, cancellationToken);
            return new(
                NativeGitOpsGlobalHandoffPublishJournalDisposition.ConcurrentUpdate,
                winner is null ? null : Deserialize(winner.Value).Snapshot(winner.Revision));
        }
    }

    internal static NativeGitOpsGlobalHandoffPublishJournalDisposition? Compare(
        NativeGitOpsGlobalHandoffPublishSnapshot current,
        NativeGitOpsPreparedHandoff proposed)
    {
        if (proposed.AuthorityEpoch < current.AuthorityEpoch)
            return NativeGitOpsGlobalHandoffPublishJournalDisposition.StaleAuthority;
        if (proposed.Descriptor.Generation < current.Generation)
            return NativeGitOpsGlobalHandoffPublishJournalDisposition.StaleGeneration;
        if (proposed.Descriptor.Generation == current.Generation &&
            (proposed.Descriptor.GlobalPlanDigest != current.GlobalPlanDigest ||
             proposed.Descriptor.HandoffDigest != current.HandoffDigest))
            return NativeGitOpsGlobalHandoffPublishJournalDisposition.HandoffConflict;
        if (proposed.SourceJournalRevision < current.SourceJournalRevision ||
            proposed.Descriptor.Generation > current.Generation &&
            proposed.SourceJournalRevision <= current.SourceJournalRevision)
            return NativeGitOpsGlobalHandoffPublishJournalDisposition.StaleSourceRevision;
        if (proposed.AuthorityEpoch == current.AuthorityEpoch &&
            proposed.Descriptor.Generation == current.Generation)
            return SamePreparedHandoff(current, proposed)
                ? null
                : NativeGitOpsGlobalHandoffPublishJournalDisposition.PreparedHandoffConflict;
        return proposed.JournalRevision > current.SignedHandoffJournalRevision
            ? null
            : NativeGitOpsGlobalHandoffPublishJournalDisposition.PreparedHandoffConflict;
    }

    internal static bool SamePreparedHandoff(
        NativeGitOpsGlobalHandoffPublishSnapshot current,
        NativeGitOpsPreparedHandoff handoff) =>
        current.Repository == handoff.Repository && current.Branch == handoff.Branch &&
        current.SourceJournalRevision == handoff.SourceJournalRevision &&
        current.AuthorityEpoch == handoff.AuthorityEpoch &&
        current.Generation == handoff.Descriptor.Generation &&
        current.GlobalPlanDigest == handoff.Descriptor.GlobalPlanDigest &&
        current.HandoffDigest == handoff.Descriptor.HandoffDigest &&
        current.SignedHandoffJournalRevision == handoff.JournalRevision &&
        current.RequiredCellCount == handoff.Cells.Count &&
        current.Cells.All(cell => handoff.Cells.Any(prepared =>
            prepared.Cell == cell.Cell && prepared.WireSha256 == cell.WireSha256));

    private static string Serialize(NativeGitOpsGlobalHandoffPublishDocument document)
    {
        document.Validate();
        var value = JsonSerializer.Serialize(
            document,
            NativeGitOpsGlobalHandoffPublishJsonContext.Default.NativeGitOpsGlobalHandoffPublishDocument);
        if (Encoding.UTF8.GetByteCount(value) > MaximumRecordBytes)
            throw new InvalidDataException("A native GitOps global publish journal exceeded its bound.");
        return value;
    }

    private static NativeGitOpsGlobalHandoffPublishDocument Deserialize(string value)
    {
        try
        {
            var document = JsonSerializer.Deserialize(
                value,
                NativeGitOpsGlobalHandoffPublishJsonContext.Default.NativeGitOpsGlobalHandoffPublishDocument)
                ?? throw new JsonException();
            document.Validate();
            if (value != Serialize(document)) throw new JsonException();
            return document;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("A native GitOps global publish journal is invalid.", exception);
        }
    }

    private static void ValidateSource(string repository, string branch)
    {
        if (!ForgejoWebhookVerifier.IsRepository(repository) || branch is not ("develop" or "main"))
            throw new ArgumentException("The native GitOps global publish source identity is invalid.");
    }

    private static string Index(string repository, string branch) => $"gitops.global-publish.{Convert.ToHexStringLower(
        SHA256.HashData(Encoding.UTF8.GetBytes($"native-gitops-global-publish:{repository}:{branch}")))}";
}

internal sealed record NativeGitOpsGlobalPublishedCellDocument(
    [property: JsonPropertyName("c")] string Cell,
    [property: JsonPropertyName("w")] string WireSha256,
    [property: JsonPropertyName("q")] ulong StreamSequence);

internal sealed record NativeGitOpsGlobalHandoffPublishDocument(
    [property: JsonPropertyName("v")] int SchemaVersion,
    [property: JsonPropertyName("r")] string Repository,
    [property: JsonPropertyName("b")] string Branch,
    [property: JsonPropertyName("s")] ulong SourceJournalRevision,
    [property: JsonPropertyName("e")] long AuthorityEpoch,
    [property: JsonPropertyName("g")] long Generation,
    [property: JsonPropertyName("p")] string GlobalPlanDigest,
    [property: JsonPropertyName("h")] string HandoffDigest,
    [property: JsonPropertyName("j")] ulong SignedHandoffJournalRevision,
    [property: JsonPropertyName("n")] int RequiredCellCount,
    [property: JsonPropertyName("c")] IReadOnlyList<NativeGitOpsGlobalPublishedCellDocument> Cells)
{
    internal static NativeGitOpsGlobalHandoffPublishDocument From(
        NativeGitOpsPreparedHandoff handoff,
        NativeGitOpsGlobalCellPublishReceipt publication) => new(
        1,
        handoff.Repository,
        handoff.Branch,
        handoff.SourceJournalRevision,
        handoff.AuthorityEpoch,
        handoff.Descriptor.Generation,
        handoff.Descriptor.GlobalPlanDigest,
        handoff.Descriptor.HandoffDigest,
        handoff.JournalRevision,
        handoff.Cells.Count,
        Array.AsReadOnly([
            new NativeGitOpsGlobalPublishedCellDocument(
                publication.Cell,
                publication.WireSha256,
                publication.StreamSequence),
        ]));

    internal bool SamePreparedHandoff(NativeGitOpsPreparedHandoff handoff) =>
        Repository == handoff.Repository && Branch == handoff.Branch &&
        SourceJournalRevision == handoff.SourceJournalRevision &&
        AuthorityEpoch == handoff.AuthorityEpoch && Generation == handoff.Descriptor.Generation &&
        GlobalPlanDigest == handoff.Descriptor.GlobalPlanDigest &&
        HandoffDigest == handoff.Descriptor.HandoffDigest &&
        SignedHandoffJournalRevision == handoff.JournalRevision &&
        RequiredCellCount == handoff.Cells.Count &&
        Cells.All(cell => handoff.Cells.Any(prepared =>
            prepared.Cell == cell.Cell && prepared.WireSha256 == cell.WireSha256));

    internal NativeGitOpsGlobalHandoffPublishDocument Add(
        NativeGitOpsGlobalCellPublishReceipt publication) => this with
        {
            Cells = Array.AsReadOnly(Cells.Append(new(
                publication.Cell,
                publication.WireSha256,
                publication.StreamSequence))
            .OrderBy(static cell => cell.Cell, StringComparer.Ordinal)
            .ToArray()),
        };

    internal NativeGitOpsGlobalHandoffPublishSnapshot Snapshot(ulong revision) => new(
        Repository,
        Branch,
        SourceJournalRevision,
        AuthorityEpoch,
        Generation,
        GlobalPlanDigest,
        HandoffDigest,
        SignedHandoffJournalRevision,
        RequiredCellCount,
        new ReadOnlyCollection<NativeGitOpsGlobalPublishedCell>(Cells.Select(static cell =>
            new NativeGitOpsGlobalPublishedCell(
            cell.Cell,
            cell.WireSha256,
            cell.StreamSequence)).ToArray()),
        revision);

    internal void Validate()
    {
        if (SchemaVersion != 1 || !ForgejoWebhookVerifier.IsRepository(Repository) ||
            Branch is not ("develop" or "main") || SourceJournalRevision == 0 || AuthorityEpoch <= 0 ||
            Generation <= 0 || !Digest(GlobalPlanDigest) || !Digest(HandoffDigest) ||
            SignedHandoffJournalRevision == 0 || RequiredCellCount is < 1 or > 64 ||
            Cells is not { Count: > 0 } || Cells.Count > RequiredCellCount ||
            !Cells.SequenceEqual(Cells.OrderBy(static cell => cell.Cell, StringComparer.Ordinal)) ||
            Cells.Select(static cell => cell.Cell).Distinct(StringComparer.Ordinal).Count() != Cells.Count ||
            Cells.Any(static cell => !Cell(cell.Cell) || !Digest(cell.WireSha256) || cell.StreamSequence == 0))
            throw new InvalidDataException("A native GitOps global publish journal is invalid.");
    }

    private static bool Cell(string value)
    {
        try
        {
            _ = new Runtime.RuntimeAllocationId(value);
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private static bool Digest(string value) => value is { Length: 64 } &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f');
}

[JsonSerializable(typeof(NativeGitOpsGlobalHandoffPublishDocument))]
internal sealed partial class NativeGitOpsGlobalHandoffPublishJsonContext : JsonSerializerContext;

