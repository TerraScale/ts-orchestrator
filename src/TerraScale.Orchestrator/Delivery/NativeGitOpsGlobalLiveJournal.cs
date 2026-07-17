using System.Buffers;
using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace TerraScale.Orchestrator.Delivery;

internal enum NativeGitOpsGlobalLiveJournalDisposition
{
    Unspecified,
    Recorded,
    Duplicate,
    Incomplete,
    StaleGlobalAuthority,
    StaleReceiptAuthority,
    StaleGeneration,
    GenerationConflict,
    StaleLiveProof,
    StaleAuthority,
    Contention,
}

internal sealed record NativeGitOpsGlobalLiveCellProof(
    [property: JsonPropertyName("c")] string Cell,
    [property: JsonPropertyName("p")] string PayloadSha256Base64,
    [property: JsonPropertyName("e")] long RegionalWriterEpoch,
    [property: JsonPropertyName("a")] ulong AcceptanceRevision,
    [property: JsonPropertyName("j")] ulong CheckpointJournalRevision,
    [property: JsonPropertyName("r")] ulong LiveReceiptJournalRevision);

internal sealed record NativeGitOpsDurableGlobalLiveBarrier(
    long Generation,
    string GlobalPlanDigest,
    string HandoffDigest,
    string BarrierDigest,
    string CompletionDigest,
    IReadOnlyList<NativeGitOpsGlobalLiveCellProof> Cells,
    long GlobalAuthorityEpoch,
    DateTimeOffset CompletedAt,
    ulong JournalRevision);

internal sealed record NativeGitOpsGlobalLiveJournalReceipt(
    NativeGitOpsGlobalLiveJournalDisposition Disposition,
    NativeGitOpsDurableGlobalLiveBarrier? Barrier)
{
    internal bool CanAdvanceGlobal =>
        (Disposition is NativeGitOpsGlobalLiveJournalDisposition.Recorded or
            NativeGitOpsGlobalLiveJournalDisposition.Duplicate) &&
        Barrier is not null;
}

/// <summary>
/// Commits the exact complete signed cross-cell live barrier before the accepted global plan can
/// advance. Raw signatures remain in the per-cell journals so restart can re-run KMS verification.
/// </summary>
internal sealed class NativeGitOpsGlobalLiveJournal(IForgejoDeliveryLedger ledger)
{
    private const string Index = "gitops.live.global";
    internal const int MaximumRecordBytes = 16 * 1024;
    private const int MaximumConflictRetries = 4;

    internal async Task<NativeGitOpsDurableGlobalLiveBarrier?> ReadAsync(
        CancellationToken cancellationToken = default)
    {
        var entry = await ledger.GetAsync(Index, cancellationToken);
        return entry is null ? null : Deserialize(entry.Value).Durable(entry.Revision);
    }

    internal async Task<NativeGitOpsGlobalLiveJournalReceipt> CompleteAsync(
        NativeGitOpsCellHandoffDescriptor handoff,
        IReadOnlyDictionary<string, long> expectedRegionalWriterEpochs,
        IEnumerable<NativeGitOpsDurableLiveReceipt> durableReceipts,
        long globalAuthorityEpoch,
        DateTimeOffset now,
        TimeSpan allowedClockSkew,
        INativeGitOpsCellConvergenceReceiptVerifier verifier,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(handoff);
        ArgumentNullException.ThrowIfNull(expectedRegionalWriterEpochs);
        ArgumentNullException.ThrowIfNull(durableReceipts);
        ArgumentNullException.ThrowIfNull(verifier);
        ArgumentNullException.ThrowIfNull(authorityStillValid);
        if (globalAuthorityEpoch <= 0) throw new ArgumentOutOfRangeException(nameof(globalAuthorityEpoch));
        if (now == default) throw new ArgumentOutOfRangeException(nameof(now));

        var captured = durableReceipts.Take(NativeGitOpsCellSpecCompiler.MaximumCellsPerHandoff + 1).ToArray();
        if (captured.Length > NativeGitOpsCellSpecCompiler.MaximumCellsPerHandoff ||
            captured.Any(receipt => receipt is null || receipt.JournalRevision == 0 ||
                receipt.AcceptedAt == default || receipt.AcceptedAt > now) ||
            captured.Select(static receipt => receipt.Envelope.Receipt.Cell)
                .Distinct(StringComparer.Ordinal).Count() != captured.Length)
            throw new InvalidDataException("The durable native GitOps live receipt set is invalid.");
        if (captured.Any(receipt => receipt.GlobalAuthorityEpoch > globalAuthorityEpoch))
            return new(NativeGitOpsGlobalLiveJournalDisposition.StaleGlobalAuthority, null);
        if (captured.Any(receipt => receipt.GlobalAuthorityEpoch < globalAuthorityEpoch))
            return new(NativeGitOpsGlobalLiveJournalDisposition.StaleReceiptAuthority, null);

        var barrier = NativeGitOpsLiveBarrierEvaluator.Evaluate(
            handoff,
            expectedRegionalWriterEpochs,
            captured.Select(static receipt => receipt.Envelope),
            now,
            allowedClockSkew,
            verifier);
        if (!barrier.IsComplete)
            return new(NativeGitOpsGlobalLiveJournalDisposition.Incomplete, null);

        var proposed = NativeGitOpsGlobalLiveDocument.From(
            barrier,
            captured,
            globalAuthorityEpoch,
            now);
        proposed.Validate();
        for (var attempt = 0; attempt < MaximumConflictRetries; attempt++)
        {
            var entry = await ledger.GetAsync(Index, cancellationToken);
            var current = entry is null ? null : Deserialize(entry.Value);
            var disposition = Compare(current, proposed);
            if (disposition is NativeGitOpsGlobalLiveJournalDisposition.Duplicate)
                return new(disposition.Value, current!.Durable(entry!.Revision));
            if (disposition is not null)
                return new(disposition.Value, current?.Durable(entry!.Revision));
            if (!authorityStillValid())
                return new(NativeGitOpsGlobalLiveJournalDisposition.StaleAuthority, null);
            try
            {
                var updated = entry is null
                    ? await ledger.CreateAsync(Index, Serialize(proposed), cancellationToken)
                    : await ledger.UpdateAsync(Index, Serialize(proposed), entry.Revision, cancellationToken);
                return new(
                    NativeGitOpsGlobalLiveJournalDisposition.Recorded,
                    proposed.Durable(updated.Revision));
            }
            catch (ForgejoDeliveryLedgerConflictException)
            {
            }
        }
        return new(NativeGitOpsGlobalLiveJournalDisposition.Contention, null);
    }

    private static NativeGitOpsGlobalLiveJournalDisposition? Compare(
        NativeGitOpsGlobalLiveDocument? current,
        NativeGitOpsGlobalLiveDocument proposed)
    {
        if (current is null) return null;
        if (proposed.GlobalAuthorityEpoch < current.GlobalAuthorityEpoch)
            return NativeGitOpsGlobalLiveJournalDisposition.StaleGlobalAuthority;
        if (proposed.Generation < current.Generation)
            return NativeGitOpsGlobalLiveJournalDisposition.StaleGeneration;
        if (proposed.Generation > current.Generation)
            return NewGenerationMonotonic(current, proposed)
                ? null
                : NativeGitOpsGlobalLiveJournalDisposition.StaleLiveProof;
        if (!SameHandoff(current, proposed))
            return NativeGitOpsGlobalLiveJournalDisposition.GenerationConflict;
        if (!Monotonic(current, proposed))
            return NativeGitOpsGlobalLiveJournalDisposition.StaleLiveProof;
        return SameCompletion(current, proposed)
            ? NativeGitOpsGlobalLiveJournalDisposition.Duplicate
            : null;
    }

    private static bool SameHandoff(
        NativeGitOpsGlobalLiveDocument current,
        NativeGitOpsGlobalLiveDocument proposed) =>
        proposed.GlobalPlanDigest == current.GlobalPlanDigest &&
        proposed.HandoffDigest == current.HandoffDigest &&
        proposed.Cells.Select(static cell => (cell.Cell, cell.PayloadSha256Base64))
            .SequenceEqual(current.Cells.Select(static cell => (cell.Cell, cell.PayloadSha256Base64)));

    private static bool Monotonic(
        NativeGitOpsGlobalLiveDocument current,
        NativeGitOpsGlobalLiveDocument proposed)
    {
        var proofAdvanced = false;
        for (var index = 0; index < proposed.Cells.Length; index++)
        {
            var before = current.Cells[index];
            var after = proposed.Cells[index];
            if (after.RegionalWriterEpoch < before.RegionalWriterEpoch ||
                after.AcceptanceRevision < before.AcceptanceRevision ||
                after.CheckpointJournalRevision < before.CheckpointJournalRevision ||
                after.LiveReceiptJournalRevision < before.LiveReceiptJournalRevision)
                return false;
            var changed = after.RegionalWriterEpoch != before.RegionalWriterEpoch ||
                after.AcceptanceRevision != before.AcceptanceRevision ||
                after.CheckpointJournalRevision != before.CheckpointJournalRevision;
            if (changed)
            {
                if (after.LiveReceiptJournalRevision <= before.LiveReceiptJournalRevision) return false;
                proofAdvanced = true;
                continue;
            }
        }
        var sameBarrier = proposed.BarrierDigest == current.BarrierDigest;
        if (proposed.GlobalAuthorityEpoch > current.GlobalAuthorityEpoch)
            return proposed.Cells.Zip(current.Cells)
                .All(pair => pair.First.LiveReceiptJournalRevision > pair.Second.LiveReceiptJournalRevision) &&
                (sameBarrier || proofAdvanced);
        return sameBarrier
            ? proposed.Cells.Zip(current.Cells).All(pair =>
                pair.First.LiveReceiptJournalRevision == pair.Second.LiveReceiptJournalRevision)
            : proofAdvanced;
    }

    private static bool NewGenerationMonotonic(
        NativeGitOpsGlobalLiveDocument current,
        NativeGitOpsGlobalLiveDocument proposed)
    {
        var previous = current.Cells.ToDictionary(static cell => cell.Cell, StringComparer.Ordinal);
        foreach (var after in proposed.Cells)
        {
            if (previous.TryGetValue(after.Cell, out var before) &&
                (after.RegionalWriterEpoch < before.RegionalWriterEpoch ||
                 after.AcceptanceRevision <= before.AcceptanceRevision ||
                 after.CheckpointJournalRevision <= before.CheckpointJournalRevision ||
                 after.LiveReceiptJournalRevision <= before.LiveReceiptJournalRevision))
                return false;
        }
        return true;
    }

    private static bool SameCompletion(
        NativeGitOpsGlobalLiveDocument current,
        NativeGitOpsGlobalLiveDocument proposed) =>
        proposed.GlobalAuthorityEpoch == current.GlobalAuthorityEpoch &&
        proposed.BarrierDigest == current.BarrierDigest &&
        proposed.Cells.SequenceEqual(current.Cells);

    private static NativeGitOpsGlobalLiveDocument Deserialize(string value)
    {
        try
        {
            var document = JsonSerializer.Deserialize(
                value,
                NativeGitOpsGlobalLiveJsonContext.Default.NativeGitOpsGlobalLiveDocument)
                ?? throw new JsonException();
            document.Validate();
            return document;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("A native GitOps global live journal record is invalid.", exception);
        }
    }

    private static string Serialize(NativeGitOpsGlobalLiveDocument document)
    {
        var value = JsonSerializer.Serialize(
            document,
            NativeGitOpsGlobalLiveJsonContext.Default.NativeGitOpsGlobalLiveDocument);
        if (Encoding.UTF8.GetByteCount(value) > MaximumRecordBytes)
            throw new InvalidDataException("A native GitOps global live journal record exceeded its bound.");
        return value;
    }
}

internal sealed record NativeGitOpsGlobalLiveDocument(
    [property: JsonPropertyName("v")] int SchemaVersion,
    [property: JsonPropertyName("g")] long Generation,
    [property: JsonPropertyName("p")] string GlobalPlanDigest,
    [property: JsonPropertyName("h")] string HandoffDigest,
    [property: JsonPropertyName("b")] string BarrierDigest,
    [property: JsonPropertyName("d")] string CompletionDigest,
    [property: JsonPropertyName("c")] NativeGitOpsGlobalLiveCellProof[] Cells,
    [property: JsonPropertyName("a")] long GlobalAuthorityEpoch,
    [property: JsonPropertyName("t")] DateTimeOffset CompletedAt)
{
    internal static NativeGitOpsGlobalLiveDocument From(
        NativeGitOpsLiveBarrier barrier,
        IReadOnlyCollection<NativeGitOpsDurableLiveReceipt> durableReceipts,
        long globalAuthorityEpoch,
        DateTimeOffset completedAt)
    {
        var durable = durableReceipts.ToDictionary(
            static receipt => receipt.Envelope.Receipt.Cell,
            StringComparer.Ordinal);
        var cells = barrier.Receipts.Select(verified =>
        {
            var receipt = durable[verified.Receipt.Cell];
            return new NativeGitOpsGlobalLiveCellProof(
                verified.Receipt.Cell,
                Convert.ToBase64String(Convert.FromHexString(verified.Receipt.PayloadSha256)),
                verified.Receipt.RegionalWriterEpoch,
                verified.Receipt.AcceptanceRevision,
                verified.Receipt.CheckpointJournalRevision,
                receipt.JournalRevision);
        }).ToArray();
        var document = new NativeGitOpsGlobalLiveDocument(
            1,
            barrier.Generation,
            barrier.GlobalPlanDigest,
            barrier.HandoffDigest,
            barrier.BarrierDigest!,
            string.Empty,
            cells,
            globalAuthorityEpoch,
            completedAt);
        return document with { CompletionDigest = ComputeCompletionDigest(document) };
    }

    internal NativeGitOpsDurableGlobalLiveBarrier Durable(ulong journalRevision) => new(
        Generation,
        GlobalPlanDigest,
        HandoffDigest,
        BarrierDigest,
        CompletionDigest,
        new ReadOnlyCollection<NativeGitOpsGlobalLiveCellProof>(Cells.ToArray()),
        GlobalAuthorityEpoch,
        CompletedAt,
        journalRevision);

    internal void Validate()
    {
        if (SchemaVersion != 1 || Generation <= 0 || GlobalAuthorityEpoch <= 0 || CompletedAt == default ||
            !Digest(GlobalPlanDigest) || !Digest(HandoffDigest) || !Digest(BarrierDigest) ||
            !Digest(CompletionDigest) ||
            Cells is not { Length: > 0 and <= NativeGitOpsCellSpecCompiler.MaximumCellsPerHandoff } ||
            Cells.Any(static cell => cell is null || PayloadSha256(cell.PayloadSha256Base64) is null ||
                cell.RegionalWriterEpoch <= 0 || cell.AcceptanceRevision == 0 ||
                cell.CheckpointJournalRevision == 0 || cell.LiveReceiptJournalRevision == 0) ||
            !Cells.SequenceEqual(
                Cells.DistinctBy(static cell => cell.Cell, StringComparer.Ordinal)
                    .OrderBy(static cell => cell.Cell, StringComparer.Ordinal)))
            throw new InvalidDataException("A native GitOps global live journal record is invalid.");

        var handoff = new NativeGitOpsCellHandoffDescriptor(
            Generation,
            GlobalPlanDigest,
            HandoffDigest,
            Cells.Select(static cell => new NativeGitOpsCellDigest(
                cell.Cell,
                PayloadSha256(cell.PayloadSha256Base64)!)).ToArray());
        if (!NativeGitOpsCellEnvelope.IsValidDescriptor(handoff) ||
            ComputeCompletionDigest(this) != CompletionDigest)
            throw new InvalidDataException("A native GitOps global live journal proof failed integrity verification.");
    }

    private static string ComputeCompletionDigest(NativeGitOpsGlobalLiveDocument document)
    {
        var bytes = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(bytes))
        {
            writer.WriteStartObject();
            writer.WriteNumber("globalAuthorityEpoch", document.GlobalAuthorityEpoch);
            writer.WriteNumber("generation", document.Generation);
            writer.WriteString("globalPlanDigest", document.GlobalPlanDigest);
            writer.WriteString("handoffDigest", document.HandoffDigest);
            writer.WriteString("barrierDigest", document.BarrierDigest);
            writer.WriteString("completedAt", document.CompletedAt);
            writer.WriteStartArray("cells");
            foreach (var cell in document.Cells)
            {
                writer.WriteStartObject();
                writer.WriteString("cell", cell.Cell);
                writer.WriteString("payloadSha256Base64", cell.PayloadSha256Base64);
                writer.WriteNumber("regionalWriterEpoch", cell.RegionalWriterEpoch);
                writer.WriteNumber("acceptanceRevision", cell.AcceptanceRevision);
                writer.WriteNumber("checkpointJournalRevision", cell.CheckpointJournalRevision);
                writer.WriteNumber("liveReceiptJournalRevision", cell.LiveReceiptJournalRevision);
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
            writer.WriteEndObject();
        }
        return Convert.ToHexStringLower(SHA256.HashData(bytes.WrittenSpan));
    }

    private static bool Digest(string? value) => value is { Length: 64 } &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static string? PayloadSha256(string? value)
    {
        if (string.IsNullOrEmpty(value)) return null;
        try
        {
            var bytes = Convert.FromBase64String(value);
            return bytes.Length == 32 && Convert.ToBase64String(bytes) == value
                ? Convert.ToHexStringLower(bytes)
                : null;
        }
        catch (FormatException)
        {
            return null;
        }
    }
}

[JsonSerializable(typeof(NativeGitOpsGlobalLiveDocument))]
internal sealed partial class NativeGitOpsGlobalLiveJsonContext : JsonSerializerContext;
