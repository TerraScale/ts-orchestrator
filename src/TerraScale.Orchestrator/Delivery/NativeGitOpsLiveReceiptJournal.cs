using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using TerraScale.Orchestrator.Protocol;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.Delivery;

internal enum NativeGitOpsLiveReceiptJournalDisposition
{
    Unspecified,
    Recorded,
    Duplicate,
    InvalidReceipt,
    StaleGlobalAuthority,
    StaleRegionalWriter,
    StaleGeneration,
    GenerationConflict,
    StaleCheckpoint,
    StaleAuthority,
    Contention,
}

internal sealed record NativeGitOpsDurableLiveReceipt(
    NativeGitOpsCellConvergenceReceiptEnvelope Envelope,
    long GlobalAuthorityEpoch,
    DateTimeOffset AcceptedAt,
    ulong JournalRevision);

internal sealed record NativeGitOpsLiveReceiptJournalReceipt(
    NativeGitOpsLiveReceiptJournalDisposition Disposition,
    NativeGitOpsCellConvergenceReceiptError ValidationError,
    NativeGitOpsDurableLiveReceipt? Receipt)
{
    internal bool CanAcknowledge =>
        (Disposition is NativeGitOpsLiveReceiptJournalDisposition.Recorded or
            NativeGitOpsLiveReceiptJournalDisposition.Duplicate) &&
        Receipt is not null;
}

/// <summary>
/// Retains the exact signed regional live receipt before global acknowledgement. Stored signature
/// bytes allow the global barrier to re-run the configured KMS trust policy after restart.
/// </summary>
internal sealed class NativeGitOpsLiveReceiptJournal(IForgejoDeliveryLedger ledger)
{
    private const int MaximumRecordBytes = 32 * 1024;
    private const int MaximumConflictRetries = 4;

    internal async Task<NativeGitOpsDurableLiveReceipt?> ReadAsync(
        string cell,
        CancellationToken cancellationToken = default)
    {
        ValidateCell(cell);
        var entry = await ledger.GetAsync(Index(cell), cancellationToken);
        if (entry is null) return null;
        var document = Deserialize(entry.Value);
        if (document.Receipt.Cell != cell)
            throw new InvalidDataException("A native GitOps live receipt journal changed cell identity.");
        return document.Durable(entry.Revision);
    }

    internal async Task<NativeGitOpsLiveReceiptJournalReceipt> AcceptAsync(
        NativeGitOpsCellHandoffDescriptor handoff,
        IReadOnlyDictionary<string, long> expectedRegionalWriterEpochs,
        NativeGitOpsCellConvergenceReceiptEnvelope envelope,
        long globalAuthorityEpoch,
        DateTimeOffset now,
        TimeSpan allowedClockSkew,
        INativeGitOpsCellConvergenceReceiptVerifier verifier,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(handoff);
        ArgumentNullException.ThrowIfNull(expectedRegionalWriterEpochs);
        ArgumentNullException.ThrowIfNull(envelope);
        ArgumentNullException.ThrowIfNull(verifier);
        ArgumentNullException.ThrowIfNull(authorityStillValid);
        if (globalAuthorityEpoch <= 0) throw new ArgumentOutOfRangeException(nameof(globalAuthorityEpoch));
        if (!expectedRegionalWriterEpochs.TryGetValue(envelope.Receipt.Cell, out var regionalEpoch))
            return new(
                NativeGitOpsLiveReceiptJournalDisposition.InvalidReceipt,
                NativeGitOpsCellConvergenceReceiptError.WrongHandoff,
                null);
        var validation = NativeGitOpsCellConvergenceReceipt.Validate(
            envelope,
            handoff,
            envelope.Receipt.Cell,
            regionalEpoch,
            now,
            allowedClockSkew,
            verifier);
        if (!validation.IsValid)
            return new(
                NativeGitOpsLiveReceiptJournalDisposition.InvalidReceipt,
                validation.Error,
                null);
        var proposed = NativeGitOpsLiveReceiptDocument.From(envelope, globalAuthorityEpoch, now);
        proposed.Validate();
        var key = Index(envelope.Receipt.Cell);

        for (var attempt = 0; attempt < MaximumConflictRetries; attempt++)
        {
            var entry = await ledger.GetAsync(key, cancellationToken);
            var current = entry is null ? null : Deserialize(entry.Value);
            var disposition = Compare(current, proposed);
            var currentDurable = current is not null && entry is { } currentEntry
                ? current.Durable(currentEntry.Revision)
                : null;
            if (disposition is NativeGitOpsLiveReceiptJournalDisposition.Duplicate)
            {
                if (currentDurable is null)
                    throw new InvalidDataException("A duplicate native GitOps live receipt lost its durable revision.");
                return new(disposition.Value, NativeGitOpsCellConvergenceReceiptError.None, currentDurable);
            }
            if (disposition is not null)
                return new(disposition.Value, NativeGitOpsCellConvergenceReceiptError.None,
                    currentDurable);
            if (!authorityStillValid())
                return new(
                    NativeGitOpsLiveReceiptJournalDisposition.StaleAuthority,
                    NativeGitOpsCellConvergenceReceiptError.None,
                    null);
            try
            {
                var updated = entry is null
                    ? await ledger.CreateAsync(key, Serialize(proposed), cancellationToken)
                    : await ledger.UpdateAsync(key, Serialize(proposed), entry.Revision, cancellationToken);
                return new(
                    NativeGitOpsLiveReceiptJournalDisposition.Recorded,
                    NativeGitOpsCellConvergenceReceiptError.None,
                    proposed.Durable(updated.Revision));
            }
            catch (ForgejoDeliveryLedgerConflictException)
            {
            }
        }
        return new(
            NativeGitOpsLiveReceiptJournalDisposition.Contention,
            NativeGitOpsCellConvergenceReceiptError.None,
            null);
    }

    private static NativeGitOpsLiveReceiptJournalDisposition? Compare(
        NativeGitOpsLiveReceiptDocument? current,
        NativeGitOpsLiveReceiptDocument proposed)
    {
        if (current is null) return null;
        if (proposed.GlobalAuthorityEpoch < current.GlobalAuthorityEpoch)
            return NativeGitOpsLiveReceiptJournalDisposition.StaleGlobalAuthority;
        if (proposed.Receipt.Generation < current.Receipt.Generation)
            return NativeGitOpsLiveReceiptJournalDisposition.StaleGeneration;
        if (proposed.Receipt.Generation == current.Receipt.Generation &&
            (proposed.Receipt.GlobalPlanDigest != current.Receipt.GlobalPlanDigest ||
             proposed.Receipt.HandoffDigest != current.Receipt.HandoffDigest ||
             proposed.Receipt.PayloadSha256 != current.Receipt.PayloadSha256))
            return NativeGitOpsLiveReceiptJournalDisposition.GenerationConflict;
        if (proposed.Receipt.RegionalWriterEpoch < current.Receipt.RegionalWriterEpoch)
            return NativeGitOpsLiveReceiptJournalDisposition.StaleRegionalWriter;
        if (proposed.SameEnvelope(current))
            return proposed.GlobalAuthorityEpoch == current.GlobalAuthorityEpoch
                ? NativeGitOpsLiveReceiptJournalDisposition.Duplicate
                : null;

        var newGeneration = proposed.Receipt.Generation > current.Receipt.Generation;
        var newRegionalWriter = proposed.Receipt.RegionalWriterEpoch > current.Receipt.RegionalWriterEpoch;
        if (proposed.Receipt.CheckpointSequence <= current.Receipt.CheckpointSequence ||
            proposed.Receipt.CheckpointJournalRevision <= current.Receipt.CheckpointJournalRevision ||
            (newGeneration || newRegionalWriter) &&
            (proposed.Receipt.AcceptanceStreamSequence <= current.Receipt.AcceptanceStreamSequence ||
             proposed.Receipt.AcceptanceRevision <= current.Receipt.AcceptanceRevision))
            return NativeGitOpsLiveReceiptJournalDisposition.StaleCheckpoint;
        return null;
    }

    private static NativeGitOpsLiveReceiptDocument Deserialize(string value)
    {
        try
        {
            var document = JsonSerializer.Deserialize(
                value,
                NativeGitOpsLiveReceiptJsonContext.Default.NativeGitOpsLiveReceiptDocument)
                ?? throw new JsonException();
            document.Validate();
            return document;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("A native GitOps live receipt journal record is invalid.", exception);
        }
    }

    private static string Serialize(NativeGitOpsLiveReceiptDocument document)
    {
        var value = JsonSerializer.Serialize(
            document,
            NativeGitOpsLiveReceiptJsonContext.Default.NativeGitOpsLiveReceiptDocument);
        if (Encoding.UTF8.GetByteCount(value) > MaximumRecordBytes)
            throw new InvalidDataException("A native GitOps live receipt journal record exceeded its bound.");
        return value;
    }

    private static void ValidateCell(string cell)
    {
        try { _ = new RuntimeAllocationId(cell); }
        catch (Exception exception) when (exception is ArgumentException or ArgumentNullException)
        {
            throw new ArgumentException("The native GitOps live receipt cell identity is invalid.", nameof(cell), exception);
        }
    }

    private static string Index(string cell) => $"gitops.live.{Convert.ToHexStringLower(
        SHA256.HashData(Encoding.UTF8.GetBytes($"native-gitops-live:{cell}")))}";
}

internal sealed record NativeGitOpsLiveReceiptDocument(
    int SchemaVersion,
    NativeGitOpsCellConvergenceReceiptData Receipt,
    string SignatureBase64,
    long GlobalAuthorityEpoch,
    DateTimeOffset AcceptedAt)
{
    internal static NativeGitOpsLiveReceiptDocument From(
        NativeGitOpsCellConvergenceReceiptEnvelope envelope,
        long globalAuthorityEpoch,
        DateTimeOffset acceptedAt) => new(
        1,
        envelope.Receipt,
        Convert.ToBase64String(envelope.Signature.Bytes),
        globalAuthorityEpoch,
        acceptedAt);

    internal NativeGitOpsDurableLiveReceipt Durable(ulong revision) => new(
        Envelope(),
        GlobalAuthorityEpoch,
        AcceptedAt,
        revision);

    internal bool SameEnvelope(NativeGitOpsLiveReceiptDocument other) =>
        Receipt == other.Receipt && SignatureBase64 == other.SignatureBase64;

    internal void Validate()
    {
        if (SchemaVersion != 1 || GlobalAuthorityEpoch <= 0 || AcceptedAt == default ||
            Receipt is null || string.IsNullOrEmpty(SignatureBase64) ||
            !NativeGitOpsCellConvergenceReceipt.StructurallyValid(Receipt))
            throw new InvalidDataException("A native GitOps live receipt journal record is invalid.");
        try
        {
            var signature = Convert.FromBase64String(SignatureBase64);
            if (signature.Length is < 1 or > NativeGitOpsCellConvergenceReceipt.MaximumSignatureBytes ||
                Convert.ToBase64String(signature) != SignatureBase64)
                throw new InvalidDataException("A native GitOps live receipt journal signature is invalid.");
        }
        catch (FormatException exception)
        {
            throw new InvalidDataException("A native GitOps live receipt journal signature is invalid.", exception);
        }
    }

    private NativeGitOpsCellConvergenceReceiptEnvelope Envelope()
    {
        if (!OpaqueSignature.TryCopyFrom(Convert.FromBase64String(SignatureBase64), out var signature) ||
            signature is null)
            throw new InvalidDataException("A native GitOps live receipt signature could not be decoded.");
        return new(Receipt, signature);
    }
}

[JsonSerializable(typeof(NativeGitOpsLiveReceiptDocument))]
internal sealed partial class NativeGitOpsLiveReceiptJsonContext : JsonSerializerContext;

