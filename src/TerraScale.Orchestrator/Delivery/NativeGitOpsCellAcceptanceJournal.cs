using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using TerraScale.Orchestrator.Protocol;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.Delivery;

internal enum NativeGitOpsCellAcceptanceDisposition
{
    Unspecified,
    Recorded,
    Duplicate,
    ProtocolRejected,
    StaleWriter,
    StaleGeneration,
    GenerationConflict,
    IdentityConflict,
    StaleAuthority,
    Contention,
}

internal sealed record NativeGitOpsAcceptedCellSpec(
    string Cell,
    long Generation,
    string GlobalPlanDigest,
    string HandoffDigest,
    string PayloadSha256,
    ReadOnlyMemory<byte> Payload,
    long WriterEpoch,
    long ProtocolVersion,
    string OperationId,
    string IdempotencyKey,
    long DeliveryAttempt,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt,
    DateTimeOffset AcceptedAt,
    ulong StreamSequence,
    string SignatureSha256,
    ulong JournalRevision);

internal sealed record NativeGitOpsCellAcceptanceReceipt(
    NativeGitOpsCellAcceptanceDisposition Disposition,
    CommandValidationError ProtocolError,
    NativeGitOpsAcceptedCellSpec? Acceptance)
{
    internal bool CanAcknowledge =>
        (Disposition is NativeGitOpsCellAcceptanceDisposition.Recorded or
            NativeGitOpsCellAcceptanceDisposition.Duplicate) &&
        Acceptance is not null;
}

/// <summary>
/// Makes a signed regional CellSpec acknowledgeable only after its immutable payload and fenced
/// acceptance pointer are durable. This journal does not execute the accepted desired state.
/// </summary>
internal sealed class NativeGitOpsCellAcceptanceJournal
{
    private const int MaximumRecordBytes = 8 * 1024;
    private const int MaximumConflictRetries = 4;
    private readonly IForgejoDeliveryLedger ledger;
    private readonly IDeliveryObjectStore payloads;

    internal NativeGitOpsCellAcceptanceJournal(
        IForgejoDeliveryLedger ledger,
        IDeliveryObjectStore payloads)
    {
        this.ledger = ledger;
        this.payloads = payloads;
    }

    internal async Task<NativeGitOpsAcceptedCellSpec?> ReadAsync(
        string cell,
        CancellationToken cancellationToken = default)
    {
        ValidateCell(cell);
        var entry = await ledger.GetAsync(Index(cell), cancellationToken);
        return entry is null ? null : await ReadAsync(cell, entry, cancellationToken);
    }

    internal Task<NativeGitOpsCellAcceptanceReceipt> AcceptAsync(
        CommandEnvelope envelope,
        NativeGitOpsCellHandoff handoff,
        string cell,
        long expectedWriterEpoch,
        ulong streamSequence,
        DateTimeOffset now,
        TimeSpan allowedClockSkew,
        ICommandSignatureVerifier signatureVerifier,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(handoff);
        var descriptor = NativeGitOpsCellEnvelope.Describe(handoff)
            ?? throw new InvalidDataException("The native GitOps cell handoff is invalid.");
        return AcceptAsync(
            envelope,
            descriptor,
            cell,
            expectedWriterEpoch,
            streamSequence,
            now,
            allowedClockSkew,
            signatureVerifier,
            authorityStillValid,
            cancellationToken);
    }

    internal async Task<NativeGitOpsCellAcceptanceReceipt> AcceptAsync(
        CommandEnvelope envelope,
        NativeGitOpsCellHandoffDescriptor handoff,
        string cell,
        long expectedWriterEpoch,
        ulong streamSequence,
        DateTimeOffset now,
        TimeSpan allowedClockSkew,
        ICommandSignatureVerifier signatureVerifier,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        ArgumentNullException.ThrowIfNull(handoff);
        ArgumentNullException.ThrowIfNull(signatureVerifier);
        ArgumentNullException.ThrowIfNull(authorityStillValid);
        ValidateCell(cell);
        if (expectedWriterEpoch <= 0) throw new ArgumentOutOfRangeException(nameof(expectedWriterEpoch));
        if (streamSequence == 0) throw new ArgumentOutOfRangeException(nameof(streamSequence));
        if (allowedClockSkew < TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(allowedClockSkew));

        var validated = NativeGitOpsCellEnvelope.Validate(
            envelope,
            handoff,
            cell,
            expectedWriterEpoch,
            now,
            allowedClockSkew,
            signatureVerifier);
        if (!validated.IsAccepted)
            return new(
                NativeGitOpsCellAcceptanceDisposition.ProtocolRejected,
                validated.ProtocolError,
                null);

        var spec = handoff.Cells.Single(item => item.Cell == cell);
        var proposed = NativeGitOpsCellAcceptanceDocument.From(
            envelope,
            handoff,
            spec,
            streamSequence,
            now);
        proposed.Validate();
        var payloadStored = false;
        var key = Index(cell);

        for (var attempt = 0; attempt < MaximumConflictRetries; attempt++)
        {
            var entry = await ledger.GetAsync(key, cancellationToken);
            NativeGitOpsAcceptedCellSpec? accepted = null;
            if (entry is not null)
            {
                accepted = await ReadAsync(cell, entry, cancellationToken);
                var disposition = Compare(accepted, proposed);
                if (disposition is not null)
                    return new(
                        disposition.Value,
                        CommandValidationError.None,
                        disposition == NativeGitOpsCellAcceptanceDisposition.Duplicate ? accepted : null);
            }

            if (!payloadStored)
            {
                await payloads.PutAsync(proposed.PayloadObject, envelope.Payload.Bytes.ToArray(), cancellationToken);
                var verified = await payloads.GetAsync(proposed.PayloadObject, cancellationToken);
                if (!verified.AsSpan().SequenceEqual(envelope.Payload.Bytes))
                    throw new InvalidDataException("The native GitOps cell payload was not durable after storage.");
                payloadStored = true;
            }
            if (!authorityStillValid())
                return new(
                    NativeGitOpsCellAcceptanceDisposition.StaleAuthority,
                    CommandValidationError.None,
                    null);

            try
            {
                var updated = entry is null
                    ? await ledger.CreateAsync(key, Serialize(proposed), cancellationToken)
                    : await ledger.UpdateAsync(key, Serialize(proposed), entry.Revision, cancellationToken);
                return new(
                    NativeGitOpsCellAcceptanceDisposition.Recorded,
                    CommandValidationError.None,
                    Accepted(proposed, envelope.Payload.Bytes.ToArray(), updated.Revision));
            }
            catch (ForgejoDeliveryLedgerConflictException)
            {
            }
        }

        return new(
            NativeGitOpsCellAcceptanceDisposition.Contention,
            CommandValidationError.None,
            null);
    }

    private async Task<NativeGitOpsAcceptedCellSpec> ReadAsync(
        string expectedCell,
        ForgejoDeliveryLedgerEntry entry,
        CancellationToken cancellationToken)
    {
        var document = Deserialize(entry.Value);
        if (document.Cell != expectedCell)
            throw new InvalidDataException("A native GitOps cell acceptance changed identity.");
        var payload = await payloads.GetAsync(document.PayloadObject, cancellationToken);
        if (payload.Length is < 1 or > NativeGitOpsCellSpecCompiler.MaximumCellSpecBytes ||
            Convert.ToHexStringLower(SHA256.HashData(payload)) != document.PayloadSha256)
            throw new InvalidDataException("The accepted native GitOps cell payload failed integrity verification.");
        ValidatePayload(payload, document);
        return Accepted(document, payload, entry.Revision);
    }

    private static NativeGitOpsCellAcceptanceDisposition? Compare(
        NativeGitOpsAcceptedCellSpec accepted,
        NativeGitOpsCellAcceptanceDocument proposed)
    {
        if (proposed.WriterEpoch < accepted.WriterEpoch)
            return NativeGitOpsCellAcceptanceDisposition.StaleWriter;
        if (proposed.Generation < accepted.Generation)
            return NativeGitOpsCellAcceptanceDisposition.StaleGeneration;
        if (proposed.Generation != accepted.Generation) return null;
        if (proposed.GlobalPlanDigest != accepted.GlobalPlanDigest ||
            proposed.HandoffDigest != accepted.HandoffDigest ||
            proposed.PayloadSha256 != accepted.PayloadSha256)
            return NativeGitOpsCellAcceptanceDisposition.GenerationConflict;
        if (proposed.WriterEpoch > accepted.WriterEpoch) return null;
        return proposed.OperationId == accepted.OperationId &&
            proposed.IdempotencyKey == accepted.IdempotencyKey &&
            proposed.IssuedAt == accepted.IssuedAt &&
            proposed.ExpiresAt == accepted.ExpiresAt &&
            proposed.SignatureSha256 == accepted.SignatureSha256
                ? NativeGitOpsCellAcceptanceDisposition.Duplicate
                : NativeGitOpsCellAcceptanceDisposition.IdentityConflict;
    }

    private static NativeGitOpsAcceptedCellSpec Accepted(
        NativeGitOpsCellAcceptanceDocument document,
        ReadOnlyMemory<byte> payload,
        ulong journalRevision) => new(
        document.Cell,
        document.Generation,
        document.GlobalPlanDigest,
        document.HandoffDigest,
        document.PayloadSha256,
        payload,
        document.WriterEpoch,
        document.ProtocolVersion,
        document.OperationId,
        document.IdempotencyKey,
        document.DeliveryAttempt,
        document.IssuedAt,
        document.ExpiresAt,
        document.AcceptedAt,
        document.StreamSequence,
        document.SignatureSha256,
        journalRevision);

    private static void ValidatePayload(
        ReadOnlyMemory<byte> payload,
        NativeGitOpsCellAcceptanceDocument document)
    {
        try
        {
            using var parsed = JsonDocument.Parse(payload, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 16,
            });
            var root = parsed.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                !root.TryGetProperty("schemaVersion", out var schemaVersion) ||
                !schemaVersion.TryGetInt32(out var schema) || schema != 1 ||
                !root.TryGetProperty("generation", out var generation) ||
                !generation.TryGetInt64(out var generationValue) || generationValue != document.Generation ||
                !root.TryGetProperty("globalPlanDigest", out var planDigest) ||
                planDigest.ValueKind != JsonValueKind.String ||
                planDigest.GetString() != document.GlobalPlanDigest ||
                !root.TryGetProperty("cell", out var cell) || cell.ValueKind != JsonValueKind.String ||
                cell.GetString() != document.Cell)
                throw new InvalidDataException("The accepted native GitOps cell payload changed identity.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("The accepted native GitOps cell payload is invalid.", exception);
        }
    }

    private static NativeGitOpsCellAcceptanceDocument Deserialize(string value)
    {
        try
        {
            var document = JsonSerializer.Deserialize(
                value,
                NativeGitOpsCellAcceptanceJsonContext.Default.NativeGitOpsCellAcceptanceDocument)
                ?? throw new JsonException();
            document.Validate();
            return document;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("A native GitOps cell acceptance record is invalid.", exception);
        }
    }

    private static string Serialize(NativeGitOpsCellAcceptanceDocument document)
    {
        var value = JsonSerializer.Serialize(
            document,
            NativeGitOpsCellAcceptanceJsonContext.Default.NativeGitOpsCellAcceptanceDocument);
        if (Encoding.UTF8.GetByteCount(value) > MaximumRecordBytes)
            throw new InvalidDataException("The native GitOps cell acceptance record exceeded its bound.");
        return value;
    }

    private static void ValidateCell(string cell)
    {
        try
        {
            _ = new RuntimeAllocationId(cell);
        }
        catch (Exception exception) when (exception is ArgumentException or ArgumentNullException)
        {
            throw new ArgumentException("The native GitOps cell identity is invalid.", nameof(cell), exception);
        }
    }

    private static string Index(string cell) => $"gitops.cell.{Convert.ToHexStringLower(
        SHA256.HashData(Encoding.UTF8.GetBytes($"native-gitops-cell:{cell}")))}";
}

internal sealed record NativeGitOpsCellAcceptanceDocument(
    int SchemaVersion,
    string Cell,
    long Generation,
    string GlobalPlanDigest,
    string HandoffDigest,
    string PayloadSha256,
    string PayloadObject,
    long WriterEpoch,
    long ProtocolVersion,
    string OperationId,
    string IdempotencyKey,
    long DeliveryAttempt,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt,
    DateTimeOffset AcceptedAt,
    ulong StreamSequence,
    string SignatureSha256)
{
    internal static NativeGitOpsCellAcceptanceDocument From(
        CommandEnvelope envelope,
        NativeGitOpsCellHandoffDescriptor handoff,
        NativeGitOpsCellDigest spec,
        ulong streamSequence,
        DateTimeOffset acceptedAt) => new(
        1,
        spec.Cell,
        handoff.Generation,
        handoff.GlobalPlanDigest,
        handoff.HandoffDigest,
        spec.PayloadSha256,
        $"native-gitops-cell-spec-{spec.PayloadSha256}",
        envelope.WriterEpoch.Value,
        envelope.ProtocolVersion.Value,
        envelope.OperationId.Value,
        envelope.IdempotencyKey.Value,
        envelope.Attempt.Value,
        envelope.IssuedAt,
        envelope.ExpiresAt,
        acceptedAt,
        streamSequence,
        Convert.ToHexStringLower(SHA256.HashData(envelope.Signature.Bytes)));

    internal void Validate()
    {
        try
        {
            _ = new RuntimeAllocationId(Cell);
        }
        catch (Exception exception) when (exception is ArgumentException or ArgumentNullException)
        {
            throw new InvalidDataException("A native GitOps cell acceptance record is invalid.", exception);
        }
        if (SchemaVersion != 1 || Generation <= 0 || WriterEpoch <= 0 || ProtocolVersion <= 0 ||
            DeliveryAttempt <= 0 || StreamSequence == 0 || ExpiresAt <= IssuedAt ||
            !IsDigest(GlobalPlanDigest) || !IsDigest(HandoffDigest) || !IsDigest(PayloadSha256) ||
            !IsDigest(SignatureSha256) || PayloadObject != $"native-gitops-cell-spec-{PayloadSha256}" ||
            OperationId != $"gitops/{HandoffDigest}/{Cell}" ||
            IdempotencyKey != $"gitops/{PayloadSha256}")
            throw new InvalidDataException("A native GitOps cell acceptance record is invalid.");
    }

    private static bool IsDigest(string value) => value.Length == 64 &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f');
}

[JsonSerializable(typeof(NativeGitOpsCellAcceptanceDocument))]
internal sealed partial class NativeGitOpsCellAcceptanceJsonContext : JsonSerializerContext;

