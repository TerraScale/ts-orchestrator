using System.Buffers;
using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Text.Json;

namespace TerraScale.Orchestrator.Delivery;

internal enum NativeGitOpsCellBarrierState
{
    Unspecified,
    Pending,
    Complete,
}

internal sealed record NativeGitOpsCellBarrier(
    NativeGitOpsCellBarrierState State,
    long Generation,
    string GlobalPlanDigest,
    string HandoffDigest,
    IReadOnlyList<NativeGitOpsAcceptedCellSpec> Receipts,
    IReadOnlyList<string> MissingCells,
    string? BarrierDigest)
{
    internal bool IsComplete => State == NativeGitOpsCellBarrierState.Complete &&
        MissingCells.Count == 0 && BarrierDigest is not null;
}

/// <summary>
/// Evaluates durable regional acceptance receipts against one exact aggregate handoff. Completion
/// proves only CellSpec acceptance, not apply, health, live convergence, or deployment success.
/// </summary>
internal static class NativeGitOpsCellBarrierEvaluator
{
    internal static NativeGitOpsCellBarrier Evaluate(
        NativeGitOpsCellHandoffDescriptor handoff,
        IEnumerable<NativeGitOpsAcceptedCellSpec> receipts)
    {
        ArgumentNullException.ThrowIfNull(handoff);
        ArgumentNullException.ThrowIfNull(receipts);
        if (!NativeGitOpsCellEnvelope.IsValidDescriptor(handoff))
            throw new InvalidDataException("The native GitOps acceptance barrier handoff is invalid.");
        var captured = receipts.Take(NativeGitOpsCellSpecCompiler.MaximumCellsPerHandoff + 1).ToArray();
        if (captured.Length > NativeGitOpsCellSpecCompiler.MaximumCellsPerHandoff ||
            captured.Any(static receipt => receipt is null))
            throw new InvalidDataException("The native GitOps acceptance barrier receipts are invalid.");
        var ordered = captured.Select(Copy)
            .OrderBy(static receipt => receipt.Cell, StringComparer.Ordinal)
            .ToArray();
        if (ordered.Select(static receipt => receipt.Cell).Distinct(StringComparer.Ordinal).Count() != ordered.Length)
            throw new InvalidDataException("The native GitOps acceptance barrier contains a duplicate cell.");
        var expected = handoff.Cells.ToDictionary(static item => item.Cell, StringComparer.Ordinal);
        foreach (var receipt in ordered)
        {
            if (!expected.TryGetValue(receipt.Cell, out var cell) || !Valid(receipt, handoff, cell))
                throw new InvalidDataException("A native GitOps acceptance receipt does not match the handoff.");
        }
        var missing = handoff.Cells.Select(static item => item.Cell)
            .Except(ordered.Select(static receipt => receipt.Cell), StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();
        return missing.Length == 0
            ? new(
                NativeGitOpsCellBarrierState.Complete,
                handoff.Generation,
                handoff.GlobalPlanDigest,
                handoff.HandoffDigest,
                ReadOnly(ordered),
                ReadOnly(missing),
                Digest(handoff, ordered))
            : new(
                NativeGitOpsCellBarrierState.Pending,
                handoff.Generation,
                handoff.GlobalPlanDigest,
                handoff.HandoffDigest,
                ReadOnly(ordered),
                ReadOnly(missing),
                null);
    }

    private static bool Valid(
        NativeGitOpsAcceptedCellSpec receipt,
        NativeGitOpsCellHandoffDescriptor handoff,
        NativeGitOpsCellDigest cell) =>
        receipt.Generation == handoff.Generation && receipt.GlobalPlanDigest == handoff.GlobalPlanDigest &&
        receipt.HandoffDigest == handoff.HandoffDigest && receipt.PayloadSha256 == cell.PayloadSha256 &&
        receipt.Payload.Length is > 0 and <= NativeGitOpsCellSpecCompiler.MaximumCellSpecBytes &&
        Convert.ToHexStringLower(SHA256.HashData(receipt.Payload.Span)) == receipt.PayloadSha256 &&
        receipt.WriterEpoch > 0 && receipt.ProtocolVersion == 1 && receipt.DeliveryAttempt == 1 &&
        receipt.OperationId == $"gitops/{handoff.HandoffDigest}/{receipt.Cell}" &&
        receipt.IdempotencyKey == $"gitops/{receipt.PayloadSha256}" &&
        receipt.ExpiresAt > receipt.IssuedAt && receipt.StreamSequence > 0 &&
        receipt.JournalRevision > 0 && receipt.AcceptedAt != default && IsDigest(receipt.SignatureSha256);

    private static NativeGitOpsAcceptedCellSpec Copy(NativeGitOpsAcceptedCellSpec receipt) => new(
        receipt.Cell,
        receipt.Generation,
        receipt.GlobalPlanDigest,
        receipt.HandoffDigest,
        receipt.PayloadSha256,
        receipt.Payload.ToArray(),
        receipt.WriterEpoch,
        receipt.ProtocolVersion,
        receipt.OperationId,
        receipt.IdempotencyKey,
        receipt.DeliveryAttempt,
        receipt.IssuedAt,
        receipt.ExpiresAt,
        receipt.AcceptedAt,
        receipt.StreamSequence,
        receipt.SignatureSha256,
        receipt.JournalRevision);

    private static string Digest(
        NativeGitOpsCellHandoffDescriptor handoff,
        IReadOnlyList<NativeGitOpsAcceptedCellSpec> receipts)
    {
        var bytes = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(bytes))
        {
            writer.WriteStartObject();
            writer.WriteNumber("generation", handoff.Generation);
            writer.WriteString("globalPlanDigest", handoff.GlobalPlanDigest);
            writer.WriteString("handoffDigest", handoff.HandoffDigest);
            writer.WriteStartArray("receipts");
            foreach (var receipt in receipts)
            {
                writer.WriteStartObject();
                writer.WriteString("cell", receipt.Cell);
                writer.WriteString("payloadSha256", receipt.PayloadSha256);
                writer.WriteNumber("writerEpoch", receipt.WriterEpoch);
                writer.WriteNumber("streamSequence", receipt.StreamSequence);
                writer.WriteNumber("journalRevision", receipt.JournalRevision);
                writer.WriteString("signatureSha256", receipt.SignatureSha256);
                writer.WriteString("acceptedAt", receipt.AcceptedAt);
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
            writer.WriteEndObject();
        }
        return Convert.ToHexStringLower(SHA256.HashData(bytes.WrittenSpan));
    }

    private static bool IsDigest(string value) => value.Length == 64 &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static IReadOnlyList<T> ReadOnly<T>(T[] values) =>
        new ReadOnlyCollection<T>(values);
}

