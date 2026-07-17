using System.Buffers;
using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Text.Json;
using TerraScale.Orchestrator.Protocol;

namespace TerraScale.Orchestrator.Delivery;

internal interface INativeGitOpsCellConvergenceReceiptSigner
{
    OpaqueSignature Sign(ReadOnlyMemory<byte> canonicalMaterial);
}

internal interface INativeGitOpsCellConvergenceReceiptVerifier
{
    VerificationOutcome Verify(
        string cell,
        ReadOnlyMemory<byte> canonicalMaterial,
        OpaqueSignature signature);
}

internal enum NativeGitOpsCellConvergenceReceiptError
{
    None,
    InvalidInput,
    WrongHandoff,
    StaleWriter,
    OutsideValidityWindow,
    InvalidSignature,
}

internal enum NativeGitOpsLiveBarrierState
{
    Unspecified,
    Pending,
    Complete,
}

internal sealed record NativeGitOpsCellConvergenceReceiptData(
    int ProtocolVersion,
    string Cell,
    long Generation,
    string GlobalPlanDigest,
    string HandoffDigest,
    string PayloadSha256,
    string ConvergenceDigest,
    long RegionalWriterEpoch,
    ulong AcceptanceStreamSequence,
    ulong AcceptanceRevision,
    long CheckpointSequence,
    string CheckpointDigest,
    ulong CheckpointJournalRevision,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt);

internal sealed record NativeGitOpsCellConvergenceReceiptEnvelope(
    NativeGitOpsCellConvergenceReceiptData Receipt,
    OpaqueSignature Signature);

internal sealed record NativeGitOpsCellConvergenceReceiptValidation(
    NativeGitOpsCellConvergenceReceiptError Error,
    NativeGitOpsCellConvergenceReceiptData? Receipt,
    string? SignatureSha256)
{
    internal bool IsValid => Error == NativeGitOpsCellConvergenceReceiptError.None &&
        Receipt is not null && SignatureSha256 is not null;
}

internal sealed record NativeGitOpsVerifiedCellConvergence(
    NativeGitOpsCellConvergenceReceiptData Receipt,
    string SignatureSha256);

internal sealed record NativeGitOpsLiveBarrier(
    NativeGitOpsLiveBarrierState State,
    long Generation,
    string GlobalPlanDigest,
    string HandoffDigest,
    IReadOnlyList<NativeGitOpsVerifiedCellConvergence> Receipts,
    IReadOnlyList<string> MissingCells,
    string? BarrierDigest)
{
    internal bool IsComplete => State == NativeGitOpsLiveBarrierState.Complete &&
        MissingCells.Count == 0 && BarrierDigest is not null;
}

/// <summary>
/// Signs and verifies exact regional live-convergence checkpoints. The injected signer/verifier
/// owns the selected production KMS algorithm, identity, trust roots, and revocation policy.
/// </summary>
internal static class NativeGitOpsCellConvergenceReceipt
{
    internal const int MaximumSignatureBytes = 16 * 1024;

    internal static NativeGitOpsCellConvergenceReceiptEnvelope Sign(
        NativeGitOpsCellConvergenceCheckpoint checkpoint,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        INativeGitOpsCellConvergenceReceiptSigner signer)
    {
        ArgumentNullException.ThrowIfNull(checkpoint);
        ArgumentNullException.ThrowIfNull(signer);
        if (!checkpoint.Decision.IsConverged || expiresAt <= issuedAt)
            throw new ArgumentException("A signed convergence receipt requires a complete checkpoint and validity window.");
        var receipt = new NativeGitOpsCellConvergenceReceiptData(
            1,
            checkpoint.Cell,
            checkpoint.Generation,
            checkpoint.GlobalPlanDigest,
            checkpoint.HandoffDigest,
            checkpoint.PayloadSha256,
            checkpoint.Decision.ConvergenceDigest!,
            checkpoint.WriterEpoch,
            checkpoint.AcceptanceStreamSequence,
            checkpoint.AcceptanceRevision,
            checkpoint.CheckpointSequence,
            checkpoint.CheckpointDigest,
            checkpoint.JournalRevision,
            issuedAt,
            expiresAt);
        if (!StructurallyValid(receipt)) throw new InvalidDataException("The convergence checkpoint is invalid.");
        var signature = signer.Sign(Material(receipt));
        if (signature is not { IsValid: true } || signature.Length > MaximumSignatureBytes)
            throw new InvalidDataException("The convergence receipt signer returned an invalid signature.");
        return new(receipt, signature);
    }

    internal static NativeGitOpsCellConvergenceReceiptValidation Validate(
        NativeGitOpsCellConvergenceReceiptEnvelope? envelope,
        NativeGitOpsCellHandoffDescriptor? handoff,
        string expectedCell,
        long expectedRegionalWriterEpoch,
        DateTimeOffset now,
        TimeSpan allowedClockSkew,
        INativeGitOpsCellConvergenceReceiptVerifier? verifier)
    {
        if (envelope is null || handoff is null || verifier is null || expectedRegionalWriterEpoch <= 0 ||
            allowedClockSkew < TimeSpan.Zero || !NativeGitOpsCellEnvelope.IsValidDescriptor(handoff))
            return Invalid(NativeGitOpsCellConvergenceReceiptError.InvalidInput);
        var receipt = envelope.Receipt;
        var expected = handoff.Cells.SingleOrDefault(value => value.Cell == expectedCell);
        if (expected is null || !StructurallyValid(receipt) || receipt.Cell != expectedCell ||
            receipt.Generation != handoff.Generation || receipt.GlobalPlanDigest != handoff.GlobalPlanDigest ||
            receipt.HandoffDigest != handoff.HandoffDigest || receipt.PayloadSha256 != expected.PayloadSha256)
            return Invalid(NativeGitOpsCellConvergenceReceiptError.WrongHandoff);
        if (receipt.RegionalWriterEpoch != expectedRegionalWriterEpoch)
            return Invalid(NativeGitOpsCellConvergenceReceiptError.StaleWriter);
        if (receipt.IssuedAt - now > allowedClockSkew || now - receipt.ExpiresAt >= allowedClockSkew)
            return Invalid(NativeGitOpsCellConvergenceReceiptError.OutsideValidityWindow);
        if (envelope.Signature is not { IsValid: true } || envelope.Signature.Length > MaximumSignatureBytes ||
            verifier.Verify(receipt.Cell, Material(receipt), envelope.Signature) != VerificationOutcome.Valid)
            return Invalid(NativeGitOpsCellConvergenceReceiptError.InvalidSignature);
        return new(
            NativeGitOpsCellConvergenceReceiptError.None,
            receipt,
            Convert.ToHexStringLower(SHA256.HashData(envelope.Signature.Bytes)));
    }

    internal static ReadOnlyMemory<byte> Material(NativeGitOpsCellConvergenceReceiptData receipt)
    {
        var bytes = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(bytes))
        {
            writer.WriteStartObject();
            writer.WriteNumber("protocolVersion", receipt.ProtocolVersion);
            writer.WriteString("cell", receipt.Cell);
            writer.WriteNumber("generation", receipt.Generation);
            writer.WriteString("globalPlanDigest", receipt.GlobalPlanDigest);
            writer.WriteString("handoffDigest", receipt.HandoffDigest);
            writer.WriteString("payloadSha256", receipt.PayloadSha256);
            writer.WriteString("convergenceDigest", receipt.ConvergenceDigest);
            writer.WriteNumber("regionalWriterEpoch", receipt.RegionalWriterEpoch);
            writer.WriteNumber("acceptanceStreamSequence", receipt.AcceptanceStreamSequence);
            writer.WriteNumber("acceptanceRevision", receipt.AcceptanceRevision);
            writer.WriteNumber("checkpointSequence", receipt.CheckpointSequence);
            writer.WriteString("checkpointDigest", receipt.CheckpointDigest);
            writer.WriteNumber("checkpointJournalRevision", receipt.CheckpointJournalRevision);
            writer.WriteString("issuedAt", receipt.IssuedAt);
            writer.WriteString("expiresAt", receipt.ExpiresAt);
            writer.WriteEndObject();
        }
        return bytes.WrittenMemory.ToArray();
    }

    private static bool StructurallyValid(NativeGitOpsCellConvergenceReceiptData receipt) =>
        receipt.ProtocolVersion == 1 && receipt.Generation > 0 && receipt.RegionalWriterEpoch > 0 &&
        receipt.AcceptanceStreamSequence > 0 && receipt.AcceptanceRevision > 0 &&
        receipt.CheckpointSequence > 0 && receipt.CheckpointJournalRevision > 0 &&
        receipt.ExpiresAt > receipt.IssuedAt && ValidCell(receipt.Cell) &&
        Digest(receipt.GlobalPlanDigest) && Digest(receipt.HandoffDigest) && Digest(receipt.PayloadSha256) &&
        Digest(receipt.ConvergenceDigest) && Digest(receipt.CheckpointDigest);

    private static bool ValidCell(string value)
    {
        try { _ = new Runtime.RuntimeAllocationId(value); return true; }
        catch (Exception exception) when (exception is ArgumentException or ArgumentNullException) { return false; }
    }

    private static bool Digest(string? value) => value is { Length: 64 } &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static NativeGitOpsCellConvergenceReceiptValidation Invalid(
        NativeGitOpsCellConvergenceReceiptError error) => new(error, null, null);
}

/// <summary>Requires one current signed live receipt for every cell in the exact handoff.</summary>
internal static class NativeGitOpsLiveBarrierEvaluator
{
    internal static NativeGitOpsLiveBarrier Evaluate(
        NativeGitOpsCellHandoffDescriptor handoff,
        IReadOnlyDictionary<string, long> expectedRegionalWriterEpochs,
        IEnumerable<NativeGitOpsCellConvergenceReceiptEnvelope> receipts,
        DateTimeOffset now,
        TimeSpan allowedClockSkew,
        INativeGitOpsCellConvergenceReceiptVerifier verifier)
    {
        ArgumentNullException.ThrowIfNull(handoff);
        ArgumentNullException.ThrowIfNull(expectedRegionalWriterEpochs);
        ArgumentNullException.ThrowIfNull(receipts);
        ArgumentNullException.ThrowIfNull(verifier);
        if (!NativeGitOpsCellEnvelope.IsValidDescriptor(handoff) || allowedClockSkew < TimeSpan.Zero ||
            expectedRegionalWriterEpochs.Count != handoff.Cells.Count ||
            expectedRegionalWriterEpochs.Any(value => value.Value <= 0) ||
            !expectedRegionalWriterEpochs.Keys.ToHashSet(StringComparer.Ordinal)
                .SetEquals(handoff.Cells.Select(static value => value.Cell)))
            throw new ArgumentException("The native GitOps live barrier input is invalid.");
        var captured = receipts.Take(NativeGitOpsCellSpecCompiler.MaximumCellsPerHandoff + 1).ToArray();
        if (captured.Length > NativeGitOpsCellSpecCompiler.MaximumCellsPerHandoff ||
            captured.Any(static value => value is null) ||
            captured.Select(static value => value.Receipt.Cell).Distinct(StringComparer.Ordinal).Count() != captured.Length)
            throw new InvalidDataException("The native GitOps live barrier receipts are invalid.");

        var verified = new List<NativeGitOpsVerifiedCellConvergence>(captured.Length);
        foreach (var envelope in captured.OrderBy(static value => value.Receipt.Cell, StringComparer.Ordinal))
        {
            if (!expectedRegionalWriterEpochs.TryGetValue(envelope.Receipt.Cell, out var epoch))
                throw new InvalidDataException("A native GitOps live receipt is foreign to the handoff.");
            var validation = NativeGitOpsCellConvergenceReceipt.Validate(
                envelope,
                handoff,
                envelope.Receipt.Cell,
                epoch,
                now,
                allowedClockSkew,
                verifier);
            if (!validation.IsValid)
                throw new InvalidDataException($"A native GitOps live receipt failed validation: {validation.Error}.");
            verified.Add(new(validation.Receipt!, validation.SignatureSha256!));
        }
        var missing = handoff.Cells.Select(static value => value.Cell)
            .Except(verified.Select(static value => value.Receipt.Cell), StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();
        var values = verified.ToArray();
        return missing.Length == 0
            ? new(
                NativeGitOpsLiveBarrierState.Complete,
                handoff.Generation,
                handoff.GlobalPlanDigest,
                handoff.HandoffDigest,
                ReadOnly(values),
                ReadOnly(missing),
                Digest(handoff, values))
            : new(
                NativeGitOpsLiveBarrierState.Pending,
                handoff.Generation,
                handoff.GlobalPlanDigest,
                handoff.HandoffDigest,
                ReadOnly(values),
                ReadOnly(missing),
                null);
    }

    private static string Digest(
        NativeGitOpsCellHandoffDescriptor handoff,
        IReadOnlyList<NativeGitOpsVerifiedCellConvergence> receipts)
    {
        var bytes = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(bytes))
        {
            writer.WriteStartObject();
            writer.WriteNumber("generation", handoff.Generation);
            writer.WriteString("globalPlanDigest", handoff.GlobalPlanDigest);
            writer.WriteString("handoffDigest", handoff.HandoffDigest);
            writer.WriteStartArray("receipts");
            foreach (var verified in receipts)
            {
                var receipt = verified.Receipt;
                writer.WriteStartObject();
                writer.WriteString("cell", receipt.Cell);
                writer.WriteString("payloadSha256", receipt.PayloadSha256);
                writer.WriteString("convergenceDigest", receipt.ConvergenceDigest);
                writer.WriteNumber("regionalWriterEpoch", receipt.RegionalWriterEpoch);
                writer.WriteNumber("acceptanceStreamSequence", receipt.AcceptanceStreamSequence);
                writer.WriteNumber("acceptanceRevision", receipt.AcceptanceRevision);
                writer.WriteNumber("checkpointSequence", receipt.CheckpointSequence);
                writer.WriteString("checkpointDigest", receipt.CheckpointDigest);
                writer.WriteNumber("checkpointJournalRevision", receipt.CheckpointJournalRevision);
                writer.WriteString("signatureSha256", verified.SignatureSha256);
                writer.WriteString("issuedAt", receipt.IssuedAt);
                writer.WriteString("expiresAt", receipt.ExpiresAt);
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
            writer.WriteEndObject();
        }
        return Convert.ToHexStringLower(SHA256.HashData(bytes.WrittenSpan));
    }

    private static IReadOnlyList<T> ReadOnly<T>(T[] values) => new ReadOnlyCollection<T>(values);
}
