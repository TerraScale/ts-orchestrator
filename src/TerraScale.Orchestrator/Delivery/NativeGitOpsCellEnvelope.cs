using System.Security.Cryptography;
using TerraScale.Orchestrator.Contracts;
using TerraScale.Orchestrator.Protocol;

namespace TerraScale.Orchestrator.Delivery;

public interface INativeGitOpsCellSpecSigner
{
    OpaqueSignature Sign(CommandSignedMaterial material);
}

public enum NativeGitOpsCellEnvelopeError
{
    Unspecified,
    None,
    InvalidInput,
    WrongCellSpec,
    ProtocolRejected,
}

public sealed record NativeGitOpsCellEnvelopeValidation(
    NativeGitOpsCellEnvelopeError Error,
    CommandValidationError ProtocolError,
    CommandAcceptance? Acceptance)
{
    public bool IsAccepted => Error == NativeGitOpsCellEnvelopeError.None && Acceptance is not null;
}

/// <summary>
/// Binds a deterministic cell specification to the shared signed-command protocol. The caller owns
/// the KMS-backed signer and verifier; this adapter never treats an unsigned payload as applicable.
/// </summary>
public static class NativeGitOpsCellEnvelope
{
    public const int MaximumSignatureBytes = 16 * 1024;

    public static CommandEnvelope Sign(
        NativeGitOpsCellHandoff handoff,
        string cell,
        long writerEpoch,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        INativeGitOpsCellSpecSigner signer)
    {
        ArgumentNullException.ThrowIfNull(handoff);
        ArgumentNullException.ThrowIfNull(signer);
        var spec = Cell(handoff, cell);
        if (spec is null || writerEpoch <= 0 || expiresAt <= issuedAt)
            throw new ArgumentException("The native GitOps cell signing request is invalid.");

        var identities = CreateIdentities(handoff, spec, writerEpoch);
        var payload = OpaquePayload.CopyFrom(spec.Payload.Span);
        var digestBytes = SHA256.HashData(spec.Payload.Span);
        PayloadDigest.TryCopyFrom(digestBytes, out var digest);
        var material = new CommandSignedMaterial(
            identities.Protocol,
            identities.Cell,
            identities.Aggregate,
            identities.Generation,
            identities.Epoch,
            identities.Operation,
            identities.Idempotency,
            issuedAt,
            expiresAt,
            identities.Attempt,
            payload,
            digest!);
        var signature = signer.Sign(material);
        if (signature is not { IsValid: true } || signature.Length > MaximumSignatureBytes)
            throw new InvalidDataException("The native GitOps cell signer returned an invalid signature.");
        return new(
            identities.Protocol,
            identities.Cell,
            identities.Aggregate,
            identities.Generation,
            identities.Epoch,
            identities.Operation,
            identities.Idempotency,
            issuedAt,
            expiresAt,
            identities.Attempt,
            payload,
            digest!,
            signature);
    }

    public static NativeGitOpsCellEnvelopeValidation Validate(
        CommandEnvelope? envelope,
        NativeGitOpsCellHandoff? expectedHandoff,
        string expectedCell,
        long expectedWriterEpoch,
        DateTimeOffset now,
        TimeSpan allowedClockSkew,
        ICommandSignatureVerifier? signatureVerifier)
    {
        if (envelope is null || expectedHandoff is null ||
            expectedWriterEpoch <= 0 || allowedClockSkew < TimeSpan.Zero || signatureVerifier is null)
            return new(
                NativeGitOpsCellEnvelopeError.InvalidInput,
                CommandValidationError.InvalidValidationContext,
                null);
        var expected = Cell(expectedHandoff, expectedCell);
        if (expected is null)
            return new(
                NativeGitOpsCellEnvelopeError.InvalidInput,
                CommandValidationError.InvalidValidationContext,
                null);
        if (envelope.Payload is null || envelope.PayloadDigest is null)
            return new(
                NativeGitOpsCellEnvelopeError.ProtocolRejected,
                CommandValidationError.MalformedEnvelope,
                null);

        var identities = CreateIdentities(expectedHandoff, expected, expectedWriterEpoch);
        var digestBytes = SHA256.HashData(expected.Payload.Span);
        PayloadDigest.TryCopyFrom(digestBytes, out var digest);
        if (envelope.ProtocolVersion != identities.Protocol || envelope.Cell != identities.Cell ||
            envelope.AggregateId != identities.Aggregate || envelope.DesiredGeneration != identities.Generation ||
            envelope.WriterEpoch != identities.Epoch || envelope.OperationId != identities.Operation ||
            envelope.IdempotencyKey != identities.Idempotency || envelope.Attempt != identities.Attempt ||
            !envelope.Payload.Bytes.SequenceEqual(expected.Payload.Span) || !envelope.PayloadDigest.Equals(digest))
            return new(
                NativeGitOpsCellEnvelopeError.WrongCellSpec,
                CommandValidationError.MalformedEnvelope,
                null);

        var context = new CommandValidationContext(
            identities.Cell,
            identities.Aggregate,
            identities.Generation,
            identities.Epoch,
            [identities.Protocol],
            allowedClockSkew,
            Sha256PayloadDigestVerifier.Instance,
            signatureVerifier);
        var result = CommandEnvelopeValidator.Validate(envelope, context, now);
        return result.IsValid
            ? new(NativeGitOpsCellEnvelopeError.None, CommandValidationError.None, result.Acceptance)
            : new(NativeGitOpsCellEnvelopeError.ProtocolRejected, result.Error, null);
    }

    private static bool ValidSpec(NativeGitOpsCellSpec spec) =>
        spec.Cell is { Length: > 0 and <= 128 } && spec.Generation > 0 &&
        CellId.TryCreate(spec.Cell, out _) &&
        IsDigest(spec.GlobalPlanDigest) && IsDigest(spec.PayloadSha256) &&
        spec.Payload.Length is > 0 and <= NativeGitOpsCellSpecCompiler.MaximumCellSpecBytes &&
        Convert.ToHexStringLower(SHA256.HashData(spec.Payload.Span)) == spec.PayloadSha256;

    private static NativeGitOpsCellSpec? Cell(NativeGitOpsCellHandoff handoff, string cell)
    {
        if (handoff.RequiredCells is null || handoff.Cells is null || handoff.Generation <= 0 ||
            !IsDigest(handoff.GlobalPlanDigest) || !IsDigest(handoff.HandoffDigest) ||
            handoff.RequiredCells.Count != handoff.Cells.Count ||
            !handoff.RequiredCells.SequenceEqual(
                handoff.RequiredCells.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal),
                StringComparer.Ordinal) ||
            !handoff.RequiredCells.SequenceEqual(handoff.Cells.Select(static spec => spec.Cell), StringComparer.Ordinal) ||
            handoff.Cells.Any(spec => !ValidSpec(spec) || spec.Generation != handoff.Generation ||
                spec.GlobalPlanDigest != handoff.GlobalPlanDigest) ||
            handoff.HandoffDigest != NativeGitOpsCellSpecCompiler.ComputeHandoffDigest(
                handoff.Generation,
                handoff.GlobalPlanDigest,
                handoff.Cells))
            return null;
        return handoff.Cells.SingleOrDefault(spec => spec.Cell == cell);
    }

    private static Identities CreateIdentities(
        NativeGitOpsCellHandoff handoff,
        NativeGitOpsCellSpec spec,
        long writerEpoch)
    {
        ProtocolRevision.TryCreate(1, out var protocol);
        CellId.TryCreate(spec.Cell, out var cell);
        AggregateId.TryCreate($"native-gitops/{spec.Cell}", out var aggregate);
        DesiredGeneration.TryCreate(spec.Generation, out var generation);
        WriterEpoch.TryCreate(writerEpoch, out var epoch);
        OperationId.TryCreate($"gitops/{handoff.HandoffDigest}/{spec.Cell}", out var operation);
        IdempotencyKey.TryCreate($"gitops/{spec.PayloadSha256}", out var idempotency);
        DeliveryAttempt.TryCreate(1, out var attempt);
        return new(protocol, cell, aggregate, generation, epoch, operation, idempotency, attempt);
    }

    private static bool IsDigest(string value) => value.Length == 64 &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private sealed class Sha256PayloadDigestVerifier : IPayloadDigestVerifier
    {
        internal static readonly Sha256PayloadDigestVerifier Instance = new();

        public VerificationOutcome Verify(OpaquePayload payload, PayloadDigest expectedDigest)
        {
            var digest = SHA256.HashData(payload.Bytes);
            return expectedDigest.Bytes.Length == digest.Length &&
                   CryptographicOperations.FixedTimeEquals(expectedDigest.Bytes, digest)
                ? VerificationOutcome.Valid
                : VerificationOutcome.Invalid;
        }
    }

    private sealed record Identities(
        ProtocolRevision Protocol,
        CellId Cell,
        AggregateId Aggregate,
        DesiredGeneration Generation,
        WriterEpoch Epoch,
        OperationId Operation,
        IdempotencyKey Idempotency,
        DeliveryAttempt Attempt);
}
