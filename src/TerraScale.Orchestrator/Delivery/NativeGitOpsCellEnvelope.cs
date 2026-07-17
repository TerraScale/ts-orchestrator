using System.Security.Cryptography;
using System.Text.Json;
using TerraScale.Orchestrator.Contracts;
using TerraScale.Orchestrator.Protocol;
using TerraScale.Orchestrator.Runtime;

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
    private static readonly HashSet<string> CellPayloadProperties =
    [
        "schemaVersion", "repository", "commit", "tree", "filePath", "blob", "contentSha256",
        "generation", "globalPlanDigest", "cell", "desiredWorkloads", "changes",
    ];

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
        var descriptor = Describe(handoff);
        if (spec is null || descriptor is null || writerEpoch <= 0 || expiresAt <= issuedAt)
            throw new ArgumentException("The native GitOps cell signing request is invalid.");

        var identities = CreateIdentities(descriptor, spec.Cell, spec.PayloadSha256, writerEpoch);
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
        var descriptor = Describe(expectedHandoff);
        if (expected is null || descriptor is null)
            return new(
                NativeGitOpsCellEnvelopeError.InvalidInput,
                CommandValidationError.InvalidValidationContext,
                null);
        return ValidateCore(
            envelope,
            descriptor,
            expectedCell,
            expectedWriterEpoch,
            now,
            allowedClockSkew,
            signatureVerifier,
            expected.Payload.Span);
    }

    internal static NativeGitOpsCellEnvelopeValidation Validate(
        CommandEnvelope? envelope,
        NativeGitOpsCellHandoffDescriptor? expectedHandoff,
        string expectedCell,
        long expectedWriterEpoch,
        DateTimeOffset now,
        TimeSpan allowedClockSkew,
        ICommandSignatureVerifier? signatureVerifier) => ValidateCore(
        envelope,
        expectedHandoff,
        expectedCell,
        expectedWriterEpoch,
        now,
        allowedClockSkew,
        signatureVerifier,
        default);

    private static NativeGitOpsCellEnvelopeValidation ValidateCore(
        CommandEnvelope? envelope,
        NativeGitOpsCellHandoffDescriptor? expectedHandoff,
        string expectedCell,
        long expectedWriterEpoch,
        DateTimeOffset now,
        TimeSpan allowedClockSkew,
        ICommandSignatureVerifier? signatureVerifier,
        ReadOnlySpan<byte> exactExpectedPayload)
    {
        if (envelope is null || expectedHandoff is null ||
            expectedWriterEpoch <= 0 || allowedClockSkew < TimeSpan.Zero || signatureVerifier is null ||
            !ValidDescriptor(expectedHandoff))
            return new(
                NativeGitOpsCellEnvelopeError.InvalidInput,
                CommandValidationError.InvalidValidationContext,
                null);
        var expected = expectedHandoff.Cells.SingleOrDefault(item => item.Cell == expectedCell);
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

        var identities = CreateIdentities(
            expectedHandoff,
            expected.Cell,
            expected.PayloadSha256,
            expectedWriterEpoch);
        var digestBytes = SHA256.HashData(envelope.Payload.Bytes);
        PayloadDigest.TryCopyFrom(digestBytes, out var digest);
        if (envelope.ProtocolVersion != identities.Protocol || envelope.Cell != identities.Cell ||
            envelope.AggregateId != identities.Aggregate || envelope.DesiredGeneration != identities.Generation ||
            envelope.WriterEpoch != identities.Epoch || envelope.OperationId != identities.Operation ||
            envelope.IdempotencyKey != identities.Idempotency || envelope.Attempt != identities.Attempt ||
            Convert.ToHexStringLower(digestBytes) != expected.PayloadSha256 ||
            !exactExpectedPayload.IsEmpty && !envelope.Payload.Bytes.SequenceEqual(exactExpectedPayload) ||
            !envelope.PayloadDigest.Equals(digest) ||
            !ValidPayloadIdentity(envelope.Payload.Bytes, expectedHandoff, expectedCell))
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
        ValidCell(spec.Cell) && spec.Generation > 0 &&
        IsDigest(spec.GlobalPlanDigest) && IsDigest(spec.PayloadSha256) &&
        spec.Payload.Length is > 0 and <= NativeGitOpsCellSpecCompiler.MaximumCellSpecBytes &&
        Convert.ToHexStringLower(SHA256.HashData(spec.Payload.Span)) == spec.PayloadSha256;

    private static NativeGitOpsCellSpec? Cell(NativeGitOpsCellHandoff handoff, string cell)
    {
        if (Describe(handoff) is null) return null;
        return handoff.Cells.SingleOrDefault(spec => spec.Cell == cell);
    }

    internal static NativeGitOpsCellHandoffDescriptor? Describe(NativeGitOpsCellHandoff handoff)
    {
        if (handoff.RequiredCells is null || handoff.Cells is null || handoff.Generation <= 0 ||
            !IsDigest(handoff.GlobalPlanDigest) || !IsDigest(handoff.HandoffDigest) ||
            handoff.RequiredCells.Count == 0 ||
            handoff.RequiredCells.Count > NativeGitOpsCellSpecCompiler.MaximumCellsPerHandoff ||
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
        return new(
            handoff.Generation,
            handoff.GlobalPlanDigest,
            handoff.HandoffDigest,
            Array.AsReadOnly(handoff.Cells.Select(static spec =>
                new NativeGitOpsCellDigest(spec.Cell, spec.PayloadSha256)).ToArray()));
    }

    private static Identities CreateIdentities(
        NativeGitOpsCellHandoffDescriptor handoff,
        string cellValue,
        string payloadSha256,
        long writerEpoch)
    {
        ProtocolRevision.TryCreate(1, out var protocol);
        CellId.TryCreate(cellValue, out var cell);
        AggregateId.TryCreate($"native-gitops/{cellValue}", out var aggregate);
        DesiredGeneration.TryCreate(handoff.Generation, out var generation);
        WriterEpoch.TryCreate(writerEpoch, out var epoch);
        OperationId.TryCreate($"gitops/{handoff.HandoffDigest}/{cellValue}", out var operation);
        IdempotencyKey.TryCreate($"gitops/{payloadSha256}", out var idempotency);
        DeliveryAttempt.TryCreate(1, out var attempt);
        return new(protocol, cell, aggregate, generation, epoch, operation, idempotency, attempt);
    }

    private static bool ValidDescriptor(NativeGitOpsCellHandoffDescriptor handoff) =>
        handoff.Generation > 0 && IsDigest(handoff.GlobalPlanDigest) && IsDigest(handoff.HandoffDigest) &&
        handoff.Cells is { Count: > 0 and <= NativeGitOpsCellSpecCompiler.MaximumCellsPerHandoff } &&
        handoff.Cells.All(static item => ValidCell(item.Cell) && IsDigest(item.PayloadSha256)) &&
        handoff.Cells.SequenceEqual(
            handoff.Cells.DistinctBy(static item => item.Cell, StringComparer.Ordinal)
                .OrderBy(static item => item.Cell, StringComparer.Ordinal)) &&
        handoff.HandoffDigest == NativeGitOpsCellSpecCompiler.ComputeHandoffDigest(
            handoff.Generation,
            handoff.GlobalPlanDigest,
            handoff.Cells);

    private static bool ValidPayloadIdentity(
        ReadOnlySpan<byte> payload,
        NativeGitOpsCellHandoffDescriptor handoff,
        string cell)
    {
        try
        {
            RejectDuplicateProperties(payload);
            using var parsed = JsonDocument.Parse(payload.ToArray(), new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 16,
            });
            var root = parsed.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                root.EnumerateObject().Count() != CellPayloadProperties.Count ||
                root.EnumerateObject().Any(property => !CellPayloadProperties.Contains(property.Name)) ||
                !root.TryGetProperty("schemaVersion", out var schema) || !schema.TryGetInt32(out var version) ||
                version != 1 ||
                !root.TryGetProperty("generation", out var generation) ||
                !generation.TryGetInt64(out var generationValue) || generationValue != handoff.Generation ||
                !root.TryGetProperty("globalPlanDigest", out var digest) ||
                digest.ValueKind != JsonValueKind.String || digest.GetString() != handoff.GlobalPlanDigest ||
                !root.TryGetProperty("cell", out var payloadCell) ||
                payloadCell.ValueKind != JsonValueKind.String || payloadCell.GetString() != cell ||
                !root.TryGetProperty("desiredWorkloads", out var workloads) ||
                workloads.ValueKind != JsonValueKind.Array ||
                !root.TryGetProperty("changes", out var changes) || changes.ValueKind != JsonValueKind.Array)
                return false;
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static void RejectDuplicateProperties(ReadOnlySpan<byte> payload)
    {
        var reader = new Utf8JsonReader(payload, new JsonReaderOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = 16,
        });
        var objects = new Stack<HashSet<string>>();
        while (reader.Read())
        {
            if (reader.TokenType == JsonTokenType.StartObject) objects.Push(new(StringComparer.Ordinal));
            else if (reader.TokenType == JsonTokenType.EndObject) objects.Pop();
            else if (reader.TokenType == JsonTokenType.PropertyName && !objects.Peek().Add(reader.GetString()!))
                throw new JsonException("A native GitOps cell payload contains duplicate fields.");
        }
    }

    private static bool ValidCell(string cell)
    {
        try
        {
            _ = new RuntimeAllocationId(cell);
            return true;
        }
        catch (Exception exception) when (exception is ArgumentException or ArgumentNullException)
        {
            return false;
        }
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
