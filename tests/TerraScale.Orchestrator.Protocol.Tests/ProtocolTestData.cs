using TerraScale.Orchestrator.Contracts;

namespace TerraScale.Orchestrator.Protocol.Tests;

internal static class ProtocolTestData
{
    public static readonly DateTimeOffset Now = new(2026, 7, 13, 12, 0, 0, TimeSpan.Zero);
    public static readonly byte[] PayloadBytes = [1, 2, 3, 4];
    public static readonly byte[] SignatureBytes = [9, 8, 7, 6];

    public static CellId Cell(string value)
    {
        CellId.TryCreate(value, out var result);
        return result;
    }

    public static AggregateId Aggregate(string value)
    {
        AggregateId.TryCreate(value, out var result);
        return result;
    }

    public static OperationId Operation(string value)
    {
        OperationId.TryCreate(value, out var result);
        return result;
    }

    public static IdempotencyKey Idempotency(string value)
    {
        IdempotencyKey.TryCreate(value, out var result);
        return result;
    }

    public static ProtocolRevision Protocol(long value)
    {
        ProtocolRevision.TryCreate(value, out var result);
        return result;
    }

    public static DesiredGeneration Generation(long value)
    {
        DesiredGeneration.TryCreate(value, out var result);
        return result;
    }

    public static WriterEpoch Epoch(long value)
    {
        WriterEpoch.TryCreate(value, out var result);
        return result;
    }

    public static DeliveryAttempt Attempt(long value)
    {
        DeliveryAttempt.TryCreate(value, out var result);
        return result;
    }

    public static PayloadDigest Digest(ReadOnlySpan<byte> bytes)
    {
        PayloadDigest.TryCopyFrom(bytes, out var result);
        return result!;
    }

    public static OpaqueSignature Signature(ReadOnlySpan<byte> bytes)
    {
        OpaqueSignature.TryCopyFrom(bytes, out var result);
        return result!;
    }

    public static CommandEnvelope ValidEnvelope(
        ProtocolRevision? protocol = null,
        CellId? cell = null,
        AggregateId? aggregate = null,
        DesiredGeneration? generation = null,
        WriterEpoch? epoch = null,
        OperationId? operation = null,
        IdempotencyKey? idempotency = null,
        DateTimeOffset? issuedAt = null,
        DateTimeOffset? expiresAt = null,
        DeliveryAttempt? attempt = null,
        OpaquePayload? payload = null,
        PayloadDigest? digest = null,
        OpaqueSignature? signature = null) =>
        new(
            protocol ?? Protocol(1),
            cell ?? Cell("gru"),
            aggregate ?? Aggregate("allocation/42"),
            generation ?? Generation(10),
            epoch ?? Epoch(7),
            operation ?? Operation("operation/abc"),
            idempotency ?? Idempotency("idempotency/abc"),
            issuedAt ?? Now.AddMinutes(-1),
            expiresAt ?? Now.AddMinutes(1),
            attempt ?? Attempt(1),
            payload ?? OpaquePayload.CopyFrom(PayloadBytes),
            digest ?? Digest(PayloadBytes),
            signature ?? Signature(SignatureBytes));

    public static CommandValidationContext ValidContext(
        CellId? expectedCell = null,
        AggregateId? expectedAggregate = null,
        DesiredGeneration? minimumGeneration = null,
        WriterEpoch? minimumEpoch = null,
        IEnumerable<ProtocolRevision>? acceptedProtocols = null,
        TimeSpan? skew = null,
        IPayloadDigestVerifier? digestVerifier = null,
        ICommandSignatureVerifier? signatureVerifier = null) =>
        new(
            expectedCell ?? Cell("gru"),
            expectedAggregate ?? Aggregate("allocation/42"),
            minimumGeneration ?? Generation(10),
            minimumEpoch ?? Epoch(7),
            acceptedProtocols ?? [Protocol(1)],
            skew ?? TimeSpan.FromMinutes(2),
            digestVerifier ?? new TestDigestVerifier(),
            signatureVerifier ?? new TestSignatureVerifier());
}

internal sealed class TestDigestVerifier(bool matches = true, bool throws = false) : IPayloadDigestVerifier
{
    public int Calls { get; private set; }

    public VerificationOutcome Verify(OpaquePayload payload, PayloadDigest expectedDigest)
    {
        Calls++;
        if (throws)
        {
            throw new InvalidOperationException("synthetic verifier failure");
        }

        return matches && payload.Bytes.SequenceEqual(expectedDigest.Bytes)
            ? VerificationOutcome.Valid
            : VerificationOutcome.Invalid;
    }
}

internal sealed class TestSignatureVerifier(bool isValid = true, bool throws = false) : ICommandSignatureVerifier
{
    public int Calls { get; private set; }

    public CommandSignedMaterial? LastMaterial { get; private set; }

    public OpaqueSignature? LastSignature { get; private set; }

    public VerificationOutcome Verify(CommandSignedMaterial signedMaterial, OpaqueSignature signature)
    {
        Calls++;
        LastMaterial = signedMaterial;
        LastSignature = signature;
        if (throws)
        {
            throw new InvalidOperationException("synthetic verifier failure");
        }

        return isValid ? VerificationOutcome.Valid : VerificationOutcome.Invalid;
    }
}
