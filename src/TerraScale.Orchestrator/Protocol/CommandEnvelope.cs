using TerraScale.Orchestrator.Contracts;

namespace TerraScale.Orchestrator.Protocol;

public sealed class CommandEnvelope
{
    public CommandEnvelope(
        ProtocolRevision protocolVersion,
        CellId cell,
        AggregateId aggregateId,
        DesiredGeneration desiredGeneration,
        WriterEpoch writerEpoch,
        OperationId operationId,
        IdempotencyKey idempotencyKey,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        DeliveryAttempt attempt,
        OpaquePayload payload,
        PayloadDigest payloadDigest,
        OpaqueSignature signature)
    {
        ProtocolVersion = protocolVersion;
        Cell = cell;
        AggregateId = aggregateId;
        DesiredGeneration = desiredGeneration;
        WriterEpoch = writerEpoch;
        OperationId = operationId;
        IdempotencyKey = idempotencyKey;
        IssuedAt = issuedAt;
        ExpiresAt = expiresAt;
        Attempt = attempt;
        Payload = payload;
        PayloadDigest = payloadDigest;
        Signature = signature;
        SignedMaterial = new CommandSignedMaterial(
            protocolVersion,
            cell,
            aggregateId,
            desiredGeneration,
            writerEpoch,
            operationId,
            idempotencyKey,
            issuedAt,
            expiresAt,
            attempt,
            payload,
            payloadDigest);
    }

    public ProtocolRevision ProtocolVersion { get; }

    public CellId Cell { get; }

    public AggregateId AggregateId { get; }

    public DesiredGeneration DesiredGeneration { get; }

    public WriterEpoch WriterEpoch { get; }

    public OperationId OperationId { get; }

    public IdempotencyKey IdempotencyKey { get; }

    public DateTimeOffset IssuedAt { get; }

    public DateTimeOffset ExpiresAt { get; }

    public DeliveryAttempt Attempt { get; }

    public OpaquePayload Payload { get; }

    public PayloadDigest PayloadDigest { get; }

    public OpaqueSignature Signature { get; }

    public CommandSignedMaterial SignedMaterial { get; }

    public override string ToString() =>
        $"CommandEnvelope {{ ProtocolVersion = {ProtocolVersion}, Cell = {Cell}, AggregateId = {AggregateId}, "
        + $"DesiredGeneration = {DesiredGeneration}, WriterEpoch = {WriterEpoch}, OperationId = {OperationId}, "
        + $"IdempotencyKey = {IdempotencyKey}, IssuedAt = {IssuedAt:O}, ExpiresAt = {ExpiresAt:O}, "
        + $"Attempt = {Attempt}, Payload = <redacted>, PayloadDigest = <redacted>, Signature = <redacted> }}";
}

/// <summary>
/// Complete algorithm-neutral material that a caller-supplied verifier must authenticate.
/// The protocol owns canonical serialization; the verifier owns signing and trust policy.
/// No field may be omitted.
/// </summary>
public sealed class CommandSignedMaterial
{
    internal CommandSignedMaterial(
        ProtocolRevision protocolVersion,
        CellId cell,
        AggregateId aggregateId,
        DesiredGeneration desiredGeneration,
        WriterEpoch writerEpoch,
        OperationId operationId,
        IdempotencyKey idempotencyKey,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        DeliveryAttempt attempt,
        OpaquePayload payload,
        PayloadDigest payloadDigest)
    {
        ProtocolVersion = protocolVersion;
        Cell = cell;
        AggregateId = aggregateId;
        DesiredGeneration = desiredGeneration;
        WriterEpoch = writerEpoch;
        OperationId = operationId;
        IdempotencyKey = idempotencyKey;
        IssuedAt = issuedAt;
        ExpiresAt = expiresAt;
        Attempt = attempt;
        Payload = payload;
        PayloadDigest = payloadDigest;
    }

    public ProtocolRevision ProtocolVersion { get; }

    public CellId Cell { get; }

    public AggregateId AggregateId { get; }

    public DesiredGeneration DesiredGeneration { get; }

    public WriterEpoch WriterEpoch { get; }

    public OperationId OperationId { get; }

    public IdempotencyKey IdempotencyKey { get; }

    public DateTimeOffset IssuedAt { get; }

    public DateTimeOffset ExpiresAt { get; }

    public DeliveryAttempt Attempt { get; }

    public OpaquePayload Payload { get; }

    public PayloadDigest PayloadDigest { get; }

    public override string ToString() => "<command-signed-material>";
}
