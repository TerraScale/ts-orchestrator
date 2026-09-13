using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TerraScale.Orchestrator.Contracts;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Protocol;

namespace TerraScale.Orchestrator.Delivery;

internal enum DirectDeliveryCommandWireError
{
    None = 0,
    MalformedEnvelope,
    ValidationRejected,
}

internal sealed record DirectDeliveryCommandWireReceipt(
    DirectDeliveryCommandWireError Error,
    CommandValidationError ValidationError,
    DeliveryRequest? Request)
{
    internal static DirectDeliveryCommandWireReceipt Malformed() =>
        new(DirectDeliveryCommandWireError.MalformedEnvelope, CommandValidationError.MalformedEnvelope, null);
}

/// <summary>
/// The validated signed envelope of one direct-delivery mutation, independent of its payload
/// kind. <see cref="OperationId"/>, <see cref="Generation"/>, <see cref="Epoch"/>, and
/// <see cref="Attempt"/> are the signed identity claims a payload must match.
/// </summary>
internal sealed record DirectDeliverySignedEnvelope(
    DirectDeliveryCommandWireError Error,
    CommandValidationError ValidationError,
    CommandEnvelope? Envelope,
    string OperationId,
    long Generation,
    long Epoch,
    int Attempt)
{
    internal static DirectDeliverySignedEnvelope Refused(
        DirectDeliveryCommandWireError error, CommandValidationError validation) =>
        new(error, validation, null, string.Empty, 0, 0, 0);
}

/// <summary>
/// The signed command-envelope seam for direct delivery mutations. The wire payload is the
/// canonical version-1 <see cref="DeliveryRequest"/> JSON; the identity fields and the detached
/// signature travel as NATS headers, exactly like the repository CI job seam. No delivery may
/// mutate anything before this validation accepts the envelope (INV-005 admission).
/// </summary>
internal static class DirectDeliveryCommandWire
{
    internal const int MaximumPayloadBytes = 64 * 1024;
    internal const int MaximumHeaderBytes = 8 * 1024;
    internal const int MaximumSignatureBytes = 16 * 1024;
    internal const string Aggregate = "direct-delivery";
    internal const string Type = "direct-delivery";

    private const string SchemaHeader = "Schema";
    private const string ProtocolHeader = "Protocol";
    private const string TypeHeader = "Type";
    private const string CellHeader = "Cell";
    private const string OperationHeader = "Operation";
    private const string GenerationHeader = "Generation";
    private const string EpochHeader = "Epoch";
    private const string AttemptHeader = "Attempt";
    private const string IssuedHeader = "Issued";
    private const string ExpiresHeader = "Expires";
    private const string PayloadSha256Header = "PayloadSha256";
    private const string SignatureHeader = "Signature";
    private const long MinimumUnixMilliseconds =
        -62_135_596_800_000; // DateTimeOffset.MinValue.ToUnixTimeMilliseconds()
    private const long MaximumUnixMilliseconds =
        253_402_300_799_999; // DateTimeOffset.MaxValue.ToUnixTimeMilliseconds()
    private const int ExpectedHeaderCount = 12;

    private static readonly HashSet<string> ExpectedHeaders = new(StringComparer.Ordinal)
    {
        SchemaHeader,
        ProtocolHeader,
        TypeHeader,
        CellHeader,
        OperationHeader,
        GenerationHeader,
        EpochHeader,
        AttemptHeader,
        IssuedHeader,
        ExpiresHeader,
        PayloadSha256Header,
        SignatureHeader,
    };

    /// <summary>
    /// Encodes a signed direct-delivery wire message: canonical request bytes plus the exact
    /// headers a signing caller publishes. The signature is produced from the same envelope
    /// material <see cref="Decode"/> validates, so the two can never drift.
    /// </summary>
    internal static (byte[] Payload, IReadOnlyDictionary<string, string> Headers) Encode(
        DeliveryRequest request,
        string cell,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        Func<CommandSignedMaterial, OpaqueSignature> sign)
    {
        ArgumentNullException.ThrowIfNull(request);
        var payload = Encoding.UTF8.GetBytes(DeliveryWireCodec.SerializeRequest(request));
        if (payload.Length is < 1 or > MaximumPayloadBytes)
            throw new ArgumentException("The direct delivery payload exceeds its bound.", nameof(request));
        var headers = EncodeSignedHeaders(
            payload,
            request.OperationId ?? string.Empty,
            request.AuthorityGeneration,
            request.WriterEpoch,
            request.Attempt,
            cell,
            issuedAt,
            expiresAt,
            sign);
        return (payload, headers);
    }

    /// <summary>
    /// Produces the exact signed headers for one already-canonical direct-delivery payload of any
    /// admitted kind (canonical DeliveryRequest or Deploy handoff manifest). Every payload kind
    /// signs through this one path, so a manifest envelope can never drift from a request envelope.
    /// </summary>
    internal static IReadOnlyDictionary<string, string> EncodeSignedHeaders(
        ReadOnlyMemory<byte> payload,
        string operationId,
        long generation,
        long epoch,
        int attempt,
        string cell,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        Func<CommandSignedMaterial, OpaqueSignature> sign)
    {
        ArgumentNullException.ThrowIfNull(sign);
        if (payload.Length is < 1 or > MaximumPayloadBytes)
            throw new ArgumentException("The direct delivery payload exceeds its bound.", nameof(payload));
        if (!ProtocolRevision.TryCreate(1, out var protocol) ||
            !CellId.TryCreate(cell, out var cellId) ||
            !AggregateId.TryCreate(Aggregate, out var aggregate) ||
            !DesiredGeneration.TryCreate(generation, out var desired) ||
            !WriterEpoch.TryCreate(epoch, out var writerEpoch) ||
            !OperationId.TryCreate(operationId, out var operation) ||
            !IdempotencyKey.TryCreate(operationId, out var idempotency) ||
            !DeliveryAttempt.TryCreate(attempt, out var deliveryAttempt))
            throw new ArgumentException("The direct delivery wire identity is invalid.", nameof(operationId));
        var digest = Convert.FromHexString(Convert.ToHexStringLower(SHA256.HashData(payload.Span)));
        if (!PayloadDigest.TryCopyFrom(digest, out var payloadDigest) || payloadDigest is null)
            throw new ArgumentException("The direct delivery payload digest is invalid.", nameof(payload));
        var material = new CommandSignedMaterial(
            protocol,
            cellId,
            aggregate,
            desired,
            writerEpoch,
            operation,
            idempotency,
            issuedAt,
            expiresAt,
            deliveryAttempt,
            OpaquePayload.CopyFrom(payload.Span),
            payloadDigest);
        var signature = sign(material);
        if (signature is not { IsValid: true } || signature.Length > MaximumSignatureBytes)
            throw new ArgumentException("The direct delivery signature is invalid.", nameof(sign));
        return new Dictionary<string, string>(ExpectedHeaderCount, StringComparer.Ordinal)
        {
            [SchemaHeader] = "1",
            [ProtocolHeader] = "1",
            [TypeHeader] = Type,
            [CellHeader] = cell,
            [OperationHeader] = operationId,
            [GenerationHeader] = generation.ToString(CultureInfo.InvariantCulture),
            [EpochHeader] = epoch.ToString(CultureInfo.InvariantCulture),
            [AttemptHeader] = attempt.ToString(CultureInfo.InvariantCulture),
            [IssuedHeader] = issuedAt.ToUnixTimeMilliseconds().ToString(CultureInfo.InvariantCulture),
            [ExpiresHeader] = expiresAt.ToUnixTimeMilliseconds().ToString(CultureInfo.InvariantCulture),
            [PayloadSha256Header] = Convert.ToHexStringLower(SHA256.HashData(payload.Span)),
            [SignatureHeader] = Convert.ToBase64String(signature.Bytes),
        };
    }

    /// <summary>Validates one signed direct-delivery mutation before any dispatch.</summary>
    internal static DirectDeliveryCommandWireReceipt Decode(
        ReadOnlyMemory<byte> payload,
        IEnumerable<KeyValuePair<string, string>>? headers,
        string expectedCell,
        DateTimeOffset now,
        TimeSpan allowedClockSkew,
        ICommandSignatureVerifier signatureVerifier) => Decode(
            payload, headers, expectedCell, now, allowedClockSkew, signatureVerifier, null, null);

    /// <summary>
    /// Validates the envelope against the currently observed durable authority. The envelope's
    /// generation and epoch are claims; they are accepted only when they equal this snapshot.
    /// </summary>
    internal static DirectDeliveryCommandWireReceipt Decode(
        ReadOnlyMemory<byte> payload,
        IEnumerable<KeyValuePair<string, string>>? headers,
        string expectedCell,
        DateTimeOffset now,
        TimeSpan allowedClockSkew,
        ICommandSignatureVerifier signatureVerifier,
        long? expectedGeneration,
        long? expectedEpoch)
    {
        // Canonicalize first and bind the payload's operation identity into the envelope check
        // BEFORE signature validation, so a mismatched Operation header is an input error
        // (malformed) rather than a signature denial — the historical single-kind semantics.
        if (Canonicalize(payload) is not { } request)
            return DirectDeliveryCommandWireReceipt.Malformed();
        var envelope = ValidateSignedEnvelope(
            payload, headers, expectedCell, now, allowedClockSkew, signatureVerifier, expectedGeneration,
            expectedEpoch, request.OperationId);
        if (envelope.Error != DirectDeliveryCommandWireError.None)
            return new(envelope.Error, envelope.ValidationError, null);
        if (request.AuthorityGeneration != envelope.Generation ||
            request.WriterEpoch != envelope.Epoch ||
            request.Attempt != envelope.Attempt)
            return new(DirectDeliveryCommandWireError.MalformedEnvelope, CommandValidationError.MalformedEnvelope, null);
        return new(DirectDeliveryCommandWireError.None, CommandValidationError.None, request);
    }

    /// <summary>
    /// Envelope-only validation, shared by every admitted payload kind: header shape, payload
    /// digest, cell, identity bounds, optional lease expectations, signature, and validity
    /// window. It binds no payload shape; the caller canonicalizes the payload and cross-checks
    /// its identity fields against <see cref="DirectDeliverySignedEnvelope.OperationId"/>,
    /// generation, epoch, and attempt.
    /// </summary>
    internal static DirectDeliverySignedEnvelope ValidateSignedEnvelope(
        ReadOnlyMemory<byte> payload,
        IEnumerable<KeyValuePair<string, string>>? headers,
        string expectedCell,
        DateTimeOffset now,
        TimeSpan allowedClockSkew,
        ICommandSignatureVerifier signatureVerifier,
        long? expectedGeneration,
        long? expectedEpoch,
        string? expectedOperationId = null)
    {
        ArgumentNullException.ThrowIfNull(signatureVerifier);
        if (allowedClockSkew < TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(allowedClockSkew));
        var values = ValidateHeaders(headers, payload);
        if (values is null) return DirectDeliverySignedEnvelope.Refused(
            DirectDeliveryCommandWireError.MalformedEnvelope, CommandValidationError.MalformedEnvelope);

        var digest = Convert.ToHexStringLower(SHA256.HashData(payload.Span));
        if (digest != values[PayloadSha256Header] ||
            !string.Equals(expectedCell, values[CellHeader], StringComparison.Ordinal) ||
            expectedOperationId is not null &&
                !string.Equals(expectedOperationId, values[OperationHeader], StringComparison.Ordinal))
            return DirectDeliverySignedEnvelope.Refused(
                DirectDeliveryCommandWireError.MalformedEnvelope, CommandValidationError.MalformedEnvelope);

        if (!TryPositive(values[GenerationHeader], out var requestedGeneration) ||
            !TryPositive(values[EpochHeader], out var requestedEpoch) ||
            !TryPositive(values[AttemptHeader], out var requestedAttempt) ||
            !ProtocolRevision.TryCreate(1, out var protocol) ||
            !CellId.TryCreate(values[CellHeader], out var cell) ||
            !AggregateId.TryCreate(Aggregate, out var aggregate) ||
            !DesiredGeneration.TryCreate(requestedGeneration, out var generation) ||
            !WriterEpoch.TryCreate(requestedEpoch, out var epoch) ||
            !OperationId.TryCreate(values[OperationHeader], out var operation) ||
            !IdempotencyKey.TryCreate(values[OperationHeader], out var idempotency) ||
            !DeliveryAttempt.TryCreate(requestedAttempt, out var attempt) ||
            !PayloadDigest.TryCopyFrom(Convert.FromHexString(digest), out var payloadDigest) ||
            payloadDigest is null ||
            !OpaqueSignature.TryCopyFrom(Convert.FromBase64String(values[SignatureHeader]), out var signature) ||
            signature is null)
            return DirectDeliverySignedEnvelope.Refused(
                DirectDeliveryCommandWireError.MalformedEnvelope, CommandValidationError.MalformedEnvelope);
        if (expectedGeneration is <= 0 || expectedEpoch is <= 0)
            return DirectDeliverySignedEnvelope.Refused(
                DirectDeliveryCommandWireError.MalformedEnvelope, CommandValidationError.MalformedEnvelope);
        if (expectedGeneration is { } generationValue && requestedGeneration != generationValue)
            return DirectDeliverySignedEnvelope.Refused(
                DirectDeliveryCommandWireError.ValidationRejected, CommandValidationError.StaleGeneration);
        if (expectedEpoch is { } epochValue && requestedEpoch != epochValue)
            return DirectDeliverySignedEnvelope.Refused(
                DirectDeliveryCommandWireError.ValidationRejected, CommandValidationError.StaleWriterEpoch);
        var issuedAt = DateTimeOffset.FromUnixTimeMilliseconds(
            long.Parse(values[IssuedHeader], CultureInfo.InvariantCulture));
        var expiresAt = DateTimeOffset.FromUnixTimeMilliseconds(
            long.Parse(values[ExpiresHeader], CultureInfo.InvariantCulture));
        var envelope = new CommandEnvelope(
            protocol,
            cell,
            aggregate,
            generation,
            epoch,
            operation,
            idempotency,
            issuedAt,
            expiresAt,
            attempt,
            OpaquePayload.CopyFrom(payload.Span),
            payloadDigest,
            signature);
        var context = new CommandValidationContext(
            cell,
            aggregate,
            generation,
            epoch,
            [protocol],
            allowedClockSkew,
            Sha256PayloadDigestVerifier.Instance,
            signatureVerifier);
        var result = CommandEnvelopeValidator.Validate(envelope, context, now);
        return result.IsValid
            ? new(DirectDeliveryCommandWireError.None, CommandValidationError.None, envelope,
                values[OperationHeader], requestedGeneration, requestedEpoch, (int)requestedAttempt)
            : DirectDeliverySignedEnvelope.Refused(
                DirectDeliveryCommandWireError.ValidationRejected, result.Error);
    }

    /// <summary>Canonicalizes a payload as a DeliveryRequest; null when it is not one.</summary>
    internal static DeliveryRequest? TryCanonicalizeDeliveryRequest(ReadOnlyMemory<byte> payload) =>
        Canonicalize(payload);

    private static Dictionary<string, string>? ValidateHeaders(
        IEnumerable<KeyValuePair<string, string>>? headers,
        ReadOnlyMemory<byte> payload)
    {
        if (payload.Length is < 1 or > MaximumPayloadBytes) return null;
        var captured = (headers ?? []).Take(ExpectedHeaderCount + 1).ToArray();
        if (captured.Length != ExpectedHeaderCount ||
            captured.Any(static item => string.IsNullOrEmpty(item.Key) || string.IsNullOrEmpty(item.Value)))
            return null;
        var values = new Dictionary<string, string>(ExpectedHeaderCount, StringComparer.Ordinal);
        foreach (var header in captured)
            if (!values.TryAdd(header.Key, header.Value)) return null;
        if (!ExpectedHeaders.SetEquals(values.Keys)) return null;
        if (values.Sum(static item =>
                Encoding.UTF8.GetByteCount(item.Key) + Encoding.UTF8.GetByteCount(item.Value) + 4) > MaximumHeaderBytes)
            return null;
        if (values[SchemaHeader] != "1" || values[ProtocolHeader] != "1" || values[TypeHeader] != Type)
            return null;
        // Timestamps are range-checked BEFORE any DateTimeOffset conversion: extreme values
        // (e.g. long.MaxValue) would otherwise throw out of range instead of yielding the
        // typed Malformed receipt.
        if (!long.TryParse(values[IssuedHeader], CultureInfo.InvariantCulture, out var issuedMilliseconds) ||
            !long.TryParse(values[ExpiresHeader], CultureInfo.InvariantCulture, out var expiresMilliseconds) ||
            issuedMilliseconds is < MinimumUnixMilliseconds or > MaximumUnixMilliseconds ||
            expiresMilliseconds is < MinimumUnixMilliseconds or > MaximumUnixMilliseconds)
            return null;
        if (!IsDigest(values[PayloadSha256Header])) return null;
        try
        {
            var bytes = Convert.FromBase64String(values[SignatureHeader]);
            if (bytes.Length is < 1 or > MaximumSignatureBytes ||
                Convert.ToBase64String(bytes) != values[SignatureHeader])
                return null;
        }
        catch (FormatException)
        {
            return null;
        }
        return values;
    }

    private static DeliveryRequest? Canonicalize(ReadOnlyMemory<byte> payload)
    {
        try
        {
            var request = DeliveryWireCodec.DeserializeRequest(Encoding.UTF8.GetString(payload.Span));
            return Encoding.UTF8.GetBytes(DeliveryWireCodec.SerializeRequest(request))
                    .AsSpan()
                    .SequenceEqual(payload.Span)
                ? request
                : null;
        }
        catch (Exception exception) when (exception is JsonException or DecoderFallbackException)
        {
            return null;
        }
    }

    private static bool IsDigest(string? value) => value is { Length: 64 } &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static bool TryPositive(string? value, out long number)
    {
        return long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out number) &&
            number > 0 && number.ToString(CultureInfo.InvariantCulture) == value;
    }

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
}

