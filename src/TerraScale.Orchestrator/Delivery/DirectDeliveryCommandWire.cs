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
        ArgumentNullException.ThrowIfNull(sign);
        if (!ProtocolRevision.TryCreate(1, out var protocol) ||
            !CellId.TryCreate(cell, out var cellId) ||
            !AggregateId.TryCreate(Aggregate, out var aggregate) ||
            !DesiredGeneration.TryCreate(request.AuthorityGeneration, out var generation) ||
            !WriterEpoch.TryCreate(request.WriterEpoch, out var epoch) ||
            !OperationId.TryCreate(request.OperationId ?? string.Empty, out var operation) ||
            !IdempotencyKey.TryCreate(request.OperationId ?? string.Empty, out var idempotency) ||
            !DeliveryAttempt.TryCreate(request.Attempt, out var attempt))
            throw new ArgumentException("The direct delivery wire identity is invalid.", nameof(request));
        var payload = Encoding.UTF8.GetBytes(DeliveryWireCodec.SerializeRequest(request));
        if (payload.Length is < 1 or > MaximumPayloadBytes)
            throw new ArgumentException("The direct delivery payload exceeds its bound.", nameof(request));
        var digest = Convert.FromHexString(Convert.ToHexStringLower(SHA256.HashData(payload)));
        if (!PayloadDigest.TryCopyFrom(digest, out var payloadDigest) || payloadDigest is null)
            throw new ArgumentException("The direct delivery payload digest is invalid.", nameof(request));
        var material = new CommandSignedMaterial(
            protocol,
            cellId,
            aggregate,
            generation,
            epoch,
            operation,
            idempotency,
            issuedAt,
            expiresAt,
            attempt,
            OpaquePayload.CopyFrom(payload),
            payloadDigest);
        var signature = sign(material);
        if (signature is not { IsValid: true } || signature.Length > MaximumSignatureBytes)
            throw new ArgumentException("The direct delivery signature is invalid.", nameof(sign));
        var headers = new Dictionary<string, string>(ExpectedHeaderCount, StringComparer.Ordinal)
        {
            [SchemaHeader] = "1",
            [ProtocolHeader] = "1",
            [TypeHeader] = Type,
            [CellHeader] = cell,
            [OperationHeader] = request.OperationId ?? string.Empty,
            [GenerationHeader] = request.AuthorityGeneration.ToString(CultureInfo.InvariantCulture),
            [EpochHeader] = request.WriterEpoch.ToString(CultureInfo.InvariantCulture),
            [AttemptHeader] = request.Attempt.ToString(CultureInfo.InvariantCulture),
            [IssuedHeader] = issuedAt.ToUnixTimeMilliseconds().ToString(CultureInfo.InvariantCulture),
            [ExpiresHeader] = expiresAt.ToUnixTimeMilliseconds().ToString(CultureInfo.InvariantCulture),
            [PayloadSha256Header] = Convert.ToHexStringLower(SHA256.HashData(payload)),
            [SignatureHeader] = Convert.ToBase64String(signature.Bytes),
        };
        return (payload, headers);
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
        ArgumentNullException.ThrowIfNull(signatureVerifier);
        if (allowedClockSkew < TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(allowedClockSkew));
        var values = ValidateHeaders(headers, payload);
        if (values is null) return DirectDeliveryCommandWireReceipt.Malformed();

        if (Canonicalize(payload) is not { } request)
            return DirectDeliveryCommandWireReceipt.Malformed();
        var digest = Convert.ToHexStringLower(SHA256.HashData(payload.Span));
        if (digest != values[PayloadSha256Header] ||
            !string.Equals(request.OperationId, values[OperationHeader], StringComparison.Ordinal) ||
            !string.Equals(expectedCell, values[CellHeader], StringComparison.Ordinal))
            return DirectDeliveryCommandWireReceipt.Malformed();

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
            return DirectDeliveryCommandWireReceipt.Malformed();
        if (expectedGeneration is <= 0 || expectedEpoch is <= 0)
            return DirectDeliveryCommandWireReceipt.Malformed();
        if (expectedGeneration is { } generationValue && requestedGeneration != generationValue)
            return new(DirectDeliveryCommandWireError.ValidationRejected, CommandValidationError.StaleGeneration, null);
        if (expectedEpoch is { } epochValue && requestedEpoch != epochValue)
            return new(DirectDeliveryCommandWireError.ValidationRejected, CommandValidationError.StaleWriterEpoch, null);
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
        if (result.IsValid &&
            (request.AuthorityGeneration != generation.Value || request.WriterEpoch != epoch.Value ||
             request.Attempt != attempt.Value))
            return new(DirectDeliveryCommandWireError.MalformedEnvelope, CommandValidationError.MalformedEnvelope, null);
        return result.IsValid
            ? new(DirectDeliveryCommandWireError.None, CommandValidationError.None, request)
            : new(DirectDeliveryCommandWireError.ValidationRejected, result.Error, null);
    }

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
