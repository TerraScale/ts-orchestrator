using System.Collections.Frozen;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Text;
using TerraScale.Orchestrator.Contracts;
using TerraScale.Orchestrator.Protocol;

namespace TerraScale.Orchestrator.Delivery;

internal sealed record NativeGitOpsCellWireMessage(
    ReadOnlyMemory<byte> Payload,
    IReadOnlyDictionary<string, string> Headers);

internal sealed record NativeGitOpsDecodedCellCommand(
    NativeGitOpsCellHandoffDescriptor Handoff,
    CommandEnvelope Envelope);

/// <summary>
/// Encodes signed CellSpecs as raw NATS payload bytes plus bounded, canonical headers. The codec
/// performs structural checks only; regional acceptance still requires the configured verifier.
/// </summary>
internal static class NativeGitOpsCellWireCodec
{
    internal const int MaximumWireBytes = 1024 * 1024;
    internal const int MaximumHeaderBytes = 64 * 1024;
    private const int ProtocolOverheadBytes = 256;
    private const int HeaderCount = 16;
    private const string Schema = "TS-CellSpec-Schema";
    private const string Protocol = "TS-Protocol-Version";
    private const string Cell = "TS-Cell";
    private const string Aggregate = "TS-Aggregate-Id";
    private const string Generation = "TS-Desired-Generation";
    private const string Epoch = "TS-Writer-Epoch";
    private const string Operation = "TS-Operation-Id";
    private const string Idempotency = "TS-Idempotency-Key";
    private const string Issued = "TS-Issued-At";
    private const string Expires = "TS-Expires-At";
    private const string Attempt = "TS-Delivery-Attempt";
    private const string PayloadDigest = "TS-Payload-Sha256";
    private const string Signature = "TS-Signature";
    private const string GlobalPlan = "TS-Global-Plan-Digest";
    private const string Handoff = "TS-Handoff-Digest";
    private const string HandoffCells = "TS-Handoff-Cells";

    internal static NativeGitOpsCellWireMessage Encode(
        NativeGitOpsCellHandoff handoff,
        CommandEnvelope envelope)
    {
        ArgumentNullException.ThrowIfNull(handoff);
        ArgumentNullException.ThrowIfNull(envelope);
        var descriptor = NativeGitOpsCellEnvelope.Describe(handoff)
            ?? throw new InvalidDataException("The native GitOps handoff cannot be encoded.");
        EnsureStructurallyValid(envelope, descriptor);

        var headers = new Dictionary<string, string>(HeaderCount, StringComparer.Ordinal)
        {
            [Schema] = "1",
            [Protocol] = Number(envelope.ProtocolVersion.Value),
            [Cell] = envelope.Cell.Value,
            [Aggregate] = envelope.AggregateId.Value,
            [Generation] = Number(envelope.DesiredGeneration.Value),
            [Epoch] = Number(envelope.WriterEpoch.Value),
            [Operation] = envelope.OperationId.Value,
            [Idempotency] = envelope.IdempotencyKey.Value,
            [Issued] = envelope.IssuedAt.ToString("O", CultureInfo.InvariantCulture),
            [Expires] = envelope.ExpiresAt.ToString("O", CultureInfo.InvariantCulture),
            [Attempt] = Number(envelope.Attempt.Value),
            [PayloadDigest] = Convert.ToHexStringLower(envelope.PayloadDigest.Bytes),
            [Signature] = Convert.ToBase64String(envelope.Signature.Bytes),
            [GlobalPlan] = descriptor.GlobalPlanDigest,
            [Handoff] = descriptor.HandoffDigest,
            [HandoffCells] = string.Join(';', descriptor.Cells.Select(static item =>
                $"{item.Cell}={item.PayloadSha256}")),
        };
        EnsureBound(envelope.Payload.Length, headers);
        return new(
            envelope.Payload.Bytes.ToArray(),
            new ReadOnlyDictionary<string, string>(headers));
    }

    internal static NativeGitOpsDecodedCellCommand Decode(
        ReadOnlyMemory<byte> payload,
        IEnumerable<KeyValuePair<string, string>> headers)
    {
        ArgumentNullException.ThrowIfNull(headers);
        if (payload.Length is < 1 or > NativeGitOpsCellSpecCompiler.MaximumCellSpecBytes)
            throw Invalid();
        var captured = headers.Take(HeaderCount + 1).ToArray();
        if (captured.Length != HeaderCount ||
            captured.Any(static item => string.IsNullOrEmpty(item.Key) || item.Value is null))
            throw Invalid();
        var values = new Dictionary<string, string>(HeaderCount, StringComparer.Ordinal);
        foreach (var header in captured)
        {
            if (!values.TryAdd(header.Key, header.Value)) throw Invalid();
        }
        if (!ExpectedHeaders.All(values.ContainsKey) || values.Keys.Any(key => !ExpectedHeaders.Contains(key)))
            throw Invalid();
        EnsureBound(payload.Length, values);
        if (values[Schema] != "1") throw Invalid();

        var descriptor = new NativeGitOpsCellHandoffDescriptor(
            Positive(values[Generation]),
            Digest(values[GlobalPlan]),
            Digest(values[Handoff]),
            Array.AsReadOnly(ParseCells(values[HandoffCells])));
        var envelope = Envelope(payload.Span, values);
        EnsureStructurallyValid(envelope, descriptor);
        return new(descriptor, envelope);
    }

    private static CommandEnvelope Envelope(ReadOnlySpan<byte> payload, IReadOnlyDictionary<string, string> values)
    {
        if (!ProtocolRevision.TryCreate(Positive(values[Protocol]), out var protocol) ||
            !CellId.TryCreate(values[Cell], out var cell) ||
            !AggregateId.TryCreate(values[Aggregate], out var aggregate) ||
            !DesiredGeneration.TryCreate(Positive(values[Generation]), out var generation) ||
            !WriterEpoch.TryCreate(Positive(values[Epoch]), out var epoch) ||
            !OperationId.TryCreate(values[Operation], out var operation) ||
            !IdempotencyKey.TryCreate(values[Idempotency], out var idempotency) ||
            !DeliveryAttempt.TryCreate(Positive(values[Attempt]), out var attempt))
            throw Invalid();
        if (!DateTimeOffset.TryParseExact(
                values[Issued],
                "O",
                CultureInfo.InvariantCulture,
                DateTimeStyles.RoundtripKind,
                out var issuedAt) ||
            !DateTimeOffset.TryParseExact(
                values[Expires],
                "O",
                CultureInfo.InvariantCulture,
                DateTimeStyles.RoundtripKind,
                out var expiresAt))
            throw Invalid();
        if (issuedAt.ToString("O", CultureInfo.InvariantCulture) != values[Issued] ||
            expiresAt.ToString("O", CultureInfo.InvariantCulture) != values[Expires])
            throw Invalid();
        var digestBytes = HexDigest(values[PayloadDigest]);
        TerraScale.Orchestrator.Protocol.PayloadDigest.TryCopyFrom(digestBytes, out var digest);
        var signatureBytes = Base64(values[Signature]);
        if (signatureBytes.Length is < 1 or > NativeGitOpsCellEnvelope.MaximumSignatureBytes)
            throw Invalid();
        OpaqueSignature.TryCopyFrom(signatureBytes, out var signature);
        return new(
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
            OpaquePayload.CopyFrom(payload),
            digest!,
            signature!);
    }

    private static NativeGitOpsCellDigest[] ParseCells(string value)
    {
        var entries = value.Split(';', StringSplitOptions.None);
        if (entries.Length is < 1 or > NativeGitOpsCellSpecCompiler.MaximumCellsPerHandoff)
            throw Invalid();
        var cells = new NativeGitOpsCellDigest[entries.Length];
        for (var index = 0; index < entries.Length; index++)
        {
            var separator = entries[index].IndexOf('=');
            if (separator <= 0 || separator != entries[index].LastIndexOf('=')) throw Invalid();
            cells[index] = new(
                entries[index][..separator],
                Digest(entries[index][(separator + 1)..]));
        }
        return cells;
    }

    private static void EnsureStructurallyValid(
        CommandEnvelope envelope,
        NativeGitOpsCellHandoffDescriptor descriptor)
    {
        var result = NativeGitOpsCellEnvelope.Validate(
            envelope,
            descriptor,
            envelope.Cell.Value,
            envelope.WriterEpoch.Value,
            envelope.IssuedAt,
            TimeSpan.Zero,
            StructuralSignatureVerifier.Instance);
        if (!result.IsAccepted) throw Invalid();
    }

    private static void EnsureBound(int payloadBytes, IReadOnlyDictionary<string, string> headers)
    {
        var headerBytes = headers.Sum(static item =>
            Encoding.UTF8.GetByteCount(item.Key) + Encoding.UTF8.GetByteCount(item.Value) + 4);
        if (headerBytes > MaximumHeaderBytes ||
            payloadBytes > MaximumWireBytes - headerBytes - ProtocolOverheadBytes)
            throw Invalid();
    }

    private static long Positive(string value)
    {
        if (!long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var number) ||
            number <= 0 || Number(number) != value)
            throw Invalid();
        return number;
    }

    private static string Digest(string value)
    {
        _ = HexDigest(value);
        return value;
    }

    private static byte[] HexDigest(string value)
    {
        if (value.Length != 64 ||
            value.Any(static character => character is not (>= '0' and <= '9') and not (>= 'a' and <= 'f')))
            throw Invalid();
        return Convert.FromHexString(value);
    }

    private static byte[] Base64(string value)
    {
        try
        {
            var bytes = Convert.FromBase64String(value);
            if (Convert.ToBase64String(bytes) != value) throw Invalid();
            return bytes;
        }
        catch (FormatException exception)
        {
            throw new InvalidDataException("A native GitOps cell wire command is invalid.", exception);
        }
    }

    private static string Number(long value) => value.ToString(CultureInfo.InvariantCulture);

    private static InvalidDataException Invalid() =>
        new("A native GitOps cell wire command is invalid.");

    private static readonly FrozenSet<string> ExpectedHeaders = new[]
    {
        Schema, Protocol, Cell, Aggregate, Generation, Epoch, Operation, Idempotency, Issued, Expires,
        Attempt, PayloadDigest, Signature, GlobalPlan, Handoff, HandoffCells,
    }.ToFrozenSet(StringComparer.Ordinal);

    private sealed class StructuralSignatureVerifier : ICommandSignatureVerifier
    {
        internal static readonly StructuralSignatureVerifier Instance = new();

        public VerificationOutcome Verify(CommandSignedMaterial signedMaterial, OpaqueSignature signature) =>
            VerificationOutcome.Valid;
    }
}
