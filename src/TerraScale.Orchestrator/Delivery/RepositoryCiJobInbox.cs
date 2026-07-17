using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Protocol;

namespace TerraScale.Orchestrator.Delivery;

internal enum RepositoryCiJobAcceptanceDisposition
{
    Unspecified,
    Recorded,
    Duplicate,
    ProtocolRejected,
    RunnerMismatch,
    StaleAttempt,
    AttemptGap,
    StaleAuthority,
    StaleFence,
    StaleStreamSequence,
    IdentityConflict,
    Contention,
}

internal sealed record RepositoryCiAcceptedJob(
    RepositoryCiJobWireDocument Command,
    ReadOnlyMemory<byte> Payload,
    ReadOnlyMemory<byte> Signature,
    string PayloadDigest,
    string ExecutionIdentityDigest,
    string SignatureDigest,
    ulong StreamSequence,
    DateTimeOffset AcceptedAt,
    ulong JournalRevision);

internal sealed record RepositoryCiJobAcceptanceReceipt(
    RepositoryCiJobAcceptanceDisposition Disposition,
    CommandValidationError ProtocolError,
    RepositoryCiAcceptedJob? Acceptance)
{
    internal bool CanAcknowledge =>
        (Disposition is RepositoryCiJobAcceptanceDisposition.Recorded or
            RepositoryCiJobAcceptanceDisposition.Duplicate) &&
        Acceptance is not null;
}

/// <summary>
/// Makes a signed runner command acknowledgeable only after its canonical payload and monotonic
/// acceptance pointer are durable. It does not execute the accepted job.
/// </summary>
internal sealed class RepositoryCiJobAcceptanceJournal
{
    private const int MaximumRecordBytes = 16 * 1024;
    private const int MaximumConflictRetries = 4;
    private readonly IForgejoDeliveryLedger ledger;
    private readonly IDeliveryObjectStore payloads;

    internal RepositoryCiJobAcceptanceJournal(
        IForgejoDeliveryLedger ledger,
        IDeliveryObjectStore payloads)
    {
        this.ledger = ledger;
        this.payloads = payloads;
    }

    internal async Task<RepositoryCiAcceptedJob?> ReadAsync(
        string runner,
        string pipelineDigest,
        string job,
        CancellationToken cancellationToken = default)
    {
        ValidateIdentity(runner, nameof(runner));
        ValidateDigest(pipelineDigest, nameof(pipelineDigest));
        ValidateIdentity(job, nameof(job));
        var entry = await ledger.GetAsync(Index(runner, pipelineDigest, job), cancellationToken);
        return entry is null
            ? null
            : await ReadAsync(runner, pipelineDigest, job, entry, cancellationToken);
    }

    internal async Task<RepositoryCiJobAcceptanceReceipt> AcceptAsync(
        RepositoryCiDecodedJobCommand command,
        string expectedRunner,
        ulong streamSequence,
        DateTimeOffset now,
        TimeSpan allowedClockSkew,
        ICommandSignatureVerifier signatureVerifier,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);
        ArgumentNullException.ThrowIfNull(signatureVerifier);
        ValidateIdentity(expectedRunner, nameof(expectedRunner));
        if (streamSequence == 0) throw new ArgumentOutOfRangeException(nameof(streamSequence));
        if (allowedClockSkew < TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(allowedClockSkew));

        var document = command.Document;
        if (document.Runner != expectedRunner)
            return new(RepositoryCiJobAcceptanceDisposition.RunnerMismatch, CommandValidationError.None, null);
        var proposed = RepositoryCiJobAcceptanceDocument.From(command, streamSequence, now);
        proposed.Validate();
        var key = Index(expectedRunner, document.PipelineDigest, document.Job);
        var persisted = await ledger.GetAsync(key, cancellationToken);
        if (persisted is not null)
        {
            var accepted = await ReadAsync(
                expectedRunner,
                document.PipelineDigest,
                document.Job,
                persisted,
                cancellationToken);
            if (Compare(accepted, proposed) == RepositoryCiJobAcceptanceDisposition.Duplicate)
                return new(
                    RepositoryCiJobAcceptanceDisposition.Duplicate,
                    CommandValidationError.None,
                    accepted);
        }
        var protocol = Validate(command, now, allowedClockSkew, signatureVerifier);
        if (!protocol.IsValid)
            return new(
                RepositoryCiJobAcceptanceDisposition.ProtocolRejected,
                protocol.Error,
                null);

        var payloadStored = false;

        for (var conflict = 0; conflict < MaximumConflictRetries; conflict++)
        {
            var entry = await ledger.GetAsync(key, cancellationToken);
            if (entry is not null)
            {
                var accepted = await ReadAsync(
                    expectedRunner,
                    document.PipelineDigest,
                    document.Job,
                    entry,
                    cancellationToken);
                var disposition = Compare(accepted, proposed);
                if (disposition is not null)
                    return new(
                        disposition.Value,
                        CommandValidationError.None,
                        disposition == RepositoryCiJobAcceptanceDisposition.Duplicate ? accepted : null);
            }

            if (!payloadStored)
            {
                await payloads.PutAsync(
                    proposed.PayloadObject,
                    command.Envelope.Payload.Bytes.ToArray(),
                    cancellationToken);
                var verified = await payloads.GetAsync(proposed.PayloadObject, cancellationToken);
                if (!verified.AsSpan().SequenceEqual(command.Envelope.Payload.Bytes))
                    throw new InvalidDataException("The CI runner command was not durable after storage.");
                await payloads.PutAsync(
                    proposed.SignatureObject,
                    command.Envelope.Signature.Bytes.ToArray(),
                    cancellationToken);
                var verifiedSignature = await payloads.GetAsync(proposed.SignatureObject, cancellationToken);
                if (!verifiedSignature.AsSpan().SequenceEqual(command.Envelope.Signature.Bytes))
                    throw new InvalidDataException("The CI runner signature was not durable after storage.");
                payloadStored = true;
            }

            try
            {
                var updated = entry is null
                    ? await ledger.CreateAsync(key, Serialize(proposed), cancellationToken)
                    : await ledger.UpdateAsync(key, Serialize(proposed), entry.Revision, cancellationToken);
                return new(
                    RepositoryCiJobAcceptanceDisposition.Recorded,
                    CommandValidationError.None,
                    Accepted(
                        proposed,
                        command.Document,
                        command.Envelope.Payload.Bytes.ToArray(),
                        command.Envelope.Signature.Bytes.ToArray(),
                        updated.Revision));
            }
            catch (ForgejoDeliveryLedgerConflictException)
            {
            }
        }

        return new(RepositoryCiJobAcceptanceDisposition.Contention, CommandValidationError.None, null);
    }

    private async Task<RepositoryCiAcceptedJob> ReadAsync(
        string expectedRunner,
        string expectedPipelineDigest,
        string expectedJob,
        ForgejoDeliveryLedgerEntry entry,
        CancellationToken cancellationToken)
    {
        var pointer = Deserialize(entry.Value);
        if (pointer.Runner != expectedRunner || pointer.PipelineDigest != expectedPipelineDigest ||
            pointer.Job != expectedJob)
            throw new InvalidDataException("A CI runner acceptance changed identity.");
        var payload = await payloads.GetAsync(pointer.PayloadObject, cancellationToken);
        if (payload.Length is < 1 or > RepositoryCiJobWireCodec.MaximumPayloadBytes ||
            Hash(payload) != pointer.PayloadDigest)
            throw new InvalidDataException("The accepted CI runner command failed integrity verification.");
        var signature = await payloads.GetAsync(pointer.SignatureObject, cancellationToken);
        if (signature.Length is < 1 or > RepositoryCiJobWireCodec.MaximumSignatureBytes ||
            Hash(signature) != pointer.SignatureDigest)
            throw new InvalidDataException("The accepted CI runner signature failed integrity verification.");

        RepositoryCiJobWireDocument command;
        try
        {
            command = JsonSerializer.Deserialize(
                payload,
                RepositoryCiJobWireJsonContext.Default.RepositoryCiJobWireDocument) ?? throw new JsonException();
            command.Validate();
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("The accepted CI runner command is invalid.", exception);
        }
        var canonical = JsonSerializer.SerializeToUtf8Bytes(
            command,
            RepositoryCiJobWireJsonContext.Default.RepositoryCiJobWireDocument);
        if (!payload.AsSpan().SequenceEqual(canonical) || command.Runner != pointer.Runner ||
            command.PipelineDigest != pointer.PipelineDigest || command.Job != pointer.Job ||
            command.JobDigest != pointer.JobDigest || command.Generation != pointer.Generation ||
            command.Attempt != pointer.Attempt || command.AuthorityEpoch != pointer.AuthorityEpoch ||
            command.FencingToken != pointer.FencingToken ||
            ExecutionIdentityDigest(command) != pointer.ExecutionIdentityDigest)
            throw new InvalidDataException("The accepted CI runner command did not match its durable pointer.");
        return Accepted(pointer, command, payload, signature, entry.Revision);
    }

    private static CommandValidationResult Validate(
        RepositoryCiDecodedJobCommand command,
        DateTimeOffset now,
        TimeSpan allowedClockSkew,
        ICommandSignatureVerifier signatureVerifier)
    {
        try
        {
            command.Document.Validate();
            var canonical = JsonSerializer.SerializeToUtf8Bytes(
                command.Document,
                RepositoryCiJobWireJsonContext.Default.RepositoryCiJobWireDocument);
            var envelope = command.Envelope;
            var digestBytes = SHA256.HashData(canonical);
            PayloadDigest.TryCopyFrom(digestBytes, out var digest);
            if (!canonical.AsSpan().SequenceEqual(envelope.Payload.Bytes) ||
                !envelope.PayloadDigest.Equals(digest) || envelope.ProtocolVersion.Value != 1 ||
                envelope.Cell.Value != "global" || envelope.AggregateId.Value != command.Document.Job ||
                envelope.DesiredGeneration.Value != command.Document.Generation ||
                envelope.WriterEpoch.Value != command.Document.AuthorityEpoch ||
                envelope.OperationId.Value != command.Document.Operation ||
                envelope.IdempotencyKey.Value != command.Document.Idempotency ||
                envelope.Attempt.Value != command.Document.Attempt ||
                envelope.IssuedAt.ToUnixTimeMilliseconds() != command.Document.IssuedAtUnixMilliseconds ||
                envelope.ExpiresAt.ToUnixTimeMilliseconds() != command.Document.ExpiresAtUnixMilliseconds)
                return CommandValidationResult.Rejected(CommandValidationError.MalformedEnvelope);

            var context = new CommandValidationContext(
                envelope.Cell,
                envelope.AggregateId,
                envelope.DesiredGeneration,
                envelope.WriterEpoch,
                [envelope.ProtocolVersion],
                allowedClockSkew,
                Sha256PayloadDigestVerifier.Instance,
                signatureVerifier);
            return CommandEnvelopeValidator.Validate(envelope, context, now);
        }
        catch (Exception exception) when (exception is InvalidDataException or ArgumentException)
        {
            return CommandValidationResult.Rejected(CommandValidationError.MalformedEnvelope);
        }
    }

    private static RepositoryCiJobAcceptanceDisposition? Compare(
        RepositoryCiAcceptedJob accepted,
        RepositoryCiJobAcceptanceDocument proposed)
    {
        var current = accepted.Command;
        if (current.JobDigest != proposed.JobDigest || current.Generation != proposed.Generation)
            return RepositoryCiJobAcceptanceDisposition.IdentityConflict;
        if (proposed.Attempt < current.Attempt)
            return RepositoryCiJobAcceptanceDisposition.StaleAttempt;
        if (proposed.Attempt > current.Attempt)
        {
            if (proposed.Attempt != current.Attempt + 1)
                return RepositoryCiJobAcceptanceDisposition.AttemptGap;
            if (proposed.AuthorityEpoch < current.AuthorityEpoch)
                return RepositoryCiJobAcceptanceDisposition.StaleAuthority;
            if (proposed.FencingToken <= current.FencingToken)
                return RepositoryCiJobAcceptanceDisposition.StaleFence;
            return proposed.StreamSequence > accepted.StreamSequence
                ? null
                : RepositoryCiJobAcceptanceDisposition.StaleStreamSequence;
        }

        if (proposed.ExecutionIdentityDigest != accepted.ExecutionIdentityDigest)
            return RepositoryCiJobAcceptanceDisposition.IdentityConflict;
        if (proposed.AuthorityEpoch < current.AuthorityEpoch)
            return RepositoryCiJobAcceptanceDisposition.StaleAuthority;
        if (proposed.FencingToken < current.FencingToken)
            return RepositoryCiJobAcceptanceDisposition.StaleFence;
        if (proposed.FencingToken == current.FencingToken)
            return proposed.PayloadDigest == accepted.PayloadDigest &&
                proposed.SignatureDigest == accepted.SignatureDigest &&
                proposed.StreamSequence == accepted.StreamSequence
                    ? RepositoryCiJobAcceptanceDisposition.Duplicate
                    : RepositoryCiJobAcceptanceDisposition.IdentityConflict;
        if (proposed.AuthorityEpoch <= current.AuthorityEpoch)
            return RepositoryCiJobAcceptanceDisposition.IdentityConflict;
        return proposed.StreamSequence > accepted.StreamSequence
            ? null
            : RepositoryCiJobAcceptanceDisposition.StaleStreamSequence;
    }

    private static RepositoryCiAcceptedJob Accepted(
        RepositoryCiJobAcceptanceDocument pointer,
        RepositoryCiJobWireDocument command,
        ReadOnlyMemory<byte> payload,
        ReadOnlyMemory<byte> signature,
        ulong revision) => new(
        command,
        payload,
        signature,
        pointer.PayloadDigest,
        pointer.ExecutionIdentityDigest,
        pointer.SignatureDigest,
        pointer.StreamSequence,
        DateTimeOffset.FromUnixTimeMilliseconds(pointer.AcceptedAtUnixMilliseconds),
        revision);

    private static string Serialize(RepositoryCiJobAcceptanceDocument document)
    {
        var value = JsonSerializer.Serialize(
            document,
            RepositoryCiJobAcceptanceJsonContext.Default.RepositoryCiJobAcceptanceDocument);
        if (Encoding.UTF8.GetByteCount(value) > MaximumRecordBytes)
            throw new InvalidDataException("The CI runner acceptance record exceeded its bound.");
        return value;
    }

    private static RepositoryCiJobAcceptanceDocument Deserialize(string value)
    {
        try
        {
            if (Encoding.UTF8.GetByteCount(value) > MaximumRecordBytes) throw new JsonException();
            var document = JsonSerializer.Deserialize(
                value,
                RepositoryCiJobAcceptanceJsonContext.Default.RepositoryCiJobAcceptanceDocument)
                ?? throw new JsonException();
            document.Validate();
            return document;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("A CI runner acceptance record is invalid.", exception);
        }
    }

    internal static string ExecutionIdentityDigest(RepositoryCiJobWireDocument command)
    {
        var normalized = command with
        {
            Controller = "fenced-controller",
            AuthorityEpoch = 1,
            FencingToken = 1,
        };
        return Hash(JsonSerializer.SerializeToUtf8Bytes(
            normalized,
            RepositoryCiJobWireJsonContext.Default.RepositoryCiJobWireDocument));
    }

    private static string Index(string runner, string pipelineDigest, string job) =>
        $"{GlobalNatsTopology.CiRunnerJournalPrefix(runner)}.{Hash(Encoding.UTF8.GetBytes($"{pipelineDigest}:{job}"))}";

    private static void ValidateIdentity(string value, string parameter)
    {
        if (value is not { Length: >= 1 and <= 512 } ||
            value.Any(static character => char.IsWhiteSpace(character) || char.IsControl(character)))
            throw new ArgumentException("The CI runner acceptance identity is invalid.", parameter);
    }

    private static void ValidateDigest(string value, string parameter)
    {
        if (!RepositoryCiJobAcceptanceDocument.IsDigest(value))
            throw new ArgumentException("The CI runner acceptance digest is invalid.", parameter);
    }

    private static string Hash(ReadOnlySpan<byte> value) =>
        Convert.ToHexStringLower(SHA256.HashData(value));

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

internal sealed record RepositoryCiJobAcceptanceDocument(
    int SchemaVersion,
    string Runner,
    string PipelineDigest,
    string Job,
    string JobDigest,
    long Generation,
    int Attempt,
    long AuthorityEpoch,
    long FencingToken,
    string ExecutionIdentityDigest,
    string PayloadDigest,
    string PayloadObject,
    string SignatureDigest,
    string SignatureObject,
    ulong StreamSequence,
    long AcceptedAtUnixMilliseconds)
{
    internal static RepositoryCiJobAcceptanceDocument From(
        RepositoryCiDecodedJobCommand command,
        ulong streamSequence,
        DateTimeOffset acceptedAt)
    {
        var wire = command.Document;
        var payloadDigest = Convert.ToHexStringLower(SHA256.HashData(command.Envelope.Payload.Bytes));
        return new(
            1,
            wire.Runner,
            wire.PipelineDigest,
            wire.Job,
            wire.JobDigest,
            wire.Generation,
            wire.Attempt,
            wire.AuthorityEpoch,
            wire.FencingToken,
            RepositoryCiJobAcceptanceJournal.ExecutionIdentityDigest(wire),
            payloadDigest,
            $"ci-job-command-{payloadDigest}",
            Convert.ToHexStringLower(SHA256.HashData(command.Envelope.Signature.Bytes)),
            $"ci-job-signature-{Convert.ToHexStringLower(SHA256.HashData(command.Envelope.Signature.Bytes))}",
            streamSequence,
            acceptedAt.ToUnixTimeMilliseconds());
    }

    internal void Validate()
    {
        if (SchemaVersion != 1 || Runner is not { Length: >= 1 and <= 512 } ||
            Runner.Any(static character => char.IsWhiteSpace(character) || char.IsControl(character)) ||
            Job is not { Length: >= 1 and <= 512 } ||
            Job.Any(static character => char.IsWhiteSpace(character) || char.IsControl(character)) ||
            !IsDigest(PipelineDigest) || !IsDigest(JobDigest) || Generation <= 0 ||
            Attempt is < 1 or > 3 || AuthorityEpoch <= 0 || FencingToken <= 0 ||
            !IsDigest(ExecutionIdentityDigest) || !IsDigest(PayloadDigest) ||
            PayloadObject != $"ci-job-command-{PayloadDigest}" || !IsDigest(SignatureDigest) ||
            SignatureObject != $"ci-job-signature-{SignatureDigest}" || StreamSequence == 0 ||
            AcceptedAtUnixMilliseconds is <= 0 or > 253_402_300_799_999)
            throw new InvalidDataException("A CI runner acceptance record is invalid.");
    }

    internal static bool IsDigest(string? value) => value is { Length: 64 } &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f') &&
        value.Any(static character => character != '0');
}

internal enum RepositoryCiJobDeliveryDisposition
{
    Unspecified,
    Malformed,
    Rejected,
    Prepared,
    Acknowledged,
}

internal sealed record RepositoryCiJobDeliveryReceipt(
    RepositoryCiJobDeliveryDisposition Disposition,
    RepositoryCiJobAcceptanceDisposition AcceptanceDisposition,
    CommandValidationError ProtocolError,
    RepositoryCiAcceptedJob? Acceptance,
    RepositoryCiJobExecutionDisposition ExecutionDisposition = RepositoryCiJobExecutionDisposition.Unspecified,
    RepositoryCiJobExecutionSnapshot? Execution = null)
{
    internal bool CanAcknowledge =>
        Disposition == RepositoryCiJobDeliveryDisposition.Prepared && Acceptance is not null && Execution is not null;
    internal bool IsAcknowledged => Disposition == RepositoryCiJobDeliveryDisposition.Acknowledged;
}

internal sealed class RepositoryCiJobInbox(
    RepositoryCiJobAcceptanceJournal journal,
    RepositoryCiJobExecutionJournal executions)
{
    internal async Task<RepositoryCiJobDeliveryReceipt> ProcessAsync(
        ReadOnlyMemory<byte> payload,
        IEnumerable<KeyValuePair<string, string>> headers,
        ulong streamSequence,
        string expectedRunner,
        DateTimeOffset now,
        TimeSpan allowedClockSkew,
        ICommandSignatureVerifier signatureVerifier,
        Func<CancellationToken, Task> acknowledge,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(acknowledge);
        var prepared = await PrepareAsync(
            payload,
            headers,
            streamSequence,
            expectedRunner,
            now,
            allowedClockSkew,
            signatureVerifier,
            cancellationToken);
        if (!prepared.CanAcknowledge) return prepared;
        await acknowledge(cancellationToken);
        return prepared with { Disposition = RepositoryCiJobDeliveryDisposition.Acknowledged };
    }

    /// <summary>
    /// Durably prepares one INV-005 execution without acknowledging its transport delivery.
    /// </summary>
    internal async Task<RepositoryCiJobDeliveryReceipt> PrepareAsync(
        ReadOnlyMemory<byte> payload,
        IEnumerable<KeyValuePair<string, string>> headers,
        ulong streamSequence,
        string expectedRunner,
        DateTimeOffset now,
        TimeSpan allowedClockSkew,
        ICommandSignatureVerifier signatureVerifier,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(headers);
        ArgumentNullException.ThrowIfNull(signatureVerifier);
        RepositoryCiDecodedJobCommand command;
        try
        {
            command = RepositoryCiJobWireCodec.Decode(payload, headers);
        }
        catch (InvalidDataException)
        {
            return new(
                RepositoryCiJobDeliveryDisposition.Malformed,
                RepositoryCiJobAcceptanceDisposition.Unspecified,
                CommandValidationError.MalformedEnvelope,
                null);
        }

        RepositoryCiJobAcceptanceReceipt acceptance;
        try
        {
            acceptance = await journal.AcceptAsync(
                command,
                expectedRunner,
                streamSequence,
                now,
                allowedClockSkew,
                signatureVerifier,
                cancellationToken);
        }
        catch (ArgumentException)
        {
            return new(
                RepositoryCiJobDeliveryDisposition.Malformed,
                RepositoryCiJobAcceptanceDisposition.Unspecified,
                CommandValidationError.InvalidValidationContext,
                null);
        }
        if (!acceptance.CanAcknowledge)
            return new(
                RepositoryCiJobDeliveryDisposition.Rejected,
                acceptance.Disposition,
                acceptance.ProtocolError,
                null);

        var execution = await executions.PrepareAsync(acceptance.Acceptance!, now, cancellationToken);
        if (!execution.CanAcknowledge)
            return new(
                RepositoryCiJobDeliveryDisposition.Rejected,
                acceptance.Disposition,
                acceptance.ProtocolError,
                null,
                execution.Disposition,
                execution.Execution);

        return new(
            RepositoryCiJobDeliveryDisposition.Prepared,
            acceptance.Disposition,
            acceptance.ProtocolError,
            acceptance.Acceptance,
            execution.Disposition,
            execution.Execution);
    }
}

[JsonSerializable(typeof(RepositoryCiJobAcceptanceDocument))]
internal sealed partial class RepositoryCiJobAcceptanceJsonContext : JsonSerializerContext;
