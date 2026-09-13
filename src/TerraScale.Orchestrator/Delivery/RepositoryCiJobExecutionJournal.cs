using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Delivery;

internal enum RepositoryCiJobExecutionPhase
{
    Unspecified,
    Ready,
    Running,
    Succeeded,
    Failed,
}

internal enum RepositoryCiJobExecutionDisposition
{
    Unspecified,
    Prepared,
    Superseded,
    Acquired,
    TakenOver,
    Renewed,
    Completed,
    Duplicate,
    NotPrepared,
    LeaseHeld,
    StaleAcceptance,
    StaleLease,
    PhaseConflict,
    IdentityConflict,
    Contention,
}

internal sealed class RepositoryCiJobExecutionSnapshot
{
    internal RepositoryCiJobExecutionSnapshot(RepositoryCiJobExecutionDocument document, ulong revision)
    {
        Document = document;
        Revision = revision;
    }

    internal RepositoryCiJobExecutionPhase Phase => Document.Phase;
    internal string Runner => Document.Runner;
    internal string PipelineDigest => Document.PipelineDigest;
    internal string Job => Document.Job;
    internal int Attempt => Document.Attempt;
    internal string LeaseId => Document.LeaseId;
    internal long LeaseSequence => Document.LeaseSequence;
    internal DateTimeOffset? LeaseExpiresAt => Document.LeaseExpiresAtUnixMilliseconds == 0
        ? null
        : DateTimeOffset.FromUnixTimeMilliseconds(Document.LeaseExpiresAtUnixMilliseconds);
    internal string EvidenceDigest => Document.EvidenceDigest;
    internal int RequiredTestSkips => Document.RequiredTestSkips;
    internal RepositoryCiJobFailureKind FailureKind => Document.FailureKind;
    internal RepositoryCiJobExecutionDocument Document { get; }
    internal ulong Revision { get; }
}

internal sealed record RepositoryCiJobExecutionReceipt(
    RepositoryCiJobExecutionDisposition Disposition,
    RepositoryCiJobExecutionSnapshot? Execution)
{
    internal bool CanAcknowledge => Disposition is
        RepositoryCiJobExecutionDisposition.Prepared or
        RepositoryCiJobExecutionDisposition.Superseded or
        RepositoryCiJobExecutionDisposition.Duplicate;
}

/// <summary>
/// Persists a fenced runner-owned execution record before a durably accepted JetStream command is
/// acknowledged. Work can start only under a bounded lease tied to the exact accepted payload,
/// signature, stream sequence, and acceptance revision.
/// </summary>
internal sealed class RepositoryCiJobExecutionJournal
{
    private const int MaximumRecordBytes = 16 * 1024;
    private const int MaximumConflictRetries = 4;
    private static readonly TimeSpan MinimumLease = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan MaximumLease = TimeSpan.FromMinutes(5);
    private readonly IForgejoDeliveryLedger ledger;

    internal RepositoryCiJobExecutionJournal(IForgejoDeliveryLedger ledger) =>
        this.ledger = ledger ?? throw new ArgumentNullException(nameof(ledger));

    internal async Task<RepositoryCiJobExecutionSnapshot?> ReadAsync(
        string runner,
        string pipelineDigest,
        string job,
        CancellationToken cancellationToken = default)
    {
        ValidateIdentity(runner, nameof(runner));
        ValidateDigest(pipelineDigest, nameof(pipelineDigest));
        ValidateIdentity(job, nameof(job));
        var entry = await ledger.GetAsync(Index(runner, pipelineDigest, job), cancellationToken);
        if (entry is null) return null;
        var document = Deserialize(entry.Value);
        if (document.Runner != runner || document.PipelineDigest != pipelineDigest || document.Job != job)
            throw new InvalidDataException("A CI runner execution record changed identity.");
        return new(document, entry.Revision);
    }

    internal async Task<RepositoryCiJobExecutionReceipt> PrepareAsync(
        RepositoryCiAcceptedJob accepted,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        ValidateAccepted(accepted);
        ValidateTimestamp(now, nameof(now));
        var proposed = RepositoryCiJobExecutionDocument.Ready(accepted, now);
        proposed.Validate();
        var key = Index(proposed.Runner, proposed.PipelineDigest, proposed.Job);

        for (var conflict = 0; conflict < MaximumConflictRetries; conflict++)
        {
            var entry = await ledger.GetAsync(key, cancellationToken);
            if (entry is null)
            {
                try
                {
                    var created = await ledger.CreateAsync(key, Serialize(proposed), cancellationToken);
                    return new(RepositoryCiJobExecutionDisposition.Prepared, new(proposed, created.Revision));
                }
                catch (ForgejoDeliveryLedgerConflictException)
                {
                    continue;
                }
            }

            var current = Deserialize(entry.Value);
            var freshness = CompareAcceptance(current, proposed);
            if (freshness != AcceptanceFreshness.Newer)
                return new(FreshnessDisposition(freshness),
                    freshness == AcceptanceFreshness.Same ? new(current, entry.Revision) : null);
            try
            {
                var updated = await ledger.UpdateAsync(key, Serialize(proposed), entry.Revision, cancellationToken);
                return new(RepositoryCiJobExecutionDisposition.Superseded, new(proposed, updated.Revision));
            }
            catch (ForgejoDeliveryLedgerConflictException)
            {
            }
        }

        return new(RepositoryCiJobExecutionDisposition.Contention, null);
    }

    internal async Task<RepositoryCiJobExecutionReceipt> AcquireAsync(
        RepositoryCiAcceptedJob accepted,
        string leaseId,
        DateTimeOffset now,
        TimeSpan leaseDuration,
        CancellationToken cancellationToken = default)
    {
        ValidateAccepted(accepted);
        ValidateIdentity(leaseId, nameof(leaseId));
        ValidateTimestamp(now, nameof(now));
        ValidateLeaseDuration(leaseDuration);
        var expected = RepositoryCiJobExecutionDocument.Ready(accepted, now);
        var key = Index(expected.Runner, expected.PipelineDigest, expected.Job);

        for (var conflict = 0; conflict < MaximumConflictRetries; conflict++)
        {
            var entry = await ledger.GetAsync(key, cancellationToken);
            if (entry is null)
                return new(RepositoryCiJobExecutionDisposition.NotPrepared, null);
            var current = Deserialize(entry.Value);
            var freshness = CompareAcceptance(current, expected);
            if (freshness != AcceptanceFreshness.Same)
                return new(FreshnessDisposition(freshness), null);
            if (current.Phase is RepositoryCiJobExecutionPhase.Succeeded or RepositoryCiJobExecutionPhase.Failed)
                return new(RepositoryCiJobExecutionDisposition.PhaseConflict, new(current, entry.Revision));
            if (current.Phase == RepositoryCiJobExecutionPhase.Running)
            {
                if (current.LeaseId == leaseId && now <= current.LeaseExpiresAt)
                    return new(RepositoryCiJobExecutionDisposition.Duplicate, new(current, entry.Revision));
                if (now <= current.LeaseExpiresAt)
                    return new(RepositoryCiJobExecutionDisposition.LeaseHeld, new(current, entry.Revision));
            }

            var disposition = current.Phase == RepositoryCiJobExecutionPhase.Ready
                ? RepositoryCiJobExecutionDisposition.Acquired
                : RepositoryCiJobExecutionDisposition.TakenOver;
            var running = current.Start(leaseId, now, leaseDuration);
            try
            {
                var updated = await ledger.UpdateAsync(key, Serialize(running), entry.Revision, cancellationToken);
                return new(disposition, new(running, updated.Revision));
            }
            catch (ForgejoDeliveryLedgerConflictException)
            {
            }
        }

        return new(RepositoryCiJobExecutionDisposition.Contention, null);
    }

    internal async Task<RepositoryCiJobExecutionReceipt> RenewAsync(
        RepositoryCiJobExecutionSnapshot lease,
        DateTimeOffset now,
        TimeSpan leaseDuration,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(lease);
        ValidateTimestamp(now, nameof(now));
        ValidateLeaseDuration(leaseDuration);
        var key = Index(lease.Runner, lease.PipelineDigest, lease.Job);

        for (var conflict = 0; conflict < MaximumConflictRetries; conflict++)
        {
            var entry = await ledger.GetAsync(key, cancellationToken);
            if (entry is null) return new(RepositoryCiJobExecutionDisposition.StaleLease, null);
            var current = Deserialize(entry.Value);
            if (!SameLease(current, lease.Document))
                return new(RepositoryCiJobExecutionDisposition.StaleLease, new(current, entry.Revision));
            if (current.Phase != RepositoryCiJobExecutionPhase.Running)
                return new(RepositoryCiJobExecutionDisposition.PhaseConflict, new(current, entry.Revision));
            if (now > current.LeaseExpiresAt)
                return new(RepositoryCiJobExecutionDisposition.StaleLease, new(current, entry.Revision));
            var renewed = current.Renew(now, leaseDuration);
            if (renewed == current)
                return new(RepositoryCiJobExecutionDisposition.Duplicate, new(current, entry.Revision));
            try
            {
                var updated = await ledger.UpdateAsync(key, Serialize(renewed), entry.Revision, cancellationToken);
                return new(RepositoryCiJobExecutionDisposition.Renewed, new(renewed, updated.Revision));
            }
            catch (ForgejoDeliveryLedgerConflictException)
            {
            }
        }

        return new(RepositoryCiJobExecutionDisposition.Contention, null);
    }

    internal async Task<RepositoryCiJobExecutionReceipt> CompleteAsync(
        RepositoryCiJobExecutionSnapshot lease,
        bool succeeded,
        string evidenceDigest,
        int requiredTestSkips,
        RepositoryCiJobFailureKind failureKind,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(lease);
        ValidateDigest(evidenceDigest, nameof(evidenceDigest));
        ValidateTimestamp(now, nameof(now));
        if (requiredTestSkips is < 0 or > 1_000_000)
            throw new ArgumentOutOfRangeException(nameof(requiredTestSkips));
        if (!Enum.IsDefined(failureKind) ||
            succeeded && failureKind != RepositoryCiJobFailureKind.Unspecified ||
            !succeeded && failureKind == RepositoryCiJobFailureKind.Unspecified)
            throw new ArgumentException("A terminal CI runner result has an invalid failure kind.", nameof(failureKind));
        var key = Index(lease.Runner, lease.PipelineDigest, lease.Job);

        for (var conflict = 0; conflict < MaximumConflictRetries; conflict++)
        {
            var entry = await ledger.GetAsync(key, cancellationToken);
            if (entry is null) return new(RepositoryCiJobExecutionDisposition.StaleLease, null);
            var current = Deserialize(entry.Value);
            if (!SameLease(current, lease.Document))
                return new(RepositoryCiJobExecutionDisposition.StaleLease, new(current, entry.Revision));
            if (current.Phase is RepositoryCiJobExecutionPhase.Succeeded or RepositoryCiJobExecutionPhase.Failed)
            {
                var exact = current.Phase == (succeeded
                        ? RepositoryCiJobExecutionPhase.Succeeded
                        : RepositoryCiJobExecutionPhase.Failed) &&
                    current.EvidenceDigest == evidenceDigest &&
                    current.RequiredTestSkips == requiredTestSkips &&
                    current.FailureKind == failureKind;
                return new(exact
                    ? RepositoryCiJobExecutionDisposition.Duplicate
                    : RepositoryCiJobExecutionDisposition.PhaseConflict, new(current, entry.Revision));
            }
            if (current.Phase != RepositoryCiJobExecutionPhase.Running)
                return new(RepositoryCiJobExecutionDisposition.PhaseConflict, new(current, entry.Revision));
            if (now > current.LeaseExpiresAt)
                return new(RepositoryCiJobExecutionDisposition.StaleLease, new(current, entry.Revision));
            var completed = current.Complete(succeeded, evidenceDigest, requiredTestSkips, failureKind, now);
            try
            {
                var updated = await ledger.UpdateAsync(key, Serialize(completed), entry.Revision, cancellationToken);
                return new(RepositoryCiJobExecutionDisposition.Completed, new(completed, updated.Revision));
            }
            catch (ForgejoDeliveryLedgerConflictException)
            {
            }
        }

        return new(RepositoryCiJobExecutionDisposition.Contention, null);
    }

    internal static void ValidateAccepted(RepositoryCiAcceptedJob accepted)
    {
        ArgumentNullException.ThrowIfNull(accepted);
        accepted.Command.Validate();
        var canonical = JsonSerializer.SerializeToUtf8Bytes(
            accepted.Command,
            RepositoryCiJobWireJsonContext.Default.RepositoryCiJobWireDocument);
        if (accepted.Payload.IsEmpty || accepted.Payload.Length > RepositoryCiJobWireCodec.MaximumPayloadBytes ||
            accepted.Signature.IsEmpty || accepted.Signature.Length > RepositoryCiJobWireCodec.MaximumSignatureBytes ||
            !accepted.Payload.Span.SequenceEqual(canonical) || accepted.StreamSequence == 0 ||
            accepted.JournalRevision == 0 || accepted.AcceptedAt.ToUnixTimeMilliseconds() <= 0 ||
            Hash(accepted.Payload.Span) != accepted.PayloadDigest ||
            Hash(accepted.Signature.Span) != accepted.SignatureDigest ||
            RepositoryCiJobAcceptanceJournal.ExecutionIdentityDigest(accepted.Command) != accepted.ExecutionIdentityDigest)
            throw new InvalidDataException("The accepted CI runner command is internally inconsistent.");
    }

    private static AcceptanceFreshness CompareAcceptance(
        RepositoryCiJobExecutionDocument current,
        RepositoryCiJobExecutionDocument proposed)
    {
        if (current.Runner != proposed.Runner || current.PipelineDigest != proposed.PipelineDigest ||
            current.Job != proposed.Job || current.JobDigest != proposed.JobDigest ||
            current.Generation != proposed.Generation)
            return AcceptanceFreshness.IdentityConflict;
        if (current.SameAcceptance(proposed)) return AcceptanceFreshness.Same;
        if (proposed.Attempt < current.Attempt)
            return AcceptanceFreshness.Stale;
        if (proposed.Attempt == current.Attempt)
        {
            if (proposed.ExecutionIdentityDigest != current.ExecutionIdentityDigest)
                return AcceptanceFreshness.IdentityConflict;
            return proposed.AuthorityEpoch > current.AuthorityEpoch &&
                proposed.FencingToken > current.FencingToken &&
                proposed.StreamSequence > current.StreamSequence &&
                proposed.AcceptanceRevision > current.AcceptanceRevision
                    ? AcceptanceFreshness.Newer
                    : AcceptanceFreshness.Stale;
        }
        if (proposed.Attempt != current.Attempt + 1)
            return AcceptanceFreshness.IdentityConflict;
        return proposed.AuthorityEpoch >= current.AuthorityEpoch &&
            proposed.FencingToken > current.FencingToken &&
            proposed.StreamSequence > current.StreamSequence &&
            proposed.AcceptanceRevision > current.AcceptanceRevision
                ? AcceptanceFreshness.Newer
                : AcceptanceFreshness.Stale;
    }

    private static RepositoryCiJobExecutionDisposition FreshnessDisposition(AcceptanceFreshness freshness) => freshness switch
    {
        AcceptanceFreshness.Same => RepositoryCiJobExecutionDisposition.Duplicate,
        AcceptanceFreshness.Stale => RepositoryCiJobExecutionDisposition.StaleAcceptance,
        AcceptanceFreshness.IdentityConflict => RepositoryCiJobExecutionDisposition.IdentityConflict,
        _ => throw new ArgumentOutOfRangeException(nameof(freshness)),
    };

    private static bool SameLease(
        RepositoryCiJobExecutionDocument current,
        RepositoryCiJobExecutionDocument expected) =>
        current.SameAcceptance(expected) && current.LeaseId == expected.LeaseId &&
        current.LeaseSequence == expected.LeaseSequence;

    private static string Serialize(RepositoryCiJobExecutionDocument document)
    {
        document.Validate();
        var value = JsonSerializer.Serialize(
            document,
            RepositoryCiJobExecutionJsonContext.Default.RepositoryCiJobExecutionDocument);
        if (Encoding.UTF8.GetByteCount(value) > MaximumRecordBytes)
            throw new InvalidDataException("The CI runner execution record exceeded its bound.");
        return value;
    }

    private static RepositoryCiJobExecutionDocument Deserialize(string value)
    {
        try
        {
            if (Encoding.UTF8.GetByteCount(value) > MaximumRecordBytes) throw new JsonException();
            var document = JsonSerializer.Deserialize(
                value,
                RepositoryCiJobExecutionJsonContext.Default.RepositoryCiJobExecutionDocument)
                ?? throw new JsonException();
            document.Validate();
            return document;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("A CI runner execution record is invalid.", exception);
        }
    }

    private static string Index(string runner, string pipelineDigest, string job) =>
        $"{GlobalNatsTopology.CiRunnerJournalPrefix(runner)}.{Hash(Encoding.UTF8.GetBytes($"{pipelineDigest}:{job}:execution"))}";

    private static void ValidateIdentity(string value, string parameter)
    {
        if (value is not { Length: >= 1 and <= 512 } ||
            value.Any(static character => char.IsWhiteSpace(character) || char.IsControl(character)))
            throw new ArgumentException("The CI runner execution identity is invalid.", parameter);
    }

    private static void ValidateDigest(string value, string parameter)
    {
        if (!RepositoryCiJobExecutionDocument.IsDigest(value))
            throw new ArgumentException("The CI runner execution digest is invalid.", parameter);
    }

    private static void ValidateTimestamp(DateTimeOffset value, string parameter)
    {
        if (value.ToUnixTimeMilliseconds() is <= 0 or > RepositoryCiJobExecutionDocument.MaximumUnixMilliseconds)
            throw new ArgumentOutOfRangeException(parameter);
    }

    private static void ValidateLeaseDuration(TimeSpan value)
    {
        if (value < MinimumLease || value > MaximumLease || value.Ticks % TimeSpan.TicksPerSecond != 0)
            throw new ArgumentOutOfRangeException(nameof(value), "A CI runner execution lease must be 30 seconds to 5 whole minutes.");
    }

    private static string Hash(ReadOnlySpan<byte> value) => Convert.ToHexStringLower(SHA256.HashData(value));

    private enum AcceptanceFreshness
    {
        Same,
        Newer,
        Stale,
        IdentityConflict,
    }
}

internal sealed record RepositoryCiJobExecutionDocument(
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
    string SignatureDigest,
    ulong StreamSequence,
    ulong AcceptanceRevision,
    RepositoryCiJobExecutionPhase Phase,
    string LeaseId,
    long LeaseSequence,
    long AcceptedAtUnixMilliseconds,
    long PreparedAtUnixMilliseconds,
    long StartedAtUnixMilliseconds,
    long LeaseExpiresAtUnixMilliseconds,
    long CompletedAtUnixMilliseconds,
    string EvidenceDigest,
    int RequiredTestSkips,
    RepositoryCiJobFailureKind FailureKind)
{
    internal const long MaximumUnixMilliseconds = 253_402_300_799_999;

    internal DateTimeOffset LeaseExpiresAt => DateTimeOffset.FromUnixTimeMilliseconds(LeaseExpiresAtUnixMilliseconds);

    internal static RepositoryCiJobExecutionDocument Ready(RepositoryCiAcceptedJob accepted, DateTimeOffset now)
    {
        var command = accepted.Command;
        return new(
            1,
            command.Runner,
            command.PipelineDigest,
            command.Job,
            command.JobDigest,
            command.Generation,
            command.Attempt,
            command.AuthorityEpoch,
            command.FencingToken,
            accepted.ExecutionIdentityDigest,
            accepted.PayloadDigest,
            accepted.SignatureDigest,
            accepted.StreamSequence,
            accepted.JournalRevision,
            RepositoryCiJobExecutionPhase.Ready,
            string.Empty,
            0,
            accepted.AcceptedAt.ToUnixTimeMilliseconds(),
            now.ToUnixTimeMilliseconds(),
            0,
            0,
            0,
            string.Empty,
            0,
            RepositoryCiJobFailureKind.Unspecified);
    }

    internal RepositoryCiJobExecutionDocument Start(string leaseId, DateTimeOffset now, TimeSpan duration) =>
        this with
        {
            Phase = RepositoryCiJobExecutionPhase.Running,
            LeaseId = leaseId,
            LeaseSequence = checked(LeaseSequence + 1),
            StartedAtUnixMilliseconds = now.ToUnixTimeMilliseconds(),
            LeaseExpiresAtUnixMilliseconds = now.Add(duration).ToUnixTimeMilliseconds(),
            CompletedAtUnixMilliseconds = 0,
            EvidenceDigest = string.Empty,
            RequiredTestSkips = 0,
            FailureKind = RepositoryCiJobFailureKind.Unspecified,
        };

    internal RepositoryCiJobExecutionDocument Renew(DateTimeOffset now, TimeSpan duration)
    {
        var expires = now.Add(duration).ToUnixTimeMilliseconds();
        return expires <= LeaseExpiresAtUnixMilliseconds
            ? this
            : this with { LeaseExpiresAtUnixMilliseconds = expires };
    }

    internal RepositoryCiJobExecutionDocument Complete(
        bool succeeded,
        string evidenceDigest,
        int requiredTestSkips,
        RepositoryCiJobFailureKind failureKind,
        DateTimeOffset now) => this with
        {
            Phase = succeeded ? RepositoryCiJobExecutionPhase.Succeeded : RepositoryCiJobExecutionPhase.Failed,
            CompletedAtUnixMilliseconds = now.ToUnixTimeMilliseconds(),
            EvidenceDigest = evidenceDigest,
            RequiredTestSkips = requiredTestSkips,
            FailureKind = failureKind,
        };

    internal bool SameAcceptance(RepositoryCiJobExecutionDocument other) =>
        Runner == other.Runner && PipelineDigest == other.PipelineDigest && Job == other.Job &&
        JobDigest == other.JobDigest && Generation == other.Generation && Attempt == other.Attempt &&
        AuthorityEpoch == other.AuthorityEpoch && FencingToken == other.FencingToken &&
        ExecutionIdentityDigest == other.ExecutionIdentityDigest && PayloadDigest == other.PayloadDigest &&
        SignatureDigest == other.SignatureDigest && StreamSequence == other.StreamSequence &&
        AcceptanceRevision == other.AcceptanceRevision;

    internal void Validate()
    {
        var ready = Phase == RepositoryCiJobExecutionPhase.Ready;
        var running = Phase == RepositoryCiJobExecutionPhase.Running;
        var succeeded = Phase == RepositoryCiJobExecutionPhase.Succeeded;
        var failed = Phase == RepositoryCiJobExecutionPhase.Failed;
        if (SchemaVersion != 1 || !Identity(Runner) || !IsDigest(PipelineDigest) || !Identity(Job) ||
            !IsDigest(JobDigest) || Generation <= 0 || Attempt is < 1 or > 3 || AuthorityEpoch <= 0 ||
            FencingToken <= 0 || !IsDigest(ExecutionIdentityDigest) || !IsDigest(PayloadDigest) ||
            !IsDigest(SignatureDigest) || StreamSequence == 0 || AcceptanceRevision == 0 ||
            Phase is not (RepositoryCiJobExecutionPhase.Ready or RepositoryCiJobExecutionPhase.Running or
                RepositoryCiJobExecutionPhase.Succeeded or RepositoryCiJobExecutionPhase.Failed) ||
            AcceptedAtUnixMilliseconds is <= 0 or > MaximumUnixMilliseconds ||
            PreparedAtUnixMilliseconds < AcceptedAtUnixMilliseconds ||
            PreparedAtUnixMilliseconds > MaximumUnixMilliseconds ||
            ready && (LeaseId.Length != 0 || LeaseSequence != 0 || StartedAtUnixMilliseconds != 0 ||
                LeaseExpiresAtUnixMilliseconds != 0 || CompletedAtUnixMilliseconds != 0 || EvidenceDigest.Length != 0 ||
                RequiredTestSkips != 0 || FailureKind != RepositoryCiJobFailureKind.Unspecified) ||
            !ready && (!Identity(LeaseId) || LeaseSequence <= 0 ||
                StartedAtUnixMilliseconds < PreparedAtUnixMilliseconds ||
                LeaseExpiresAtUnixMilliseconds < StartedAtUnixMilliseconds ||
                LeaseExpiresAtUnixMilliseconds > MaximumUnixMilliseconds) ||
            running && (CompletedAtUnixMilliseconds != 0 || EvidenceDigest.Length != 0 || RequiredTestSkips != 0 ||
                FailureKind != RepositoryCiJobFailureKind.Unspecified) ||
            (succeeded || failed) && (CompletedAtUnixMilliseconds < StartedAtUnixMilliseconds ||
                CompletedAtUnixMilliseconds > LeaseExpiresAtUnixMilliseconds ||
                CompletedAtUnixMilliseconds > MaximumUnixMilliseconds || !IsDigest(EvidenceDigest) ||
                RequiredTestSkips is < 0 or > 1_000_000) ||
            succeeded && FailureKind != RepositoryCiJobFailureKind.Unspecified ||
            failed && FailureKind == RepositoryCiJobFailureKind.Unspecified ||
            failed && !Enum.IsDefined(FailureKind))
            throw new InvalidDataException("A CI runner execution record is invalid.");
    }

    internal static bool IsDigest(string? value) => value is { Length: 64 } &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f') &&
        value.Any(static character => character != '0');

    private static bool Identity(string? value) => value is { Length: >= 1 and <= 512 } &&
        !value.Any(static character => char.IsWhiteSpace(character) || char.IsControl(character));
}

[JsonSerializable(typeof(RepositoryCiJobExecutionDocument))]
internal sealed partial class RepositoryCiJobExecutionJsonContext : JsonSerializerContext;

