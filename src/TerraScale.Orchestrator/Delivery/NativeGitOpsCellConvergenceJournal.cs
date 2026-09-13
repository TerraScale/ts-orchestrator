using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.Delivery;

internal enum NativeGitOpsCellConvergenceJournalDisposition
{
    Unspecified,
    Recorded,
    Duplicate,
    StaleWriter,
    StaleAcceptance,
    AcceptanceConflict,
    StaleGeneration,
    GenerationConflict,
    AcceptedBaseMismatch,
    StaleObservation,
    StaleAuthority,
    Contention,
}

internal sealed record NativeGitOpsCellConvergenceCheckpoint(
    string Cell,
    long Generation,
    string GlobalPlanDigest,
    string HandoffDigest,
    string PayloadSha256,
    long WriterEpoch,
    ulong AcceptanceStreamSequence,
    string AcceptanceSignatureSha256,
    ulong AcceptanceRevision,
    long ObservationWatermark,
    NativeGitOpsCellConvergenceDecision Decision,
    long CheckpointSequence,
    string PreviousCheckpointDigest,
    string CheckpointDigest,
    ulong JournalRevision);

internal sealed record NativeGitOpsCellConvergenceJournalReceipt(
    NativeGitOpsCellConvergenceJournalDisposition Disposition,
    NativeGitOpsCellConvergenceCheckpoint? Checkpoint)
{
    internal bool CanDispatch =>
        Disposition is NativeGitOpsCellConvergenceJournalDisposition.Recorded or
            NativeGitOpsCellConvergenceJournalDisposition.Duplicate &&
        Checkpoint?.Decision.State == NativeGitOpsCellConvergenceState.Pending &&
        Checkpoint.Decision.Intent is not null;

    internal bool CanAdvanceGlobal =>
        Disposition is NativeGitOpsCellConvergenceJournalDisposition.Recorded or
            NativeGitOpsCellConvergenceJournalDisposition.Duplicate &&
        Checkpoint?.Decision.IsConverged == true;
}

/// <summary>
/// Commits one fenced regional convergence decision before its intent may be dispatched. Exact
/// retries recover the same checkpoint; observation changes require a strictly newer watermark.
/// </summary>
internal sealed class NativeGitOpsCellConvergenceJournal(IForgejoDeliveryLedger ledger)
{
    private const int MaximumRecordBytes = 16 * 1024;
    private const int MaximumConflictRetries = 4;
    private static readonly string EmptyCheckpointDigest = Convert.ToHexStringLower(
        SHA256.HashData(Encoding.UTF8.GetBytes("TerraScale.NativeGitOpsCellConvergence.v1")));

    internal async Task<NativeGitOpsCellConvergenceCheckpoint?> ReadAsync(
        string cell,
        CancellationToken cancellationToken = default)
    {
        ValidateCell(cell);
        var entry = await ledger.GetAsync(Index(cell), cancellationToken);
        if (entry is null) return null;
        var document = Deserialize(entry.Value);
        if (document.Cell != cell)
            throw new InvalidDataException("A native GitOps convergence journal changed cell identity.");
        return document.Checkpoint(entry.Revision);
    }

    internal async Task<NativeGitOpsCellConvergenceJournalReceipt> AdvanceAsync(
        NativeGitOpsAcceptedCellSpec accepted,
        IEnumerable<NativeGitOpsWorkloadObservation> observations,
        IEnumerable<NativeGitOpsRetirementEvidence> retirementEvidence,
        NativeGitOpsRollbackTarget? rollbackTarget,
        long observationWatermark,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(accepted);
        ArgumentNullException.ThrowIfNull(observations);
        ArgumentNullException.ThrowIfNull(retirementEvidence);
        ArgumentNullException.ThrowIfNull(authorityStillValid);
        ValidateCell(accepted.Cell);
        var observed = observations.Take(NativeGitOpsManifest.MaximumWorkloads + 1).ToArray();
        var retirements = retirementEvidence.Take(NativeGitOpsManifest.MaximumWorkloads + 1).ToArray();
        if (observed.Length > NativeGitOpsManifest.MaximumWorkloads ||
            retirements.Length > NativeGitOpsManifest.MaximumWorkloads)
            throw new ArgumentException("The native GitOps convergence input exceeded its bound.");
        var spec = NativeGitOpsCellPayload.Parse(accepted);
        var key = Index(accepted.Cell);

        for (var attempt = 0; attempt < MaximumConflictRetries; attempt++)
        {
            var entry = await ledger.GetAsync(key, cancellationToken);
            var current = entry is null ? null : Deserialize(entry.Value);
            var currentCheckpoint = current is null
                ? null
                : entry is { } currentEntry
                    ? current.Checkpoint(currentEntry.Revision)
                    : throw new InvalidDataException("A native GitOps convergence record lost its durable revision.");
            var comparison = Compare(current, spec, accepted);
            if (comparison is { } rejected)
                return new(rejected, currentCheckpoint);
            var baseline = Baseline(current, spec, accepted.Cell);
            var decision = NativeGitOpsCellConvergencePlanner.Decide(
                accepted,
                baseline,
                observed,
                retirements,
                rollbackTarget,
                observationWatermark);
            var proposed = NativeGitOpsCellConvergenceDocument.From(
                accepted,
                spec,
                decision,
                observationWatermark,
                current,
                EmptyCheckpointDigest);
            proposed.Validate(EmptyCheckpointDigest);
            if (current is not null && proposed.SameCheckpoint(current))
                return new(
                    NativeGitOpsCellConvergenceJournalDisposition.Duplicate,
                    currentCheckpoint ?? throw new InvalidDataException(
                        "A duplicate native GitOps convergence record lost its durable revision."));
            if (current is not null && accepted.Generation == current.Generation &&
                accepted.WriterEpoch == current.WriterEpoch &&
                observationWatermark <= current.ObservationWatermark)
                return new(
                    NativeGitOpsCellConvergenceJournalDisposition.StaleObservation,
                    currentCheckpoint ?? throw new InvalidDataException(
                        "A stale native GitOps convergence record lost its durable revision."));
            if (!authorityStillValid())
                return new(NativeGitOpsCellConvergenceJournalDisposition.StaleAuthority, null);
            try
            {
                var updated = entry is null
                    ? await ledger.CreateAsync(key, Serialize(proposed), cancellationToken)
                    : await ledger.UpdateAsync(key, Serialize(proposed), entry.Revision, cancellationToken);
                return new(
                    NativeGitOpsCellConvergenceJournalDisposition.Recorded,
                    proposed.Checkpoint(updated.Revision));
            }
            catch (ForgejoDeliveryLedgerConflictException)
            {
            }
        }
        return new(NativeGitOpsCellConvergenceJournalDisposition.Contention, null);
    }

    private static NativeGitOpsCellConvergenceJournalDisposition? Compare(
        NativeGitOpsCellConvergenceDocument? current,
        NativeGitOpsParsedCellSpec spec,
        NativeGitOpsAcceptedCellSpec accepted)
    {
        if (current is null)
            return spec.AcceptedGeneration is null
                ? null
                : NativeGitOpsCellConvergenceJournalDisposition.AcceptedBaseMismatch;
        if (accepted.WriterEpoch < current.WriterEpoch)
            return NativeGitOpsCellConvergenceJournalDisposition.StaleWriter;
        if (accepted.Generation < current.Generation)
            return NativeGitOpsCellConvergenceJournalDisposition.StaleGeneration;
        if (accepted.Generation == current.Generation)
        {
            if (accepted.GlobalPlanDigest != current.GlobalPlanDigest ||
                accepted.HandoffDigest != current.HandoffDigest ||
                accepted.PayloadSha256 != current.PayloadSha256)
                return NativeGitOpsCellConvergenceJournalDisposition.GenerationConflict;
            if (accepted.WriterEpoch == current.WriterEpoch)
                return accepted.StreamSequence != current.AcceptanceStreamSequence ||
                    accepted.SignatureSha256 != current.AcceptanceSignatureSha256 ||
                    accepted.JournalRevision != current.AcceptanceRevision
                        ? NativeGitOpsCellConvergenceJournalDisposition.AcceptanceConflict
                        : null;
        }
        if (accepted.StreamSequence <= current.AcceptanceStreamSequence ||
            accepted.JournalRevision <= current.AcceptanceRevision)
            return NativeGitOpsCellConvergenceJournalDisposition.StaleAcceptance;
        if (accepted.Generation == current.Generation) return null;
        return spec.AcceptedGeneration != current.Generation ||
            spec.AcceptedGlobalPlanDigest != current.GlobalPlanDigest
                ? NativeGitOpsCellConvergenceJournalDisposition.AcceptedBaseMismatch
                : null;
    }

    private static NativeGitOpsAcceptedCellBaseline? Baseline(
        NativeGitOpsCellConvergenceDocument? current,
        NativeGitOpsParsedCellSpec spec,
        string cell)
    {
        if (spec.AcceptedGeneration is null) return null;
        if (current is null)
            throw new InvalidOperationException("A noninitial CellSpec requires accepted regional history.");
        if (current.Generation != spec.Generation)
            return new(cell, current.Generation, current.GlobalPlanDigest);
        if (current.AcceptedBaseGeneration is not { } acceptedBaseGeneration ||
            current.AcceptedBaseGlobalPlanDigest is not { } acceptedBaseGlobalPlanDigest)
            throw new InvalidDataException("A native GitOps convergence record is missing its accepted base proof.");
        return new(cell, acceptedBaseGeneration, acceptedBaseGlobalPlanDigest);
    }

    private static NativeGitOpsCellConvergenceDocument Deserialize(string value)
    {
        try
        {
            var document = JsonSerializer.Deserialize(
                value,
                NativeGitOpsCellConvergenceJsonContext.Default.NativeGitOpsCellConvergenceDocument)
                ?? throw new JsonException();
            document.Validate(EmptyCheckpointDigest);
            return document;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("A native GitOps convergence journal record is invalid.", exception);
        }
    }

    private static string Serialize(NativeGitOpsCellConvergenceDocument document)
    {
        var value = JsonSerializer.Serialize(
            document,
            NativeGitOpsCellConvergenceJsonContext.Default.NativeGitOpsCellConvergenceDocument);
        if (Encoding.UTF8.GetByteCount(value) > MaximumRecordBytes)
            throw new InvalidDataException("A native GitOps convergence journal record exceeded its bound.");
        return value;
    }

    private static void ValidateCell(string cell)
    {
        try { _ = new RuntimeAllocationId(cell); }
        catch (Exception exception) when (exception is ArgumentException or ArgumentNullException)
        {
            throw new ArgumentException("The native GitOps convergence cell identity is invalid.", nameof(cell), exception);
        }
    }

    private static string Index(string cell) => $"gitops.convergence.{Convert.ToHexStringLower(
        SHA256.HashData(Encoding.UTF8.GetBytes($"native-gitops-convergence:{cell}")))}";
}

internal sealed record NativeGitOpsCellConvergenceDocument(
    int SchemaVersion,
    string Cell,
    long Generation,
    string GlobalPlanDigest,
    string HandoffDigest,
    string PayloadSha256,
    long WriterEpoch,
    ulong AcceptanceStreamSequence,
    string AcceptanceSignatureSha256,
    ulong AcceptanceRevision,
    long? AcceptedBaseGeneration,
    string? AcceptedBaseGlobalPlanDigest,
    long ObservationWatermark,
    NativeGitOpsCellConvergenceState State,
    NativeGitOpsCellConvergenceHoldReason HoldReason,
    NativeGitOpsCellConvergenceIntentKind IntentKind,
    string? IntentWorkloadId,
    long? IntentGeneration,
    string? IntentWorkloadSha256,
    string? IntentObservationEvidenceSha256,
    long? RollbackQualifiedGeneration,
    string? RollbackGlobalPlanDigest,
    string? RollbackQualificationProofSha256,
    string? ConvergenceDigest,
    long CheckpointSequence,
    string PreviousCheckpointDigest,
    string CheckpointDigest)
{
    internal static NativeGitOpsCellConvergenceDocument From(
        NativeGitOpsAcceptedCellSpec accepted,
        NativeGitOpsParsedCellSpec spec,
        NativeGitOpsCellConvergenceDecision decision,
        long observationWatermark,
        NativeGitOpsCellConvergenceDocument? current,
        string emptyDigest)
    {
        var intent = decision.Intent;
        var rollback = intent?.RollbackTarget;
        var provisional = new NativeGitOpsCellConvergenceDocument(
            1,
            accepted.Cell,
            accepted.Generation,
            accepted.GlobalPlanDigest,
            accepted.HandoffDigest,
            accepted.PayloadSha256,
            accepted.WriterEpoch,
            accepted.StreamSequence,
            accepted.SignatureSha256,
            accepted.JournalRevision,
            spec.AcceptedGeneration,
            spec.AcceptedGlobalPlanDigest,
            observationWatermark,
            decision.State,
            decision.HoldReason,
            intent?.Kind ?? NativeGitOpsCellConvergenceIntentKind.Unspecified,
            intent?.WorkloadId,
            intent?.Generation,
            intent?.WorkloadSha256,
            intent?.ObservationEvidenceSha256,
            rollback?.QualifiedGeneration,
            rollback?.GlobalPlanDigest,
            rollback?.QualificationProofSha256,
            decision.ConvergenceDigest,
            (current?.CheckpointSequence ?? 0) + 1,
            current?.CheckpointDigest ?? emptyDigest,
            string.Empty);
        return provisional with { CheckpointDigest = provisional.ComputeDigest() };
    }

    internal NativeGitOpsCellConvergenceCheckpoint Checkpoint(ulong journalRevision) => new(
        Cell,
        Generation,
        GlobalPlanDigest,
        HandoffDigest,
        PayloadSha256,
        WriterEpoch,
        AcceptanceStreamSequence,
        AcceptanceSignatureSha256,
        AcceptanceRevision,
        ObservationWatermark,
        Decision(),
        CheckpointSequence,
        PreviousCheckpointDigest,
        CheckpointDigest,
        journalRevision);

    internal bool SameCheckpoint(NativeGitOpsCellConvergenceDocument other) => this with
    {
        CheckpointSequence = other.CheckpointSequence,
        PreviousCheckpointDigest = other.PreviousCheckpointDigest,
        CheckpointDigest = other.CheckpointDigest,
    } == other;

    internal void Validate(string emptyDigest)
    {
        try { _ = new RuntimeAllocationId(Cell); }
        catch (Exception exception) when (exception is ArgumentException or ArgumentNullException)
        {
            throw new InvalidDataException("A native GitOps convergence journal record is invalid.", exception);
        }
        if (SchemaVersion != 1 || Generation <= 0 || WriterEpoch <= 0 || AcceptanceStreamSequence == 0 ||
            AcceptanceRevision == 0 || ObservationWatermark <= 0 || CheckpointSequence <= 0 ||
            !Digest(GlobalPlanDigest) || !Digest(HandoffDigest) || !Digest(PayloadSha256) ||
            !Digest(AcceptanceSignatureSha256) || !Digest(PreviousCheckpointDigest) || !Digest(CheckpointDigest) ||
            (CheckpointSequence == 1) != (PreviousCheckpointDigest == emptyDigest) ||
            (AcceptedBaseGeneration is null) != (AcceptedBaseGlobalPlanDigest is null) ||
            AcceptedBaseGeneration is <= 0 || AcceptedBaseGeneration > Generation ||
            AcceptedBaseGlobalPlanDigest is not null && !Digest(AcceptedBaseGlobalPlanDigest) ||
            !ValidDecision() || CheckpointDigest != ComputeDigest())
            throw new InvalidDataException("A native GitOps convergence journal record is invalid.");
    }

    private bool ValidDecision()
    {
        if (!Enum.IsDefined(State) || !Enum.IsDefined(HoldReason) || !Enum.IsDefined(IntentKind))
            return false;
        var hasIntent = IntentKind != NativeGitOpsCellConvergenceIntentKind.Unspecified;
        var intentValid = hasIntent && !string.IsNullOrWhiteSpace(IntentWorkloadId) &&
            IntentGeneration > 0 && Digest(IntentWorkloadSha256) &&
            (IntentObservationEvidenceSha256 is null || Digest(IntentObservationEvidenceSha256));
        var hasRollback = RollbackQualifiedGeneration is not null || RollbackGlobalPlanDigest is not null ||
            RollbackQualificationProofSha256 is not null;
        var rollbackValid = IntentKind == NativeGitOpsCellConvergenceIntentKind.RequestRollbackGeneration
            ? RollbackQualifiedGeneration is > 0 && RollbackQualifiedGeneration < Generation &&
                Digest(RollbackGlobalPlanDigest) && Digest(RollbackQualificationProofSha256)
            : !hasRollback;
        return State switch
        {
            NativeGitOpsCellConvergenceState.Pending =>
                HoldReason == NativeGitOpsCellConvergenceHoldReason.None && intentValid && rollbackValid &&
                ConvergenceDigest is null,
            NativeGitOpsCellConvergenceState.Held =>
                HoldReason != NativeGitOpsCellConvergenceHoldReason.None && !hasIntent &&
                IntentWorkloadId is null && IntentGeneration is null && IntentWorkloadSha256 is null &&
                IntentObservationEvidenceSha256 is null && !hasRollback && ConvergenceDigest is null,
            NativeGitOpsCellConvergenceState.Converged =>
                HoldReason == NativeGitOpsCellConvergenceHoldReason.None && !hasIntent &&
                IntentWorkloadId is null && IntentGeneration is null && IntentWorkloadSha256 is null &&
                IntentObservationEvidenceSha256 is null && !hasRollback && Digest(ConvergenceDigest),
            _ => false,
        };
    }

    private NativeGitOpsCellConvergenceDecision Decision()
    {
        if (IntentKind == NativeGitOpsCellConvergenceIntentKind.Unspecified)
            return new(State, HoldReason, null, ConvergenceDigest);
        if (IntentWorkloadId is not { } workloadId || IntentGeneration is not { } generation ||
            IntentWorkloadSha256 is not { } workloadSha256)
            throw new InvalidDataException("A native GitOps convergence intent is missing its required proof.");
        NativeGitOpsRollbackTarget? rollbackTarget = null;
        if (RollbackQualifiedGeneration is { } qualifiedGeneration)
        {
            if (RollbackGlobalPlanDigest is not { } globalPlanDigest ||
                RollbackQualificationProofSha256 is not { } qualificationProofSha256)
                throw new InvalidDataException("A native GitOps rollback intent is missing its qualification proof.");
            rollbackTarget = new(qualifiedGeneration, globalPlanDigest, qualificationProofSha256);
        }
        else if (RollbackGlobalPlanDigest is not null || RollbackQualificationProofSha256 is not null)
        {
            throw new InvalidDataException("A native GitOps rollback intent has an incomplete target.");
        }
        var intent = new NativeGitOpsCellConvergenceIntent(
            IntentKind,
            workloadId,
            generation,
            workloadSha256,
            IntentObservationEvidenceSha256,
            rollbackTarget);
        return new(State, HoldReason, intent, ConvergenceDigest);
    }

    private string ComputeDigest()
    {
        var canonical = JsonSerializer.Serialize(
            this with { CheckpointDigest = string.Empty },
            NativeGitOpsCellConvergenceJsonContext.Default.NativeGitOpsCellConvergenceDocument);
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }

    private static bool Digest(string? value) => value is { Length: 64 } &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f');
}

[JsonSerializable(typeof(NativeGitOpsCellConvergenceDocument))]
internal sealed partial class NativeGitOpsCellConvergenceJsonContext : JsonSerializerContext;

