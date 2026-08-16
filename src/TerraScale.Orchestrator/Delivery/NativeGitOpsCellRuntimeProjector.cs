using TerraScale.Orchestrator.ControlPlane.Runtime;
using HostRuntimePlan = TerraScale.Orchestrator.Runtime.HostRuntimePlan;
using System.Security.Cryptography;
using System.Text;

namespace TerraScale.Orchestrator.Delivery;

/// <summary>
/// Scalar receipt captured immediately after the authoritative convergence journal has returned a
/// durable dispatch result. The projector deliberately refuses raw checkpoint records.
/// </summary>
internal sealed record NativeGitOpsVerifiedConvergenceDispatchV1
{
    private NativeGitOpsVerifiedConvergenceDispatchV1(NativeGitOpsCellConvergenceCheckpoint checkpoint)
    {
        var intent = checkpoint.Decision.Intent!;
        Cell = checkpoint.Cell;
        Generation = checkpoint.Generation;
        GlobalPlanDigest = checkpoint.GlobalPlanDigest;
        HandoffDigest = checkpoint.HandoffDigest;
        PayloadSha256 = checkpoint.PayloadSha256;
        WriterEpoch = checkpoint.WriterEpoch;
        AcceptanceStreamSequence = checkpoint.AcceptanceStreamSequence;
        AcceptanceSignatureSha256 = checkpoint.AcceptanceSignatureSha256;
        AcceptanceRevision = checkpoint.AcceptanceRevision;
        IntentKind = intent.Kind;
        IntentWorkloadId = intent.WorkloadId;
        IntentGeneration = intent.Generation;
        IntentWorkloadSha256 = intent.WorkloadSha256;
        CheckpointSequence = checkpoint.CheckpointSequence;
        PreviousCheckpointDigest = checkpoint.PreviousCheckpointDigest;
        CheckpointDigest = checkpoint.CheckpointDigest;
        JournalRevision = checkpoint.JournalRevision;
    }

    internal string Cell { get; }
    internal long Generation { get; }
    internal string GlobalPlanDigest { get; }
    internal string HandoffDigest { get; }
    internal string PayloadSha256 { get; }
    internal long WriterEpoch { get; }
    internal ulong AcceptanceStreamSequence { get; }
    internal string AcceptanceSignatureSha256 { get; }
    internal ulong AcceptanceRevision { get; }
    internal NativeGitOpsCellConvergenceIntentKind IntentKind { get; }
    internal string IntentWorkloadId { get; }
    internal long IntentGeneration { get; }
    internal string IntentWorkloadSha256 { get; }
    internal long CheckpointSequence { get; }
    internal string PreviousCheckpointDigest { get; }
    internal string CheckpointDigest { get; }
    internal ulong JournalRevision { get; }

    /// <summary>
    /// The future journal-to-projector composition must call this directly with the receipt from
    /// <see cref="NativeGitOpsCellConvergenceJournal.AdvanceAsync"/> and its immediately preceding
    /// persisted checkpoint when the sequence is greater than one.
    /// </summary>
    internal static NativeGitOpsVerifiedConvergenceDispatchV1 FromAuthoritativeJournalReceipt(
        NativeGitOpsCellConvergenceJournalReceipt receipt,
        NativeGitOpsCellConvergenceCheckpoint? previousCheckpoint = null)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        if (!receipt.CanDispatch || receipt.Checkpoint is null)
            throw new InvalidOperationException("The convergence receipt is not durable dispatch authority.");
        var checkpoint = receipt.Checkpoint
            ?? throw new InvalidOperationException("The convergence receipt omitted its durable checkpoint.");
        var intent = checkpoint.Decision.Intent;
        try
        {
            _ = new RuntimeLifecycleCellId(checkpoint.Cell);
            _ = new RuntimeWorkloadId(intent?.WorkloadId ?? string.Empty);
        }
        catch (ArgumentException exception)
        {
            throw new InvalidOperationException("The convergence receipt identities are not canonical.", exception);
        }
        if (checkpoint.Decision.State != NativeGitOpsCellConvergenceState.Pending ||
            checkpoint.Decision.HoldReason != NativeGitOpsCellConvergenceHoldReason.None ||
            intent is null || intent.Generation <= 0 || checkpoint.Generation <= 0 || checkpoint.WriterEpoch <= 0 ||
            checkpoint.AcceptanceStreamSequence == 0 || checkpoint.AcceptanceRevision == 0 ||
            checkpoint.ObservationWatermark <= 0 || checkpoint.CheckpointSequence <= 0 ||
            checkpoint.JournalRevision == 0 || !Digest(checkpoint.GlobalPlanDigest) ||
            !Digest(checkpoint.HandoffDigest) || !Digest(checkpoint.PayloadSha256) ||
            !Digest(checkpoint.AcceptanceSignatureSha256) || !Digest(checkpoint.PreviousCheckpointDigest) ||
            !Digest(checkpoint.CheckpointDigest) || !Digest(intent.WorkloadSha256))
        {
            throw new InvalidOperationException("The convergence receipt checkpoint is not internally valid.");
        }
        if (checkpoint.CheckpointSequence == 1)
        {
            if (previousCheckpoint is not null || checkpoint.PreviousCheckpointDigest != GenesisDigest)
                throw new InvalidOperationException("The convergence receipt genesis chain is invalid.");
        }
        else if (previousCheckpoint is null || previousCheckpoint.Cell != checkpoint.Cell ||
                 previousCheckpoint.CheckpointSequence != checkpoint.CheckpointSequence - 1 ||
                 previousCheckpoint.CheckpointDigest != checkpoint.PreviousCheckpointDigest ||
                 previousCheckpoint.JournalRevision >= checkpoint.JournalRevision)
        {
            throw new InvalidOperationException("The convergence receipt predecessor chain is invalid.");
        }
        return new(checkpoint);
    }

    private static readonly string GenesisDigest = Convert.ToHexStringLower(
        SHA256.HashData(Encoding.UTF8.GetBytes("TerraScale.NativeGitOpsCellConvergence.v1")));

    private static bool Digest(string? value) => value is { Length: 64 } &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f');
}

/// <summary>
/// Pure internal boundary from durably accepted regional GitOps state to a future host command.
/// It intentionally publishes nothing and has no runtime executor dependency.
/// </summary>
internal static class NativeGitOpsCellRuntimeProjector
{
    internal static RuntimeCommandV1 Project(
        RuntimeAssignmentProjectionScopeV1 scope,
        NativeGitOpsAcceptedCellSpec accepted,
        NativeGitOpsVerifiedConvergenceDispatchV1 convergence,
        RuntimeHostAssignmentV1 assignment,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(accepted);
        ArgumentNullException.ThrowIfNull(convergence);
        ArgumentNullException.ThrowIfNull(assignment);
        if (now == default) throw new ArgumentOutOfRangeException(nameof(now));
        ValidateScope(scope, assignment);
        ValidateAccepted(accepted, assignment, now);
        ValidateCheckpoint(accepted, convergence, assignment);

        var spec = NativeGitOpsCellPayload.Parse(accepted);
        var workload = spec.DesiredWorkloads.SingleOrDefault(value => value.Id == assignment.WorkloadId.Value)
            ?? throw new InvalidOperationException("The assignment workload is not present in the accepted cell specification.");
        if (workload.Suspended || workload.Role != assignment.Role || workload.Runtime != assignment.Driver ||
            workload.ArtifactDigest != assignment.ArtifactDigest ||
            NativeGitOpsCellSpecCompiler.WorkloadDigest(workload) != convergence.IntentWorkloadSha256)
        {
            throw new InvalidOperationException("The assignment does not exactly bind the accepted workload.");
        }

        var plan = HostRuntimePlan.Create(
            assignment.Role,
            assignment.Driver,
            assignment.AllocationId,
            assignment.ArtifactDigest,
            assignment.Architecture,
            assignment.Resources);
        var fingerprint = RuntimeLifecycleFingerprint.Plan(plan);
        if (fingerprint != assignment.ExpectedPlanFingerprint)
            throw new InvalidOperationException("The persisted assignment plan fingerprint is not canonical.");

        var request = new RuntimeLifecycleOperationRequest(
            assignment.Cell,
            assignment.Node,
            assignment.WorkloadGeneration,
            assignment.ConvergenceCheckpointDigest,
            plan,
            LifecycleAction.Converge,
            assignment.WriterEpoch,
            assignment.Authorization.AuthorizationEvidenceDigest,
            assignment.Authorization.DeadlineEvidence);
        return new(accepted, convergence, assignment, request);
    }

    private static void ValidateScope(
        RuntimeAssignmentProjectionScopeV1 scope,
        RuntimeHostAssignmentV1 assignment)
    {
        if (scope.Cell != assignment.Cell || scope.Node != assignment.Node || scope.WriterEpoch != assignment.WriterEpoch)
            throw new InvalidOperationException("The assignment is foreign to this cell, node, or writer epoch.");
    }

    private static void ValidateAccepted(
        NativeGitOpsAcceptedCellSpec accepted,
        RuntimeHostAssignmentV1 assignment,
        DateTimeOffset now)
    {
        if (accepted.ProtocolVersion != 1 || accepted.Generation <= 0 || accepted.WriterEpoch <= 0 ||
            accepted.StreamSequence == 0 || accepted.JournalRevision == 0 || accepted.DeliveryAttempt <= 0 ||
            accepted.IssuedAt == default || accepted.AcceptedAt == default || accepted.IssuedAt > now ||
            accepted.AcceptedAt > now || accepted.IssuedAt >= accepted.ExpiresAt ||
            accepted.AcceptedAt < accepted.IssuedAt || accepted.AcceptedAt >= accepted.ExpiresAt ||
            now >= accepted.ExpiresAt || now >= assignment.Authorization.ExpiresAt ||
            accepted.ExpiresAt != assignment.Authorization.ExpiresAt ||
            accepted.Cell != assignment.Cell.Value || accepted.Generation != (long)assignment.AcceptedGeneration.Value ||
            accepted.GlobalPlanDigest != assignment.AcceptedGlobalPlanDigest.Sha256 ||
            accepted.HandoffDigest != assignment.AcceptedHandoffDigest.Sha256 ||
            accepted.PayloadSha256 != assignment.AcceptedPayloadDigest.Sha256 ||
            accepted.WriterEpoch != (long)assignment.WriterEpoch.Value ||
            accepted.StreamSequence != assignment.AcceptanceStreamSequence ||
            accepted.SignatureSha256 != assignment.AcceptanceSignatureDigest.Sha256 ||
            accepted.JournalRevision != assignment.AcceptanceJournalRevision ||
            accepted.OperationId != $"gitops/{accepted.HandoffDigest}/{accepted.Cell}" ||
            accepted.IdempotencyKey != $"gitops/{accepted.PayloadSha256}")
        {
            throw new InvalidOperationException("The persisted assignment does not bind the accepted native GitOps identity.");
        }
    }

    private static void ValidateCheckpoint(
        NativeGitOpsAcceptedCellSpec accepted,
        NativeGitOpsVerifiedConvergenceDispatchV1 checkpoint,
        RuntimeHostAssignmentV1 assignment)
    {
        if (checkpoint.IntentKind != NativeGitOpsCellConvergenceIntentKind.Apply ||
            checkpoint.Cell != accepted.Cell || checkpoint.Generation != accepted.Generation ||
            checkpoint.GlobalPlanDigest != accepted.GlobalPlanDigest || checkpoint.HandoffDigest != accepted.HandoffDigest ||
            checkpoint.PayloadSha256 != accepted.PayloadSha256 || checkpoint.WriterEpoch != accepted.WriterEpoch ||
            checkpoint.AcceptanceStreamSequence != accepted.StreamSequence ||
            checkpoint.AcceptanceSignatureSha256 != accepted.SignatureSha256 ||
            checkpoint.AcceptanceRevision != accepted.JournalRevision ||
            checkpoint.JournalRevision != assignment.ConvergenceJournalRevision ||
            checkpoint.CheckpointDigest != assignment.ConvergenceCheckpointDigest.Sha256 ||
            checkpoint.IntentWorkloadId != assignment.WorkloadId.Value ||
            checkpoint.IntentGeneration != accepted.Generation || checkpoint.IntentGeneration != (long)assignment.WorkloadGeneration.Value ||
            assignment.AssignmentGeneration != assignment.WorkloadGeneration ||
            assignment.WorkloadGeneration != assignment.AcceptedGeneration)
        {
            throw new InvalidOperationException("The convergence checkpoint and assignment are not an exact current apply intent.");
        }
    }
}
