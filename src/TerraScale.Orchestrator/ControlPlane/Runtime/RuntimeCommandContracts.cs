using System.Security.Cryptography;
using System.Text;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.ControlPlane.Runtime;

/// <summary>
/// Internal v1 command for a future durable host consumer. It is deliberately not a transport DTO
/// and is emitted only by the Native GitOps projector after all persisted fences agree.
/// </summary>
internal sealed record RuntimeCommandV1
{
    internal const int CurrentSchemaVersion = 1;

    internal RuntimeCommandV1(
        NativeGitOpsAcceptedCellSpec accepted,
        NativeGitOpsVerifiedConvergenceDispatchV1 checkpoint,
        RuntimeHostAssignmentV1 assignment,
        RuntimeLifecycleOperationRequest request)
    {
        SchemaVersion = CurrentSchemaVersion;
        ArgumentNullException.ThrowIfNull(accepted);
        ArgumentNullException.ThrowIfNull(checkpoint);
        Assignment = assignment ?? throw new ArgumentNullException(nameof(assignment));
        Request = request ?? throw new ArgumentNullException(nameof(request));
        AcceptedOperationId = accepted.OperationId;
        AcceptedIdempotencyKey = accepted.IdempotencyKey;
        AcceptedCell = new(accepted.Cell);
        AcceptedGeneration = new((ulong)accepted.Generation);
        AcceptedGlobalPlanDigest = new(accepted.GlobalPlanDigest);
        AcceptedHandoffDigest = new(accepted.HandoffDigest);
        AcceptedPayloadDigest = new(accepted.PayloadSha256);
        AcceptedWriterEpoch = new((ulong)accepted.WriterEpoch);
        AcceptedProtocolVersion = accepted.ProtocolVersion;
        AcceptedDeliveryAttempt = accepted.DeliveryAttempt;
        AcceptedIssuedAt = accepted.IssuedAt;
        AcceptedExpiresAt = accepted.ExpiresAt;
        AcceptedAt = accepted.AcceptedAt;
        AcceptanceStreamSequence = accepted.StreamSequence;
        AcceptanceSignatureDigest = new(accepted.SignatureSha256);
        AcceptanceJournalRevision = accepted.JournalRevision;
        ConvergenceIntentWorkloadId = checkpoint.IntentWorkloadId;
        ConvergenceIntentGeneration = checkpoint.IntentGeneration;
        ConvergenceIntentWorkloadDigest = new(checkpoint.IntentWorkloadSha256);
        ConvergenceCheckpointSequence = checkpoint.CheckpointSequence;
        PreviousConvergenceCheckpointDigest = new(checkpoint.PreviousCheckpointDigest);
        ConvergenceCheckpointDigest = new(checkpoint.CheckpointDigest);
        ConvergenceJournalRevision = checkpoint.JournalRevision;
        CanonicalDigest = new(RuntimeCommandFingerprint.Compute(this));
    }

    internal int SchemaVersion { get; }
    internal string AcceptedOperationId { get; }
    internal string AcceptedIdempotencyKey { get; }
    internal RuntimeLifecycleCellId AcceptedCell { get; }
    internal RuntimeGeneration AcceptedGeneration { get; }
    internal RuntimeDigest AcceptedGlobalPlanDigest { get; }
    internal RuntimeDigest AcceptedHandoffDigest { get; }
    internal RuntimeDigest AcceptedPayloadDigest { get; }
    internal RuntimeEpoch AcceptedWriterEpoch { get; }
    internal long AcceptedProtocolVersion { get; }
    internal long AcceptedDeliveryAttempt { get; }
    internal DateTimeOffset AcceptedIssuedAt { get; }
    internal DateTimeOffset AcceptedExpiresAt { get; }
    internal DateTimeOffset AcceptedAt { get; }
    internal ulong AcceptanceStreamSequence { get; }
    internal RuntimeDigest AcceptanceSignatureDigest { get; }
    internal ulong AcceptanceJournalRevision { get; }
    internal string ConvergenceIntentWorkloadId { get; }
    internal long ConvergenceIntentGeneration { get; }
    internal RuntimeDigest ConvergenceIntentWorkloadDigest { get; }
    internal long ConvergenceCheckpointSequence { get; }
    internal RuntimeDigest PreviousConvergenceCheckpointDigest { get; }
    internal RuntimeDigest ConvergenceCheckpointDigest { get; }
    internal ulong ConvergenceJournalRevision { get; }
    internal RuntimeHostAssignmentV1 Assignment { get; }
    internal RuntimeLifecycleOperationRequest Request { get; }
    internal RuntimeDigest CanonicalDigest { get; }
}

internal static class RuntimeCommandFingerprint
{
    internal static string Compute(RuntimeCommandV1 command)
    {
        ArgumentNullException.ThrowIfNull(command);
        var assignment = command.Assignment;
        var values = new List<string>
        {
            "runtime-command-v1",
            command.SchemaVersion.ToString(System.Globalization.CultureInfo.InvariantCulture),
            command.AcceptedOperationId,
            command.AcceptedIdempotencyKey,
            command.AcceptedCell.Value,
            command.AcceptedGeneration.Value.ToString(System.Globalization.CultureInfo.InvariantCulture),
            command.AcceptedGlobalPlanDigest.Sha256,
            command.AcceptedHandoffDigest.Sha256,
            command.AcceptedPayloadDigest.Sha256,
            command.AcceptedWriterEpoch.Value.ToString(System.Globalization.CultureInfo.InvariantCulture),
            command.AcceptedProtocolVersion.ToString(System.Globalization.CultureInfo.InvariantCulture),
            command.AcceptedDeliveryAttempt.ToString(System.Globalization.CultureInfo.InvariantCulture),
            command.AcceptedIssuedAt.UtcDateTime.Ticks.ToString(System.Globalization.CultureInfo.InvariantCulture),
            command.AcceptedExpiresAt.UtcDateTime.Ticks.ToString(System.Globalization.CultureInfo.InvariantCulture),
            command.AcceptedAt.UtcDateTime.Ticks.ToString(System.Globalization.CultureInfo.InvariantCulture),
            command.AcceptanceStreamSequence.ToString(System.Globalization.CultureInfo.InvariantCulture),
            command.AcceptanceSignatureDigest.Sha256,
            command.AcceptanceJournalRevision.ToString(System.Globalization.CultureInfo.InvariantCulture),
            command.ConvergenceIntentWorkloadId,
            command.ConvergenceIntentGeneration.ToString(System.Globalization.CultureInfo.InvariantCulture),
            command.ConvergenceIntentWorkloadDigest.Sha256,
            command.PreviousConvergenceCheckpointDigest.Sha256,
            command.ConvergenceCheckpointDigest.Sha256,
            command.ConvergenceCheckpointSequence.ToString(System.Globalization.CultureInfo.InvariantCulture),
            command.ConvergenceJournalRevision.ToString(System.Globalization.CultureInfo.InvariantCulture),
            assignment.Cell.Value,
            assignment.WorkloadId.Value,
            assignment.AllocationId.Value,
            assignment.Node.Value,
            assignment.AssignmentGeneration.Value.ToString(System.Globalization.CultureInfo.InvariantCulture),
            assignment.WorkloadGeneration.Value.ToString(System.Globalization.CultureInfo.InvariantCulture),
            assignment.WriterEpoch.Value.ToString(System.Globalization.CultureInfo.InvariantCulture),
            assignment.AcceptedGeneration.Value.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ((int)assignment.Role).ToString(System.Globalization.CultureInfo.InvariantCulture),
            ((int)assignment.Driver).ToString(System.Globalization.CultureInfo.InvariantCulture),
            ((int)assignment.Architecture).ToString(System.Globalization.CultureInfo.InvariantCulture),
            assignment.ArtifactDigest.Value,
            assignment.Resources.MemoryMaxBytes.ToString(System.Globalization.CultureInfo.InvariantCulture),
            assignment.Resources.TasksMax.ToString(System.Globalization.CultureInfo.InvariantCulture),
            assignment.Resources.CpuQuotaPercent.ToString(System.Globalization.CultureInfo.InvariantCulture),
            assignment.Resources.CpuWeight.ToString(System.Globalization.CultureInfo.InvariantCulture),
            assignment.Resources.IoWeight.ToString(System.Globalization.CultureInfo.InvariantCulture),
            assignment.Resources.Nice.ToString(System.Globalization.CultureInfo.InvariantCulture),
            assignment.ConfigId.Value,
            assignment.ExpectedPlanFingerprint.Value,
            command.Request.OperationKey.Value,
            command.Request.PlanFingerprint.Value,
            command.Request.AcceptedConvergenceDigest.Sha256,
            ((int)command.Request.Action).ToString(System.Globalization.CultureInfo.InvariantCulture),
            command.Request.WriterEpoch.Value.ToString(System.Globalization.CultureInfo.InvariantCulture),
            command.Request.AuthorizationEvidenceDigest.Sha256,
            command.Request.DeadlineEvidence.Digest.Sha256,
            command.Request.DeadlineEvidence.Watermark.ToString(System.Globalization.CultureInfo.InvariantCulture),
            assignment.Authorization.ExpiresAt.UtcDateTime.Ticks.ToString(System.Globalization.CultureInfo.InvariantCulture)
        };
        Add(values, assignment.SecretVersions.Select(static value => value.Value));
        Add(values, assignment.Volumes.Select(static value => $"{value.VolumeId.Value}:{(int)value.Retention}"));
        Add(values, assignment.Ports.Select(static value => value.Value.ToString(System.Globalization.CultureInfo.InvariantCulture)));
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(Canonical(values))));
    }

    private static void Add(ICollection<string> values, IEnumerable<string> items)
    {
        var copy = items.ToArray();
        values.Add(copy.Length.ToString(System.Globalization.CultureInfo.InvariantCulture));
        foreach (var value in copy) values.Add(value);
    }

    private static string Canonical(IEnumerable<string> values)
    {
        var builder = new StringBuilder();
        foreach (var value in values)
        {
            ArgumentNullException.ThrowIfNull(value);
            builder.Append(value.Length).Append(':').Append(value).Append(';');
        }
        return builder.ToString();
    }
}

