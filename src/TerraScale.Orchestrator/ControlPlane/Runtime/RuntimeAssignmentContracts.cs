using System.Collections.ObjectModel;
using HostArchitecture = TerraScale.Orchestrator.Runtime.HostArchitecture;
using HostArtifactDigest = TerraScale.Orchestrator.Runtime.ArtifactDigest;
using HostRole = TerraScale.Orchestrator.Runtime.AdmittedRole;
using HostRuntimeAllocationId = TerraScale.Orchestrator.Runtime.RuntimeAllocationId;
using HostRuntimeDriver = TerraScale.Orchestrator.Runtime.RuntimeDriver;
using HostRuntimeResources = TerraScale.Orchestrator.Runtime.RuntimeResourceLimits;

namespace TerraScale.Orchestrator.ControlPlane.Runtime;

/// <summary>
/// Internal persisted host assignment. It contains references to admitted configuration and secret
/// versions, never configuration paths, secret material, or a caller-provided host execution plan.
/// </summary>
internal sealed record RuntimeHostAssignmentV1
{
    internal const int CurrentSchemaVersion = 1;

    internal RuntimeHostAssignmentV1(
        int schemaVersion,
        RuntimeLifecycleCellId cell,
        RuntimeWorkloadId workloadId,
        HostRuntimeAllocationId allocationId,
        RuntimeNodeId node,
        RuntimeGeneration assignmentGeneration,
        RuntimeGeneration workloadGeneration,
        RuntimeEpoch writerEpoch,
        RuntimeGeneration acceptedGeneration,
        RuntimeDigest acceptedGlobalPlanDigest,
        RuntimeDigest acceptedHandoffDigest,
        RuntimeDigest acceptedPayloadDigest,
        ulong acceptanceStreamSequence,
        RuntimeDigest acceptanceSignatureDigest,
        ulong acceptanceJournalRevision,
        ulong convergenceJournalRevision,
        RuntimeDigest convergenceCheckpointDigest,
        HostRole role,
        HostRuntimeDriver driver,
        HostArchitecture architecture,
        HostArtifactDigest artifactDigest,
        HostRuntimeResources resources,
        RuntimeConfigId configId,
        IEnumerable<RuntimeSecretVersionId> secretVersions,
        IEnumerable<RuntimeVolumeBinding> volumes,
        IEnumerable<RuntimePort> ports,
        RuntimeLifecyclePlanFingerprint expectedPlanFingerprint,
        RuntimeAssignmentAuthorizationV1 authorization)
    {
        if (schemaVersion != CurrentSchemaVersion) throw new ArgumentOutOfRangeException(nameof(schemaVersion));
        SchemaVersion = schemaVersion;
        Cell = cell ?? throw new ArgumentNullException(nameof(cell));
        WorkloadId = workloadId ?? throw new ArgumentNullException(nameof(workloadId));
        AllocationId = allocationId ?? throw new ArgumentNullException(nameof(allocationId));
        Node = node ?? throw new ArgumentNullException(nameof(node));
        AssignmentGeneration = assignmentGeneration ?? throw new ArgumentNullException(nameof(assignmentGeneration));
        WorkloadGeneration = workloadGeneration ?? throw new ArgumentNullException(nameof(workloadGeneration));
        WriterEpoch = writerEpoch ?? throw new ArgumentNullException(nameof(writerEpoch));
        AcceptedGeneration = acceptedGeneration ?? throw new ArgumentNullException(nameof(acceptedGeneration));
        AcceptedGlobalPlanDigest = acceptedGlobalPlanDigest ?? throw new ArgumentNullException(nameof(acceptedGlobalPlanDigest));
        AcceptedHandoffDigest = acceptedHandoffDigest ?? throw new ArgumentNullException(nameof(acceptedHandoffDigest));
        AcceptedPayloadDigest = acceptedPayloadDigest ?? throw new ArgumentNullException(nameof(acceptedPayloadDigest));
        if (acceptanceStreamSequence == 0) throw new ArgumentOutOfRangeException(nameof(acceptanceStreamSequence));
        AcceptanceStreamSequence = acceptanceStreamSequence;
        AcceptanceSignatureDigest = acceptanceSignatureDigest ?? throw new ArgumentNullException(nameof(acceptanceSignatureDigest));
        if (acceptanceJournalRevision == 0) throw new ArgumentOutOfRangeException(nameof(acceptanceJournalRevision));
        AcceptanceJournalRevision = acceptanceJournalRevision;
        if (convergenceJournalRevision == 0) throw new ArgumentOutOfRangeException(nameof(convergenceJournalRevision));
        ConvergenceJournalRevision = convergenceJournalRevision;
        ConvergenceCheckpointDigest = convergenceCheckpointDigest ?? throw new ArgumentNullException(nameof(convergenceCheckpointDigest));
        Role = RuntimeEnums.Defined(role, nameof(role));
        Driver = RuntimeEnums.Defined(driver, nameof(driver));
        Architecture = RuntimeEnums.Defined(architecture, nameof(architecture));
        ArtifactDigest = artifactDigest ?? throw new ArgumentNullException(nameof(artifactDigest));
        Resources = resources ?? throw new ArgumentNullException(nameof(resources));
        ConfigId = configId ?? throw new ArgumentNullException(nameof(configId));
        SecretVersions = CopyDistinct(secretVersions, nameof(secretVersions), static value => value.Value);
        Volumes = CopyDistinct(volumes, nameof(volumes), static value => value.VolumeId.Value);
        Ports = CopyDistinct(ports, nameof(ports), static value => value.Value);
        ExpectedPlanFingerprint = expectedPlanFingerprint ?? throw new ArgumentNullException(nameof(expectedPlanFingerprint));
        Authorization = authorization ?? throw new ArgumentNullException(nameof(authorization));
    }

    internal int SchemaVersion { get; }
    internal RuntimeLifecycleCellId Cell { get; }
    internal RuntimeWorkloadId WorkloadId { get; }
    internal HostRuntimeAllocationId AllocationId { get; }
    internal RuntimeNodeId Node { get; }
    internal RuntimeGeneration AssignmentGeneration { get; }
    internal RuntimeGeneration WorkloadGeneration { get; }
    internal RuntimeEpoch WriterEpoch { get; }
    internal RuntimeGeneration AcceptedGeneration { get; }
    internal RuntimeDigest AcceptedGlobalPlanDigest { get; }
    internal RuntimeDigest AcceptedHandoffDigest { get; }
    internal RuntimeDigest AcceptedPayloadDigest { get; }
    internal ulong AcceptanceStreamSequence { get; }
    internal RuntimeDigest AcceptanceSignatureDigest { get; }
    internal ulong AcceptanceJournalRevision { get; }
    internal ulong ConvergenceJournalRevision { get; }
    internal RuntimeDigest ConvergenceCheckpointDigest { get; }
    internal HostRole Role { get; }
    internal HostRuntimeDriver Driver { get; }
    internal HostArchitecture Architecture { get; }
    internal HostArtifactDigest ArtifactDigest { get; }
    internal HostRuntimeResources Resources { get; }
    internal RuntimeConfigId ConfigId { get; }
    internal IReadOnlyList<RuntimeSecretVersionId> SecretVersions { get; }
    internal IReadOnlyList<RuntimeVolumeBinding> Volumes { get; }
    internal IReadOnlyList<RuntimePort> Ports { get; }
    internal RuntimeLifecyclePlanFingerprint ExpectedPlanFingerprint { get; }
    internal RuntimeAssignmentAuthorizationV1 Authorization { get; }

    private static IReadOnlyList<T> CopyDistinct<T, TKey>(
        IEnumerable<T> values,
        string name,
        Func<T, TKey> key) where T : notnull where TKey : notnull
    {
        ArgumentNullException.ThrowIfNull(values, name);
        var copy = RuntimeInputSnapshot.Copy(values, RuntimeTechnicalLimits.MaximumCapturedItems, name);
        if (copy.Any(static value => value is null) || copy.Select(key).Distinct().Count() != copy.Length)
            throw new ArgumentException("Assignment bindings must be non-null and distinct.", name);
        return new ReadOnlyCollection<T>(copy.OrderBy(key).ToArray());
    }
}

/// <summary>Persisted evidence accepted by the regional assignment authority for one bounded command.</summary>
internal sealed record RuntimeAssignmentAuthorizationV1
{
    internal RuntimeAssignmentAuthorizationV1(
        RuntimeDigest authorizationEvidenceDigest,
        RuntimeLifecycleDeadlineEvidence deadlineEvidence,
        DateTimeOffset expiresAt)
    {
        AuthorizationEvidenceDigest = authorizationEvidenceDigest ?? throw new ArgumentNullException(nameof(authorizationEvidenceDigest));
        DeadlineEvidence = deadlineEvidence ?? throw new ArgumentNullException(nameof(deadlineEvidence));
        if (expiresAt == default) throw new ArgumentOutOfRangeException(nameof(expiresAt));
        ExpiresAt = expiresAt;
    }

    internal RuntimeDigest AuthorizationEvidenceDigest { get; }
    internal RuntimeLifecycleDeadlineEvidence DeadlineEvidence { get; }
    internal DateTimeOffset ExpiresAt { get; }
}

/// <summary>Local projector fence. A command cannot cross a cell/node/epoch ownership boundary.</summary>
internal sealed record RuntimeAssignmentProjectionScopeV1
{
    internal RuntimeAssignmentProjectionScopeV1(
        RuntimeLifecycleCellId cell,
        RuntimeNodeId node,
        RuntimeEpoch writerEpoch)
    {
        Cell = cell ?? throw new ArgumentNullException(nameof(cell));
        Node = node ?? throw new ArgumentNullException(nameof(node));
        WriterEpoch = writerEpoch ?? throw new ArgumentNullException(nameof(writerEpoch));
    }

    internal RuntimeLifecycleCellId Cell { get; }
    internal RuntimeNodeId Node { get; }
    internal RuntimeEpoch WriterEpoch { get; }
}

