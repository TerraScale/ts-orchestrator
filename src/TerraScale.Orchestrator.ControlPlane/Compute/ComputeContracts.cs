using System.Collections.ObjectModel;

namespace TerraScale.Orchestrator.ControlPlane.Compute;

/// <summary>Technical caller-input snapshot limits; these are not scaling, replica, or capacity policy caps.</summary>
public static class ComputeTechnicalInputLimits
{
    public const int MaximumSurvivalSecretVersionCount = 4_096;
    public const int MaximumSurvivalNodeTemplateCount = 4_096;
}

internal static class ComputeInputSnapshot
{
    internal static IReadOnlyList<T> Copy<T>(IEnumerable<T> source, int maximum, string parameterName, string inputName)
    {
        ArgumentNullException.ThrowIfNull(source, parameterName);
        var snapshot = new List<T>(Math.Min(maximum, 256));
        try
        {
            using var enumerator = source.GetEnumerator();
            while (enumerator.MoveNext())
            {
                if (snapshot.Count == maximum)
                    throw new ArgumentException($"{inputName} exceeds the technical snapshot bound.", parameterName);
                var current = enumerator.Current;
                if (current is null)
                    throw new ArgumentException($"{inputName} contains a null item.", parameterName);
                snapshot.Add(current);
            }
        }
        catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException and not AccessViolationException)
        {
            throw new ArgumentException($"{inputName} could not be captured within the technical snapshot bound.", parameterName);
        }
        return new ReadOnlyCollection<T>(snapshot.ToArray());
    }
}

public sealed record ComputeCellId { public ComputeCellId(string value) => Value = Required(value); public string Value { get; } private static string Required(string value) => value ?? throw new ArgumentNullException(nameof(value)); }
public sealed record ComputeNodeId { public ComputeNodeId(string value) => Value = Required(value); public string Value { get; } private static string Required(string value) => value ?? throw new ArgumentNullException(nameof(value)); }
public sealed record NodeClassId { public NodeClassId(string value) => Value = Required(value); public string Value { get; } private static string Required(string value) => value ?? throw new ArgumentNullException(nameof(value)); }
public sealed record NodeTemplateId { public NodeTemplateId(string value) => Value = Required(value); public string Value { get; } private static string Required(string value) => value ?? throw new ArgumentNullException(nameof(value)); }
public sealed record ComputeShapeId { public ComputeShapeId(string value) => Value = Required(value); public string Value { get; } private static string Required(string value) => value ?? throw new ArgumentNullException(nameof(value)); }
public sealed record PlacementDomainId { public PlacementDomainId(string value) => Value = Required(value); public string Value { get; } private static string Required(string value) => value ?? throw new ArgumentNullException(nameof(value)); }
public sealed record ComputeArtifactId { public ComputeArtifactId(string value) => Value = Required(value); public string Value { get; } private static string Required(string value) => value ?? throw new ArgumentNullException(nameof(value)); }
public sealed record ComputeDigestId { public ComputeDigestId(string value) => Value = Required(value); public string Value { get; } private static string Required(string value) => value ?? throw new ArgumentNullException(nameof(value)); }
public sealed record SecretVersionId { public SecretVersionId(string value) => Value = Required(value); public string Value { get; } private static string Required(string value) => value ?? throw new ArgumentNullException(nameof(value)); }
public sealed record SurvivalBundleId { public SurvivalBundleId(string value) => Value = Required(value); public string Value { get; } private static string Required(string value) => value ?? throw new ArgumentNullException(nameof(value)); }
public sealed record DemandObservationId { public DemandObservationId(string value) => Value = Required(value); public string Value { get; } private static string Required(string value) => value ?? throw new ArgumentNullException(nameof(value)); }
public sealed record ComputeOperationId { public ComputeOperationId(string value) => Value = Required(value); public string Value { get; } private static string Required(string value) => value ?? throw new ArgumentNullException(nameof(value)); }
public sealed record ProviderFingerprintId { public ProviderFingerprintId(string value) => Value = Required(value); public string Value { get; } private static string Required(string value) => value ?? throw new ArgumentNullException(nameof(value)); }
public sealed record ProviderResourceId { public ProviderResourceId(string value) => Value = Required(value); public string Value { get; } private static string Required(string value) => value ?? throw new ArgumentNullException(nameof(value)); }
public sealed record ProviderCreateKey { public ProviderCreateKey(string value) => Value = Required(value); public string Value { get; } private static string Required(string value) => value ?? throw new ArgumentNullException(nameof(value)); }
public sealed record WorkRequestId { public WorkRequestId(string value) => Value = Required(value); public string Value { get; } private static string Required(string value) => value ?? throw new ArgumentNullException(nameof(value)); }
public sealed record ComputeProofId { public ComputeProofId(string value) => Value = Required(value); public string Value { get; } private static string Required(string value) => value ?? throw new ArgumentNullException(nameof(value)); }
public sealed record StatefulOwnerId { public StatefulOwnerId(string value) => Value = Required(value); public string Value { get; } private static string Required(string value) => value ?? throw new ArgumentNullException(nameof(value)); }
public sealed record LoadBalancerRegistrationId { public LoadBalancerRegistrationId(string value) => Value = Required(value); public string Value { get; } private static string Required(string value) => value ?? throw new ArgumentNullException(nameof(value)); }
public sealed record ComputeVolumeId { public ComputeVolumeId(string value) => Value = Required(value); public string Value { get; } private static string Required(string value) => value ?? throw new ArgumentNullException(nameof(value)); }
public sealed record TrustReferenceId { public TrustReferenceId(string value) => Value = Required(value); public string Value { get; } private static string Required(string value) => value ?? throw new ArgumentNullException(nameof(value)); }
public sealed record NatsReferenceId { public NatsReferenceId(string value) => Value = Required(value); public string Value { get; } private static string Required(string value) => value ?? throw new ArgumentNullException(nameof(value)); }
public sealed record DnsReferenceId { public DnsReferenceId(string value) => Value = Required(value); public string Value { get; } private static string Required(string value) => value ?? throw new ArgumentNullException(nameof(value)); }
public sealed record BackupReferenceId { public BackupReferenceId(string value) => Value = Required(value); public string Value { get; } private static string Required(string value) => value ?? throw new ArgumentNullException(nameof(value)); }

public enum ComputeTrigger { Unspecified, Unschedulable, Utilization, QueueBacklog, Concurrency, DatabaseMember, RolloutSurge, PredictiveWarm, FailedHostReplacement, SafetyRecovery }
public enum ComputeNodeRole { Unspecified, ElasticStateless, ElasticStateful, SeedController, ControlNats, ProductNats, TerraBase }
public enum ScaleOutState { Unspecified, DemandObserved, PlanPersisted, Authorized, RequestRecorded, InstanceCreated, Enrolled, Ready, Completed }
public enum ScaleInState { Unspecified, CandidateSelected, Cordoned, Drained, Deregistered, StorageHandled, Revoked, Terminated, Audited, Completed }
public enum ProviderCreateStatus { Unspecified, ProvenAbsent, OutcomeUnknown, Created }
public enum StatefulDisposition { Unspecified, NotStateful, Approved, Vetoed }
public enum VolumeDisposition { Unspecified, DetachedEphemeral, RetainedStateful }
public enum ComputeAction { Unspecified, Observe, PersistPlan, Authorize, RequestCreate, Enroll, Ready, Cordon, Drain, Deregister, Detach, Revoke, Terminate, Audit, Hold }
public enum ComputeErrorCode { Unspecified, InvalidInput, EvidenceMismatch, EvidenceStale, MissingProof, BudgetDenied, QuotaDenied, CapacityDenied, CostDenied, PlacementDenied, ConflictingOperation, FloorDenied, AvailabilityDenied, StatefulVeto, UnsafeTermination, OrphanDenied, BundleIncomplete, BundleExpired, AuthorityDenied }
public enum ComputeTraceCode { Unspecified, ObservationRequired, PlanRequired, AuthorizationReady, CreateReady, EnrollmentReady, ReadinessReady, CordonReady, DrainReady, DeregistrationReady, VolumeReady, RevocationReady, TerminationReady, AuditReady, Completed, Held }
public enum ComputeRequirementCode { Unspecified = 0, Inv005 = 5, ReqO011 = 11 }

public sealed record ComputeBinding(
    ComputeCellId Cell,
    NodeClassId NodeClass,
    NodeTemplateId Template,
    ComputeShapeId Shape,
    PlacementDomainId Domain,
    ComputeArtifactId Artifact,
    ComputeDigestId ArtifactDigest,
    DemandObservationId Demand,
    ComputeOperationId Operation,
    ProviderFingerprintId ProviderFingerprint,
    long Generation,
    long ControllerEpoch);

public sealed record ResourceEnvelope(ulong Ocpus, ulong MemoryMib, ulong StorageGib, ulong EstimatedHourlyCostMicros);

public sealed record DemandEvidence(
    ComputeBinding Binding,
    ComputeTrigger Trigger,
    long ObservationSequence,
    long FreshThroughSequence,
    int RequiredNodes,
    bool ExplicitDemand,
    bool Sustained,
    bool SafetyBounded);

public sealed record CapacityAuthorization(
    ComputeBinding Binding,
    ResourceEnvelope Resources,
    int AuthorizedNodes,
    ComputeProofId BudgetProof,
    ComputeProofId QuotaProof,
    ComputeProofId CapacityProof,
    ComputeProofId CostProof,
    ComputeProofId PlacementProof,
    bool BudgetAllowed,
    bool QuotaAllowed,
    bool CapacityAvailable,
    bool CostAllowed,
    bool PlacementAllowed);

public sealed record ScaleOutPlan(
    ComputeBinding Binding,
    ResourceEnvelope Resources,
    int DesiredNodes,
    ComputeProofId PlanIdentity);
public sealed record PersistedScaleOutPlan(
    ScaleOutPlan Plan,
    ComputeProofId PersistenceProof);

public sealed record ProviderCreateEvidence(
    ComputeBinding Binding,
    ProviderCreateKey CreateKey,
    ProviderCreateStatus Status,
    ProviderResourceId? Resource,
    WorkRequestId? WorkRequest,
    ComputeProofId ObservationProof);

public sealed record ScaleOutProgress(
    ComputeBinding Binding,
    ProviderResourceId? Resource,
    ComputeNodeId? Node,
    ComputeProofId? IdentityProof,
    ComputeProofId? EnrollmentProof,
    ComputeProofId? BootstrapProof,
    ComputeProofId? DiskProof,
    ComputeProofId? PlacementProof,
    ComputeProofId? HealthProof,
    bool IdentityAttested,
    bool Enrolled,
    bool BootstrapPassed,
    bool DiskPassed,
    bool PlacementComplete,
    bool ServiceHealthy);

public sealed record ScaleOutRequest(
    ComputeBinding Binding,
    ScaleOutState State,
    DemandEvidence Demand,
    ScaleOutPlan Plan,
    PersistedScaleOutPlan? PersistedPlan,
    CapacityAuthorization? Authorization,
    ProviderCreateEvidence? CreateEvidence,
    ScaleOutProgress? Progress,
    long EvaluationSequence,
    int MaximumIdentityLength);

public sealed record ScaleInBinding(
    ComputeBinding Compute,
    ComputeNodeId Node,
    ProviderResourceId Resource,
    LoadBalancerRegistrationId LoadBalancerRegistration,
    ComputeVolumeId Volume,
    ComputeNodeRole Role);

public sealed record ScaleInAuthorization(
    ScaleInBinding Binding,
    DemandObservationId LowUseObservation,
    long ObservationSequence,
    long FreshThroughSequence,
    int CurrentCount,
    int MinimumCount,
    int ReplacementCapacity,
    int AvailabilityHeadroom,
    ComputeProofId LowUseProof,
    ComputeProofId CooldownProof,
    ComputeProofId LifetimeProof,
    ComputeProofId CostBenefitProof,
    ComputeProofId ControlHealthProof,
    ComputeProofId NatsHealthProof,
    ComputeProofId AvailabilityProof,
    StatefulDisposition StatefulDisposition,
    ComputeProofId StatefulProof,
    bool SustainedLowUse,
    bool CooldownPassed,
    bool LifetimePassed,
    bool CostBenefitPassed,
    bool RegionalControlHealthy,
    bool NatsHealthy,
    bool ConflictingOperation,
    bool StatefulApproved);

public sealed record ScaleInProgress(
    ScaleInBinding Binding,
    ComputeProofId? CordonProof,
    ComputeProofId? DrainProof,
    ComputeProofId? DeregistrationProof,
    ComputeProofId? VolumeProof,
    ComputeProofId? RevocationProof,
    ComputeProofId? TerminationProof,
    ComputeProofId? BootAbsenceProof,
    ComputeProofId? OrphanAuditProof,
    VolumeDisposition VolumeDisposition,
    StatefulOwnerId? StatefulOwner,
    bool Cordoned,
    bool Drained,
    bool Deregistered,
    bool VolumeHandled,
    bool Revoked,
    bool ExactInstanceTerminated,
    bool BootVolumeAbsent,
    bool OrphanAuditPassed);

public sealed record ScaleInRequest(
    ScaleInBinding Binding,
    ScaleInState State,
    ScaleInAuthorization Authorization,
    ScaleInProgress Progress,
    long EvaluationSequence,
    int MaximumIdentityLength);

public sealed class RegionalSurvivalBundle
{
    public RegionalSurvivalBundle(SurvivalBundleId bundle, ComputeCellId cell, long generation,
        ProviderFingerprintId providerFingerprint, ComputeArtifactId acceptedArtifact, ComputeDigestId acceptedDigest,
        ComputeProofId acceptedSignature, ComputeArtifactId rollbackArtifact, ComputeDigestId rollbackDigest,
        ComputeProofId rollbackSignature, IEnumerable<SecretVersionId> encryptedSecretVersions,
        IEnumerable<SurvivalNodeTemplate> templates, TrustReferenceId trust, NatsReferenceId nats, DnsReferenceId dns,
        BackupReferenceId backup, long authorityEpoch, long journalPosition, long snapshotPosition,
        long freshThroughPosition, long expiresAfterPosition)
    {
        Bundle = bundle; Cell = cell; Generation = generation; ProviderFingerprint = providerFingerprint;
        AcceptedArtifact = acceptedArtifact; AcceptedDigest = acceptedDigest; AcceptedSignature = acceptedSignature;
        RollbackArtifact = rollbackArtifact; RollbackDigest = rollbackDigest; RollbackSignature = rollbackSignature;
        EncryptedSecretVersions = ComputeInputSnapshot.Copy(encryptedSecretVersions,
            ComputeTechnicalInputLimits.MaximumSurvivalSecretVersionCount, nameof(encryptedSecretVersions),
            "Survival secret versions");
        Templates = ComputeInputSnapshot.Copy(templates,
            ComputeTechnicalInputLimits.MaximumSurvivalNodeTemplateCount, nameof(templates),
            "Survival node templates");
        Trust = trust; Nats = nats;
        Dns = dns; Backup = backup; AuthorityEpoch = authorityEpoch; JournalPosition = journalPosition;
        SnapshotPosition = snapshotPosition; FreshThroughPosition = freshThroughPosition; ExpiresAfterPosition = expiresAfterPosition;
    }
    public SurvivalBundleId Bundle { get; }
    public ComputeCellId Cell { get; }
    public long Generation { get; }
    public ProviderFingerprintId ProviderFingerprint { get; }
    public ComputeArtifactId AcceptedArtifact { get; }
    public ComputeDigestId AcceptedDigest { get; }
    public ComputeProofId AcceptedSignature { get; }
    public ComputeArtifactId RollbackArtifact { get; }
    public ComputeDigestId RollbackDigest { get; }
    public ComputeProofId RollbackSignature { get; }
    public IReadOnlyList<SecretVersionId> EncryptedSecretVersions { get; }
    public IReadOnlyList<SurvivalNodeTemplate> Templates { get; }
    public TrustReferenceId Trust { get; }
    public NatsReferenceId Nats { get; }
    public DnsReferenceId Dns { get; }
    public BackupReferenceId Backup { get; }
    public long AuthorityEpoch { get; }
    public long JournalPosition { get; }
    public long SnapshotPosition { get; }
    public long FreshThroughPosition { get; }
    public long ExpiresAfterPosition { get; }
}

public sealed record SurvivalNodeTemplate(
    NodeClassId NodeClass,
    NodeTemplateId Template,
    ComputeShapeId Shape,
    PlacementDomainId Domain);

public sealed record SurvivalBundleEvidence(
    RegionalSurvivalBundle Observed,
    ComputeProofId BundleSignature,
    ComputeProofId EncryptionProof,
    bool SignatureValid,
    bool MetadataEncrypted,
    bool ArtifactsLocal,
    bool SecretsLocal,
    bool ProviderReady,
    bool TrustReady,
    bool NatsReady,
    bool DnsReady,
    bool BackupReady);

public sealed record RegionalAuthorityProof(
    ComputeCellId Cell,
    long AuthorityEpoch,
    long JournalPosition,
    ComputeProofId Proof,
    bool QuorumAuthoritative);

public sealed record SurvivalRequest(
    RegionalSurvivalBundle Required,
    SurvivalBundleEvidence Evidence,
    RegionalAuthorityProof Authority,
    long EvaluationPosition,
    bool DisconnectedReplacementRequested,
    SurvivalReplacementTarget? ReplacementTarget,
    int MaximumIdentityLength);

public sealed record SurvivalReplacementTarget(
    ComputeCellId Cell,
    NodeClassId NodeClass,
    NodeTemplateId Template,
    ComputeShapeId Shape,
    PlacementDomainId Domain,
    ComputeArtifactId Artifact,
    ComputeDigestId ArtifactDigest,
    ComputeOperationId Operation,
    ProviderFingerprintId ProviderFingerprint,
    ProviderCreateKey CreateKey,
    long BundleGeneration,
    long ControllerEpoch);

public sealed class ComputeError
{
    internal ComputeError(ComputeErrorCode code, ComputeRequirementCode requirement, ComputeOperationId? operation)
    { Code = code; Requirement = requirement; Operation = operation; }
    public ComputeErrorCode Code { get; }
    public ComputeRequirementCode Requirement { get; }
    public ComputeOperationId? Operation { get; }
}
public sealed class ComputeTrace
{
    internal ComputeTrace(int sequence, ComputeTraceCode code, ComputeAction action)
    { Sequence = sequence; Code = code; Action = action; }
    public int Sequence { get; }
    public ComputeTraceCode Code { get; }
    public ComputeAction Action { get; }
}

public abstract class ComputeIntent { internal ComputeIntent(ComputeAction action) => Action = action; public ComputeAction Action { get; } }
public sealed class ObserveCreateIntent : ComputeIntent { internal ObserveCreateIntent(ComputeBinding binding, ProviderCreateKey key) : base(ComputeAction.Observe) { Binding = binding; CreateKey = key; } public ComputeBinding Binding { get; } public ProviderCreateKey CreateKey { get; } }
public sealed class PersistScalePlanIntent : ComputeIntent { internal PersistScalePlanIntent(ComputeBinding binding, ResourceEnvelope resources, int desiredNodes, ComputeProofId planIdentity) : base(ComputeAction.PersistPlan) { Binding = binding; Resources = resources; DesiredNodes = desiredNodes; PlanIdentity = planIdentity; } public ComputeBinding Binding { get; } public ResourceEnvelope Resources { get; } public int DesiredNodes { get; } public ComputeProofId PlanIdentity { get; } }
public sealed class AuthorizeCapacityIntent : ComputeIntent { internal AuthorizeCapacityIntent(ComputeBinding binding, PersistedScaleOutPlan persistedPlan) : base(ComputeAction.Authorize) { Binding = binding; PersistedPlan = persistedPlan; } public ComputeBinding Binding { get; } public PersistedScaleOutPlan PersistedPlan { get; } }
public sealed class RequestCreateIntent : ComputeIntent { internal RequestCreateIntent(ComputeBinding binding, ProviderCreateKey key) : base(ComputeAction.RequestCreate) { Binding = binding; CreateKey = key; } public ComputeBinding Binding { get; } public ProviderCreateKey CreateKey { get; } }
public sealed class EnrollNodeIntent : ComputeIntent { internal EnrollNodeIntent(ComputeBinding binding, ProviderResourceId resource, ComputeNodeId node, ComputeProofId identityProof) : base(ComputeAction.Enroll) { Binding = binding; Resource = resource; Node = node; IdentityProof = identityProof; } public ComputeBinding Binding { get; } public ProviderResourceId Resource { get; } public ComputeNodeId Node { get; } public ComputeProofId IdentityProof { get; } }
public sealed class ReadyNodeIntent : ComputeIntent { internal ReadyNodeIntent(ComputeBinding binding, ProviderResourceId resource, ComputeNodeId node, ComputeProofId bootstrapProof, ComputeProofId diskProof, ComputeProofId placementProof) : base(ComputeAction.Ready) { Binding = binding; Resource = resource; Node = node; BootstrapProof = bootstrapProof; DiskProof = diskProof; PlacementProof = placementProof; } public ComputeBinding Binding { get; } public ProviderResourceId Resource { get; } public ComputeNodeId Node { get; } public ComputeProofId BootstrapProof { get; } public ComputeProofId DiskProof { get; } public ComputeProofId PlacementProof { get; } }
public sealed class CordonNodeIntent : ComputeIntent { internal CordonNodeIntent(ScaleInBinding binding) : base(ComputeAction.Cordon) => Binding = binding; public ScaleInBinding Binding { get; } }
public sealed class DrainNodeIntent : ComputeIntent { internal DrainNodeIntent(ScaleInBinding binding, ComputeProofId cordonProof) : base(ComputeAction.Drain) { Binding = binding; CordonProof = cordonProof; } public ScaleInBinding Binding { get; } public ComputeProofId CordonProof { get; } }
public sealed class DeregisterNodeIntent : ComputeIntent { internal DeregisterNodeIntent(ScaleInBinding binding, ComputeProofId statefulProof) : base(ComputeAction.Deregister) { Binding = binding; StatefulProof = statefulProof; } public ScaleInBinding Binding { get; } public ComputeProofId StatefulProof { get; } }
public sealed class DetachVolumeIntent : ComputeIntent { internal DetachVolumeIntent(ScaleInBinding binding, VolumeDisposition disposition, StatefulOwnerId? owner) : base(ComputeAction.Detach) { Binding = binding; Disposition = disposition; StatefulOwner = owner; } public ScaleInBinding Binding { get; } public VolumeDisposition Disposition { get; } public StatefulOwnerId? StatefulOwner { get; } }
public sealed class RevokeNodeIntent : ComputeIntent { internal RevokeNodeIntent(ScaleInBinding binding, ComputeProofId volumeProof) : base(ComputeAction.Revoke) { Binding = binding; VolumeProof = volumeProof; } public ScaleInBinding Binding { get; } public ComputeProofId VolumeProof { get; } }
public sealed class TerminateNodeIntent : ComputeIntent { internal TerminateNodeIntent(ScaleInBinding binding, ComputeProofId revocationProof) : base(ComputeAction.Terminate) { Binding = binding; RevocationProof = revocationProof; } public ScaleInBinding Binding { get; } public ComputeProofId RevocationProof { get; } }
public sealed class AuditOrphansIntent : ComputeIntent { internal AuditOrphansIntent(ScaleInBinding binding, ComputeProofId terminationProof, ComputeProofId bootAbsenceProof) : base(ComputeAction.Audit) { Binding = binding; TerminationProof = terminationProof; BootAbsenceProof = bootAbsenceProof; } public ScaleInBinding Binding { get; } public ComputeProofId TerminationProof { get; } public ComputeProofId BootAbsenceProof { get; } }
public sealed class AuthorizeSurvivalIntent : ComputeIntent { internal AuthorizeSurvivalIntent(RegionalSurvivalBundle bundle, RegionalAuthorityProof authority, SurvivalReplacementTarget target) : base(ComputeAction.Authorize) { Bundle = bundle; Authority = authority; Target = target; } public RegionalSurvivalBundle Bundle { get; } public RegionalAuthorityProof Authority { get; } public SurvivalReplacementTarget Target { get; } }
public sealed class ReadySurvivalIntent : ComputeIntent { internal ReadySurvivalIntent(RegionalSurvivalBundle bundle) : base(ComputeAction.Ready) => Bundle = bundle; public RegionalSurvivalBundle Bundle { get; } }
public sealed class HoldComputeIntent : ComputeIntent { internal HoldComputeIntent(ComputeErrorCode reason, ComputeOperationId? operation) : base(ComputeAction.Hold) { Reason = reason; Operation = operation; } public ComputeErrorCode Reason { get; } public ComputeOperationId? Operation { get; } }

public sealed class ComputeDecision
{
    internal ComputeDecision(IReadOnlyList<ComputeIntent> intents, IReadOnlyList<ComputeError> errors, IReadOnlyList<ComputeTrace> trace)
    { Intents = intents; Errors = errors; Trace = trace; }
    public IReadOnlyList<ComputeIntent> Intents { get; }
    public IReadOnlyList<ComputeError> Errors { get; }
    public IReadOnlyList<ComputeTrace> Trace { get; }
}
