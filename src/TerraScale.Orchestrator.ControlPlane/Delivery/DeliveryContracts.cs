using System.Collections.ObjectModel;

namespace TerraScale.Orchestrator.ControlPlane.Delivery;

/// <summary>Technical caller-input snapshot limits; these are not release, rollout, or CI policy caps.</summary>
public static class DeliveryTechnicalInputLimits
{
    public const int MaximumDependencyCount = 4_096;
    public const int MaximumTrustZoneCount = 64;
    public const int MaximumRunnerCapabilityCount = 64;
    public const int MaximumRolloutCellCount = 4_096;
    public const int MaximumRunnerEvidenceCount = 4_096;
}

internal static class DeliveryInputSnapshot
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

public sealed record SourceId { public SourceId(string value) => Value = Required(value); public string Value { get; } private static string Required(string value) => value ?? throw new ArgumentNullException(nameof(value)); }
public sealed record RefId { public RefId(string value) => Value = Required(value); public string Value { get; } private static string Required(string value) => value ?? throw new ArgumentNullException(nameof(value)); }
public sealed record CommitId { public CommitId(string value) => Value = Required(value); public string Value { get; } private static string Required(string value) => value ?? throw new ArgumentNullException(nameof(value)); }
public sealed record TreeId { public TreeId(string value) => Value = Required(value); public string Value { get; } private static string Required(string value) => value ?? throw new ArgumentNullException(nameof(value)); }
public sealed record ManifestId { public ManifestId(string value) => Value = Required(value); public string Value { get; } private static string Required(string value) => value ?? throw new ArgumentNullException(nameof(value)); }
public sealed record PipelineId { public PipelineId(string value) => Value = Required(value); public string Value { get; } private static string Required(string value) => value ?? throw new ArgumentNullException(nameof(value)); }
public sealed record JobId { public JobId(string value) => Value = Required(value); public string Value { get; } private static string Required(string value) => value ?? throw new ArgumentNullException(nameof(value)); }
public sealed record RunnerId { public RunnerId(string value) => Value = Required(value); public string Value { get; } private static string Required(string value) => value ?? throw new ArgumentNullException(nameof(value)); }
public sealed record ArtifactId { public ArtifactId(string value) => Value = Required(value); public string Value { get; } private static string Required(string value) => value ?? throw new ArgumentNullException(nameof(value)); }
public sealed record DigestId { public DigestId(string value) => Value = Required(value); public string Value { get; } private static string Required(string value) => value ?? throw new ArgumentNullException(nameof(value)); }
public sealed record SignatureId { public SignatureId(string value) => Value = Required(value); public string Value { get; } private static string Required(string value) => value ?? throw new ArgumentNullException(nameof(value)); }
public sealed record AttestationId { public AttestationId(string value) => Value = Required(value); public string Value { get; } private static string Required(string value) => value ?? throw new ArgumentNullException(nameof(value)); }
public sealed record ApprovalId { public ApprovalId(string value) => Value = Required(value); public string Value { get; } private static string Required(string value) => value ?? throw new ArgumentNullException(nameof(value)); }
public sealed record SigningIdentityId { public SigningIdentityId(string value) => Value = Required(value); public string Value { get; } private static string Required(string value) => value ?? throw new ArgumentNullException(nameof(value)); }
public sealed record ReleaseId { public ReleaseId(string value) => Value = Required(value); public string Value { get; } private static string Required(string value) => value ?? throw new ArgumentNullException(nameof(value)); }
public sealed record DeliveryCellId { public DeliveryCellId(string value) => Value = Required(value); public string Value { get; } private static string Required(string value) => value ?? throw new ArgumentNullException(nameof(value)); }
public sealed record DeliveryOperationId { public DeliveryOperationId(string value) => Value = Required(value); public string Value { get; } private static string Required(string value) => value ?? throw new ArgumentNullException(nameof(value)); }
public sealed record ObservationId { public ObservationId(string value) => Value = Required(value); public string Value { get; } private static string Required(string value) => value ?? throw new ArgumentNullException(nameof(value)); }
public sealed record IdempotencyId { public IdempotencyId(string value) => Value = Required(value); public string Value { get; } private static string Required(string value) => value ?? throw new ArgumentNullException(nameof(value)); }

public enum SourceState { Unspecified, Proposed, Fetched, Verified, Planned, Applied }
public enum JobKind { Unspecified, ProductValidation, TrustedBuild, Promotion, ControlRecovery }
public enum TrustZone { Unspecified, UntrustedProduct, TrustedBuild, ProductionRelease, ControlRecovery }
public enum RunnerCapability { Unspecified, Compile, Test, Sign, Promote, ProductionDeploy, ControlRecover }
public enum PromotionState { Unspecified, Candidate, Qualified, Promoted }
public enum DeliveryArchitecture { Unspecified, LinuxArm64, LinuxX64 }
public enum RolloutStrategy { Unspecified, Rolling, Canary, BlueGreen, OrderedStateful }
public enum RollbackPolicy { Unspecified, AutomaticOnFailedHealth, HoldForApproval }
public enum StageHealth { Unspecified, Pending, Healthy, Failed }
public enum DeliveryAction { Unspecified, Fetch, Verify, Plan, Dispatch, Promote, Stage, Advance, Rollback, Hold }
public enum DeliveryTraceCode { Unspecified, FetchRequired, VerificationRequired, PlanReady, Idempotent, RunnerSelected, PromotionReady, StageReady, AdvanceReady, RollbackRequired, Held }
public enum DeliveryRequirementCode { Unspecified = 0, Inv005 = 5 }

public enum DeliveryErrorCode
{
    Unspecified,
    InvalidInput,
    DuplicateEvidence,
    MissingEvidence,
    StaleGeneration,
    ConflictingGeneration,
    EvidenceInvalidated,
    TrustZoneDenied,
    CapabilityMissing,
    RunnerStale,
    AttemptsExhausted,
    RetryDenied,
    CompatibilityDenied,
    ApprovalDenied,
    ArtifactMismatch,
    StageOutOfOrder,
    AvailabilityDenied,
    HealthDenied,
    RollbackUnavailable,
}

public sealed class DeliveryError
{
    internal DeliveryError(DeliveryErrorCode code, DeliveryRequirementCode requirement, JobId? job, ReleaseId? release, DeliveryCellId? cell)
    { Code = code; Requirement = requirement; Job = job; Release = release; Cell = cell; }
    public DeliveryErrorCode Code { get; }
    public DeliveryRequirementCode Requirement { get; }
    public JobId? Job { get; }
    public ReleaseId? Release { get; }
    public DeliveryCellId? Cell { get; }
}
public sealed class DeliveryTrace
{
    internal DeliveryTrace(int sequence, DeliveryTraceCode code, DeliveryAction action)
    { Sequence = sequence; Code = code; Action = action; }
    public int Sequence { get; }
    public DeliveryTraceCode Code { get; }
    public DeliveryAction Action { get; }
}

public sealed record DependencyProof(ManifestId Manifest, long Generation, DigestId Digest);

public sealed class SourceRevision
{
    public SourceRevision(SourceId source, RefId reference, CommitId commit, TreeId tree, ManifestId manifest,
        long generation, DigestId desiredDigest, SignatureId signature, IEnumerable<DependencyProof> dependencies)
    {
        Source = source ?? throw new ArgumentNullException(nameof(source));
        Reference = reference ?? throw new ArgumentNullException(nameof(reference));
        Commit = commit ?? throw new ArgumentNullException(nameof(commit));
        Tree = tree ?? throw new ArgumentNullException(nameof(tree));
        Manifest = manifest ?? throw new ArgumentNullException(nameof(manifest));
        Generation = generation;
        DesiredDigest = desiredDigest ?? throw new ArgumentNullException(nameof(desiredDigest));
        Signature = signature ?? throw new ArgumentNullException(nameof(signature));
        Dependencies = DeliveryInputSnapshot.Copy(dependencies, DeliveryTechnicalInputLimits.MaximumDependencyCount,
            nameof(dependencies), "Source dependency input");
    }
    public SourceId Source { get; }
    public RefId Reference { get; }
    public CommitId Commit { get; }
    public TreeId Tree { get; }
    public ManifestId Manifest { get; }
    public long Generation { get; }
    public DigestId DesiredDigest { get; }
    public SignatureId Signature { get; }
    public IReadOnlyList<DependencyProof> Dependencies { get; }
}

public sealed class SourceEvidence
{
    public SourceEvidence(ObservationId observation, SourceState state, SourceId source, RefId reference,
        long generation, CommitId commit, TreeId tree,
        ManifestId manifest, DigestId desiredDigest, SignatureId signature, AttestationId schemaAttestation,
        AttestationId dependencyAttestation, AttestationId signatureAttestation, IEnumerable<DependencyProof> dependencies,
        bool signatureValid, bool schemaValid, bool dependenciesValid)
    {
        Observation = observation; State = state; Source = source; Reference = reference; Generation = generation;
        Commit = commit; Tree = tree; Manifest = manifest;
        DesiredDigest = desiredDigest; Signature = signature; SchemaAttestation = schemaAttestation;
        DependencyAttestation = dependencyAttestation; SignatureAttestation = signatureAttestation;
        Dependencies = DeliveryInputSnapshot.Copy(dependencies, DeliveryTechnicalInputLimits.MaximumDependencyCount,
            nameof(dependencies), "Source evidence dependency input");
        SignatureValid = signatureValid; SchemaValid = schemaValid; DependenciesValid = dependenciesValid;
    }
    public ObservationId Observation { get; }
    public SourceState State { get; }
    public SourceId Source { get; }
    public RefId Reference { get; }
    public long Generation { get; }
    public CommitId Commit { get; }
    public TreeId Tree { get; }
    public ManifestId Manifest { get; }
    public DigestId DesiredDigest { get; }
    public SignatureId Signature { get; }
    public AttestationId SchemaAttestation { get; }
    public AttestationId DependencyAttestation { get; }
    public AttestationId SignatureAttestation { get; }
    public IReadOnlyList<DependencyProof> Dependencies { get; }
    public bool SignatureValid { get; }
    public bool SchemaValid { get; }
    public bool DependenciesValid { get; }
}

public sealed record SourceDecisionRequest(SourceRevision Proposed, SourceRevision? Accepted, SourceEvidence? Evidence, int MaximumIdentityLength);

public sealed class JobRequest
{
    public JobRequest(PipelineId pipeline, JobId job, JobKind kind, TreeId tree, long generation, int attempt,
        int maximumAttempts, IdempotencyId idempotency, IEnumerable<TrustZone> allowedZones,
        IEnumerable<RunnerCapability> requiredCapabilities, long minimumRunnerSequence, long maximumRunnerSequence,
        bool retryAuthorized)
    {
        Pipeline = pipeline; Job = job; Kind = kind; Tree = tree; Generation = generation; Attempt = attempt;
        MaximumAttempts = maximumAttempts; Idempotency = idempotency;
        AllowedZones = DeliveryInputSnapshot.Copy(allowedZones, DeliveryTechnicalInputLimits.MaximumTrustZoneCount,
            nameof(allowedZones), "Allowed trust-zone input");
        RequiredCapabilities = DeliveryInputSnapshot.Copy(requiredCapabilities,
            DeliveryTechnicalInputLimits.MaximumRunnerCapabilityCount, nameof(requiredCapabilities),
            "Required runner-capability input");
        MinimumRunnerSequence = minimumRunnerSequence; MaximumRunnerSequence = maximumRunnerSequence;
        RetryAuthorized = retryAuthorized;
    }
    public PipelineId Pipeline { get; }
    public JobId Job { get; }
    public JobKind Kind { get; }
    public TreeId Tree { get; }
    public long Generation { get; }
    public int Attempt { get; }
    public int MaximumAttempts { get; }
    public IdempotencyId Idempotency { get; }
    public IReadOnlyList<TrustZone> AllowedZones { get; }
    public IReadOnlyList<RunnerCapability> RequiredCapabilities { get; }
    public long MinimumRunnerSequence { get; }
    public long MaximumRunnerSequence { get; }
    public bool RetryAuthorized { get; }
}

public sealed class RunnerEvidence
{
    public RunnerEvidence(RunnerId runner, TrustZone zone, long sequence, bool available, IEnumerable<RunnerCapability> capabilities)
    { Runner = runner; Zone = zone; Sequence = sequence; Available = available;
        Capabilities = DeliveryInputSnapshot.Copy(capabilities, DeliveryTechnicalInputLimits.MaximumRunnerCapabilityCount,
            nameof(capabilities), "Runner capability input"); }
    public RunnerId Runner { get; }
    public TrustZone Zone { get; }
    public long Sequence { get; }
    public bool Available { get; }
    public IReadOnlyList<RunnerCapability> Capabilities { get; }
}

public sealed record EvidenceSubject(TreeId Tree, DigestId DependencyLock, DigestId GeneratedSchemas,
    ArtifactId Artifact, DigestId ArtifactDigest, DeliveryArchitecture Architecture);
public sealed record CompatibilityProof(
    AttestationId CurrentToCurrent,
    AttestationId CurrentToPrevious,
    AttestationId PreviousToCurrent,
    bool CurrentToCurrentCompatible,
    bool CurrentToPreviousCompatible,
    bool PreviousToCurrentCompatible);
public sealed record QualificationEvidence(
    ReleaseId Release,
    long Generation,
    EvidenceSubject Subject,
    AttestationId Tests,
    AttestationId Evidence,
    SigningIdentityId SigningIdentity,
    SignatureId Signature,
    ApprovalId Approval,
    CompatibilityProof Compatibility,
    bool TestsPassed,
    bool EvidenceValid,
    bool SignatureValid,
    bool ApprovalValid);
public sealed record PromotionRequest(ReleaseId Release, long Generation, EvidenceSubject Current, QualificationEvidence Qualification, int MaximumIdentityLength);

public sealed record CellArtifactAvailability(
    ReleaseId Release,
    DeliveryOperationId Operation,
    long Generation,
    DeliveryCellId Cell,
    ArtifactId ForwardArtifact,
    DigestId ForwardDigest,
    SigningIdentityId ForwardSigningIdentity,
    SignatureId ForwardSignature,
    DeliveryArchitecture ForwardArchitecture,
    ArtifactId RollbackArtifact,
    DigestId RollbackDigest,
    SigningIdentityId RollbackSigningIdentity,
    SignatureId RollbackSignature,
    DeliveryArchitecture RollbackArchitecture,
    bool ForwardAvailable,
    bool RollbackAvailable);
public sealed class ReleaseSpec
{
    public ReleaseSpec(ReleaseId release, DeliveryOperationId operation, long generation, ArtifactId artifact,
        DigestId digest, SigningIdentityId signingIdentity, SignatureId signature, DeliveryArchitecture architecture,
        ArtifactId rollbackArtifact, DigestId rollbackDigest, SigningIdentityId rollbackSigningIdentity, SignatureId rollbackSignature,
        DeliveryArchitecture rollbackArchitecture,
        RolloutStrategy strategy, RollbackPolicy rollbackPolicy, IEnumerable<DeliveryCellId> orderedCells)
    {
        Release = release; Operation = operation; Generation = generation; Artifact = artifact; Digest = digest;
        SigningIdentity = signingIdentity; Signature = signature; Architecture = architecture; RollbackArtifact = rollbackArtifact;
        RollbackDigest = rollbackDigest; RollbackSigningIdentity = rollbackSigningIdentity; RollbackSignature = rollbackSignature;
        RollbackArchitecture = rollbackArchitecture;
        Strategy = strategy; RollbackPolicy = rollbackPolicy;
        OrderedCells = DeliveryInputSnapshot.Copy(orderedCells, DeliveryTechnicalInputLimits.MaximumRolloutCellCount,
            nameof(orderedCells), "Ordered rollout-cell input");
    }
    public ReleaseId Release { get; }
    public DeliveryOperationId Operation { get; }
    public long Generation { get; }
    public ArtifactId Artifact { get; }
    public DigestId Digest { get; }
    public SigningIdentityId SigningIdentity { get; }
    public SignatureId Signature { get; }
    public DeliveryArchitecture Architecture { get; }
    public ArtifactId RollbackArtifact { get; }
    public DigestId RollbackDigest { get; }
    public SigningIdentityId RollbackSigningIdentity { get; }
    public SignatureId RollbackSignature { get; }
    public DeliveryArchitecture RollbackArchitecture { get; }
    public RolloutStrategy Strategy { get; }
    public RollbackPolicy RollbackPolicy { get; }
    public IReadOnlyList<DeliveryCellId> OrderedCells { get; }
}

public sealed record StageEvidence(
    ObservationId Observation,
    DeliveryOperationId Operation,
    DeliveryCellId Cell,
    ReleaseId Release,
    long Generation,
    ArtifactId Artifact,
    DigestId Digest,
    SigningIdentityId SigningIdentity,
    SignatureId Signature,
    DeliveryArchitecture Architecture,
    StageHealth Health,
    AttestationId HealthProof,
    bool DisruptionAuthorized,
    bool AvailabilityAuthorized);
public sealed record CellCompletionEvidence(
    DeliveryOperationId Operation,
    DeliveryCellId Cell,
    ReleaseId Release,
    long Generation,
    ArtifactId Artifact,
    DigestId Digest,
    SigningIdentityId SigningIdentity,
    SignatureId Signature,
    DeliveryArchitecture Architecture,
    AttestationId HealthProof,
    StageHealth Health);
public sealed class RolloutRequest
{
    public RolloutRequest(ReleaseSpec release, IEnumerable<CellCompletionEvidence> completedCells,
        IEnumerable<CellArtifactAvailability> availability, StageEvidence? currentStage, int maximumIdentityLength)
    {
        Release = release;
        CompletedCells = DeliveryInputSnapshot.Copy(completedCells, DeliveryTechnicalInputLimits.MaximumRolloutCellCount,
            nameof(completedCells), "Completed rollout-cell input");
        Availability = DeliveryInputSnapshot.Copy(availability, DeliveryTechnicalInputLimits.MaximumRolloutCellCount,
            nameof(availability), "Rollout availability input");
        CurrentStage = currentStage;
        MaximumIdentityLength = maximumIdentityLength;
    }
    public ReleaseSpec Release { get; }
    public IReadOnlyList<CellCompletionEvidence> CompletedCells { get; }
    public IReadOnlyList<CellArtifactAvailability> Availability { get; }
    public StageEvidence? CurrentStage { get; }
    public int MaximumIdentityLength { get; }
}

public abstract class DeliveryIntent
{
    internal DeliveryIntent(DeliveryAction action) => Action = action;
    public DeliveryAction Action { get; }
}
public sealed class FetchSourceIntent : DeliveryIntent
{
    internal FetchSourceIntent(SourceId source, CommitId commit, TreeId tree) : base(DeliveryAction.Fetch)
    { Source = source; Commit = commit; Tree = tree; }
    public SourceId Source { get; }
    public CommitId Commit { get; }
    public TreeId Tree { get; }
}
public sealed class VerifySourceIntent : DeliveryIntent
{
    internal VerifySourceIntent(SourceId source, CommitId commit, TreeId tree, ManifestId manifest, DigestId digest, SignatureId signature) : base(DeliveryAction.Verify)
    { Source = source; Commit = commit; Tree = tree; Manifest = manifest; Digest = digest; Signature = signature; }
    public SourceId Source { get; }
    public CommitId Commit { get; }
    public TreeId Tree { get; }
    public ManifestId Manifest { get; }
    public DigestId Digest { get; }
    public SignatureId Signature { get; }
}
public sealed class PlanApplyIntent : DeliveryIntent
{
    internal PlanApplyIntent(SourceId source, CommitId commit, TreeId tree, ManifestId manifest, long generation,
        DigestId digest, SignatureId signature, AttestationId schemaAttestation, AttestationId dependencyAttestation,
        AttestationId signatureAttestation, IReadOnlyList<DependencyProof> dependencies) : base(DeliveryAction.Plan)
    { Source = source; Commit = commit; Tree = tree; Manifest = manifest; Generation = generation; Digest = digest; Signature = signature; SchemaAttestation = schemaAttestation; DependencyAttestation = dependencyAttestation; SignatureAttestation = signatureAttestation; Dependencies = dependencies; }
    public SourceId Source { get; }
    public CommitId Commit { get; }
    public TreeId Tree { get; }
    public ManifestId Manifest { get; }
    public long Generation { get; }
    public DigestId Digest { get; }
    public SignatureId Signature { get; }
    public AttestationId SchemaAttestation { get; }
    public AttestationId DependencyAttestation { get; }
    public AttestationId SignatureAttestation { get; }
    public IReadOnlyList<DependencyProof> Dependencies { get; }
}
public sealed class DispatchJobIntent : DeliveryIntent
{
    internal DispatchJobIntent(JobRequest request, RunnerEvidence selectedRunnerEvidence, int maximumIdentityLength)
        : base(DeliveryAction.Dispatch)
    {
        Request = request;
        SelectedRunnerEvidence = selectedRunnerEvidence;
        MaximumIdentityLength = maximumIdentityLength;
    }
    public JobRequest Request { get; }
    public RunnerEvidence SelectedRunnerEvidence { get; }
    public int MaximumIdentityLength { get; }
    public PipelineId Pipeline => Request.Pipeline;
    public JobId Job => Request.Job;
    public RunnerId Runner => SelectedRunnerEvidence.Runner;
    public TreeId Tree => Request.Tree;
    public long Generation => Request.Generation;
    public int Attempt => Request.Attempt;
    public IdempotencyId Idempotency => Request.Idempotency;
}
public sealed class PromoteArtifactIntent : DeliveryIntent
{
    internal PromoteArtifactIntent(ReleaseId release, long generation, EvidenceSubject subject,
        AttestationId tests, SigningIdentityId signingIdentity, SignatureId signature, ApprovalId approval, AttestationId evidence,
        CompatibilityProof compatibility) : base(DeliveryAction.Promote)
    { Release = release; Generation = generation; Subject = subject; Tests = tests; SigningIdentity = signingIdentity; Signature = signature; Approval = approval; Evidence = evidence; Compatibility = compatibility; }
    public ReleaseId Release { get; }
    public long Generation { get; }
    public EvidenceSubject Subject { get; }
    public AttestationId Tests { get; }
    public SigningIdentityId SigningIdentity { get; }
    public SignatureId Signature { get; }
    public ApprovalId Approval { get; }
    public AttestationId Evidence { get; }
    public CompatibilityProof Compatibility { get; }
}
public sealed class StageReleaseIntent : DeliveryIntent
{
    internal StageReleaseIntent(ReleaseId release, DeliveryOperationId operation, DeliveryCellId cell, long generation,
        ArtifactId artifact, DigestId digest, SigningIdentityId signingIdentity, SignatureId signature, DeliveryArchitecture architecture,
        ArtifactId rollbackArtifact, DigestId rollbackDigest, SigningIdentityId rollbackSigningIdentity, SignatureId rollbackSignature,
        DeliveryArchitecture rollbackArchitecture) : base(DeliveryAction.Stage)
    { Release = release; Operation = operation; Cell = cell; Generation = generation; Artifact = artifact; Digest = digest; SigningIdentity = signingIdentity; Signature = signature; Architecture = architecture; RollbackArtifact = rollbackArtifact; RollbackDigest = rollbackDigest; RollbackSigningIdentity = rollbackSigningIdentity; RollbackSignature = rollbackSignature; RollbackArchitecture = rollbackArchitecture; }
    public ReleaseId Release { get; }
    public DeliveryOperationId Operation { get; }
    public DeliveryCellId Cell { get; }
    public long Generation { get; }
    public ArtifactId Artifact { get; }
    public DigestId Digest { get; }
    public SigningIdentityId SigningIdentity { get; }
    public SignatureId Signature { get; }
    public DeliveryArchitecture Architecture { get; }
    public ArtifactId RollbackArtifact { get; }
    public DigestId RollbackDigest { get; }
    public SigningIdentityId RollbackSigningIdentity { get; }
    public SignatureId RollbackSignature { get; }
    public DeliveryArchitecture RollbackArchitecture { get; }
}
public sealed class AdvanceReleaseIntent : DeliveryIntent
{
    internal AdvanceReleaseIntent(ReleaseId release, DeliveryOperationId operation, DeliveryCellId completedCell,
        DeliveryCellId? nextCell, long generation, ArtifactId artifact, DigestId digest, SignatureId signature,
        SigningIdentityId signingIdentity, DeliveryArchitecture architecture, AttestationId healthProof) : base(DeliveryAction.Advance)
    { Release = release; Operation = operation; CompletedCell = completedCell; NextCell = nextCell; Generation = generation; Artifact = artifact; Digest = digest; SigningIdentity = signingIdentity; Signature = signature; Architecture = architecture; HealthProof = healthProof; }
    public ReleaseId Release { get; }
    public DeliveryOperationId Operation { get; }
    public DeliveryCellId CompletedCell { get; }
    public DeliveryCellId? NextCell { get; }
    public long Generation { get; }
    public ArtifactId Artifact { get; }
    public DigestId Digest { get; }
    public SigningIdentityId SigningIdentity { get; }
    public SignatureId Signature { get; }
    public DeliveryArchitecture Architecture { get; }
    public AttestationId HealthProof { get; }
}
public sealed class RollbackReleaseIntent : DeliveryIntent
{
    internal RollbackReleaseIntent(ReleaseId release, DeliveryOperationId operation, DeliveryCellId cell,
        long generation, ArtifactId failedArtifact, DigestId failedDigest, SignatureId failedSignature,
        SigningIdentityId failedSigningIdentity, DeliveryArchitecture failedArchitecture,
        ArtifactId rollbackArtifact, DigestId rollbackDigest, SigningIdentityId rollbackSigningIdentity, SignatureId rollbackSignature,
        DeliveryArchitecture rollbackArchitecture, AttestationId healthProof) : base(DeliveryAction.Rollback)
    { Release = release; Operation = operation; Cell = cell; Generation = generation; FailedArtifact = failedArtifact; FailedDigest = failedDigest; FailedSigningIdentity = failedSigningIdentity; FailedSignature = failedSignature; FailedArchitecture = failedArchitecture; RollbackArtifact = rollbackArtifact; RollbackDigest = rollbackDigest; RollbackSigningIdentity = rollbackSigningIdentity; RollbackSignature = rollbackSignature; RollbackArchitecture = rollbackArchitecture; HealthProof = healthProof; }
    public ReleaseId Release { get; }
    public DeliveryOperationId Operation { get; }
    public DeliveryCellId Cell { get; }
    public long Generation { get; }
    public ArtifactId FailedArtifact { get; }
    public DigestId FailedDigest { get; }
    public SigningIdentityId FailedSigningIdentity { get; }
    public SignatureId FailedSignature { get; }
    public DeliveryArchitecture FailedArchitecture { get; }
    public ArtifactId RollbackArtifact { get; }
    public DigestId RollbackDigest { get; }
    public SigningIdentityId RollbackSigningIdentity { get; }
    public SignatureId RollbackSignature { get; }
    public DeliveryArchitecture RollbackArchitecture { get; }
    public AttestationId HealthProof { get; }
}
public sealed class HoldDeliveryIntent : DeliveryIntent
{
    internal HoldDeliveryIntent(DeliveryErrorCode reason, JobId? job, ReleaseId? release, DeliveryCellId? cell) : base(DeliveryAction.Hold)
    { Reason = reason; Job = job; Release = release; Cell = cell; }
    public DeliveryErrorCode Reason { get; }
    public JobId? Job { get; }
    public ReleaseId? Release { get; }
    public DeliveryCellId? Cell { get; }
}
public sealed class DeliveryDecision
{
    internal DeliveryDecision(IReadOnlyList<DeliveryIntent> intents, IReadOnlyList<DeliveryError> errors,
        IReadOnlyList<DeliveryTrace> trace)
    { Intents = intents; Errors = errors; Trace = trace; }
    public IReadOnlyList<DeliveryIntent> Intents { get; }
    public IReadOnlyList<DeliveryError> Errors { get; }
    public IReadOnlyList<DeliveryTrace> Trace { get; }
}
