using System.Collections.ObjectModel;

namespace TerraScale.Orchestrator.ControlPlane.Delivery;

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

public sealed record DeliveryError(DeliveryErrorCode Code, DeliveryRequirementCode Requirement, JobId? Job, ReleaseId? Release, DeliveryCellId? Cell);
public sealed record DeliveryTrace(int Sequence, DeliveryTraceCode Code, DeliveryAction Action);

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
        Dependencies = Copy(dependencies);
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
    private static IReadOnlyList<DependencyProof> Copy(IEnumerable<DependencyProof> values)
    {
        var copy = (values ?? throw new ArgumentNullException(nameof(values))).ToArray();
        if (copy.Any(static value => value is null)) throw new ArgumentException("Null dependency.", nameof(values));
        return new ReadOnlyCollection<DependencyProof>(copy);
    }
}

public sealed class SourceEvidence
{
    public SourceEvidence(ObservationId observation, SourceState state, SourceId source, RefId reference,
        long generation, CommitId commit, TreeId tree,
        ManifestId manifest, DigestId desiredDigest, SignatureId signature, AttestationId schemaAttestation,
        AttestationId dependencyAttestation, IEnumerable<DependencyProof> dependencies,
        bool schemaValid, bool dependenciesValid)
    {
        Observation = observation; State = state; Source = source; Reference = reference; Generation = generation;
        Commit = commit; Tree = tree; Manifest = manifest;
        DesiredDigest = desiredDigest; Signature = signature; SchemaAttestation = schemaAttestation;
        DependencyAttestation = dependencyAttestation;
        var copy = (dependencies ?? throw new ArgumentNullException(nameof(dependencies))).ToArray();
        if (copy.Any(static value => value is null)) throw new ArgumentException("Null dependency.", nameof(dependencies));
        Dependencies = new ReadOnlyCollection<DependencyProof>(copy);
        SchemaValid = schemaValid; DependenciesValid = dependenciesValid;
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
    public IReadOnlyList<DependencyProof> Dependencies { get; }
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
        AllowedZones = Copy(allowedZones); RequiredCapabilities = Copy(requiredCapabilities);
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
    private static IReadOnlyList<T> Copy<T>(IEnumerable<T> values) => new ReadOnlyCollection<T>((values ?? throw new ArgumentNullException(nameof(values))).ToArray());
}

public sealed class RunnerEvidence
{
    public RunnerEvidence(RunnerId runner, TrustZone zone, long sequence, bool available, IEnumerable<RunnerCapability> capabilities)
    { Runner = runner; Zone = zone; Sequence = sequence; Available = available; Capabilities = new ReadOnlyCollection<RunnerCapability>((capabilities ?? throw new ArgumentNullException(nameof(capabilities))).ToArray()); }
    public RunnerId Runner { get; }
    public TrustZone Zone { get; }
    public long Sequence { get; }
    public bool Available { get; }
    public IReadOnlyList<RunnerCapability> Capabilities { get; }
}

public sealed record EvidenceSubject(TreeId Tree, DigestId DependencyLock, DigestId GeneratedSchemas, ArtifactId Artifact, DigestId ArtifactDigest);
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
    SignatureId ForwardSignature,
    ArtifactId RollbackArtifact,
    DigestId RollbackDigest,
    bool ForwardAvailable,
    bool RollbackAvailable);
public sealed class ReleaseSpec
{
    public ReleaseSpec(ReleaseId release, DeliveryOperationId operation, long generation, ArtifactId artifact,
        DigestId digest, SignatureId signature, ArtifactId rollbackArtifact, DigestId rollbackDigest,
        RolloutStrategy strategy, RollbackPolicy rollbackPolicy, IEnumerable<DeliveryCellId> orderedCells)
    {
        Release = release; Operation = operation; Generation = generation; Artifact = artifact; Digest = digest;
        Signature = signature; RollbackArtifact = rollbackArtifact; RollbackDigest = rollbackDigest;
        Strategy = strategy; RollbackPolicy = rollbackPolicy;
        OrderedCells = new ReadOnlyCollection<DeliveryCellId>((orderedCells ?? throw new ArgumentNullException(nameof(orderedCells))).ToArray());
    }
    public ReleaseId Release { get; }
    public DeliveryOperationId Operation { get; }
    public long Generation { get; }
    public ArtifactId Artifact { get; }
    public DigestId Digest { get; }
    public SignatureId Signature { get; }
    public ArtifactId RollbackArtifact { get; }
    public DigestId RollbackDigest { get; }
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
    SignatureId Signature,
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
    SignatureId Signature,
    AttestationId HealthProof,
    StageHealth Health);
public sealed class RolloutRequest
{
    public RolloutRequest(ReleaseSpec release, IEnumerable<CellCompletionEvidence> completedCells,
        IEnumerable<CellArtifactAvailability> availability, StageEvidence? currentStage, int maximumIdentityLength)
    {
        Release = release;
        CompletedCells = Copy(completedCells);
        Availability = Copy(availability);
        CurrentStage = currentStage;
        MaximumIdentityLength = maximumIdentityLength;
    }
    public ReleaseSpec Release { get; }
    public IReadOnlyList<CellCompletionEvidence> CompletedCells { get; }
    public IReadOnlyList<CellArtifactAvailability> Availability { get; }
    public StageEvidence? CurrentStage { get; }
    public int MaximumIdentityLength { get; }
    private static IReadOnlyList<T> Copy<T>(IEnumerable<T> values)
    {
        var copy = (values ?? throw new ArgumentNullException(nameof(values))).ToArray();
        if (copy.Any(static value => value is null)) throw new ArgumentException("Null item.", nameof(values));
        return new ReadOnlyCollection<T>(copy);
    }
}

public abstract record DeliveryIntent(DeliveryAction Action);
public sealed record FetchSourceIntent(SourceId Source, CommitId Commit, TreeId Tree) : DeliveryIntent(DeliveryAction.Fetch);
public sealed record VerifySourceIntent(SourceId Source, CommitId Commit, TreeId Tree, ManifestId Manifest, DigestId Digest, SignatureId Signature) : DeliveryIntent(DeliveryAction.Verify);
public sealed record PlanApplyIntent(SourceId Source, CommitId Commit, TreeId Tree, ManifestId Manifest, long Generation, DigestId Digest, IReadOnlyList<DependencyProof> Dependencies) : DeliveryIntent(DeliveryAction.Plan);
public sealed record DispatchJobIntent(PipelineId Pipeline, JobId Job, RunnerId Runner, TreeId Tree, long Generation, int Attempt, IdempotencyId Idempotency) : DeliveryIntent(DeliveryAction.Dispatch);
public sealed record PromoteArtifactIntent(ReleaseId Release, long Generation, EvidenceSubject Subject, SigningIdentityId SigningIdentity, SignatureId Signature, ApprovalId Approval, AttestationId Evidence, CompatibilityProof Compatibility) : DeliveryIntent(DeliveryAction.Promote);
public sealed record StageReleaseIntent(ReleaseId Release, DeliveryOperationId Operation, DeliveryCellId Cell, long Generation, ArtifactId Artifact, DigestId Digest, SignatureId Signature, ArtifactId RollbackArtifact, DigestId RollbackDigest) : DeliveryIntent(DeliveryAction.Stage);
public sealed record AdvanceReleaseIntent(ReleaseId Release, DeliveryCellId CompletedCell, DeliveryCellId? NextCell, long Generation, ArtifactId Artifact, DigestId Digest, AttestationId HealthProof) : DeliveryIntent(DeliveryAction.Advance);
public sealed record RollbackReleaseIntent(ReleaseId Release, DeliveryOperationId Operation, DeliveryCellId Cell, long Generation, ArtifactId FailedArtifact, DigestId FailedDigest, ArtifactId RollbackArtifact, DigestId RollbackDigest, AttestationId HealthProof) : DeliveryIntent(DeliveryAction.Rollback);
public sealed record HoldDeliveryIntent(DeliveryErrorCode Reason, JobId? Job, ReleaseId? Release, DeliveryCellId? Cell) : DeliveryIntent(DeliveryAction.Hold);
public sealed record DeliveryDecision(IReadOnlyList<DeliveryIntent> Intents, IReadOnlyList<DeliveryError> Errors, IReadOnlyList<DeliveryTrace> Trace);
