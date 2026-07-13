using System.Collections.ObjectModel;

namespace TerraScale.Orchestrator.ControlPlane.Reconciliation;

public sealed record ResourceIdentity(string Value);

public enum ObservedCondition
{
    Ready,
    Failed,
    Held,
}

public enum ReconciliationErrorCode
{
    InvalidPolicy,
    ResourceLimitExceeded,
    InvalidIdentity,
    InvalidKind,
    KindNotAllowed,
    InvalidGeneration,
    GenerationRegression,
    InvalidDigest,
    DependencyLimitExceeded,
    DuplicateResource,
    DuplicateDependency,
    MissingDependency,
    SelfDependency,
    DependencyCycle,
    InvalidObservation,
    DuplicateObservation,
    ObservationWithoutDesired,
    IdentityMismatch,
}

public enum ReconciliationReasonCode
{
    InputInvalid,
    MissingObservation,
    StaleObservation,
    DependencyNotConverged,
    MissingDependency,
    CyclicDependency,
    FailedObservation,
    HeldObservation,
    FutureObservation,
    ConflictingObservation,
    ExactConvergence,
    DriftEligible,
}

public sealed record ReconciliationError(
    ReconciliationErrorCode Code,
    string Requirement,
    ResourceIdentity? Resource,
    ResourceIdentity? RelatedResource,
    string Message);

public sealed class DesiredResource
{
    public DesiredResource(
        ResourceIdentity identity,
        string kind,
        long generation,
        string digest,
        IEnumerable<ResourceIdentity> dependencies)
    {
        ArgumentNullException.ThrowIfNull(dependencies);
        Identity = identity;
        Kind = kind;
        Generation = generation;
        Digest = digest;
        Dependencies = new ReadOnlyCollection<ResourceIdentity>(dependencies.ToArray());
    }

    public ResourceIdentity Identity { get; }
    public string Kind { get; }
    public long Generation { get; }
    public string Digest { get; }
    public IReadOnlyList<ResourceIdentity> Dependencies { get; }
}

public sealed record ObservedResourceState(
    ResourceIdentity Identity,
    string Kind,
    long Generation,
    string Digest,
    string ObservationId,
    long FreshnessSequence,
    ObservedCondition Condition);

public sealed class ReconciliationPolicy
{
    public ReconciliationPolicy(
        IEnumerable<string> allowedKinds,
        IReadOnlyDictionary<ResourceIdentity, long> generationFloors,
        int maximumResources,
        int maximumIdentityLength,
        int maximumKindLength,
        int maximumDigestLength,
        int maximumObservationIdLength,
        int maximumDependenciesPerResource,
        long minimumFreshnessSequence)
    {
        ArgumentNullException.ThrowIfNull(allowedKinds);
        ArgumentNullException.ThrowIfNull(generationFloors);
        AllowedKinds = new ReadOnlyCollection<string>(allowedKinds.ToArray());
        GenerationFloors = new ReadOnlyDictionary<ResourceIdentity, long>(
            new Dictionary<ResourceIdentity, long>(generationFloors));
        MaximumResources = maximumResources;
        MaximumIdentityLength = maximumIdentityLength;
        MaximumKindLength = maximumKindLength;
        MaximumDigestLength = maximumDigestLength;
        MaximumObservationIdLength = maximumObservationIdLength;
        MaximumDependenciesPerResource = maximumDependenciesPerResource;
        MinimumFreshnessSequence = minimumFreshnessSequence;
    }

    public IReadOnlyList<string> AllowedKinds { get; }
    public IReadOnlyDictionary<ResourceIdentity, long> GenerationFloors { get; }
    public int MaximumResources { get; }
    public int MaximumIdentityLength { get; }
    public int MaximumKindLength { get; }
    public int MaximumDigestLength { get; }
    public int MaximumObservationIdLength { get; }
    public int MaximumDependenciesPerResource { get; }
    public long MinimumFreshnessSequence { get; }
}

public sealed class ReconciliationRequest
{
    public ReconciliationRequest(
        IEnumerable<DesiredResource> desired,
        IEnumerable<ObservedResourceState> observed,
        ReconciliationPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(desired);
        ArgumentNullException.ThrowIfNull(observed);
        Desired = new ReadOnlyCollection<DesiredResource>(desired.Select(Copy).ToArray());
        Observed = new ReadOnlyCollection<ObservedResourceState>(observed.ToArray());
        Policy = policy;
    }

    public IReadOnlyList<DesiredResource> Desired { get; }
    public IReadOnlyList<ObservedResourceState> Observed { get; }
    public ReconciliationPolicy Policy { get; }

    private static DesiredResource Copy(DesiredResource resource) => new(
        resource.Identity, resource.Kind, resource.Generation, resource.Digest, resource.Dependencies);
}

public sealed record DependencyProof(ResourceIdentity Identity, long Generation, string Digest);

public abstract record ReconciliationOutput(ResourceIdentity Identity, string Kind, long Generation, string Digest);

public sealed record ObserveResourceIntent(
    ResourceIdentity Identity,
    string Kind,
    long Generation,
    string Digest)
    : ReconciliationOutput(Identity, Kind, Generation, Digest);

public sealed record ReconcileResourceIntent(
    ResourceIdentity Identity,
    string Kind,
    long Generation,
    string Digest,
    IReadOnlyList<DependencyProof> DependencyProofs)
    : ReconciliationOutput(Identity, Kind, Generation, Digest);

public sealed record HoldResource(
    ResourceIdentity Identity,
    string Kind,
    long Generation,
    string Digest,
    ReconciliationReasonCode Reason,
    ResourceIdentity RootResource)
    : ReconciliationOutput(Identity, Kind, Generation, Digest);

public sealed record ConvergedResource(
    ResourceIdentity Identity,
    string Kind,
    long Generation,
    string Digest)
    : ReconciliationOutput(Identity, Kind, Generation, Digest);

public sealed record ReconciliationTrace(
    int Sequence,
    ResourceIdentity Resource,
    ReconciliationReasonCode Reason,
    ResourceIdentity? RelatedResource,
    string Message);

public sealed record ReconciliationStep(
    int Order,
    DesiredResource Desired,
    ObservedResourceState? Observation,
    ReconciliationOutput Output,
    IReadOnlyList<ReconciliationTrace> Trace);

public sealed record ReconciliationPlan(
    IReadOnlyList<ReconciliationStep> Steps,
    IReadOnlyList<ReconciliationError> Errors,
    IReadOnlyList<ReconciliationTrace> Trace);
