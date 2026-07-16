using System.Collections.ObjectModel;

namespace TerraScale.Orchestrator.ControlPlane.Reconciliation;

/// <summary>Technical caller-input capture bound; this is independent of reconciliation resource and dependency policy limits.</summary>
public static class ReconciliationTechnicalInputLimits
{
    public const int MaximumCapturedItems = 16_384;
}

internal static class ReconciliationInputSnapshot
{
    internal static IReadOnlyList<T> Copy<T>(IEnumerable<T> source, string parameterName, string inputName)
    {
        ArgumentNullException.ThrowIfNull(source, parameterName);
        var snapshot = new List<T>(256);
        try
        {
            using var enumerator = source.GetEnumerator();
            while (enumerator.MoveNext())
            {
                if (snapshot.Count == ReconciliationTechnicalInputLimits.MaximumCapturedItems)
                    throw new ArgumentException("The input exceeds the technical capture bound.", parameterName);
                var current = enumerator.Current;
                if (current is null)
                    throw new ArgumentException("The input contains a null item.", parameterName);
                snapshot.Add(current);
            }
        }
        catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException and not AccessViolationException)
        {
            throw new ArgumentException($"{inputName} could not be captured within the technical bound.", parameterName);
        }
        return new ReadOnlyCollection<T>(snapshot.ToArray());
    }
}

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
    ResourceIdentity? RelatedResource);

public sealed class DesiredResource
{
    public DesiredResource(
        ResourceIdentity identity,
        string kind,
        long generation,
        string digest,
        IEnumerable<ResourceIdentity> dependencies)
    {
        Identity = identity;
        Kind = kind;
        Generation = generation;
        Digest = digest;
        Dependencies = ReconciliationInputSnapshot.Copy(dependencies, nameof(dependencies), "Resource dependencies");
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
        ArgumentNullException.ThrowIfNull(generationFloors);
        AllowedKinds = ReconciliationInputSnapshot.Copy(allowedKinds, nameof(allowedKinds), "Allowed kinds");
        var floors = ReconciliationInputSnapshot.Copy(generationFloors, nameof(generationFloors), "Generation floors");
        try
        {
            GenerationFloors = new ReadOnlyDictionary<ResourceIdentity, long>(new Dictionary<ResourceIdentity, long>(floors));
        }
        catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException and not AccessViolationException)
        {
            throw new ArgumentException("Generation floors could not be captured within the technical bound.", nameof(generationFloors));
        }
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
        Desired = new ReadOnlyCollection<DesiredResource>(
            ReconciliationInputSnapshot.Copy(desired, nameof(desired), "Desired resources").Select(Copy).ToArray());
        Observed = ReconciliationInputSnapshot.Copy(observed, nameof(observed), "Observed resources");
        Policy = policy;
    }

    public IReadOnlyList<DesiredResource> Desired { get; }
    public IReadOnlyList<ObservedResourceState> Observed { get; }
    public ReconciliationPolicy Policy { get; }

    private static DesiredResource Copy(DesiredResource resource) => new(
        resource.Identity, resource.Kind, resource.Generation, resource.Digest, resource.Dependencies);
}

public sealed record DependencyProof
{
    internal DependencyProof(
        ResourceIdentity identity,
        string kind,
        long generation,
        string digest,
        string observationId,
        long freshnessSequence,
        ObservedCondition condition)
    {
        Identity = identity;
        Kind = kind;
        Generation = generation;
        Digest = digest;
        ObservationId = observationId;
        FreshnessSequence = freshnessSequence;
        Condition = condition;
    }

    public ResourceIdentity Identity { get; }
    public string Kind { get; }
    public long Generation { get; }
    public string Digest { get; }
    public string ObservationId { get; }
    public long FreshnessSequence { get; }
    public ObservedCondition Condition { get; }
}

public sealed record ReconciliationObservationProof
{
    internal ReconciliationObservationProof(
        ResourceIdentity identity,
        string kind,
        long generation,
        string digest,
        string observationId,
        long freshnessSequence,
        ObservedCondition condition)
    {
        Identity = identity;
        Kind = kind;
        Generation = generation;
        Digest = digest;
        ObservationId = observationId;
        FreshnessSequence = freshnessSequence;
        Condition = condition;
    }

    public ResourceIdentity Identity { get; }
    public string Kind { get; }
    public long Generation { get; }
    public string Digest { get; }
    public string ObservationId { get; }
    public long FreshnessSequence { get; }
    public ObservedCondition Condition { get; }
}

public abstract record ReconciliationOutput
{
    internal ReconciliationOutput(ResourceIdentity identity, string kind, long generation, string digest)
    {
        Identity = identity;
        Kind = kind;
        Generation = generation;
        Digest = digest;
    }

    public ResourceIdentity Identity { get; }
    public string Kind { get; }
    public long Generation { get; }
    public string Digest { get; }
}

public sealed record ObserveResourceIntent : ReconciliationOutput
{
    internal ObserveResourceIntent(ResourceIdentity identity, string kind, long generation, string digest)
        : base(identity, kind, generation, digest) { }
}

public sealed record ReconcileResourceIntent : ReconciliationOutput
{
    internal ReconcileResourceIntent(
        ResourceIdentity identity,
        string kind,
        long generation,
        string digest,
        ReconciliationObservationProof observationProof,
        IReadOnlyList<DependencyProof> dependencyProofs,
        ReconciliationPolicy acceptedPolicy)
        : base(identity, kind, generation, digest)
    {
        ObservationProof = observationProof;
        DependencyProofs = dependencyProofs;
        AcceptedPolicy = acceptedPolicy;
    }

    public ReconciliationObservationProof ObservationProof { get; }
    public IReadOnlyList<DependencyProof> DependencyProofs { get; }
    public ReconciliationPolicy AcceptedPolicy { get; }
}

public sealed record HoldResource : ReconciliationOutput
{
    internal HoldResource(
        ResourceIdentity identity,
        string kind,
        long generation,
        string digest,
        ReconciliationReasonCode reason,
        ResourceIdentity rootResource)
        : base(identity, kind, generation, digest)
    {
        Reason = reason;
        RootResource = rootResource;
    }

    public ReconciliationReasonCode Reason { get; }
    public ResourceIdentity RootResource { get; }
}

public sealed record ConvergedResource : ReconciliationOutput
{
    internal ConvergedResource(ResourceIdentity identity, string kind, long generation, string digest)
        : base(identity, kind, generation, digest) { }
}

public sealed record ReconciliationTrace(
    int Sequence,
    ResourceIdentity Resource,
    ReconciliationReasonCode Reason,
    ResourceIdentity? RelatedResource);

public sealed record ReconciliationStep
{
    internal ReconciliationStep(
        int order,
        DesiredResource desired,
        ObservedResourceState? observation,
        ReconciliationOutput output,
        IReadOnlyList<ReconciliationTrace> trace)
    {
        Order = order;
        Desired = desired;
        Observation = observation;
        Output = output;
        Trace = trace;
    }

    public int Order { get; }
    public DesiredResource Desired { get; }
    public ObservedResourceState? Observation { get; }
    public ReconciliationOutput Output { get; }
    public IReadOnlyList<ReconciliationTrace> Trace { get; }
}

public sealed record ReconciliationPlan
{
    internal ReconciliationPlan(
        IReadOnlyList<ReconciliationStep> steps,
        IReadOnlyList<ReconciliationError> errors,
        IReadOnlyList<ReconciliationTrace> trace)
    {
        Steps = steps;
        Errors = errors;
        Trace = trace;
    }

    public IReadOnlyList<ReconciliationStep> Steps { get; }
    public IReadOnlyList<ReconciliationError> Errors { get; }
    public IReadOnlyList<ReconciliationTrace> Trace { get; }
}
