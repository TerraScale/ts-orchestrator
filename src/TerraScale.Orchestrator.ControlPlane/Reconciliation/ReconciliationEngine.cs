using System.Collections.ObjectModel;

namespace TerraScale.Orchestrator.ControlPlane.Reconciliation;

public static class ReconciliationEngine
{
    private const string Invariant = "INV-005";
    private static readonly StringComparer Sorter = StringComparer.Ordinal;

    public static ReconciliationPlan Plan(ReconciliationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var desired = request.Desired.ToArray();
        var observed = request.Observed.ToArray();
        var errors = Validate(request.Policy, desired, observed);
        var orderedDesired = desired
            .Where(static item => item?.Identity?.Value is not null)
            .OrderBy(static item => item.Identity.Value, Sorter)
            .ToArray();

        if (errors.Any(IsFatal))
            return InvalidPlan(orderedDesired, errors);

        var resources = desired.ToDictionary(static item => item.Identity, ResourceIdentityComparer.Instance);
        var observations = observed.ToDictionary(static item => item.Identity, ResourceIdentityComparer.Instance);
        var missing = errors
            .Where(static error => error.Code == ReconciliationErrorCode.MissingDependency)
            .GroupBy(static error => error.Resource!, ResourceIdentityComparer.Instance)
            .ToDictionary(
                static group => group.Key,
                static group => group.Select(static error => error.RelatedResource!).OrderBy(static id => id.Value, Sorter).First(),
                ResourceIdentityComparer.Instance);

        var (order, cyclic) = TopologicalOrder(resources);
        foreach (var identity in cyclic)
        {
            errors.Add(Error(ReconciliationErrorCode.DependencyCycle, identity, identity,
                "Dependency cycle prevents a complete topological order."));
        }

        var steps = new List<ReconciliationStep>(desired.Length);
        var byIdentity = new Dictionary<ResourceIdentity, ReconciliationStep>(ResourceIdentityComparer.Instance);
        var trace = new List<ReconciliationTrace>(desired.Length);

        foreach (var identity in order.Concat(cyclic.OrderBy(static id => id.Value, Sorter)))
        {
            var resource = resources[identity];
            observations.TryGetValue(identity, out var observation);
            var evaluation = Evaluate(resource, observation, request.Policy, missing, cyclic, byIdentity);
            var stepTrace = new ReconciliationTrace(
                trace.Count + 1, identity, evaluation.Reason, evaluation.Related, Message(evaluation.Reason));
            trace.Add(stepTrace);
            var step = new ReconciliationStep(
                steps.Count + 1,
                Copy(resource),
                observation,
                evaluation.Output,
                new ReadOnlyCollection<ReconciliationTrace>([stepTrace]));
            steps.Add(step);
            byIdentity.Add(identity, step);
        }

        return new(
            new ReadOnlyCollection<ReconciliationStep>(steps),
            new ReadOnlyCollection<ReconciliationError>(errors.OrderBy(ErrorKey, Sorter).ToArray()),
            new ReadOnlyCollection<ReconciliationTrace>(trace));
    }

    private static Evaluation Evaluate(
        DesiredResource resource,
        ObservedResourceState? observation,
        ReconciliationPolicy policy,
        IReadOnlyDictionary<ResourceIdentity, ResourceIdentity> missing,
        IReadOnlySet<ResourceIdentity> cyclic,
        IReadOnlyDictionary<ResourceIdentity, ReconciliationStep> completed)
    {
        if (missing.TryGetValue(resource.Identity, out var absent))
            return Hold(resource, ReconciliationReasonCode.MissingDependency, absent);
        if (cyclic.Contains(resource.Identity))
            return Hold(resource, ReconciliationReasonCode.CyclicDependency, resource.Identity);

        // Observation is always safe and may proceed in parallel. Dependency convergence gates mutation,
        // not acquisition of the current evidence needed by a later plan.
        if (observation is null)
            return new(new ObserveResourceIntent(resource.Identity, resource.Kind, resource.Generation, resource.Digest),
                ReconciliationReasonCode.MissingObservation, null);
        if (observation.FreshnessSequence < policy.MinimumFreshnessSequence)
            return new(new ObserveResourceIntent(resource.Identity, resource.Kind, resource.Generation, resource.Digest),
                ReconciliationReasonCode.StaleObservation, null);
        if (observation.Condition == ObservedCondition.Failed)
            return Hold(resource, ReconciliationReasonCode.FailedObservation, resource.Identity);
        if (observation.Condition == ObservedCondition.Held)
            return Hold(resource, ReconciliationReasonCode.HeldObservation, resource.Identity);
        if (observation.Generation > resource.Generation)
            return Hold(resource, ReconciliationReasonCode.FutureObservation, resource.Identity);
        if (observation.Generation == resource.Generation && !Sorter.Equals(observation.Digest, resource.Digest))
            return Hold(resource, ReconciliationReasonCode.ConflictingObservation, resource.Identity);

        foreach (var dependency in resource.Dependencies.OrderBy(static item => item.Value, Sorter))
        {
            var dependencyStep = completed[dependency];
            if (dependencyStep.Output is HoldResource dependencyHold)
                return Hold(resource, dependencyHold.Reason, dependencyHold.RootResource, dependency);
            if (dependencyStep.Output is not ConvergedResource)
                return Hold(resource, ReconciliationReasonCode.DependencyNotConverged, dependency, dependency);
        }

        if (observation.Generation == resource.Generation && Sorter.Equals(observation.Digest, resource.Digest))
            return new(new ConvergedResource(resource.Identity, resource.Kind, resource.Generation, resource.Digest),
                ReconciliationReasonCode.ExactConvergence, null);

        var proofs = resource.Dependencies
            .OrderBy(static item => item.Value, Sorter)
            .Select(dependency => completed[dependency].Desired)
            .Select(static dependency => new DependencyProof(
                dependency.Identity, dependency.Generation, dependency.Digest))
            .ToArray();
        return new(new ReconcileResourceIntent(
                resource.Identity, resource.Kind, resource.Generation, resource.Digest,
                new ReadOnlyCollection<DependencyProof>(proofs)),
            ReconciliationReasonCode.DriftEligible, null);
    }

    private static List<ReconciliationError> Validate(
        ReconciliationPolicy? policy,
        IReadOnlyList<DesiredResource> desired,
        IReadOnlyList<ObservedResourceState> observed)
    {
        var errors = new List<ReconciliationError>();
        if (policy is null || policy.MaximumResources <= 0 || policy.MaximumIdentityLength <= 0 ||
            policy.MaximumKindLength <= 0 || policy.MaximumDigestLength <= 0 ||
            policy.MaximumObservationIdLength <= 0 || policy.MaximumDependenciesPerResource < 0 ||
            policy.MinimumFreshnessSequence < 0 || policy.AllowedKinds.Count == 0 ||
            policy.AllowedKinds.Any(kind => !Valid(kind, policy.MaximumKindLength)) ||
            policy.AllowedKinds.Distinct(Sorter).Count() != policy.AllowedKinds.Count ||
            policy.GenerationFloors.Any(pair => pair.Key is null ||
                !Valid(pair.Key.Value, policy.MaximumIdentityLength) || pair.Value < 0))
        {
            errors.Add(Error(ReconciliationErrorCode.InvalidPolicy, null, null,
                "Caller policy must provide positive bounds, a unique closed kind catalog, and non-negative generation/freshness floors."));
            return errors;
        }

        if (desired.Count > policy.MaximumResources || observed.Count > policy.MaximumResources)
            errors.Add(Error(ReconciliationErrorCode.ResourceLimitExceeded, null, null,
                "Desired or observed resources exceed the caller-supplied resource bound."));

        var allowedKinds = new HashSet<string>(policy.AllowedKinds, Sorter);
        var identities = new HashSet<ResourceIdentity>(ResourceIdentityComparer.Instance);
        foreach (var resource in desired)
        {
            if (resource is null || !Valid(resource.Identity?.Value, policy.MaximumIdentityLength))
            {
                errors.Add(Error(ReconciliationErrorCode.InvalidIdentity, resource?.Identity, null, "Desired resource identity is blank or out of bounds."));
                continue;
            }
            if (!identities.Add(resource.Identity!))
                errors.Add(Error(ReconciliationErrorCode.DuplicateResource, resource.Identity, null, "Desired resource identity is duplicated."));
            if (!Valid(resource.Kind, policy.MaximumKindLength))
                errors.Add(Error(ReconciliationErrorCode.InvalidKind, resource.Identity, null, "Desired resource kind is blank or out of bounds."));
            else if (!allowedKinds.Contains(resource.Kind))
                errors.Add(Error(ReconciliationErrorCode.KindNotAllowed, resource.Identity, null, "Desired resource kind is outside the closed caller catalog."));
            if (resource.Generation <= 0)
                errors.Add(Error(ReconciliationErrorCode.InvalidGeneration, resource.Identity, null, "Desired generation must be positive."));
            if (policy.GenerationFloors.TryGetValue(resource.Identity!, out var floor) && resource.Generation < floor)
                errors.Add(Error(ReconciliationErrorCode.GenerationRegression, resource.Identity, null, "Desired generation is lower than the caller-supplied accepted floor."));
            if (!Valid(resource.Digest, policy.MaximumDigestLength))
                errors.Add(Error(ReconciliationErrorCode.InvalidDigest, resource.Identity, null, "Desired digest is blank or out of bounds."));
            if (resource.Dependencies.Count > policy.MaximumDependenciesPerResource)
                errors.Add(Error(ReconciliationErrorCode.DependencyLimitExceeded, resource.Identity, null, "Dependency count exceeds the caller-supplied bound."));
            var dependencySet = new HashSet<ResourceIdentity>(ResourceIdentityComparer.Instance);
            foreach (var dependency in resource.Dependencies)
            {
                if (!Valid(dependency?.Value, policy.MaximumIdentityLength))
                    errors.Add(Error(ReconciliationErrorCode.InvalidIdentity, resource.Identity, dependency, "Dependency identity is blank or out of bounds."));
                else if (!dependencySet.Add(dependency!))
                    errors.Add(Error(ReconciliationErrorCode.DuplicateDependency, resource.Identity, dependency, "Dependency identity is duplicated."));
                else if (ResourceIdentityComparer.Instance.Equals(resource.Identity, dependency))
                    errors.Add(Error(ReconciliationErrorCode.SelfDependency, resource.Identity, dependency, "Resource depends on itself."));
            }
        }

        if (errors.Any(IsFatal)) return errors;
        foreach (var resource in desired)
        {
            foreach (var dependency in resource.Dependencies)
            {
                if (!identities.Contains(dependency))
                    errors.Add(Error(ReconciliationErrorCode.MissingDependency, resource.Identity, dependency, "Dependency does not exist in desired state."));
            }
        }

        var observationIdentities = new HashSet<ResourceIdentity>(ResourceIdentityComparer.Instance);
        var desiredByIdentity = desired.ToDictionary(static item => item.Identity, ResourceIdentityComparer.Instance);
        foreach (var observation in observed)
        {
            if (observation is null || !Valid(observation.Identity?.Value, policy.MaximumIdentityLength) ||
                !Valid(observation.Kind, policy.MaximumKindLength) ||
                observation.Generation < 0 || !Valid(observation.Digest, policy.MaximumDigestLength) ||
                !Valid(observation.ObservationId, policy.MaximumObservationIdLength) || observation.FreshnessSequence < 0 ||
                !Enum.IsDefined(observation.Condition))
            {
                errors.Add(Error(ReconciliationErrorCode.InvalidObservation, observation?.Identity, null, "Observation is malformed or out of bounds."));
                continue;
            }
            if (!observationIdentities.Add(observation.Identity!))
                errors.Add(Error(ReconciliationErrorCode.DuplicateObservation, observation.Identity, null, "Observation identity is duplicated."));
            if (!desiredByIdentity.TryGetValue(observation.Identity!, out var desiredResource))
                errors.Add(Error(ReconciliationErrorCode.ObservationWithoutDesired, observation.Identity, null, "Observation has no exact desired identity."));
            else if (!Sorter.Equals(observation.Kind, desiredResource.Kind))
                errors.Add(Error(ReconciliationErrorCode.IdentityMismatch, observation.Identity, null, "Observed kind does not exactly match desired identity pairing."));
        }

        return errors;
    }

    private static (IReadOnlyList<ResourceIdentity> Ordered, IReadOnlySet<ResourceIdentity> Cyclic) TopologicalOrder(
        IReadOnlyDictionary<ResourceIdentity, DesiredResource> resources)
    {
        var indegree = resources.Keys.ToDictionary(static identity => identity, static _ => 0, ResourceIdentityComparer.Instance);
        var dependents = resources.Keys.ToDictionary(
            static identity => identity,
            static _ => new List<ResourceIdentity>(),
            ResourceIdentityComparer.Instance);
        foreach (var resource in resources.Values)
        {
            foreach (var dependency in resource.Dependencies.Distinct(ResourceIdentityComparer.Instance))
            {
                if (!resources.ContainsKey(dependency)) continue;
                indegree[resource.Identity]++;
                dependents[dependency].Add(resource.Identity);
            }
        }

        var ready = new PriorityQueue<ResourceIdentity, string>(Sorter);
        foreach (var pair in indegree.Where(static pair => pair.Value == 0)) ready.Enqueue(pair.Key, pair.Key.Value);
        var ordered = new List<ResourceIdentity>(resources.Count);
        while (ready.TryDequeue(out var identity, out _))
        {
            ordered.Add(identity);
            foreach (var dependent in dependents[identity].OrderBy(static item => item.Value, Sorter))
            {
                indegree[dependent]--;
                if (indegree[dependent] == 0) ready.Enqueue(dependent, dependent.Value);
            }
        }

        var cyclic = new HashSet<ResourceIdentity>(
            indegree.Where(static pair => pair.Value != 0).Select(static pair => pair.Key),
            ResourceIdentityComparer.Instance);
        return (ordered, cyclic);
    }

    private static ReconciliationPlan InvalidPlan(
        IReadOnlyList<DesiredResource> desired,
        IReadOnlyList<ReconciliationError> errors)
    {
        var trace = new List<ReconciliationTrace>(desired.Count);
        var steps = new List<ReconciliationStep>(desired.Count);
        foreach (var resource in desired)
        {
            var item = new ReconciliationTrace(trace.Count + 1, resource.Identity,
                ReconciliationReasonCode.InputInvalid, null, Message(ReconciliationReasonCode.InputInvalid));
            trace.Add(item);
            steps.Add(new ReconciliationStep(steps.Count + 1, Copy(resource), null,
                new HoldResource(resource.Identity, resource.Kind, resource.Generation, resource.Digest,
                    ReconciliationReasonCode.InputInvalid, resource.Identity),
                new ReadOnlyCollection<ReconciliationTrace>([item])));
        }
        return new(new ReadOnlyCollection<ReconciliationStep>(steps),
            new ReadOnlyCollection<ReconciliationError>(errors.OrderBy(ErrorKey, Sorter).ToArray()),
            new ReadOnlyCollection<ReconciliationTrace>(trace));
    }

    private static bool IsFatal(ReconciliationError error) => error.Code is not (
        ReconciliationErrorCode.MissingDependency or ReconciliationErrorCode.DependencyCycle);

    private static Evaluation Hold(
        DesiredResource resource,
        ReconciliationReasonCode reason,
        ResourceIdentity root,
        ResourceIdentity? related = null) => new(
        new HoldResource(resource.Identity, resource.Kind, resource.Generation, resource.Digest, reason, root),
        reason,
        related ?? root);

    private static bool Valid(string? value, int maximumLength) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= maximumLength;

    private static ReconciliationError Error(
        ReconciliationErrorCode code,
        ResourceIdentity? resource,
        ResourceIdentity? related,
        string message) => new(code, Invariant, resource, related, message);

    private static string ErrorKey(ReconciliationError error) =>
        $"{error.Resource?.Value}\u001f{error.RelatedResource?.Value}\u001f{(int)error.Code:D3}\u001f{error.Message}";

    private static string Message(ReconciliationReasonCode reason) => reason switch
    {
        ReconciliationReasonCode.InputInvalid => "Input validation failed; reconciliation is held.",
        ReconciliationReasonCode.MissingObservation => "No observation exists; obtain one before mutation.",
        ReconciliationReasonCode.StaleObservation => "Observation freshness is below the explicit caller floor.",
        ReconciliationReasonCode.DependencyNotConverged => "A dependency is not exactly converged.",
        ReconciliationReasonCode.MissingDependency => "A declared dependency is missing.",
        ReconciliationReasonCode.CyclicDependency => "A dependency cycle prevents safe ordering.",
        ReconciliationReasonCode.FailedObservation => "The resource observation reports failure.",
        ReconciliationReasonCode.HeldObservation => "The resource observation reports a hold.",
        ReconciliationReasonCode.FutureObservation => "Observed generation is newer than desired generation.",
        ReconciliationReasonCode.ConflictingObservation => "Observed digest conflicts at the desired generation.",
        ReconciliationReasonCode.ExactConvergence => "Observed generation and digest exactly match desired state.",
        ReconciliationReasonCode.DriftEligible => "Older observed generation is eligible for typed reconciliation.",
        _ => throw new ArgumentOutOfRangeException(nameof(reason)),
    };

    private static DesiredResource Copy(DesiredResource value) => new(
        value.Identity, value.Kind, value.Generation, value.Digest, value.Dependencies);

    private sealed record Evaluation(
        ReconciliationOutput Output,
        ReconciliationReasonCode Reason,
        ResourceIdentity? Related);

    private sealed class ResourceIdentityComparer : IEqualityComparer<ResourceIdentity>
    {
        public static ResourceIdentityComparer Instance { get; } = new();
        public bool Equals(ResourceIdentity? x, ResourceIdentity? y) => Sorter.Equals(x?.Value, y?.Value);
        public int GetHashCode(ResourceIdentity obj) => Sorter.GetHashCode(obj.Value);
    }
}
