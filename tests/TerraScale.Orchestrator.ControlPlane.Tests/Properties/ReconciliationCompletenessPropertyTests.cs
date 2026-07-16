using TerraScale.Orchestrator.ControlPlane.Reconciliation;

namespace TerraScale.Orchestrator.ControlPlane.Tests.Properties;

public sealed class ReconciliationCompletenessPropertyTests
{
    private const int Cases = 1000;

    [Test]
    public async Task Closed_enum_and_output_inventories_are_exact_and_numeric_values_are_stable()
    {
        var errors = Enum.GetValues<ReconciliationErrorCode>();
        var reasons = Enum.GetValues<ReconciliationReasonCode>();
        var conditions = Enum.GetValues<ObservedCondition>();
        var outputs = typeof(ReconciliationOutput).Assembly.GetExportedTypes()
            .Where(type => type != typeof(ReconciliationOutput) &&
                typeof(ReconciliationOutput).IsAssignableFrom(type) && !type.IsAbstract)
            .OrderBy(type => type.Name, StringComparer.Ordinal)
            .Select(type => type.Name)
            .ToArray();

        await Assert.That(errors.Length).IsEqualTo(18);
        await Assert.That(errors.Select(value => (int)value).SequenceEqual(Enumerable.Range(0, 18))).IsTrue();
        await Assert.That(reasons.Length).IsEqualTo(11);
        await Assert.That(reasons.Select(value => (int)value).SequenceEqual(Enumerable.Range(0, 11))).IsTrue();
        await Assert.That(conditions.Length).IsEqualTo(3);
        await Assert.That(conditions.Select(value => (int)value).SequenceEqual([0, 1, 2])).IsTrue();
        await Assert.That(outputs).IsEquivalentTo(
            new[] { nameof(ConvergedResource), nameof(HoldResource), nameof(ObserveResourceIntent), nameof(ReconcileResourceIntent) });
    }

    [Test]
    public async Task Every_validation_error_has_an_exact_deterministic_oracle_across_1000_cases()
    {
        var observedCodes = new HashSet<ReconciliationErrorCode>();
        for (var seed = 1; seed <= Cases; seed++)
        {
            var variant = (seed - 1) % 18;
            var (plan, expected) = ErrorCase(seed, variant);
            var actual = plan.Errors.Select(ErrorSignature).ToArray();
            Require(actual.SequenceEqual(expected, StringComparer.Ordinal), seed, "exact error tuples and ordering");
            foreach (var error in plan.Errors)
            {
                Require(error.Requirement == "INV-005", seed, "error requirement");
                observedCodes.Add(error.Code);
            }

            var nonFatal = variant is 11 or 13;
            Require(nonFatal ? plan.Steps.Count > 0 : plan.Steps.Count == 0, seed, "fatal boundary");
            Require(nonFatal ? plan.Trace.Count > 0 : plan.Trace.Count == 0, seed, "fatal trace boundary");
            Require(plan.Steps.All(step => step.Output is not ObserveResourceIntent and not ReconcileResourceIntent),
                seed, "validation side-effect exclusion");
        }

        await Assert.That(observedCodes.OrderBy(code => (int)code))
            .IsEquivalentTo(Enum.GetValues<ReconciliationErrorCode>());
    }

    [Test]
    public async Task Every_reason_precedence_root_trace_and_output_are_exact_across_1000_adversarial_cases()
    {
        var observedReasons = new HashSet<ReconciliationReasonCode>();
        var observedOutputs = new HashSet<Type>();
        for (var seed = 1; seed <= Cases; seed++)
        {
            var variant = (seed - 1) % 11;
            var item = ReasonCase(seed, variant);
            var step = item.Plan.Steps.Single(candidate => candidate.Desired.Identity == item.Target.Identity);
            var trace = step.Trace.Single();

            Require(trace == item.Plan.Trace[step.Order - 1], seed, "plan and step trace identity");
            Require(trace.Resource == item.Target.Identity && trace.Reason == item.Reason &&
                trace.RelatedResource == item.Related, seed, "exact trace");
            Require(step.Output.GetType() == item.OutputType &&
                step.Output.Identity == item.Target.Identity && step.Output.Kind == item.Target.Kind &&
                step.Output.Generation == item.Target.Generation && step.Output.Digest == item.Target.Digest,
                seed, "exact typed output subject");
            if (step.Output is HoldResource hold)
                Require(hold.Reason == item.Reason && hold.RootResource == item.Root, seed, "exact hold root");
            if (step.Output is ReconcileResourceIntent reconcile)
            {
                var observation = step.Observation!;
                Require(reconcile.ObservationProof.Identity == observation.Identity &&
                    reconcile.ObservationProof.Kind == observation.Kind &&
                    reconcile.ObservationProof.Generation == observation.Generation &&
                    reconcile.ObservationProof.Digest == observation.Digest &&
                    reconcile.ObservationProof.ObservationId == observation.ObservationId &&
                    reconcile.ObservationProof.FreshnessSequence == observation.FreshnessSequence &&
                    reconcile.ObservationProof.Condition == observation.Condition,
                    seed, "exact drift observation proof");
            }

            observedReasons.Add(item.Reason);
            observedOutputs.Add(step.Output.GetType());
        }

        await Assert.That(observedReasons.OrderBy(reason => (int)reason))
            .IsEquivalentTo(Enum.GetValues<ReconciliationReasonCode>());
        await Assert.That(observedOutputs.Select(type => type.Name))
            .IsEquivalentTo(new[] { nameof(ConvergedResource), nameof(HoldResource), nameof(ObserveResourceIntent), nameof(ReconcileResourceIntent) });
    }

    [Test]
    public async Task Undefined_observed_condition_is_exactly_invalid_and_emits_no_plan()
    {
        var desired = Resource("undefined-condition");
        var invalid = Exact(desired) with { Condition = (ObservedCondition)int.MaxValue };
        var plan = Plan([desired], [invalid]);

        await Assert.That(plan.Errors).HasSingleItem();
        await Assert.That(plan.Errors[0].Code).IsEqualTo(ReconciliationErrorCode.InvalidObservation);
        await Assert.That(plan.Errors[0].Requirement).IsEqualTo("INV-005");
        await Assert.That(plan.Errors[0].Resource).IsEqualTo(desired.Identity);
        await Assert.That(plan.Errors[0].RelatedResource).IsNull();
        await Assert.That(plan.Steps).IsEmpty();
        await Assert.That(plan.Trace).IsEmpty();
    }

    private static (ReconciliationPlan Plan, string[] Expected) ErrorCase(int seed, int variant)
    {
        var prefix = $"validation-{seed:D4}";
        var a = Resource($"{prefix}-a");
        var b = Resource($"{prefix}-b");
        return variant switch
        {
            0 => (Plan([a], [], Policy(kinds: [])), [Error(ReconciliationErrorCode.InvalidPolicy)]),
            1 => (Plan([a, b], [], Policy(maximumResources: 1)), [Error(ReconciliationErrorCode.ResourceLimitExceeded)]),
            2 => (Plan([new DesiredResource(new(""), "service", 2, "digest", [])], []), [Error(ReconciliationErrorCode.InvalidIdentity)]),
            3 => (Plan([new DesiredResource(a.Identity, "", 2, "digest", [])], []), [Error(ReconciliationErrorCode.InvalidKind, a)]),
            4 => (Plan([new DesiredResource(a.Identity, "database", 2, "digest", [])], []), [Error(ReconciliationErrorCode.KindNotAllowed, a)]),
            5 => (Plan([new DesiredResource(a.Identity, "service", 0, "digest", [])], []), [Error(ReconciliationErrorCode.InvalidGeneration, a)]),
            6 => (Plan([new DesiredResource(a.Identity, "service", 1, "digest", [])], [],
                Policy(floors: new Dictionary<ResourceIdentity, long> { [a.Identity] = 2 })), [Error(ReconciliationErrorCode.GenerationRegression, a)]),
            7 => (Plan([new DesiredResource(a.Identity, "service", 2, "", [])], []), [Error(ReconciliationErrorCode.InvalidDigest, a)]),
            8 => (Plan([new DesiredResource(b.Identity, "service", 2, "digest", [a.Identity]), a], [],
                Policy(maximumDependencies: 0)), [Error(ReconciliationErrorCode.DependencyLimitExceeded, b)]),
            9 => (Plan([a, a], []), [Error(ReconciliationErrorCode.DuplicateResource, a)]),
            10 => (Plan([a, new DesiredResource(b.Identity, "service", 2, "digest", [a.Identity, a.Identity])], []),
                [Error(ReconciliationErrorCode.DuplicateDependency, b, a.Identity)]),
            11 => (Plan([new DesiredResource(a.Identity, "service", 2, "digest", [new($"{prefix}-missing")])], []),
                [Error(ReconciliationErrorCode.MissingDependency, a, new($"{prefix}-missing"))]),
            12 => (Plan([new DesiredResource(a.Identity, "service", 2, "digest", [a.Identity])], []),
                [Error(ReconciliationErrorCode.SelfDependency, a, a.Identity)]),
            13 => CycleErrorCase(a, b),
            14 => (Plan([a], [Exact(a) with { Generation = 0 }]), [Error(ReconciliationErrorCode.InvalidObservation, a)]),
            15 => (Plan([a], [Exact(a), Exact(a)]), [Error(ReconciliationErrorCode.DuplicateObservation, a)]),
            16 => (Plan([a], [Exact(b)]), [Error(ReconciliationErrorCode.ObservationWithoutDesired, b)]),
            _ => (Plan([a], [Exact(a) with { Kind = "database" }]), [Error(ReconciliationErrorCode.IdentityMismatch, a)]),
        };
    }

    private static (ReconciliationPlan Plan, string[] Expected) CycleErrorCase(DesiredResource a, DesiredResource b)
    {
        var cycleA = new DesiredResource(a.Identity, a.Kind, a.Generation, a.Digest, [b.Identity]);
        var cycleB = new DesiredResource(b.Identity, b.Kind, b.Generation, b.Digest, [a.Identity]);
        return (Plan([cycleB, cycleA], [Exact(cycleA), Exact(cycleB)]),
            [Error(ReconciliationErrorCode.DependencyCycle, a, a.Identity), Error(ReconciliationErrorCode.DependencyCycle, b, b.Identity)]);
    }

    private static ReasonCaseResult ReasonCase(int seed, int variant)
    {
        var prefix = $"precedence-{seed:D4}";
        var target = Resource($"{prefix}-target");
        var exact = Exact(target);
        return variant switch
        {
            0 => Result(Plan([target], []), target, ReconciliationReasonCode.MissingObservation,
                typeof(ObserveResourceIntent)),
            1 => Result(Plan([target], [exact with
                { FreshnessSequence = 49, Condition = ObservedCondition.Failed, Generation = 3, Digest = "conflict" }]),
                target, ReconciliationReasonCode.StaleObservation, typeof(ObserveResourceIntent)),
            2 => Result(Plan([target], [exact with
                { Condition = ObservedCondition.Failed, Generation = 3, Digest = "conflict" }]),
                target, ReconciliationReasonCode.FailedObservation, typeof(HoldResource), target.Identity, target.Identity),
            3 => Result(Plan([target], [exact with
                { Condition = ObservedCondition.Held, Generation = 3, Digest = "conflict" }]),
                target, ReconciliationReasonCode.HeldObservation, typeof(HoldResource), target.Identity, target.Identity),
            4 => Result(Plan([target], [exact with { Generation = 3, Digest = "conflict" }]),
                target, ReconciliationReasonCode.FutureObservation, typeof(HoldResource), target.Identity, target.Identity),
            5 => Result(Plan([target], [exact with { Digest = "conflict" }]),
                target, ReconciliationReasonCode.ConflictingObservation, typeof(HoldResource), target.Identity, target.Identity),
            6 => Result(Plan([target], [exact]), target, ReconciliationReasonCode.ExactConvergence,
                typeof(ConvergedResource)),
            7 => Result(Plan([target], [exact with { Generation = 1, Digest = "old" }]),
                target, ReconciliationReasonCode.DriftEligible, typeof(ReconcileResourceIntent)),
            8 => DependencyNotConvergedCase(prefix),
            9 => MissingDependencyCase(prefix),
            _ => CyclicReasonCase(prefix),
        };
    }

    private static ReasonCaseResult DependencyNotConvergedCase(string prefix)
    {
        var dependency = Resource($"{prefix}-dependency");
        var target = Resource($"{prefix}-target", dependency.Identity);
        var plan = Plan([target, dependency],
            [Exact(target), Exact(dependency) with { Generation = 1, Digest = "old" }]);
        return Result(plan, target, ReconciliationReasonCode.DependencyNotConverged,
            typeof(HoldResource), dependency.Identity, dependency.Identity);
    }

    private static ReasonCaseResult MissingDependencyCase(string prefix)
    {
        var missing = new ResourceIdentity($"{prefix}-missing");
        var target = Resource($"{prefix}-target", missing);
        return Result(Plan([target], []), target, ReconciliationReasonCode.MissingDependency,
            typeof(HoldResource), missing, missing);
    }

    private static ReasonCaseResult CyclicReasonCase(string prefix)
    {
        var aIdentity = new ResourceIdentity($"{prefix}-a");
        var bIdentity = new ResourceIdentity($"{prefix}-b");
        var a = Resource(aIdentity.Value, bIdentity);
        var b = Resource(bIdentity.Value, aIdentity);
        return Result(Plan([b, a], []), a, ReconciliationReasonCode.CyclicDependency,
            typeof(HoldResource), aIdentity, aIdentity);
    }

    private static ReasonCaseResult Result(
        ReconciliationPlan plan,
        DesiredResource target,
        ReconciliationReasonCode reason,
        Type outputType,
        ResourceIdentity? root = null,
        ResourceIdentity? related = null) => new(plan, target, reason, outputType, root, related);

    private static DesiredResource Resource(string identity, params ResourceIdentity[] dependencies) => new(
        new(identity), "service", 2, $"digest-{identity}", dependencies);

    private static ObservedResourceState Exact(DesiredResource resource) => new(
        resource.Identity, resource.Kind, resource.Generation, resource.Digest,
        $"observation-{resource.Identity.Value}", 50, ObservedCondition.Ready);

    private static ReconciliationPlan Plan(
        IEnumerable<DesiredResource> desired,
        IEnumerable<ObservedResourceState> observed,
        ReconciliationPolicy? policy = null) => ReconciliationEngine.Plan(
            new ReconciliationRequest(desired, observed, policy ?? Policy()));

    private static ReconciliationPolicy Policy(
        IEnumerable<string>? kinds = null,
        IReadOnlyDictionary<ResourceIdentity, long>? floors = null,
        int maximumResources = 16,
        int maximumDependencies = 4) => new(
        kinds ?? ["service"], floors ?? new Dictionary<ResourceIdentity, long>(),
        maximumResources, 96, 32, 192, 128, maximumDependencies, 50);

    private static string Error(
        ReconciliationErrorCode code,
        DesiredResource? resource = null,
        ResourceIdentity? related = null) => $"{code}:INV-005:{resource?.Identity.Value}:{related?.Value}";

    private static string Error(
        ReconciliationErrorCode code,
        ResourceIdentity resource,
        ResourceIdentity? related = null) => $"{code}:INV-005:{resource.Value}:{related?.Value}";

    private static string ErrorSignature(ReconciliationError error) =>
        $"{error.Code}:{error.Requirement}:{error.Resource?.Value}:{error.RelatedResource?.Value}";

    private static void Require(bool condition, int seed, string property)
    {
        if (!condition) throw new InvalidOperationException($"{property} failed at seed {seed}.");
    }

    private sealed record ReasonCaseResult(
        ReconciliationPlan Plan,
        DesiredResource Target,
        ReconciliationReasonCode Reason,
        Type OutputType,
        ResourceIdentity? Root,
        ResourceIdentity? Related);
}
