using TerraScale.Orchestrator.ControlPlane.Reconciliation;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

/// <summary>Pure desired/observed planning coverage for INV-005 and native GitOps dependency safety.</summary>
public sealed class ReconciliationEngineTests
{
    [Test]
    public async Task InputPermutationsProduceTheSameTopologicalPlanAndStableTrace()
    {
        var desired = Graph();
        var observed = desired.Select(Exact).ToArray();

        var first = Plan(desired, observed);
        var permuted = desired.Reverse().Select(resource => new DesiredResource(
            resource.Identity, resource.Kind, resource.Generation, resource.Digest, resource.Dependencies.Reverse()));
        var second = Plan(permuted, observed.Reverse());

        await Assert.That(Signature(first)).IsEqualTo(Signature(second));
        await Assert.That(first.Steps.Select(static step => step.Desired.Identity.Value)
            .SequenceEqual(new[] { "database", "api", "dashboard" }, StringComparer.Ordinal)).IsTrue();
        await Assert.That(first.Steps.All(static step => step.Output is ConvergedResource)).IsTrue();
        await Assert.That(first.Trace.Select(static item => item.Sequence))
            .IsEquivalentTo(new[] { 1, 2, 3 });
    }

    [Test]
    public async Task ExactConvergenceIsRequiredAndDriftWaitsForEveryDependency()
    {
        var desired = Graph();
        var observed = new[]
        {
            Exact(desired[0]) with { Generation = 1, Digest = "old-db" },
            Exact(desired[1]) with { Generation = 1, Digest = "old-api" },
            Exact(desired[2]) with { Generation = 1, Digest = "old-dashboard" },
        };

        var plan = Plan(desired, observed);

        var database = plan.Steps.Single(static step => step.Desired.Identity.Value == "database");
        var api = plan.Steps.Single(static step => step.Desired.Identity.Value == "api");
        var dashboard = plan.Steps.Single(static step => step.Desired.Identity.Value == "dashboard");
        await Assert.That(database.Output).IsTypeOf<ReconcileResourceIntent>();
        await Assert.That(api.Output).IsTypeOf<HoldResource>();
        await Assert.That(((HoldResource)api.Output).Reason).IsEqualTo(ReconciliationReasonCode.DependencyNotConverged);
        await Assert.That(((HoldResource)api.Output).RootResource.Value).IsEqualTo("database");
        await Assert.That(((HoldResource)dashboard.Output).RootResource.Value).IsEqualTo("database");

        var databaseIntent = (ReconcileResourceIntent)database.Output;
        await Assert.That(databaseIntent.DependencyProofs).IsEmpty();
    }

    [Test]
    public async Task EligibleDriftEmitsOnlyFrozenIdentityGenerationDigestAndDependencyProof()
    {
        var desired = Graph();
        var observations = desired.Select(Exact).ToArray();
        var apiIndex = Array.FindIndex(observations, static observation => observation.Identity.Value == "api");
        observations[apiIndex] = observations[apiIndex] with { Generation = 1, Digest = "old-api" };

        var plan = Plan(desired, observations);
        var intent = (ReconcileResourceIntent)plan.Steps
            .Single(static step => step.Desired.Identity.Value == "api").Output;

        await Assert.That(intent.Identity.Value).IsEqualTo("api");
        await Assert.That(intent.Kind).IsEqualTo("service");
        await Assert.That(intent.Generation).IsEqualTo(2);
        await Assert.That(intent.Digest).IsEqualTo("digest-api");
        await Assert.That(intent.DependencyProofs).HasSingleItem();
        await Assert.That(intent.DependencyProofs[0])
            .IsEqualTo(new DependencyProof(Id("database"), 2, "digest-database"));
    }

    [Test]
    public async Task MissingAndFreshnessStaleObservationsRequestObservationWithoutMutation()
    {
        var desired = new[] { Desired("a") };

        var missing = Plan(desired, []);
        var stale = Plan(desired, [Exact(desired[0]) with { FreshnessSequence = 9 }]);

        await Assert.That(missing.Steps.Single().Output).IsTypeOf<ObserveResourceIntent>();
        await Assert.That(missing.Trace.Single().Reason).IsEqualTo(ReconciliationReasonCode.MissingObservation);
        await Assert.That(stale.Steps.Single().Output).IsTypeOf<ObserveResourceIntent>();
        await Assert.That(stale.Trace.Single().Reason).IsEqualTo(ReconciliationReasonCode.StaleObservation);
    }

    [Test]
    public async Task MissingObservationIsRequestedEvenWhenDependencyNeedsThisWaveReconcile()
    {
        var dependency = Desired("a");
        var dependent = Desired("b", "a");
        var plan = Plan(
            [dependent, dependency],
            [Exact(dependency) with { Generation = 1, Digest = "old-a" }]);

        await Assert.That(plan.Steps.Single(static step => step.Desired.Identity.Value == "a").Output)
            .IsTypeOf<ReconcileResourceIntent>();
        await Assert.That(plan.Steps.Single(static step => step.Desired.Identity.Value == "b").Output)
            .IsTypeOf<ObserveResourceIntent>();
    }

    [Test]
    public async Task FutureAndSameGenerationDigestConflictHoldFailClosed()
    {
        var desired = new[] { Desired("a") };
        var future = Plan(desired, [Exact(desired[0]) with { Generation = 3, Digest = "future" }]);
        var conflict = Plan(desired, [Exact(desired[0]) with { Digest = "conflict" }]);

        await AssertHold(future, ReconciliationReasonCode.FutureObservation, "a");
        await AssertHold(conflict, ReconciliationReasonCode.ConflictingObservation, "a");
    }

    [Test]
    public async Task FailedAndHeldDependencyRootReasonPropagatesTransitively()
    {
        var desired = Graph();
        foreach (var condition in new[] { ObservedCondition.Failed, ObservedCondition.Held })
        {
            var observations = desired.Select(Exact).ToArray();
            var databaseIndex = Array.FindIndex(observations, static observation => observation.Identity.Value == "database");
            observations[databaseIndex] = observations[databaseIndex] with { Condition = condition };
            var plan = Plan(desired, observations);
            var expected = condition == ObservedCondition.Failed
                ? ReconciliationReasonCode.FailedObservation
                : ReconciliationReasonCode.HeldObservation;

            foreach (var step in plan.Steps)
            {
                var hold = (HoldResource)step.Output;
                await Assert.That(hold.Reason).IsEqualTo(expected);
                await Assert.That(hold.RootResource.Value).IsEqualTo("database");
            }
        }
    }

    [Test]
    public async Task MissingDependencyHoldsItAndAllDependentsWithStableRoot()
    {
        var desired = new[]
        {
            Desired("a", "missing"),
            Desired("b", "a"),
        };

        var plan = Plan(desired, desired.Select(Exact));

        await Assert.That(plan.Errors.Any(static error => error.Code == ReconciliationErrorCode.MissingDependency)).IsTrue();
        await Assert.That(((HoldResource)plan.Steps[0].Output).RootResource.Value).IsEqualTo("missing");
        await Assert.That(((HoldResource)plan.Steps[1].Output).RootResource.Value).IsEqualTo("missing");
    }

    [Test]
    public async Task SelfEdgesAndCyclesNeverEmitObserveOrReconcile()
    {
        var self = Plan([Desired("a", "a")], []);
        await Assert.That(self.Errors.Any(static error => error.Code == ReconciliationErrorCode.SelfDependency)).IsTrue();
        await Assert.That(self.Steps.Single().Output).IsTypeOf<HoldResource>();

        var cycleDesired = new[] { Desired("a", "b"), Desired("b", "a"), Desired("c", "b") };
        var cycle = Plan(cycleDesired, cycleDesired.Select(Exact));
        await Assert.That(cycle.Errors.Count(static error => error.Code == ReconciliationErrorCode.DependencyCycle)).IsEqualTo(3);
        await Assert.That(cycle.Steps.All(static step => step.Output is HoldResource)).IsTrue();
    }

    [Test]
    public async Task DuplicateResourcesObservationsAndDependenciesAreRejected()
    {
        var duplicateResource = Plan([Desired("a"), Desired("a")], []);
        await AssertError(duplicateResource, ReconciliationErrorCode.DuplicateResource);

        var resource = Desired("a");
        var duplicateObservation = Plan([resource], [Exact(resource), Exact(resource)]);
        await AssertError(duplicateObservation, ReconciliationErrorCode.DuplicateObservation);

        var duplicateDependency = Plan([Desired("a"), Desired("b", "a", "a")], []);
        await AssertError(duplicateDependency, ReconciliationErrorCode.DuplicateDependency);
    }

    [Test]
    public async Task ClosedCatalogGenerationFloorAndExactKindPairingAreValidated()
    {
        var resource = Desired("a");
        var disallowed = ReconciliationEngine.Plan(new ReconciliationRequest(
            [resource], [], Policy(["database"], new Dictionary<ResourceIdentity, long>())));
        await AssertError(disallowed, ReconciliationErrorCode.KindNotAllowed);

        var regressed = ReconciliationEngine.Plan(new ReconciliationRequest(
            [resource], [], Policy(["service"], new Dictionary<ResourceIdentity, long> { [Id("a")] = 3 })));
        await AssertError(regressed, ReconciliationErrorCode.GenerationRegression);

        var wrongKind = Plan([resource], [Exact(resource) with { Kind = "database" }]);
        await AssertError(wrongKind, ReconciliationErrorCode.IdentityMismatch);
        await Assert.That(wrongKind.Steps.Single().Output).IsTypeOf<HoldResource>();

        var extraObservation = Plan([resource], [Exact(resource), Exact(Desired("other"))]);
        await AssertError(extraObservation, ReconciliationErrorCode.ObservationWithoutDesired);
    }

    [Test]
    public async Task ContractsDefensivelyCopyCollectionsAndPlanningDoesNotMutateInputs()
    {
        var dependencies = new List<ResourceIdentity> { Id("a") };
        var resource = new DesiredResource(Id("b"), "service", 2, "digest-b", dependencies);
        dependencies.Clear();
        await Assert.That(resource.Dependencies).HasSingleItem();

        var desired = new List<DesiredResource> { Desired("a"), resource };
        var observed = desired.Select(Exact).ToList();
        var request = new ReconciliationRequest(desired, observed, Policy());
        desired.Clear();
        observed.Clear();
        var first = ReconciliationEngine.Plan(request);
        var second = ReconciliationEngine.Plan(request);

        await Assert.That(first.Steps).Count().IsEqualTo(2);
        await Assert.That(Signature(first)).IsEqualTo(Signature(second));
        await Assert.That(resource.Dependencies).HasSingleItem();
    }

    [Test]
    public async Task TenThousandResourceGraphIsCompleteDeterministicAndNonRecursive()
    {
        const int count = 10_000;
        var desired = Enumerable.Range(0, count)
            .Select(index => new DesiredResource(
                Id($"resource-{index:D5}"), "service", 2, $"digest-{index:D5}",
                index == 0 ? [] : [Id($"resource-{index - 1:D5}")]))
            .ToArray();
        var observed = desired.Select(Exact).ToArray();
        var policy = Policy(maximumResources: count, maximumDependencies: 1);

        var forward = ReconciliationEngine.Plan(new ReconciliationRequest(desired, observed, policy));
        var reverse = ReconciliationEngine.Plan(new ReconciliationRequest(desired.Reverse(), observed.Reverse(), policy));

        await Assert.That(forward.Errors).IsEmpty();
        await Assert.That(forward.Steps).Count().IsEqualTo(count);
        await Assert.That(forward.Steps[0].Desired.Identity.Value).IsEqualTo("resource-00000");
        await Assert.That(forward.Steps[^1].Desired.Identity.Value).IsEqualTo("resource-09999");
        await Assert.That(forward.Steps.All(static step => step.Output is ConvergedResource)).IsTrue();
        await Assert.That(Signature(forward)).IsEqualTo(Signature(reverse));
    }

    private static ReconciliationPlan Plan(
        IEnumerable<DesiredResource> desired,
        IEnumerable<ObservedResourceState> observed) =>
        ReconciliationEngine.Plan(new ReconciliationRequest(desired, observed, Policy()));

    private static ReconciliationPolicy Policy(
        IEnumerable<string>? kinds = null,
        IReadOnlyDictionary<ResourceIdentity, long>? floors = null,
        int maximumResources = 10_000,
        int maximumDependencies = 8) => new(
        kinds ?? ["service"], floors ?? new Dictionary<ResourceIdentity, long>(),
        maximumResources, 64, 32, 128, 64, maximumDependencies, 10);

    private static DesiredResource[] Graph() =>
    [
        Desired("dashboard", "database", "api"),
        Desired("database"),
        Desired("api", "database"),
    ];

    private static DesiredResource Desired(string identity, params string[] dependencies) => new(
        Id(identity), "service", 2, $"digest-{identity}", dependencies.Select(Id));

    private static ObservedResourceState Exact(DesiredResource resource) => new(
        resource.Identity, resource.Kind, resource.Generation, resource.Digest,
        $"observation-{resource.Identity.Value}", 10, ObservedCondition.Ready);

    private static ResourceIdentity Id(string value) => new(value);

    private static string Signature(ReconciliationPlan plan) => string.Join('|', plan.Steps.Select(step =>
        $"{step.Order}:{step.Desired.Identity.Value}:{step.Output.GetType().Name}:{step.Trace.Single().Reason}:{(step.Output is HoldResource hold ? hold.RootResource.Value : null)}"));

    private static async Task AssertHold(
        ReconciliationPlan plan,
        ReconciliationReasonCode reason,
        string root)
    {
        var hold = (HoldResource)plan.Steps.Single().Output;
        await Assert.That(hold.Reason).IsEqualTo(reason);
        await Assert.That(hold.RootResource.Value).IsEqualTo(root);
        await Assert.That(plan.Steps.Any(static step => step.Output is ObserveResourceIntent or ReconcileResourceIntent)).IsFalse();
    }

    private static async Task AssertError(ReconciliationPlan plan, ReconciliationErrorCode code)
    {
        await Assert.That(plan.Errors.Any(error => error.Code == code)).IsTrue();
        await Assert.That(plan.Steps.Any(static step => step.Output is ObserveResourceIntent or ReconcileResourceIntent)).IsFalse();
    }
}
