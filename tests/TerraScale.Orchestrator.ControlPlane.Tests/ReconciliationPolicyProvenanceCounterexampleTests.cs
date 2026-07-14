using System.Globalization;
using System.Reflection;
using TerraScale.Orchestrator.ControlPlane.Reconciliation;
using TerraScale.Orchestrator.ControlPlane.Tests.Properties;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class ReconciliationPolicyProvenanceCounterexampleTests
{
    [Test]
    public async Task Distinct_policies_authorizing_the_same_reconcile_must_not_collapse_to_one_mutation_output()
    {
        var desired = Desired("api");
        var observation = Drift(desired);
        var firstPolicy = Policy(["service"], new Dictionary<ResourceIdentity, long>(), 100, 8, 10);
        var secondPolicy = Policy(["service", "database"],
            new Dictionary<ResourceIdentity, long> { [desired.Identity] = 1 }, 200, 16, 9);

        var first = ReconciliationEngine.Plan(new([desired], [observation], firstPolicy));
        var second = ReconciliationEngine.Plan(new([desired], [observation], secondPolicy));
        var firstIntent = (ReconcileResourceIntent)first.Steps.Single().Output;
        var secondIntent = (ReconcileResourceIntent)second.Steps.Single().Output;

        await Assert.That(first.Errors).IsEmpty();
        await Assert.That(second.Errors).IsEmpty();
        await Assert.That(ReferenceEquals(firstIntent.AcceptedPolicy, firstPolicy)).IsTrue();
        await Assert.That(ReferenceEquals(secondIntent.AcceptedPolicy, secondPolicy)).IsTrue();
        await Assert.That(PublicFingerprint(first)).IsNotEqualTo(PublicFingerprint(second));
    }

    [Test]
    public async Task Every_eligible_reconcile_retains_the_exact_policy_and_nonmutation_outputs_expose_none()
    {
        foreach (var dependencyCount in new[] { 0, 1, 2 })
        {
            var dependencies = Enumerable.Range(0, dependencyCount).Select(index => Desired($"dependency-{index}")).ToArray();
            var target = Desired("target", dependencies.Select(item => item.Identity.Value).ToArray());
            var desired = dependencies.Append(target).Reverse().ToArray();
            var observed = dependencies.Select(Exact).Append(Drift(target)).Reverse().ToArray();
            var policy = Policy();
            var plan = ReconciliationEngine.Plan(new(desired, observed, policy));
            var intent = (ReconcileResourceIntent)plan.Steps.Single(step => step.Desired.Identity == target.Identity).Output;

            await Assert.That(plan.Errors).IsEmpty();
            await Assert.That(ReferenceEquals(intent.AcceptedPolicy, policy)).IsTrue();
            await Assert.That(intent.DependencyProofs.Count).IsEqualTo(dependencyCount);
        }

        var exactDesired = Desired("exact");
        var missingDesired = Desired("missing");
        var heldDesired = Desired("held");
        var policyForNonmutations = Policy();
        var nonmutations = new ReconciliationOutput[]
        {
            ReconciliationEngine.Plan(new([exactDesired], [Exact(exactDesired)], policyForNonmutations)).Steps.Single().Output,
            ReconciliationEngine.Plan(new([missingDesired], [], policyForNonmutations)).Steps.Single().Output,
            ReconciliationEngine.Plan(new([heldDesired], [Exact(heldDesired) with { Condition = ObservedCondition.Held }],
                policyForNonmutations)).Steps.Single().Output,
        };
        await Assert.That(nonmutations.Select(output => output.GetType()).SequenceEqual(
            new[] { typeof(ConvergedResource), typeof(ObserveResourceIntent), typeof(HoldResource) })).IsTrue();
        await Assert.That(nonmutations.All(output => output.GetType().GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .All(property => property.PropertyType != typeof(ReconciliationPolicy)))).IsTrue();
    }

    [Test]
    public async Task Every_policy_scalar_and_collection_count_or_item_changes_the_accepted_policy_independently()
    {
        var desired = Desired("api");
        var observation = Drift(desired);
        var baseline = Policy(["service", "database"],
            new Dictionary<ResourceIdentity, long> { [desired.Identity] = 1 }, 100, 8, 10);
        var variants = new (string Name, ReconciliationPolicy Policy)[]
        {
            ("allowed-count", Policy(["service", "database", "cache"], baseline.GenerationFloors, 100, 8, 10)),
            ("allowed-item", Policy(["service", "cache"], baseline.GenerationFloors, 100, 8, 10)),
            ("floor-count", Policy(baseline.AllowedKinds, new Dictionary<ResourceIdentity, long>
                { [desired.Identity] = 1, [new("other")] = 0 }, 100, 8, 10)),
            ("floor-key", Policy(baseline.AllowedKinds, new Dictionary<ResourceIdentity, long>
                { [new("other")] = 1 }, 100, 8, 10)),
            ("floor-value", Policy(baseline.AllowedKinds, new Dictionary<ResourceIdentity, long>
                { [desired.Identity] = 0 }, 100, 8, 10)),
            ("maximum-resources", Rebuild(baseline, maximumResources: 101)),
            ("maximum-identity", Rebuild(baseline, maximumIdentityLength: 65)),
            ("maximum-kind", Rebuild(baseline, maximumKindLength: 33)),
            ("maximum-digest", Rebuild(baseline, maximumDigestLength: 129)),
            ("maximum-observation", Rebuild(baseline, maximumObservationIdLength: 65)),
            ("maximum-dependencies", Rebuild(baseline, maximumDependencies: 9)),
            ("minimum-freshness", Rebuild(baseline, minimumFreshness: 9)),
        };
        var baselineFingerprint = PolicyFingerprint(baseline);

        foreach (var variant in variants)
        {
            var plan = ReconciliationEngine.Plan(new([desired], [observation], variant.Policy));
            var intent = (ReconcileResourceIntent)plan.Steps.Single().Output;
            await Assert.That(plan.Errors).IsEmpty();
            await Assert.That(ReferenceEquals(intent.AcceptedPolicy, variant.Policy)).IsTrue();
        }
        await Assert.That(variants.Select(item => item.Name).Distinct(StringComparer.Ordinal).Count()).IsEqualTo(variants.Length);
        await Assert.That(variants.All(item => PolicyFingerprint(item.Policy) != baselineFingerprint)).IsTrue();
        await Assert.That(variants.Select(item => PolicyFingerprint(item.Policy)).Distinct(StringComparer.Ordinal).Count())
            .IsEqualTo(variants.Length);
    }

    [Test]
    public async Task Policy_output_is_permutation_culture_replay_and_existing_corpus_stable()
    {
        var dependencyA = Desired("a");
        var dependencyB = Desired("b");
        var target = Desired("target", "b", "a");
        var permutedTarget = Desired("target", "a", "b");
        var firstPolicy = Policy(["service", "database"], new Dictionary<ResourceIdentity, long>
        { [target.Identity] = 1, [dependencyA.Identity] = 1 }, 100, 8, 10);
        var secondPolicy = Policy(["database", "service"], new Dictionary<ResourceIdentity, long>
        { [dependencyA.Identity] = 1, [target.Identity] = 1 }, 100, 8, 10);
        var firstRequest = new ReconciliationRequest([target, dependencyA, dependencyB],
            [Drift(target), Exact(dependencyA), Exact(dependencyB)], firstPolicy);
        var secondRequest = new ReconciliationRequest([dependencyB, dependencyA, permutedTarget],
            [Exact(dependencyB), Exact(dependencyA), Drift(permutedTarget)], secondPolicy);
        string? baseline = null;

        foreach (var cultureName in new[] { "en-US", "tr-TR", "ar-SA" })
        foreach (var request in new[] { firstRequest, secondRequest })
        {
            var previous = CultureInfo.CurrentCulture;
            try
            {
                CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(cultureName);
                var actual = PublicFingerprint(ReconciliationEngine.Plan(request));
                baseline ??= actual;
                await Assert.That(actual).IsEqualTo(baseline);
                await Assert.That(PublicFingerprint(ReconciliationEngine.Plan(request))).IsEqualTo(actual);
            }
            finally { CultureInfo.CurrentCulture = previous; }
        }

        await Assert.That(ReconciliationCorpus.Load().Count).IsEqualTo(12);
    }

    [Test]
    public async Task Reconciliation_plan_step_output_proof_policy_request_and_collections_are_exhaustively_closed()
    {
        var outputTypes = new[] { typeof(ReconciliationOutput), typeof(ObserveResourceIntent),
            typeof(ReconcileResourceIntent), typeof(HoldResource), typeof(ConvergedResource) };
        var closedTypes = outputTypes.Concat(new[] { typeof(DependencyProof), typeof(ReconciliationObservationProof),
            typeof(ReconciliationStep), typeof(ReconciliationPlan) }).ToArray();
        await Assert.That(closedTypes.All(type => type.GetConstructors(BindingFlags.Public | BindingFlags.Instance).Length == 0))
            .IsTrue();
        await Assert.That(closedTypes.SelectMany(type => type.GetProperties(BindingFlags.Public | BindingFlags.Instance))
            .All(property => property.GetMethod is not null && property.SetMethod is null)).IsTrue();
        await Assert.That(closedTypes.SelectMany(type => type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly))
            .All(method => method.Name != "Deconstruct")).IsTrue();

        var cloneTypes = closedTypes.Where(type => type.IsAssignableTo(typeof(ReconciliationOutput)) ||
            type == typeof(DependencyProof) || type == typeof(ReconciliationObservationProof) ||
            type == typeof(ReconciliationStep) || type == typeof(ReconciliationPlan)).ToArray();
        await Assert.That(cloneTypes.All(type => Clone(type) is { IsStatic: false } clone &&
            clone.ReturnType == type && clone.GetParameters().Length == 0)).IsTrue();
        var inspectableRecordClones = new[] { typeof(ResourceIdentity), typeof(ObservedResourceState),
            typeof(ReconciliationError), typeof(ReconciliationTrace) };
        await Assert.That(inspectableRecordClones.All(type => Clone(type) is { IsStatic: false } clone &&
            clone.ReturnType == type && clone.GetParameters().Length == 0)).IsTrue();

        var origins = typeof(ReconciliationEngine).Assembly.ExportedTypes.SelectMany(type => type.GetMethods(
                BindingFlags.Public | BindingFlags.Static | BindingFlags.Instance | BindingFlags.DeclaredOnly))
            .Where(method => method.IsStatic && method.ReturnType == typeof(ReconciliationPlan)).ToArray();
        await Assert.That(origins).HasSingleItem();
        await Assert.That(origins[0]).IsEqualTo(typeof(ReconciliationEngine).GetMethod(nameof(ReconciliationEngine.Plan))!);

        AssertProperties<DesiredResource>(nameof(DesiredResource.Identity), nameof(DesiredResource.Kind),
            nameof(DesiredResource.Generation), nameof(DesiredResource.Digest), nameof(DesiredResource.Dependencies));
        AssertProperties<ObservedResourceState>(nameof(ObservedResourceState.Identity), nameof(ObservedResourceState.Kind),
            nameof(ObservedResourceState.Generation), nameof(ObservedResourceState.Digest),
            nameof(ObservedResourceState.ObservationId), nameof(ObservedResourceState.FreshnessSequence),
            nameof(ObservedResourceState.Condition));
        AssertProperties<ReconciliationPolicy>(nameof(ReconciliationPolicy.AllowedKinds), nameof(ReconciliationPolicy.GenerationFloors),
            nameof(ReconciliationPolicy.MaximumResources), nameof(ReconciliationPolicy.MaximumIdentityLength),
            nameof(ReconciliationPolicy.MaximumKindLength), nameof(ReconciliationPolicy.MaximumDigestLength),
            nameof(ReconciliationPolicy.MaximumObservationIdLength), nameof(ReconciliationPolicy.MaximumDependenciesPerResource),
            nameof(ReconciliationPolicy.MinimumFreshnessSequence));
        AssertProperties<ReconciliationRequest>(nameof(ReconciliationRequest.Desired), nameof(ReconciliationRequest.Observed),
            nameof(ReconciliationRequest.Policy));
        AssertProperties<ReconciliationOutput>(nameof(ReconciliationOutput.Identity), nameof(ReconciliationOutput.Kind),
            nameof(ReconciliationOutput.Generation), nameof(ReconciliationOutput.Digest));
        AssertProperties<ObserveResourceIntent>(nameof(ReconciliationOutput.Identity), nameof(ReconciliationOutput.Kind),
            nameof(ReconciliationOutput.Generation), nameof(ReconciliationOutput.Digest));
        AssertProperties<ConvergedResource>(nameof(ReconciliationOutput.Identity), nameof(ReconciliationOutput.Kind),
            nameof(ReconciliationOutput.Generation), nameof(ReconciliationOutput.Digest));
        AssertProperties<HoldResource>(nameof(ReconciliationOutput.Identity), nameof(ReconciliationOutput.Kind),
            nameof(ReconciliationOutput.Generation), nameof(ReconciliationOutput.Digest), nameof(HoldResource.Reason),
            nameof(HoldResource.RootResource));
        AssertProperties<ReconcileResourceIntent>(nameof(ReconciliationOutput.Identity), nameof(ReconciliationOutput.Kind),
            nameof(ReconciliationOutput.Generation), nameof(ReconciliationOutput.Digest),
            nameof(ReconcileResourceIntent.ObservationProof), nameof(ReconcileResourceIntent.DependencyProofs),
            nameof(ReconcileResourceIntent.AcceptedPolicy));
        AssertProperties<DependencyProof>(nameof(DependencyProof.Identity), nameof(DependencyProof.Kind),
            nameof(DependencyProof.Generation), nameof(DependencyProof.Digest), nameof(DependencyProof.ObservationId),
            nameof(DependencyProof.FreshnessSequence), nameof(DependencyProof.Condition));
        AssertProperties<ReconciliationObservationProof>(nameof(ReconciliationObservationProof.Identity),
            nameof(ReconciliationObservationProof.Kind), nameof(ReconciliationObservationProof.Generation),
            nameof(ReconciliationObservationProof.Digest), nameof(ReconciliationObservationProof.ObservationId),
            nameof(ReconciliationObservationProof.FreshnessSequence), nameof(ReconciliationObservationProof.Condition));
        AssertProperties<ReconciliationStep>(nameof(ReconciliationStep.Order), nameof(ReconciliationStep.Desired),
            nameof(ReconciliationStep.Observation), nameof(ReconciliationStep.Output), nameof(ReconciliationStep.Trace));
        AssertProperties<ReconciliationPlan>(nameof(ReconciliationPlan.Steps), nameof(ReconciliationPlan.Errors),
            nameof(ReconciliationPlan.Trace));
        AssertProperties<ReconciliationError>(nameof(ReconciliationError.Code), nameof(ReconciliationError.Requirement),
            nameof(ReconciliationError.Resource), nameof(ReconciliationError.RelatedResource));
        AssertProperties<ReconciliationTrace>(nameof(ReconciliationTrace.Sequence), nameof(ReconciliationTrace.Resource),
            nameof(ReconciliationTrace.Reason), nameof(ReconciliationTrace.RelatedResource));

        var collectionAccessors = new[]
        {
            typeof(DesiredResource).GetProperty(nameof(DesiredResource.Dependencies))!.GetMethod!,
            typeof(ReconciliationPolicy).GetProperty(nameof(ReconciliationPolicy.AllowedKinds))!.GetMethod!,
            typeof(ReconciliationPolicy).GetProperty(nameof(ReconciliationPolicy.GenerationFloors))!.GetMethod!,
            typeof(ReconciliationRequest).GetProperty(nameof(ReconciliationRequest.Desired))!.GetMethod!,
            typeof(ReconciliationRequest).GetProperty(nameof(ReconciliationRequest.Observed))!.GetMethod!,
            typeof(ReconcileResourceIntent).GetProperty(nameof(ReconcileResourceIntent.DependencyProofs))!.GetMethod!,
            typeof(ReconciliationStep).GetProperty(nameof(ReconciliationStep.Trace))!.GetMethod!,
            typeof(ReconciliationPlan).GetProperty(nameof(ReconciliationPlan.Steps))!.GetMethod!,
            typeof(ReconciliationPlan).GetProperty(nameof(ReconciliationPlan.Errors))!.GetMethod!,
            typeof(ReconciliationPlan).GetProperty(nameof(ReconciliationPlan.Trace))!.GetMethod!,
        };
        var actualCollections = new[] { typeof(DesiredResource), typeof(ReconciliationPolicy), typeof(ReconciliationRequest),
                typeof(ReconcileResourceIntent), typeof(ReconciliationStep), typeof(ReconciliationPlan) }
            .SelectMany(type => type.GetProperties(BindingFlags.Public | BindingFlags.Instance))
            .Where(property => property.PropertyType != typeof(string) &&
                typeof(System.Collections.IEnumerable).IsAssignableFrom(property.PropertyType))
            .Select(property => property.GetMethod!).ToArray();
        await Assert.That(Signatures(actualCollections).SequenceEqual(Signatures(collectionAccessors))).IsTrue();

        await Assert.That(typeof(ReconciliationPolicy).GetConstructors(BindingFlags.Public | BindingFlags.Instance)).HasSingleItem();
        await Assert.That(typeof(ReconciliationRequest).GetConstructors(BindingFlags.Public | BindingFlags.Instance)).HasSingleItem();
        await Assert.That(typeof(DesiredResource).GetConstructors(BindingFlags.Public | BindingFlags.Instance)).HasSingleItem();

        var policy = Policy();
        var intent = (ReconcileResourceIntent)ReconciliationEngine.Plan(new([Desired("clone")], [Drift(Desired("clone"))],
            policy)).Steps.Single().Output;
        var intentClone = (ReconcileResourceIntent)Clone(typeof(ReconcileResourceIntent)).Invoke(intent, null)!;
        await Assert.That(ReferenceEquals(intent.AcceptedPolicy, policy)).IsTrue();
        await Assert.That(ReferenceEquals(intentClone.AcceptedPolicy, policy)).IsTrue();
    }

    private static ReconciliationPolicy Rebuild(ReconciliationPolicy value, int? maximumResources = null,
        int? maximumIdentityLength = null, int? maximumKindLength = null, int? maximumDigestLength = null,
        int? maximumObservationIdLength = null, int? maximumDependencies = null, long? minimumFreshness = null) =>
        new(value.AllowedKinds, value.GenerationFloors, maximumResources ?? value.MaximumResources,
            maximumIdentityLength ?? value.MaximumIdentityLength, maximumKindLength ?? value.MaximumKindLength,
            maximumDigestLength ?? value.MaximumDigestLength,
            maximumObservationIdLength ?? value.MaximumObservationIdLength,
            maximumDependencies ?? value.MaximumDependenciesPerResource,
            minimumFreshness ?? value.MinimumFreshnessSequence);

    private static ReconciliationPolicy Policy(IEnumerable<string>? kinds = null,
        IReadOnlyDictionary<ResourceIdentity, long>? floors = null, int maximumResources = 100,
        int maximumDependencies = 8, long minimumFreshness = 10) => new(kinds ?? ["service"],
        floors ?? new Dictionary<ResourceIdentity, long>(), maximumResources, 64, 32, 128, 64,
        maximumDependencies, minimumFreshness);

    private static DesiredResource Desired(string identity, params string[] dependencies) => new(
        new(identity), "service", 2, $"digest-{identity}", dependencies.Select(value => new ResourceIdentity(value)));
    private static ObservedResourceState Exact(DesiredResource resource) => new(resource.Identity, resource.Kind,
        resource.Generation, resource.Digest, $"observation-{resource.Identity.Value}", 10, ObservedCondition.Ready);
    private static ObservedResourceState Drift(DesiredResource resource) => Exact(resource) with
        { Generation = 1, Digest = $"old-{resource.Identity.Value}" };

    private static string PublicFingerprint(ReconciliationPlan plan) => string.Join('|', plan.Steps.Select(step =>
    {
        var policy = step.Output is ReconcileResourceIntent intent ? PolicyFingerprint(intent.AcceptedPolicy) : string.Empty;
        var proofs = step.Output is ReconcileResourceIntent reconcile ? string.Join(',', reconcile.DependencyProofs.Select(proof =>
            string.Join('~', proof.Identity.Value, proof.Kind, proof.Generation, proof.Digest, proof.ObservationId,
                proof.FreshnessSequence, proof.Condition))) : string.Empty;
        return string.Join(':', step.Order, step.Desired.Identity.Value, step.Output.GetType().Name,
            step.Output.Identity.Value, step.Output.Kind, step.Output.Generation, step.Output.Digest,
            step.Observation?.ObservationId, step.Observation?.FreshnessSequence, step.Trace.Single().Reason,
            proofs, policy);
    }).Concat(plan.Errors.Select(error => $"error:{error.Code}:{error.Requirement}:{error.Resource?.Value}:{error.RelatedResource?.Value}")));

    private static string PolicyFingerprint(ReconciliationPolicy policy) => string.Join('|',
        $"kinds={string.Join(',', policy.AllowedKinds.Order(StringComparer.Ordinal))}",
        $"floors={string.Join(',', policy.GenerationFloors.OrderBy(pair => pair.Key.Value, StringComparer.Ordinal).Select(pair => $"{pair.Key.Value}:{pair.Value.ToString(CultureInfo.InvariantCulture)}"))}",
        $"resources={policy.MaximumResources.ToString(CultureInfo.InvariantCulture)}",
        $"identity={policy.MaximumIdentityLength.ToString(CultureInfo.InvariantCulture)}",
        $"kind={policy.MaximumKindLength.ToString(CultureInfo.InvariantCulture)}",
        $"digest={policy.MaximumDigestLength.ToString(CultureInfo.InvariantCulture)}",
        $"observation={policy.MaximumObservationIdLength.ToString(CultureInfo.InvariantCulture)}",
        $"dependencies={policy.MaximumDependenciesPerResource.ToString(CultureInfo.InvariantCulture)}",
        $"freshness={policy.MinimumFreshnessSequence.ToString(CultureInfo.InvariantCulture)}");

    private static MethodInfo Clone(Type type) => type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
        .Single(method => method.Name == "<Clone>$");
    private static void AssertProperties<T>(params string[] expected)
    {
        var actual = typeof(T).GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Select(property => property.Name).ToHashSet(StringComparer.Ordinal);
        if (!actual.SetEquals(expected))
            throw new InvalidOperationException($"Public property inventory drifted for {typeof(T).Name}.");
    }
    private static IEnumerable<string> Signatures(IEnumerable<MethodInfo> methods) => methods.Select(method =>
        $"{method.DeclaringType!.FullName}|{method.Name}|{method.ReturnType.FullName}").Order(StringComparer.Ordinal);
}
