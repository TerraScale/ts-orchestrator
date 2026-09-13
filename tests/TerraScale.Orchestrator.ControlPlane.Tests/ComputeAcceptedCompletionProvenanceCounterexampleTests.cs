using System.Collections;
using System.Globalization;
using System.Reflection;
using TerraScale.Orchestrator.ControlPlane.Compute;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class ComputeAcceptedCompletionProvenanceCounterexampleTests
{
    [Test]
    public async Task Distinct_completed_scale_out_requests_must_not_collapse_to_the_same_public_accepted_output()
    {
        var firstRequest = Request(ScaleOutState.Completed, "first", generation: 7);
        var secondRequest = Request(ScaleOutState.Completed, "second", generation: 8);
        var first = ComputeEngine.DecideScaleOut(firstRequest);
        var second = ComputeEngine.DecideScaleOut(secondRequest);

        await Assert.That(first.Errors).IsEmpty();
        await Assert.That(second.Errors).IsEmpty();
        await Assert.That(first.Intents).IsEmpty();
        await Assert.That(second.Intents).IsEmpty();
        await Assert.That(ReferenceEquals(first.AcceptedScaleOutRequest, firstRequest)).IsTrue();
        await Assert.That(ReferenceEquals(second.AcceptedScaleOutRequest, secondRequest)).IsTrue();
        await Assert.That(PublicFingerprint(first)).IsNotEqualTo(PublicFingerprint(second));
    }

    [Test]
    public async Task Accepted_scale_out_request_is_exactly_present_iff_the_scale_out_decision_is_error_free()
    {
        foreach (var state in Enum.GetValues<ScaleOutState>().Where(state => state != ScaleOutState.Unspecified))
        {
            var request = Request(state, state.ToString().ToLowerInvariant(), generation: 7);
            var decision = ComputeEngine.DecideScaleOut(request);
            await Assert.That(decision.Errors).IsEmpty();
            await Assert.That(ReferenceEquals(decision.AcceptedScaleOutRequest, request)).IsTrue();
        }

        var complete = Request(ScaleOutState.Completed, "held", generation: 7);
        var held = new[]
        {
            complete with { State = ScaleOutState.Unspecified },
            complete with { Plan = complete.Plan with { DesiredNodes = 2 } },
            complete with { EvaluationSequence = 61 },
            complete with { Demand = complete.Demand with { ExplicitDemand = false } },
            Request(ScaleOutState.Authorized, "budget", 7) with
            { Authorization = Request(ScaleOutState.Authorized, "budget", 7).Authorization! with { BudgetAllowed = false } },
            Request(ScaleOutState.Authorized, "quota", 7) with
            { Authorization = Request(ScaleOutState.Authorized, "quota", 7).Authorization! with { QuotaAllowed = false } },
            Request(ScaleOutState.Authorized, "capacity", 7) with
            { Authorization = Request(ScaleOutState.Authorized, "capacity", 7).Authorization! with { CapacityAvailable = false } },
            Request(ScaleOutState.Authorized, "cost", 7) with
            { Authorization = Request(ScaleOutState.Authorized, "cost", 7).Authorization! with { CostAllowed = false } },
            Request(ScaleOutState.Authorized, "placement", 7) with
            { Authorization = Request(ScaleOutState.Authorized, "placement", 7).Authorization! with { PlacementAllowed = false } },
        };
        var expected = new[] { ComputeErrorCode.InvalidInput, ComputeErrorCode.EvidenceMismatch,
            ComputeErrorCode.EvidenceStale, ComputeErrorCode.MissingProof, ComputeErrorCode.BudgetDenied,
            ComputeErrorCode.QuotaDenied, ComputeErrorCode.CapacityDenied, ComputeErrorCode.CostDenied,
            ComputeErrorCode.PlacementDenied };
        var actual = held.Select(ComputeEngine.DecideScaleOut).ToArray();
        await Assert.That(actual.Select(decision => decision.Errors.Single().Code).SequenceEqual(expected)).IsTrue();
        await Assert.That(actual.All(decision => decision.AcceptedScaleOutRequest is null)).IsTrue();

        await Assert.That(ComputeEngine.DecideScaleIn(ScaleIn()).AcceptedScaleOutRequest).IsNull();
        await Assert.That(ComputeEngine.DecideScaleIn(ScaleIn() with { State = ScaleInState.Unspecified })
            .AcceptedScaleOutRequest).IsNull();
        await Assert.That(ComputeEngine.DecideSurvival(Survival()).AcceptedScaleOutRequest).IsNull();
        await Assert.That(ComputeEngine.DecideSurvival(Survival() with { CurrentAcceptedGeneration = 1 })
            .AcceptedScaleOutRequest).IsNull();
    }

    [Test]
    public async Task Every_independently_variable_complete_request_leaf_or_count_changes_the_accepted_fingerprint()
    {
        var baseline = Request(ScaleOutState.Completed, "baseline", 7);
        var mutations = Mutations(baseline).ToArray();
        var baselineFingerprint = Canonical(baseline);

        await Assert.That(mutations.Select(mutation => mutation.Name).Distinct(StringComparer.Ordinal).Count())
            .IsEqualTo(mutations.Length);
        await Assert.That(mutations.All(mutation => ComputeEngine.DecideScaleOut(mutation.Request).Errors.Count == 0)).IsTrue();
        await Assert.That(mutations.All(mutation => Canonical(mutation.Request) != baselineFingerprint)).IsTrue();
        await Assert.That(mutations.Select(mutation => Canonical(mutation.Request)).Distinct(StringComparer.Ordinal).Count())
            .IsEqualTo(mutations.Length);
    }

    [Test]
    public async Task Accepted_request_fingerprint_is_culture_discovery_order_replay_and_corpus_stable()
    {
        var request = Request(ScaleOutState.Completed, "stable", 7);
        string? baseline = null;
        foreach (var cultureName in new[] { "en-US", "tr-TR", "ar-SA" })
        foreach (var reverseDiscovery in new[] { false, true })
        {
            var previous = CultureInfo.CurrentCulture;
            try
            {
                CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(cultureName);
                var accepted = ComputeEngine.DecideScaleOut(request).AcceptedScaleOutRequest!;
                var actual = Canonical(accepted, reverseDiscovery);
                baseline ??= actual;
                await Assert.That(actual).IsEqualTo(baseline);
                await Assert.That(Canonical(ComputeEngine.DecideScaleOut(request).AcceptedScaleOutRequest!, reverseDiscovery))
                    .IsEqualTo(actual);
            }
            finally { CultureInfo.CurrentCulture = previous; }
        }

        await Assert.That(StorageComputeReplayCorpus.Load().Count).IsEqualTo(8);
        await Assert.That(StorageComputeReplayCorpus.ContentSha256)
            .IsEqualTo("f0f97770a45ab50329b71b07e8b48921a0ee26d1c3ade443ac8f604b49f557ff");
    }

    [Test]
    public async Task Every_exported_compute_decision_intent_collection_request_accessor_clone_and_origin_is_closed()
    {
        var assembly = typeof(ComputeDecision).Assembly;
        var methods = assembly.ExportedTypes.SelectMany(type => type.GetMethods(
            BindingFlags.Public | BindingFlags.Static | BindingFlags.Instance | BindingFlags.DeclaredOnly)).ToArray();
        var intentEnumerable = typeof(IEnumerable<ComputeIntent>);
        var relevant = methods.Where(method => method.ReturnType == typeof(ComputeDecision) ||
            typeof(ComputeIntent).IsAssignableFrom(method.ReturnType) ||
            intentEnumerable.IsAssignableFrom(method.ReturnType) ||
            method.ReturnType == typeof(ScaleOutRequest)).ToArray();
        var requestClone = Clone(typeof(ScaleOutRequest));
        var expected = new[]
        {
            typeof(ComputeEngine).GetMethod(nameof(ComputeEngine.DecideScaleOut))!,
            typeof(ComputeEngine).GetMethod(nameof(ComputeEngine.DecideScaleIn))!,
            typeof(ComputeEngine).GetMethod(nameof(ComputeEngine.DecideSurvival))!,
            typeof(ComputeDecision).GetProperty(nameof(ComputeDecision.Intents))!.GetMethod!,
            typeof(ComputeDecision).GetProperty(nameof(ComputeDecision.AcceptedScaleOutRequest))!.GetMethod!,
            requestClone,
        };
        await Assert.That(Signatures(relevant).SequenceEqual(Signatures(expected))).IsTrue();

        var protectedTypes = assembly.ExportedTypes.Where(type => type == typeof(ComputeDecision) ||
            typeof(ComputeIntent).IsAssignableFrom(type)).ToArray();
        await Assert.That(protectedTypes.All(type => type.GetConstructors(BindingFlags.Public | BindingFlags.Instance).Length == 0))
            .IsTrue();
        await Assert.That(protectedTypes.SelectMany(type => type.GetProperties(BindingFlags.Public | BindingFlags.Instance))
            .All(property => property.GetMethod is not null && property.SetMethod is null)).IsTrue();

        var request = Request(ScaleOutState.Completed, "clone", 7);
        var clone = (ScaleOutRequest)requestClone.Invoke(request, null)!;
        var decision = ComputeEngine.DecideScaleOut(clone);
        await Assert.That(ReferenceEquals(decision.AcceptedScaleOutRequest, clone)).IsTrue();
        await Assert.That(Canonical(decision.AcceptedScaleOutRequest!)).IsEqualTo(Canonical(request));
    }

    private static IEnumerable<(string Name, ScaleOutRequest Request)> Mutations(ScaleOutRequest request)
    {
        var binding = request.Binding;
        yield return ("binding-cell", Rebind(request, binding with { Cell = new("other-cell") }));
        yield return ("binding-class", Rebind(request, binding with { NodeClass = new("other-class") }));
        yield return ("binding-template", Rebind(request, binding with { Template = new("other-template") }));
        yield return ("binding-shape", Rebind(request, binding with { Shape = new("other-shape") }));
        yield return ("binding-domain", Rebind(request, binding with { Domain = new("other-domain") }));
        yield return ("binding-artifact", Rebind(request, binding with { Artifact = new("other-artifact") }));
        yield return ("binding-digest", Rebind(request, binding with { ArtifactDigest = new("other-digest") }));
        yield return ("binding-demand", Rebind(request, binding with { Demand = new("other-demand") }));
        yield return ("binding-operation", Rebind(request, binding with { Operation = new("other-operation") }));
        yield return ("binding-provider", Rebind(request, binding with { ProviderFingerprint = new("other-provider") }));
        yield return ("binding-generation", Rebind(request, binding with { Generation = binding.Generation + 1 }));
        yield return ("binding-epoch", Rebind(request, binding with { ControllerEpoch = binding.ControllerEpoch + 1 }));
        yield return ("request-state", request with { State = ScaleOutState.Ready });
        yield return ("request-evaluation", request with { EvaluationSequence = request.EvaluationSequence + 1 });
        yield return ("request-limit", request with { MaximumIdentityLength = request.MaximumIdentityLength + 1 });
        yield return ("demand-trigger", request with { Demand = request.Demand with { Trigger = ComputeTrigger.Utilization } });
        yield return ("demand-observation", request with { Demand = request.Demand with { ObservationSequence = 44 } });
        yield return ("demand-freshness", request with { Demand = request.Demand with { FreshThroughSequence = 61 } });
        yield return ("demand-safety", request with { Demand = request.Demand with { SafetyBounded = true } });
        yield return ("demand-count", WithCount(request, 2));
        yield return ("plan-identity", request with { Plan = request.Plan with { PlanIdentity = new("other-plan") },
            PersistedPlan = request.PersistedPlan! with { Plan = request.Plan with { PlanIdentity = new("other-plan") } } });
        yield return ("persisted-proof", request with
            { PersistedPlan = request.PersistedPlan! with { PersistenceProof = new("other-persistence") } });
        yield return ("resources-ocpu", WithResources(request, request.Plan.Resources with { Ocpus = 5 }));
        yield return ("resources-memory", WithResources(request, request.Plan.Resources with { MemoryMib = 25_000 }));
        yield return ("resources-storage", WithResources(request, request.Plan.Resources with { StorageGib = 101 }));
        yield return ("resources-cost", WithResources(request, request.Plan.Resources with { EstimatedHourlyCostMicros = 120_001 }));
        yield return ("authorization-budget", request with { Authorization = request.Authorization! with { BudgetProof = new("other-budget") } });
        yield return ("authorization-quota", request with { Authorization = request.Authorization! with { QuotaProof = new("other-quota") } });
        yield return ("authorization-capacity", request with { Authorization = request.Authorization! with { CapacityProof = new("other-capacity") } });
        yield return ("authorization-cost", request with { Authorization = request.Authorization! with { CostProof = new("other-cost") } });
        yield return ("authorization-placement", request with { Authorization = request.Authorization! with { PlacementProof = new("other-placement") } });
        yield return ("create-key", request with { CreateEvidence = request.CreateEvidence! with { CreateKey = new("other-key") } });
        var otherResource = new ProviderResourceId("other-resource");
        yield return ("create-resource", request with { CreateEvidence = request.CreateEvidence! with { Resource = otherResource },
            Progress = request.Progress! with { Resource = otherResource } });
        yield return ("create-work-request", request with { CreateEvidence = request.CreateEvidence! with { WorkRequest = new("other-work") } });
        yield return ("create-observation", request with { CreateEvidence = request.CreateEvidence! with { ObservationProof = new("other-observation") } });
        yield return ("progress-node", request with { Progress = request.Progress! with { Node = new("other-node") } });
        yield return ("progress-identity", request with { Progress = request.Progress! with { IdentityProof = new("other-identity") } });
        yield return ("progress-enrollment", request with { Progress = request.Progress! with { EnrollmentProof = new("other-enrollment") } });
        yield return ("progress-bootstrap", request with { Progress = request.Progress! with { BootstrapProof = new("other-bootstrap") } });
        yield return ("progress-disk", request with { Progress = request.Progress! with { DiskProof = new("other-disk") } });
        yield return ("progress-placement", request with { Progress = request.Progress! with { PlacementProof = new("other-progress-placement") } });
        yield return ("progress-health", request with { Progress = request.Progress! with { HealthProof = new("other-health") } });
    }

    private static ScaleOutRequest Rebind(ScaleOutRequest request, ComputeBinding binding)
    {
        var plan = request.Plan with { Binding = binding };
        return request with
        {
            Binding = binding,
            Demand = request.Demand with { Binding = binding },
            Plan = plan,
            PersistedPlan = request.PersistedPlan! with { Plan = plan },
            Authorization = request.Authorization! with { Binding = binding },
            CreateEvidence = request.CreateEvidence! with { Binding = binding },
            Progress = request.Progress! with { Binding = binding },
        };
    }

    private static ScaleOutRequest WithResources(ScaleOutRequest request, ResourceEnvelope resources)
    {
        var plan = request.Plan with { Resources = resources };
        return request with { Plan = plan, PersistedPlan = request.PersistedPlan! with { Plan = plan },
            Authorization = request.Authorization! with { Resources = resources } };
    }

    private static ScaleOutRequest WithCount(ScaleOutRequest request, int count)
    {
        var plan = request.Plan with { DesiredNodes = count };
        return request with { Demand = request.Demand with { RequiredNodes = count }, Plan = plan,
            PersistedPlan = request.PersistedPlan! with { Plan = plan },
            Authorization = request.Authorization! with { AuthorizedNodes = count } };
    }

    private static ScaleOutRequest Request(ScaleOutState state, string suffix, long generation)
    {
        var binding = new ComputeBinding(new("gru"), new("app"), new($"template-{suffix}"), new("a1-flex"),
            new("fault-domain-1"), new($"artifact-{suffix}"), new($"digest-{suffix}"), new($"demand-{suffix}"),
            new($"operation-{suffix}"), new("provider-fingerprint"), generation, 3);
        var resources = new ResourceEnvelope(4, 24_576, 100, 120_000);
        var demand = new DemandEvidence(binding, ComputeTrigger.Unschedulable, 45, 60, 1, true, true, false);
        var plan = new ScaleOutPlan(binding, resources, 1, new($"plan-{suffix}"));
        var persisted = state == ScaleOutState.DemandObserved ? null : new PersistedScaleOutPlan(plan, new($"persisted-{suffix}"));
        var authorization = state < ScaleOutState.Authorized ? null : new CapacityAuthorization(binding, resources, 1,
            new($"budget-{suffix}"), new($"quota-{suffix}"), new($"capacity-{suffix}"), new($"cost-{suffix}"),
            new($"placement-{suffix}"), true, true, true, true, true);
        var created = state >= ScaleOutState.RequestRecorded;
        var resource = new ProviderResourceId($"instance-{suffix}");
        var create = state < ScaleOutState.Authorized ? null : new ProviderCreateEvidence(binding, new($"create-{suffix}"),
            created ? ProviderCreateStatus.Created : ProviderCreateStatus.ProvenAbsent, created ? resource : null,
            created ? new($"work-request-{suffix}") : null, new($"provider-observation-{suffix}"));
        ScaleOutProgress? progress = null;
        if (created)
        {
            var enrolled = state >= ScaleOutState.Enrolled;
            var ready = state >= ScaleOutState.Ready;
            progress = new(binding, resource, new($"node-{suffix}"), new($"identity-{suffix}"),
                enrolled ? new($"enrollment-{suffix}") : null, enrolled ? new($"bootstrap-{suffix}") : null,
                enrolled ? new($"disk-{suffix}") : null, ready ? new($"placement-progress-{suffix}") : null,
                ready ? new($"health-{suffix}") : null, true, enrolled, enrolled, enrolled, ready, ready);
        }
        return new(binding, state, demand, plan, persisted, authorization, create, progress, 50, 96);
    }

    private static ScaleInRequest ScaleIn()
    {
        var compute = Request(ScaleOutState.Completed, "scale-in", 7).Binding;
        var binding = new ScaleInBinding(compute, new("node"), new("resource"), new("lb"), new("volume"),
            ComputeNodeRole.ElasticStateless);
        var authorization = new ScaleInAuthorization(binding, new("low"), 45, 60, 5, 1, 2, 1, new("low-proof"),
            new("cooldown"), new("lifetime"), new("benefit"), new("control"), new("nats"), new("availability"),
            StatefulDisposition.NotStateful, new("stateful"), true, true, true, true, true, true, false, false);
        var progress = new ScaleInProgress(binding, null, null, null, null, null, null, null, null,
            VolumeDisposition.DetachedEphemeral, null, false, false, false, false, false, false, false, false);
        return new(binding, ScaleInState.CandidateSelected, authorization, progress, 50, 96);
    }

    private static SurvivalRequest Survival()
    {
        var bundle = new RegionalSurvivalBundle(new("bundle"), new("gru"), 2, new("provider"), new("accepted"),
            new("accepted-digest"), new("accepted-signature"), new("rollback"), new("rollback-digest"),
            new("rollback-signature"), [new("secret")], [new(new("class"), new("template"), new("shape"), new("domain"))],
            new("trust"), new("nats"), new("dns"), new("backup"), 7, 90, 80, 150, 200);
        var evidence = new SurvivalBundleEvidence(bundle, new("signature"), new("encryption"), true, true, true, true,
            true, true, true, true, true);
        return new(bundle, evidence, new(bundle.Cell, 7, 90, new("authority"), true), 2, 100, false, null, 96);
    }

    private static string PublicFingerprint(ComputeDecision decision) => string.Join('|',
        decision.Intents.Select(intent => $"intent:{intent.GetType().Name}:{intent.Action}")
            .Concat(decision.Errors.Select(error => $"error:{error.Code}:{error.Requirement}:{error.Operation?.Value}"))
            .Concat(decision.Trace.Select(trace => $"trace:{trace.Sequence}:{trace.Code}:{trace.Action}"))
            .Append($"accepted:{Canonical(decision.AcceptedScaleOutRequest)}"));

    private static string Canonical(object? value, bool reverseDiscovery = false)
    {
        if (value is null) return "null";
        if (value is string text) return $"{text.Length}:{text}";
        if (value is Enum enumeration) return Convert.ToInt64(enumeration, CultureInfo.InvariantCulture).ToString(CultureInfo.InvariantCulture);
        if (value is bool boolean) return boolean ? "true" : "false";
        if (value is IFormattable scalar && value.GetType().IsPrimitive)
            return scalar.ToString(null, CultureInfo.InvariantCulture) ?? throw new InvalidOperationException();
        if (value is IEnumerable sequence)
            return $"[{string.Join(',', sequence.Cast<object?>().Select(item => Canonical(item, reverseDiscovery)).Order(StringComparer.Ordinal))}]";
        var properties = value.GetType().GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(property => property.GetMethod is not null && property.GetIndexParameters().Length == 0);
        properties = reverseDiscovery ? properties.Reverse() : properties;
        return $"{value.GetType().FullName}{{{string.Join(',', properties.OrderBy(property => property.Name, StringComparer.Ordinal)
            .Select(property => $"{property.Name}={Canonical(property.GetValue(value), reverseDiscovery)}"))}}}";
    }

    private static MethodInfo Clone(Type type) => type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
        .Single(method => method.Name == "<Clone>$");
    private static IEnumerable<string> Signatures(IEnumerable<MethodInfo> methods) => methods.Select(method =>
        $"{method.DeclaringType!.FullName}|{method.Name}|{method.IsStatic}|{method.ReturnType.FullName}|{string.Join(',', method.GetParameters().Select(parameter => parameter.ParameterType.FullName))}")
        .Order(StringComparer.Ordinal);
}

