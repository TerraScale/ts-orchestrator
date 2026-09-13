using System.Reflection;
using TerraScale.Orchestrator.ControlPlane.Authority;
using TerraScale.Orchestrator.ControlPlane.Observability;
using TerraScale.Orchestrator.ControlPlane.Operations;
using TerraScale.Orchestrator.ControlPlane.Providers;

namespace TerraScale.Orchestrator.ControlPlane.Tests.Properties;

public sealed class ObservabilityCompletenessPropertyTests
{
    private const int Cases = 1000;

    [Test]
    public async Task Alert_route_intent_preserves_the_exact_authorized_event_for_1000_cases()
    {
        for (var seed = 1UL; seed <= Cases; seed++)
        {
            var state = seed % 2 == 0 ? AlertState.Firing : AlertState.Resolved;
            var request = Alert(seed, state);
            var decision = ObservabilityDecisionEngine.EvaluateAlertRouting(request);
            var intent = decision.Intent as RouteAlertIntent;

            Require(decision.Authorized && intent is not null, seed, "route authorization");
            Require(ReferenceEquals(intent!.Request, request), seed, "exact route request");
            Require(intent.OperationId == request.Alert.OperationId && intent.AlertId == request.Alert.AlertId &&
                intent.ContactId == request.ContactId && intent.Contact == request.Contact, seed, "convenience projections");
            Require(intent.Request.Alert.State == state && intent.Request.Alert.Severity == request.Alert.Severity &&
                intent.Request.Alert.Generation == request.Alert.Generation && intent.Request.Alert.RuleDigest == request.Alert.RuleDigest,
                seed, "exact alert fields");
            Require(intent.Request.Dedupe.DeliveredEvents.SequenceEqual(request.Dedupe.DeliveredEvents) &&
                intent.Request.Dedupe.Sequence == request.Dedupe.Sequence &&
                intent.Request.Dedupe.Completeness == request.Dedupe.Completeness, seed, "exact dedupe snapshot");

            var opposite = Alert(seed, state == AlertState.Firing ? AlertState.Resolved : AlertState.Firing);
            var oppositeIntent = (RouteAlertIntent)ObservabilityDecisionEngine.EvaluateAlertRouting(opposite).Intent;
            Require(RouteFingerprint(intent) != RouteFingerprint(oppositeIntent), seed, "distinct alert transitions");
        }
    }

    [Test]
    public async Task Every_authorized_observability_output_is_closed_out_of_mutation_authority_for_1000_cases()
    {
        Type[] forbiddenRoots =
        [
            typeof(AuthorityIntent),
            typeof(OperationIntent),
            typeof(ProviderMutationIntent),
            typeof(MutationAuthorityPermit),
            typeof(AuthorityDecision),
            typeof(ProviderAuthorizationDecision),
        ];

        var reachable = ReachablePublicTypes(typeof(ObservabilityIntent)).ToArray();
        await Assert.That(reachable.Any(type => forbiddenRoots.Any(root => root.IsAssignableFrom(type)))).IsFalse();
        var concreteIntents = typeof(ObservabilityIntent).Assembly.GetTypes()
            .Where(type => typeof(ObservabilityIntent).IsAssignableFrom(type) && !type.IsAbstract)
            .OrderBy(type => type.Name, StringComparer.Ordinal)
            .ToArray();
        await Assert.That(concreteIntents).IsEquivalentTo(new[]
        {
            typeof(AdmitTelemetryIntent),
            typeof(AggregateRegionalTelemetryIntent),
            typeof(DropTelemetryIntent),
            typeof(HoldObservabilityIntent),
            typeof(ProjectGrafanaIntent),
            typeof(RouteAlertIntent),
        });

        for (var seed = 1UL; seed <= Cases; seed++)
        {
            ObservabilityDecision[] decisions =
            [
                ObservabilityDecisionEngine.EvaluateTelemetryAdmission(ObservabilityData.Admission(seed, 0)),
                ObservabilityDecisionEngine.EvaluateRegionalHealth(ObservabilityData.Regional(seed, 0)),
                ObservabilityDecisionEngine.EvaluateGrafanaProjection(ObservabilityData.Projection(seed, 0)),
                ObservabilityDecisionEngine.EvaluateAlertRouting(ObservabilityData.Alert(seed, 0)),
            ];

            Require(decisions.All(static decision => decision.Authorized), seed, "authorized fixtures");
            Require(decisions.Select(static decision => decision.Intent.GetType()).SequenceEqual(
            [
                typeof(AdmitTelemetryIntent),
                typeof(AggregateRegionalTelemetryIntent),
                typeof(ProjectGrafanaIntent),
                typeof(RouteAlertIntent),
            ]), seed, "closed output families");
        }
    }

    private static AlertRoutingRequest Alert(ulong seed, AlertState state)
    {
        var operation = new ObservabilityOperationId($"alert-operation-{seed}");
        var tenant = new ObservabilityTenantId($"alert-tenant-{seed}");
        var cell = new ObservabilityCellId($"alert-cell-{seed}");
        var signal = new ObservabilitySignalId($"alert-signal-{seed}");
        var alert = new AlertEvent(new($"alert-{seed}"), operation, tenant, cell, signal, new(seed), Digest(),
            seed % 3 == 0 ? AlertSeverity.Warning : AlertSeverity.Critical, state);
        var delivered = state == AlertState.Resolved
            ? new[] { new AlertDeliveryKey(alert.AlertId, AlertState.Firing) }
            : [];
        var dedupe = new AlertDedupeEvidence(operation, tenant, cell, signal, new(seed), Digest(), new(seed),
            new($"contact-{seed}"), ContactCatalogEntry.GlobalOnCall, alert.Severity, state,
            EvidenceCompleteness.Complete, new(2), delivered);
        return new(alert, operation, tenant, cell, signal, new(seed), Digest(), new(seed),
            dedupe.ContactId, dedupe.Contact, dedupe);
    }

    private static IEnumerable<Type> ReachablePublicTypes(Type root)
    {
        var queue = new Queue<Type>();
        var seen = new HashSet<Type>();
        queue.Enqueue(root);
        while (queue.Count > 0)
        {
            var type = Normalize(queue.Dequeue());
            if (!seen.Add(type)) continue;
            yield return type;

            foreach (var property in type.GetProperties(BindingFlags.Public | BindingFlags.Instance))
                queue.Enqueue(property.PropertyType);
            if (type.IsGenericType)
                foreach (var argument in type.GetGenericArguments()) queue.Enqueue(argument);
            foreach (var derived in root.Assembly.GetTypes().Where(candidate => type.IsAssignableFrom(candidate)))
                queue.Enqueue(derived);
        }
    }

    private static Type Normalize(Type type) => type.IsArray ? type.GetElementType()! : type;
    private static string RouteFingerprint(RouteAlertIntent intent) =>
        $"{intent.Request.Alert.AlertId.Value}|{intent.Request.Alert.State}|{intent.Request.Alert.Severity}|" +
        string.Join(',', intent.Request.Dedupe.DeliveredEvents.Select(item => $"{item.AlertId.Value}:{item.State}"));
    private static ObservabilityDigest Digest() => new(new string('a', 64));
    private static void Require(bool condition, ulong seed, string property)
    {
        if (!condition) throw new InvalidOperationException($"{property} failed at seed {seed}.");
    }
}

