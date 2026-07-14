using System.Globalization;
using System.Reflection;
using TerraScale.Orchestrator.Scheduler.Availability;

namespace TerraScale.Orchestrator.Scheduler.Tests;

public sealed class SchedulerAudit4CounterexampleTests
{
    private readonly AvailabilityPolicyEvaluator evaluator = new();

    [Test]
    public async Task Distinct_admitted_placement_targets_no_longer_collapse_to_the_same_output()
    {
        var first = Evaluate(Request(change: Place("replica-d", "node-d", "fd-d")));
        var second = Evaluate(Request(change: Place("replica-e", "node-e", "fd-e")));

        await Assert.That(Trace(first)).IsEqualTo(Trace(second));
        await Assert.That(AvailabilityAcceptedRequestFingerprint.Create(first))
            .IsNotEqualTo(AvailabilityAcceptedRequestFingerprint.Create(second));
    }

    [Test]
    public async Task Admission_retains_the_exact_request_and_its_defensive_observation_snapshot()
    {
        var policy = Policy();
        var change = Place("replica-d", "node-d", "fd-d");
        var observations = HealthyThree().ToList();
        var firstObservation = observations[0];
        var request = Request(policy, change, observations);
        var decision = Evaluate(request);
        observations.Clear();

        await Assert.That(decision.Admitted).IsTrue();
        await Assert.That(decision.AcceptedRequest).IsSameReferenceAs(request);
        await Assert.That(decision.AcceptedRequest!.Policy).IsSameReferenceAs(policy);
        await Assert.That(decision.AcceptedRequest.Change).IsSameReferenceAs(change);
        await Assert.That(decision.AcceptedRequest.Observations.Count).IsEqualTo(3);
        await Assert.That(decision.AcceptedRequest.Observations[0]).IsSameReferenceAs(firstObservation);
    }

    [Test]
    public async Task Place_maintain_and_drain_admissions_all_retain_their_exact_request()
    {
        var requests = new[]
        {
            Request(change: Place("replica-d", "node-d", "fd-d")),
            Request(change: new MaintainReplicaChange(new("replica-a"))),
            Request(change: new DrainNodeChange(new("node-a"))),
        };

        foreach (var request in requests)
        {
            var decision = Evaluate(request);
            await Assert.That(decision.Admitted).IsTrue();
            await Assert.That(decision.AcceptedRequest).IsSameReferenceAs(request);
        }
    }

    [Test]
    public async Task Complete_projection_is_sensitive_to_every_accepted_request_field_family()
    {
        var baseline = Evaluate(Request());
        var variants = new List<AvailabilityDecision>
        {
            Evaluate(Request(Policy(service: "other-service"), observations: HealthyThree("other-service"))),
            Evaluate(Request(Policy(desired: 5))),
            Evaluate(Request(Policy(minimum: 1))),
            Evaluate(Request(Policy(quorum: 1))),
            Evaluate(Request(Policy(disruptions: 3))),
            Evaluate(Request(Policy(criticality: ServiceCriticality.Critical))),
            Evaluate(Request(Policy(onePerHost: true))),
            Evaluate(Request(Policy(domains: 1))),
            Evaluate(Request(Policy(reserveDisposition: ReserveDisposition.Preserve))),
            Evaluate(Request(change: Place("other-replica", "node-d", "fd-d"))),
            Evaluate(Request(change: Place("replica-d", "other-node", "fd-d"))),
            Evaluate(Request(change: Place("replica-d", "node-d", "other-domain"))),
            Evaluate(Request(change: new MaintainReplicaChange(new("replica-a")))),
            Evaluate(Request(change: new DrainNodeChange(new("node-a")))),
            Evaluate(Request(observationGeneration: 2, currentGeneration: 2)),
            Evaluate(Request(observations: MutateObservation(replica: "other-replica"))),
            Evaluate(Request(observations: MutateObservation(node: "other-node"))),
            Evaluate(Request(observations: MutateObservation(domain: "other-domain"))),
            Evaluate(Request(observations: MutateObservation(state: ReplicaAvailabilityState.Unavailable))),
        };
        for (var dimension = 0; dimension < 8; dimension++)
        {
            variants.Add(Evaluate(Request(Policy(reserve: Dimension(dimension, 1)))));
            variants.Add(Evaluate(Request(change: Place("replica-d", "node-d", "fd-d",
                requested: Dimension(dimension, 1), available: Resources(10)))));
            variants.Add(Evaluate(Request(change: Place("replica-d", "node-d", "fd-d",
                requested: ResourceVector.Zero, available: Dimension(dimension, 9, other: 10)))));
        }

        var fingerprint = AvailabilityAcceptedRequestFingerprint.Create(baseline);
        await Assert.That(baseline.Admitted).IsTrue();
        foreach (var variant in variants)
        {
            await Assert.That(variant.Admitted).IsTrue();
            await Assert.That(AvailabilityAcceptedRequestFingerprint.Create(variant)).IsNotEqualTo(fingerprint);
        }
    }

    [Test]
    public async Task Semantic_observation_permutations_and_cultures_have_one_canonical_fingerprint()
    {
        var observations = HealthyThree();
        string? expected = null;
        var original = CultureInfo.CurrentCulture;
        try
        {
            foreach (var culture in new[] { "en-US", "tr-TR", "ar-SA" })
            foreach (var permutation in new[] { observations, observations.Reverse().ToArray(), [observations[1], observations[2], observations[0]] })
            {
                CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(culture);
                var decision = Evaluate(Request(observations: permutation));
                var fingerprint = AvailabilityAcceptedRequestFingerprint.Create(decision);
                expected ??= fingerprint;
                await Assert.That(fingerprint).IsEqualTo(expected);
            }
        }
        finally
        {
            CultureInfo.CurrentCulture = original;
        }
    }

    [Test]
    public async Task Every_held_or_rejected_result_has_no_accepted_request_and_admission_is_iff()
    {
        var observations = HealthyThree();
        var denied = new[]
        {
            Request(completeness: ObservationCompleteness.Incomplete),
            Request(observationGeneration: 1, currentGeneration: 2),
            Request(observationGeneration: 2, currentGeneration: 1),
            Request(observations: observations.Append(observations[0])),
            Request(observations: observations.Append(new ReplicaObservation(new("replica-a"), Service,
                new("conflict-node"), new("conflict-domain"), ReplicaAvailabilityState.Available))),
            Request(observations: [new ReplicaObservation(new("replica-a"), Service, null,
                new("fd-a"), ReplicaAvailabilityState.Available)]),
            Request(observations: [Observation("replica-a", "other-service", "node-a", "fd-a")]),
            Request(change: new MaintainReplicaChange(new("missing-replica"))),
            Request(Policy(desired: 3, disruptions: 3)),
            Request(Policy(minimum: 4), observations: MutateObservation(state: ReplicaAvailabilityState.Unavailable)),
            Request(Policy(quorum: 4), observations: MutateObservation(state: ReplicaAvailabilityState.Unavailable)),
            Request(Policy(disruptions: 0), change: new MaintainReplicaChange(new("replica-a"))),
            Request(Policy(onePerHost: true), change: Place("replica-d", "node-a", "fd-d")),
            Request(Policy(domains: 4), change: Place("replica-d", "node-d", "fd-a")),
            Request(Policy(reserve: Resources(11), reserveDisposition: ReserveDisposition.Preserve)),
            Request(change: Place("replica-d", "node-d", "fd-d", Resources(11), Resources(10))),
        }.Select(Evaluate).ToArray();

        foreach (var decision in denied)
        {
            await Assert.That(decision.Admitted).IsFalse();
            await Assert.That(decision.AcceptedRequest).IsNull();
            await Assert.That(AvailabilityAcceptedRequestFingerprint.Create(decision)).IsEqualTo("denied");
        }
        var admitted = Evaluate(Request());
        await Assert.That(admitted.Admitted).IsEqualTo(admitted.AcceptedRequest is not null);
        await Assert.That(denied.All(decision => decision.Admitted == (decision.AcceptedRequest is not null))).IsTrue();
    }

    [Test]
    public async Task Availability_decision_admission_surface_is_assembly_wide_construction_closed()
    {
        var decisionType = typeof(AvailabilityDecision);
        await Assert.That(decisionType.GetConstructors(BindingFlags.Public | BindingFlags.Instance)).IsEmpty();
        await Assert.That(decisionType.GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(static property => property.SetMethod is not null)).IsEmpty();
        await Assert.That(decisionType.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static)
            .Where(static method => method.Name == "Deconstruct")).IsEmpty();
        var factories = decisionType.Assembly.ExportedTypes.SelectMany(static type => type.GetMethods(
                BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly))
            .Where(method => method.ReturnType == decisionType && !method.IsSpecialName).ToArray();
        var originators = factories.Where(method => method.DeclaringType != decisionType).ToArray();
        await Assert.That(originators).HasSingleItem();
        await Assert.That(originators[0].DeclaringType).IsEqualTo(typeof(AvailabilityPolicyEvaluator));
        await Assert.That(originators[0].Name).IsEqualTo(nameof(AvailabilityPolicyEvaluator.Evaluate));
        await Assert.That(originators[0].GetParameters().Select(static parameter => parameter.ParameterType))
            .IsEquivalentTo(new[] { typeof(AvailabilityEvaluationRequest) });
        var recordClones = factories.Where(method => method.DeclaringType == decisionType).ToArray();
        await Assert.That(recordClones).HasSingleItem();
        await Assert.That(recordClones[0].Name).IsEqualTo("<Clone>$");
        await Assert.That(recordClones[0].IsStatic).IsFalse();
        await Assert.That(recordClones[0].GetParameters()).IsEmpty();
    }

    private AvailabilityDecision Evaluate(AvailabilityEvaluationRequest request) => evaluator.Evaluate(request);

    private static AvailabilityEvaluationRequest Request(
        ServiceAvailabilityPolicy? policy = null,
        AvailabilityChange? change = null,
        IEnumerable<ReplicaObservation>? observations = null,
        ObservationCompleteness completeness = ObservationCompleteness.Complete,
        ulong observationGeneration = 1,
        ulong currentGeneration = 1) => new(
        policy ?? Policy(), change ?? Place("replica-d", "node-d", "fd-d"), completeness,
        new(observationGeneration), new(currentGeneration), observations ?? HealthyThree());

    private static ServiceAvailabilityPolicy Policy(
        string service = "control-service",
        ulong desired = 4,
        ulong minimum = 0,
        ulong quorum = 0,
        ulong disruptions = 4,
        ServiceCriticality criticality = ServiceCriticality.Ordinary,
        bool onePerHost = false,
        ulong domains = 0,
        ResourceVector? reserve = null,
        ReserveDisposition reserveDisposition = ReserveDisposition.MayConsume) => new(
        new(service), new(desired), new(minimum), new(quorum), new(disruptions), criticality, onePerHost,
        new(domains), reserve ?? ResourceVector.Zero, reserveDisposition);

    private static PlaceReplicaChange Place(string replica, string node, string domain,
        ResourceVector? requested = null, ResourceVector? available = null) => new(
        new(replica), new(node), new(domain), requested ?? ResourceVector.Zero, available ?? Resources(10));

    private static ReplicaObservation[] HealthyThree(string service = "control-service") =>
    [
        Observation("replica-a", service, "node-a", "fd-a"),
        Observation("replica-b", service, "node-b", "fd-b"),
        Observation("replica-c", service, "node-c", "fd-c"),
    ];

    private static IEnumerable<ReplicaObservation> MutateObservation(
        string replica = "replica-a",
        string node = "node-a",
        string domain = "fd-a",
        ReplicaAvailabilityState state = ReplicaAvailabilityState.Available) =>
    [
        Observation(replica, "control-service", node, domain, state),
        Observation("replica-b", "control-service", "node-b", "fd-b"),
        Observation("replica-c", "control-service", "node-c", "fd-c"),
    ];

    private static ReplicaObservation Observation(string replica, string service, string node, string domain,
        ReplicaAvailabilityState state = ReplicaAvailabilityState.Available) =>
        new(new(replica), new(service), new(node), new(domain), state);

    private static ServiceId Service { get; } = new("control-service");

    private static ResourceVector Resources(long value) => new(value, value, value, value, value, value, value, value);

    private static ResourceVector Dimension(int index, long value, long other = 0)
    {
        var values = Enumerable.Repeat(other, 8).ToArray();
        values[index] = value;
        return new(values[0], values[1], values[2], values[3], values[4], values[5], values[6], values[7]);
    }

    private static string Trace(AvailabilityDecision decision) => string.Join(';', decision.Trace.Select(reason =>
        $"{(int)reason.Code}:{(int)reason.Outcome}:{reason.Observed}:{reason.Required}"));
}
