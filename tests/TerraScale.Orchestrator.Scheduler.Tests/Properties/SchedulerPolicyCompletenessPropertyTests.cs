using TerraScale.Orchestrator.Scheduler.Availability;

namespace TerraScale.Orchestrator.Scheduler.Tests.Properties;

public sealed class SchedulerPolicyCompletenessPropertyTests
{
    private readonly AvailabilityPolicyEvaluator evaluator = new();
    private readonly DeterministicScheduler scheduler = new();

    [Test]
    public async Task ConsumableReserveNeverPermitsPlacementBeyondCapacityAcrossOneThousandSeeds()
    {
        for (ulong seed = 110_001; seed < 110_001 + PropertyLimits.FeatureCases; seed++)
        {
            var dimension = (int)(seed % 8);
            var requestedAmount = checked((long)(seed % 100) + 1);
            var requested = Resources(requestedAmount);
            var exactPlacement = Place(requested, requested);
            var exact = Evaluate(Policy(ReserveDisposition.MayConsume), exactPlacement, []);

            await Assert.That(exact.Admitted).IsTrue();
            await Assert.That(exact.Trace.Select(reason => reason.Code).SequenceEqual(AllReasonCodes)).IsTrue();
            await Assert.That(Reasons(exact, ReserveCodes).All(reason => reason.Outcome == AvailabilityReasonOutcome.NotApplicable)).IsTrue();
            await Assert.That(Reasons(exact, CapacityCodes).All(reason =>
                reason.Outcome == AvailabilityReasonOutcome.Passed && reason.Observed == (ulong)requestedAmount && reason.Required == (ulong)requestedAmount)).IsTrue();

            var available = SchedulerPropertyGenerator.WithOneDimension(requested, dimension, -1);
            var rejected = Evaluate(Policy(ReserveDisposition.MayConsume), Place(requested, available), []);
            var rejectedCapacity = Reason(rejected, CapacityCodes[dimension]);

            await Assert.That(rejected.Admitted).IsFalse();
            await Assert.That(rejectedCapacity.Outcome).IsEqualTo(AvailabilityReasonOutcome.Rejected);
            await Assert.That(rejectedCapacity.Observed).IsEqualTo((ulong)(requestedAmount - 1));
            await Assert.That(rejectedCapacity.Required).IsEqualTo((ulong)requestedAmount);
            await Assert.That(Reasons(rejected, CapacityCodes).Where(reason => reason.Code != CapacityCodes[dimension])
                .All(reason => reason.Outcome == AvailabilityReasonOutcome.Passed)).IsTrue();
            await Assert.That(Reasons(rejected, ReserveCodes).All(reason => reason.Outcome == AvailabilityReasonOutcome.NotApplicable)).IsTrue();
        }
    }

    [Test]
    public async Task EveryAvailabilityPathEmitsTheExactStableTwentyRowPrefixAndEightCapacityRows()
    {
        for (ulong seed = 120_001; seed < 120_001 + PropertyLimits.FeatureCases; seed++)
        {
            var observation = Observation();
            var request = (seed % 5) switch
            {
                0 => new AvailabilityEvaluationRequest(Policy(ReserveDisposition.Preserve), Place(Resources(1), Resources(1)), ObservationCompleteness.Complete, []),
                1 => new AvailabilityEvaluationRequest(MutationPolicy(), new MaintainReplicaChange(observation.ReplicaId), ObservationCompleteness.Complete, [observation]),
                2 => new AvailabilityEvaluationRequest(MutationPolicy(), new DrainNodeChange(observation.NodeId!), ObservationCompleteness.Complete, [observation]),
                3 => new AvailabilityEvaluationRequest(MutationPolicy(), new MaintainReplicaChange(observation.ReplicaId), ObservationCompleteness.Incomplete, [observation]),
                _ => new AvailabilityEvaluationRequest(MutationPolicy(), new MaintainReplicaChange(new("replica-missing")), ObservationCompleteness.Complete, [observation]),
            };

            var decision = evaluator.Evaluate(request);
            var codes = decision.Trace.Select(reason => reason.Code).ToArray();

            await Assert.That(codes).IsEquivalentTo(AllReasonCodes);
            await Assert.That(codes.SequenceEqual(AllReasonCodes)).IsTrue();
            await Assert.That(codes.Take(20).Select(code => (int)code).SequenceEqual(Enumerable.Range(1, 20))).IsTrue();
            await Assert.That(decision.Trace.Count).IsEqualTo(28);
            await Assert.That(codes.Distinct().Count()).IsEqualTo(28);
        }
    }

    [Test]
    public async Task EveryClosedCandidateVetoProducesTheExactCallerHoldAcrossOneThousandSeeds()
    {
        var vetoes = Enum.GetValues<CandidateVetoCode>();
        var hits = vetoes.ToDictionary(veto => veto, _ => 0);
        for (ulong seed = 130_001; seed < 130_001 + PropertyLimits.FeatureCases; seed++)
        {
            var property = SchedulerPropertyGenerator.Valid(seed);
            var veto = vetoes[(int)(seed % (ulong)vetoes.Length)];
            hits[veto]++;
            var result = scheduler.Schedule(
                property.Workload,
                [SchedulerPropertyGenerator.Vetoed(property.Workload, veto)],
                property.Policy);
            var reason = result.Candidates.Single().Reasons.Single(item => item.Check == PlacementCheck.CallerVeto);

            await Assert.That(result).IsTypeOf<Unschedulable>();
            await Assert.That(reason).IsEqualTo(new PlacementReason(
                PlacementCheck.CallerVeto,
                CheckOutcome.Rejected,
                $"code={veto}"));
        }

        await Assert.That(hits.Keys).IsEquivalentTo(vetoes);
        await Assert.That(hits.Values.All(count => count == PropertyLimits.FeatureCases / vetoes.Length)).IsTrue();
    }

    private AvailabilityDecision Evaluate(
        ServiceAvailabilityPolicy policy,
        AvailabilityChange change,
        IEnumerable<ReplicaObservation> observations) =>
        evaluator.Evaluate(new(policy, change, ObservationCompleteness.Complete, observations));

    private static ServiceAvailabilityPolicy Policy(ReserveDisposition disposition) => new(
        Service,
        new(1),
        new(1),
        new(1),
        new(0),
        ServiceCriticality.Critical,
        true,
        new(1),
        ResourceVector.Zero,
        disposition);

    private static ServiceAvailabilityPolicy MutationPolicy() => new(
        Service,
        new(1),
        new(0),
        new(0),
        new(1),
        ServiceCriticality.Critical,
        true,
        new(0),
        ResourceVector.Zero,
        ReserveDisposition.Preserve);

    private static PlaceReplicaChange Place(ResourceVector requested, ResourceVector available) => new(
        new("replica-a"),
        new("node-a"),
        new("fd-a"),
        requested,
        available);

    private static ReplicaObservation Observation() => new(
        new("replica-a"),
        Service,
        new("node-a"),
        new("fd-a"),
        ReplicaAvailabilityState.Available);

    private static ResourceVector Resources(long value) => new(value, value, value, value, value, value, value, value);

    private static AvailabilityReason Reason(AvailabilityDecision decision, AvailabilityReasonCode code) =>
        decision.Trace.Single(reason => reason.Code == code);

    private static IEnumerable<AvailabilityReason> Reasons(
        AvailabilityDecision decision,
        IReadOnlyCollection<AvailabilityReasonCode> codes) =>
        decision.Trace.Where(reason => codes.Contains(reason.Code));

    private static ServiceId Service { get; } = new("critical-service");
    private static AvailabilityReasonCode[] AllReasonCodes { get; } = Enum.GetValues<AvailabilityReasonCode>();

    private static AvailabilityReasonCode[] ReserveCodes { get; } =
    [
        AvailabilityReasonCode.ReserveCpu,
        AvailabilityReasonCode.ReserveMemory,
        AvailabilityReasonCode.ReserveBlockIo,
        AvailabilityReasonCode.ReserveEphemeralDisk,
        AvailabilityReasonCode.ReserveBandwidth,
        AvailabilityReasonCode.ReservePids,
        AvailabilityReasonCode.ReserveFileDescriptors,
        AvailabilityReasonCode.ReserveHugePages,
    ];

    private static AvailabilityReasonCode[] CapacityCodes { get; } =
    [
        AvailabilityReasonCode.CapacityCpu,
        AvailabilityReasonCode.CapacityMemory,
        AvailabilityReasonCode.CapacityBlockIo,
        AvailabilityReasonCode.CapacityEphemeralDisk,
        AvailabilityReasonCode.CapacityBandwidth,
        AvailabilityReasonCode.CapacityPids,
        AvailabilityReasonCode.CapacityFileDescriptors,
        AvailabilityReasonCode.CapacityHugePages,
    ];
}
