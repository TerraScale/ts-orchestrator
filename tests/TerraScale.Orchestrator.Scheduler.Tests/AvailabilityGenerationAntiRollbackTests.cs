using System.Globalization;
using TerraScale.Orchestrator.Scheduler.Availability;

namespace TerraScale.Orchestrator.Scheduler.Tests;

public sealed class AvailabilityGenerationAntiRollbackTests
{
    private readonly AvailabilityPolicyEvaluator evaluator = new();

    [Test]
    public async Task OlderHealthySnapshotCannotReauthorizeASecondDisruption()
    {
        var healthyGenerationThree = HealthyThree();
        var maintainB = new MaintainReplicaChange(new("replica-b"));
        var initiallyAccepted = Evaluate(maintainB, healthyGenerationThree, observationGeneration: 3, currentGeneration: 3,
            policy: ReplayPolicy);
        await Assert.That(initiallyAccepted.Admitted).IsTrue();

        var generationFour = HealthyThree();
        generationFour[0] = Observation("replica-a", "node-a", "fd-a", ReplicaAvailabilityState.Disrupting);
        var current = Evaluate(maintainB, generationFour, observationGeneration: 4, currentGeneration: 4,
            policy: ReplayPolicy);
        await Assert.That(current.Admitted).IsFalse();
        await Assert.That(Reason(current, AvailabilityReasonCode.Quorum).Outcome).IsEqualTo(AvailabilityReasonOutcome.Rejected);
        await Assert.That(Reason(current, AvailabilityReasonCode.DisruptionBudget).Outcome).IsEqualTo(AvailabilityReasonOutcome.Rejected);

        var replay = Evaluate(maintainB, healthyGenerationThree, observationGeneration: 3, currentGeneration: 4,
            policy: ReplayPolicy);
        await Assert.That(replay.Admitted).IsFalse();
        await AssertGeneration(replay, AvailabilityReasonCode.ObservationGenerationNotRollback,
            AvailabilityReasonOutcome.Held, 3, 4);
        await AssertGeneration(replay, AvailabilityReasonCode.ObservationGenerationNotFuture,
            AvailabilityReasonOutcome.Passed, 3, 4);
        await Assert.That(replay.Trace.Skip(5).Take(23)
            .All(reason => reason.Outcome is AvailabilityReasonOutcome.Held or AvailabilityReasonOutcome.NotApplicable)).IsTrue();
    }

    [Test]
    public async Task FutureSnapshotIsNotTreatedAsAlreadyAcceptedEvidence()
    {
        var decision = Evaluate(new MaintainReplicaChange(new("replica-b")), HealthyThree(),
            observationGeneration: 5, currentGeneration: 4);

        await Assert.That(decision.Admitted).IsFalse();
        await AssertGeneration(decision, AvailabilityReasonCode.ObservationGenerationNotRollback,
            AvailabilityReasonOutcome.Passed, 5, 4);
        await AssertGeneration(decision, AvailabilityReasonCode.ObservationGenerationNotFuture,
            AvailabilityReasonOutcome.Held, 5, 4);
        await Assert.That(Reason(decision, AvailabilityReasonCode.ChangeTargetValid).Outcome)
            .IsEqualTo(AvailabilityReasonOutcome.Held);
    }

    [Test]
    public async Task GenerationContractAndTraceNumericSurfaceAreExact()
    {
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => new AvailabilityGeneration(0))).IsTrue();
        await Assert.That(Throws<ArgumentNullException>(() => new AvailabilityEvaluationRequest(
            ReplayPolicy, new MaintainReplicaChange(new("replica-b")), ObservationCompleteness.Complete,
            null!, new(1), HealthyThree()))).IsTrue();
        await Assert.That(Throws<ArgumentNullException>(() => new AvailabilityEvaluationRequest(
            ReplayPolicy, new MaintainReplicaChange(new("replica-b")), ObservationCompleteness.Complete,
            new(1), null!, HealthyThree()))).IsTrue();
        await Assert.That(Enum.GetValues<AvailabilityReasonCode>().Select(code => (int)code)
            .SequenceEqual(Enumerable.Range(1, 30))).IsTrue();

        var decision = Evaluate(new MaintainReplicaChange(new("replica-b")), HealthyThree(), 7, 7);
        await Assert.That(decision.Admitted).IsTrue();
        await Assert.That(decision.Trace.Select(reason => (int)reason.Code)
            .SequenceEqual(Enumerable.Range(1, 30))).IsTrue();
        await AssertGeneration(decision, AvailabilityReasonCode.ObservationGenerationNotRollback,
            AvailabilityReasonOutcome.Passed, 7, 7);
        await AssertGeneration(decision, AvailabilityReasonCode.ObservationGenerationNotFuture,
            AvailabilityReasonOutcome.Passed, 7, 7);
        await Assert.That(Serialize(decision)).EndsWith(
            "ObservationGenerationNotRollback:Passed:7:7;ObservationGenerationNotFuture:Passed:7:7");
        await Assert.That(Properties.PropertySerialization.Availability(decision)).EndsWith("29:1:7:7;30:1:7:7");
    }

    [Test]
    public async Task EqualGenerationRetriesOnlyAppendGenerationDistinctPassedRows()
    {
        var generationThree = Evaluate(new MaintainReplicaChange(new("replica-b")), HealthyThree(), 3, 3);
        var generationFour = Evaluate(new MaintainReplicaChange(new("replica-b")), HealthyThree(), 4, 4);

        await Assert.That(generationThree.Admitted).IsTrue();
        await Assert.That(generationFour.Admitted).IsTrue();
        await Assert.That(Serialize(generationThree.Trace.Take(28))).IsEqualTo(Serialize(generationFour.Trace.Take(28)));
        await Assert.That(Serialize(generationThree.Trace.Skip(28))).IsNotEqualTo(Serialize(generationFour.Trace.Skip(28)));
    }

    [Test]
    public async Task LowerEqualAndHigherGenerationsHaveExactInvariantPrecedenceAcrossOneThousandSeeds()
    {
        for (ulong seed = 140_001; seed < 141_001; seed++)
        {
            var observations = HealthyThree();
            var change = Change(seed);
            var current = checked(seed + 10);
            var relation = seed % 3;
            var observed = relation switch { 0 => current - 1, 1 => current, _ => current + 1 };
            var baseline = Evaluate(change, observations, observed, current);

            await Assert.That(baseline.Trace.Select(reason => (int)reason.Code)
                .SequenceEqual(Enumerable.Range(1, 30))).IsTrue();
            await Assert.That(baseline.Admitted).IsEqualTo(relation == 1);
            await AssertGeneration(baseline, AvailabilityReasonCode.ObservationGenerationNotRollback,
                relation == 0 ? AvailabilityReasonOutcome.Held : AvailabilityReasonOutcome.Passed, observed, current);
            await AssertGeneration(baseline, AvailabilityReasonCode.ObservationGenerationNotFuture,
                relation == 2 ? AvailabilityReasonOutcome.Held : AvailabilityReasonOutcome.Passed, observed, current);

            if (relation != 1)
            {
                await Assert.That(baseline.Trace.Skip(5).Take(23)
                    .All(reason => reason.Outcome is AvailabilityReasonOutcome.Held or AvailabilityReasonOutcome.NotApplicable)).IsTrue();
            }

            foreach (var cultureName in new[] { "tr-TR", "ar-SA" })
            {
                var original = CultureInfo.CurrentCulture;
                try
                {
                    CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(cultureName);
                    var permuted = Evaluate(change, observations.Reverse(), observed, current);
                    await Assert.That(Serialize(permuted)).IsEqualTo(Serialize(baseline));
                }
                finally
                {
                    CultureInfo.CurrentCulture = original;
                }
            }
        }
    }

    private AvailabilityDecision Evaluate(
        AvailabilityChange change,
        IEnumerable<ReplicaObservation> observations,
        ulong observationGeneration,
        ulong currentGeneration,
        ServiceAvailabilityPolicy? policy = null) => evaluator.Evaluate(new(
        policy ?? Policy,
        change,
        ObservationCompleteness.Complete,
        new(observationGeneration),
        new(currentGeneration),
        observations));

    private static AvailabilityChange Change(ulong seed) => (seed % 3) switch
    {
        0 => new PlaceReplicaChange(new("replica-d"), new("node-d"), new("fd-d"),
            ResourceVector.Zero, ResourceVector.Zero),
        1 => new MaintainReplicaChange(new("replica-b")),
        _ => new DrainNodeChange(new("node-a")),
    };

    private static ReplicaObservation[] HealthyThree() =>
    [
        Observation("replica-a", "node-a", "fd-a"),
        Observation("replica-b", "node-b", "fd-b"),
        Observation("replica-c", "node-c", "fd-c"),
    ];

    private static ReplicaObservation Observation(
        string replica,
        string node,
        string domain,
        ReplicaAvailabilityState state = ReplicaAvailabilityState.Available) =>
        new(new(replica), Service, new(node), new(domain), state);

    private static AvailabilityReason Reason(AvailabilityDecision decision, AvailabilityReasonCode code) =>
        decision.Trace.Single(reason => reason.Code == code);

    private static async Task AssertGeneration(
        AvailabilityDecision decision,
        AvailabilityReasonCode code,
        AvailabilityReasonOutcome outcome,
        ulong observed,
        ulong required)
    {
        var reason = Reason(decision, code);
        await Assert.That(reason.Outcome).IsEqualTo(outcome);
        await Assert.That(reason.Observed).IsEqualTo(observed);
        await Assert.That(reason.Required).IsEqualTo(required);
    }

    private static string Serialize(AvailabilityDecision decision) => Serialize(decision.Trace);

    private static string Serialize(IEnumerable<AvailabilityReason> trace) => string.Join(';', trace.Select(
        reason => $"{reason.Code}:{reason.Outcome}:{reason.Observed.ToString(CultureInfo.InvariantCulture)}:{reason.Required.ToString(CultureInfo.InvariantCulture)}"));

    private static bool Throws<TException>(Action action)
        where TException : Exception
    {
        try
        {
            action();
            return false;
        }
        catch (TException)
        {
            return true;
        }
    }

    private static ServiceId Service { get; } = new("control-service");

    private static ServiceAvailabilityPolicy Policy { get; } = new(
        Service,
        new(4),
        new(0),
        new(0),
        new(4),
        ServiceCriticality.Critical,
        onePerHost: false,
        new(0),
        ResourceVector.Zero,
        ReserveDisposition.MayConsume);

    private static ServiceAvailabilityPolicy ReplayPolicy { get; } = new(
        Service,
        new(3),
        new(2),
        new(2),
        new(1),
        ServiceCriticality.Critical,
        onePerHost: true,
        new(2),
        ResourceVector.Zero,
        ReserveDisposition.Preserve);
}
