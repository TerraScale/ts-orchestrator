using System.Globalization;
using TerraScale.Orchestrator.Scheduler.Availability;

namespace TerraScale.Orchestrator.Scheduler.Tests;

public sealed class AvailabilityPolicyTests
{
    private readonly AvailabilityPolicyEvaluator evaluator = new();

    [Test]
    public async Task ThreeNodeExplicitTwoOfThreeQuorumAllowsOneMaintenance()
    {
        var decision = Evaluate(Policy(3, 2, 2, 1, domains: 2), new MaintainReplicaChange(new("replica-a")), HealthyThree());

        await Assert.That(decision.Admitted).IsTrue();
        await Assert.That(Reason(decision, AvailabilityReasonCode.Quorum).Observed).IsEqualTo(2UL);
        await Assert.That(Reason(decision, AvailabilityReasonCode.Quorum).Required).IsEqualTo(2UL);
        await Assert.That(Reason(decision, AvailabilityReasonCode.DisruptionBudget).Observed).IsEqualTo(1UL);
        await Assert.That(decision.Trace.Count).IsEqualTo(30);
    }

    [Test]
    public async Task SecondLossFromTwoOfThreeRejectsQuorumAndDisruptionBudget()
    {
        var observations = HealthyThree().ToArray();
        observations[0] = Observation("replica-a", "node-a", "fd-a", ReplicaAvailabilityState.Disrupting);
        var decision = Evaluate(Policy(3, 2, 2, 1, domains: 1), new MaintainReplicaChange(new("replica-b")), observations);

        await Assert.That(decision.Admitted).IsFalse();
        await Assert.That(Reason(decision, AvailabilityReasonCode.Quorum).Outcome).IsEqualTo(AvailabilityReasonOutcome.Rejected);
        await Assert.That(Reason(decision, AvailabilityReasonCode.Quorum).Observed).IsEqualTo(1UL);
        await Assert.That(Reason(decision, AvailabilityReasonCode.DisruptionBudget).Outcome).IsEqualTo(AvailabilityReasonOutcome.Rejected);
        await Assert.That(Reason(decision, AvailabilityReasonCode.DisruptionBudget).Observed).IsEqualTo(2UL);
    }

    [Test]
    public async Task OneAtATimeMaintenanceRejectsConcurrentDisruptionEvenWhenQuorumAllowsIt()
    {
        var observations = HealthyThree().ToArray();
        observations[0] = Observation("replica-a", "node-a", "fd-a", ReplicaAvailabilityState.Disrupting);
        var decision = Evaluate(Policy(3, 1, 1, 1, domains: 1), new MaintainReplicaChange(new("replica-b")), observations);

        await Assert.That(Reason(decision, AvailabilityReasonCode.Quorum).Outcome).IsEqualTo(AvailabilityReasonOutcome.Passed);
        await Assert.That(Reason(decision, AvailabilityReasonCode.DisruptionBudget).Outcome).IsEqualTo(AvailabilityReasonOutcome.Rejected);
    }

    [Test]
    public async Task LastFailureDomainMarginRejectsMaintenance()
    {
        var decision = Evaluate(Policy(3, 2, 2, 1, domains: 3), new MaintainReplicaChange(new("replica-a")), HealthyThree());

        await Assert.That(decision.Admitted).IsFalse();
        await Assert.That(Reason(decision, AvailabilityReasonCode.FailureDomainSpread).Outcome).IsEqualTo(AvailabilityReasonOutcome.Rejected);
        await Assert.That(Reason(decision, AvailabilityReasonCode.FailureDomainSpread).Observed).IsEqualTo(2UL);
    }

    [Test]
    public async Task PlacementRejectsHostColocationAndDomainCollapseIndependently()
    {
        var placement = Place("replica-d", "node-a", "fd-a", Resources(1), Resources(10));
        var decision = Evaluate(Policy(4, 2, 2, 1, domains: 4), placement, HealthyThree());

        await Assert.That(decision.Admitted).IsFalse();
        await Assert.That(Reason(decision, AvailabilityReasonCode.OnePerHost).Outcome).IsEqualTo(AvailabilityReasonOutcome.Rejected);
        await Assert.That(Reason(decision, AvailabilityReasonCode.FailureDomainSpread).Outcome).IsEqualTo(AvailabilityReasonOutcome.Rejected);
        await Assert.That(Reason(decision, AvailabilityReasonCode.FailureDomainSpread).Observed).IsEqualTo(3UL);
    }

    [Test]
    public async Task PlacementRestoresExplicitMinimumAndQuorumFromTwoToThree()
    {
        var observations = HealthyThree().Take(2).ToArray();
        var placement = Place("replica-c", "node-c", "fd-c", ResourceVector.Zero, ResourceVector.Zero);
        var decision = Evaluate(Policy(3, 3, 3, 0, domains: 3, reserve: ResourceVector.Zero), placement, observations);

        await Assert.That(decision.Admitted).IsTrue();
        await Assert.That(Reason(decision, AvailabilityReasonCode.MinimumAvailable).Observed).IsEqualTo(3UL);
        await Assert.That(Reason(decision, AvailabilityReasonCode.MinimumAvailable).Outcome).IsEqualTo(AvailabilityReasonOutcome.Passed);
        await Assert.That(Reason(decision, AvailabilityReasonCode.Quorum).Observed).IsEqualTo(3UL);
        await Assert.That(Reason(decision, AvailabilityReasonCode.Quorum).Outcome).IsEqualTo(AvailabilityReasonOutcome.Passed);
    }

    [Test]
    public async Task CheckedProjectedAvailabilityAdditionFailsClosedAtMaximumBoundary()
    {
        var maximumProjectedAvailable = new AvailabilityCount(ulong.MaxValue);

        await Assert.That(Throws<OverflowException>(() => maximumProjectedAvailable.AddChecked(new(1)))).IsTrue();
    }

    [Test]
    public async Task UnavailableAllocationStillBlocksOnePerHostPlacement()
    {
        var observations = HealthyThree().ToArray();
        observations[0] = Observation("replica-a", "node-a", "fd-a", ReplicaAvailabilityState.Unavailable);
        var placement = Place("replica-d", "node-a", "fd-d", Resources(1), Resources(10));
        var decision = Evaluate(Policy(4, 1, 1, 1, domains: 1), placement, observations);

        await Assert.That(Reason(decision, AvailabilityReasonCode.OnePerHost).Outcome).IsEqualTo(AvailabilityReasonOutcome.Rejected);
    }

    [Test]
    public async Task DrainAccountsForEveryAvailableReplicaOnTargetNode()
    {
        var observations = new[]
        {
            Observation("replica-a", "node-a", "fd-a"),
            Observation("replica-b", "node-a", "fd-a"),
            Observation("replica-c", "node-c", "fd-c"),
        };
        var decision = Evaluate(
            Policy(3, 2, 2, 1, domains: 1, onePerHost: false), new DrainNodeChange(new("node-a")), observations);

        await Assert.That(Reason(decision, AvailabilityReasonCode.MinimumAvailable).Observed).IsEqualTo(1UL);
        await Assert.That(Reason(decision, AvailabilityReasonCode.MinimumAvailable).Outcome).IsEqualTo(AvailabilityReasonOutcome.Rejected);
        await Assert.That(Reason(decision, AvailabilityReasonCode.DisruptionBudget).Observed).IsEqualTo(2UL);
    }

    [Test]
    public async Task ReserveExactBoundaryPassesAndOneUnitConsumptionRejectsExactDimension()
    {
        var policy = Policy(4, 2, 2, 1, domains: 3, reserve: Resources(2));
        var exact = Evaluate(policy, Place("replica-d", "node-d", "fd-d", Resources(3), Resources(5)), HealthyThree());
        await Assert.That(exact.Admitted).IsTrue();
        await Assert.That(ReserveReasons(exact).All(reason => reason.Outcome == AvailabilityReasonOutcome.Passed)).IsTrue();

        var reserveCodes = ReserveCodes;
        for (var index = 0; index < reserveCodes.Length; index++)
        {
            var shortDecision = Evaluate(policy, Place(
                "replica-d", "node-d", "fd-d", Resources(3), ResourceWithOneShortDimension(index)), HealthyThree());
            await Assert.That(Reason(shortDecision, reserveCodes[index]).Outcome).IsEqualTo(AvailabilityReasonOutcome.Rejected);
            await Assert.That(ReserveReasons(shortDecision).Where(reason => reason.Code != reserveCodes[index])
                .All(reason => reason.Outcome == AvailabilityReasonOutcome.Passed)).IsTrue();
        }
    }

    [Test]
    public async Task ExplicitMayConsumeReserveMakesEveryReserveCheckNotApplicable()
    {
        var policy = Policy(4, 2, 2, 1, domains: 3, reserve: Resources(long.MaxValue),
            reserveDisposition: ReserveDisposition.MayConsume);
        var decision = Evaluate(policy, Place("replica-d", "node-d", "fd-d", Resources(1), Resources(1)), HealthyThree());

        await Assert.That(ReserveReasons(decision).All(reason => reason.Outcome == AvailabilityReasonOutcome.NotApplicable)).IsTrue();
        await Assert.That(CapacityReasons(decision).All(reason => reason.Outcome == AvailabilityReasonOutcome.Passed)).IsTrue();
    }

    [Test]
    public async Task DuplicateAndConflictingObservationsHoldBeforePolicyArithmetic()
    {
        var exactDuplicate = HealthyThree().Append(HealthyThree()[0]).ToArray();
        var duplicateDecision = Evaluate(Policy(3, 2, 2, 1, domains: 2),
            new MaintainReplicaChange(new("replica-a")), exactDuplicate);
        var conflict = HealthyThree().Append(Observation("replica-a", "node-z", "fd-z")).ToArray();
        var conflictDecision = Evaluate(Policy(3, 2, 2, 1, domains: 2),
            new MaintainReplicaChange(new("replica-a")), conflict);

        await Assert.That(Reason(duplicateDecision, AvailabilityReasonCode.ReplicaObservationsUnique).Outcome)
            .IsEqualTo(AvailabilityReasonOutcome.Held);
        await Assert.That(Reason(duplicateDecision, AvailabilityReasonCode.ReplicaObservationsConsistent).Outcome)
            .IsEqualTo(AvailabilityReasonOutcome.Passed);
        await Assert.That(Reason(conflictDecision, AvailabilityReasonCode.ReplicaObservationsUnique).Outcome)
            .IsEqualTo(AvailabilityReasonOutcome.Held);
        await Assert.That(Reason(conflictDecision, AvailabilityReasonCode.ReplicaObservationsConsistent).Outcome)
            .IsEqualTo(AvailabilityReasonOutcome.Held);
        await Assert.That(Reason(conflictDecision, AvailabilityReasonCode.Quorum).Outcome).IsEqualTo(AvailabilityReasonOutcome.Held);
    }

    [Test]
    public async Task IncompleteSetMissingIdentitiesAndWrongServiceAllHold()
    {
        var missingIdentity = new[]
        {
            new ReplicaObservation(new("replica-a"), Service, null, new("fd-a"), ReplicaAvailabilityState.Available),
        };
        var missingDecision = Evaluate(Policy(1, 1, 1, 0, domains: 1),
            new MaintainReplicaChange(new("replica-a")), missingIdentity);
        var incomplete = new AvailabilityEvaluationRequest(
            Policy(3, 2, 2, 1, domains: 2), new MaintainReplicaChange(new("replica-a")),
            ObservationCompleteness.Incomplete,new AvailabilityGeneration(1),new AvailabilityGeneration(1), HealthyThree());
        var wrongService = new[]
        {
            new ReplicaObservation(new("replica-a"), new("other-service"), new("node-a"), new("fd-a"), ReplicaAvailabilityState.Available),
        };

        await Assert.That(Reason(missingDecision, AvailabilityReasonCode.ReplicaIdentitiesComplete).Outcome)
            .IsEqualTo(AvailabilityReasonOutcome.Held);
        await Assert.That(Reason(evaluator.Evaluate(incomplete), AvailabilityReasonCode.ObservationSetComplete).Outcome)
            .IsEqualTo(AvailabilityReasonOutcome.Held);
        await Assert.That(Reason(Evaluate(Policy(1, 1, 1, 0, domains: 1),
            new MaintainReplicaChange(new("replica-a")), wrongService), AvailabilityReasonCode.ServiceIdentityConsistent).Outcome)
            .IsEqualTo(AvailabilityReasonOutcome.Held);
    }

    [Test]
    public async Task ZeroMaximumAndOverflowCountBoundariesAreExact()
    {
        var zeroPolicy = Policy(0, 0, 0, 0, domains: 0, reserve: ResourceVector.Zero);
        var zeroPlacement = Evaluate(zeroPolicy,
            Place("replica-a", "node-a", "fd-a", ResourceVector.Zero, ResourceVector.Zero), []);
        var maximum = new AvailabilityCount(ulong.MaxValue);
        var maximumPolicy = Policy(
            ulong.MaxValue, ulong.MaxValue, ulong.MaxValue, ulong.MaxValue, domains: ulong.MaxValue,
            reserve: Resources(long.MaxValue));

        await Assert.That(Reason(zeroPlacement, AvailabilityReasonCode.DesiredCount).Outcome)
            .IsEqualTo(AvailabilityReasonOutcome.Rejected);
        await Assert.That(Throws<OverflowException>(() => maximum.AddChecked(new(1)))).IsTrue();
        await Assert.That(Throws<OverflowException>(() => new AvailabilityCount(0).SubtractChecked(new(1)))).IsTrue();
        await Assert.That(maximum.SubtractChecked(new(ulong.MaxValue)).Value).IsEqualTo(0UL);
        await Assert.That(maximumPolicy.Desired.Value).IsEqualTo(ulong.MaxValue);
        await Assert.That(maximumPolicy.RequiredDistinctFailureDomains.Value).IsEqualTo(ulong.MaxValue);
        await Assert.That(Throws<ArgumentException>(() => Policy(2, 3, 1, 1, domains: 1))).IsTrue();
    }

    [Test]
    public async Task DuplicatePlacementIdentityAndUnavailableMaintenanceTargetReject()
    {
        var duplicate = Evaluate(Policy(4, 2, 2, 1, domains: 2),
            Place("replica-a", "node-d", "fd-d", Resources(1), Resources(10)), HealthyThree());
        var observations = HealthyThree().ToArray();
        observations[0] = Observation("replica-a", "node-a", "fd-a", ReplicaAvailabilityState.Disrupting);
        var unavailableTarget = Evaluate(Policy(3, 1, 1, 2, domains: 1),
            new MaintainReplicaChange(new("replica-a")), observations);

        await Assert.That(Reason(duplicate, AvailabilityReasonCode.ChangeTargetValid).Outcome).IsEqualTo(AvailabilityReasonOutcome.Rejected);
        await Assert.That(Reason(unavailableTarget, AvailabilityReasonCode.ChangeTargetValid).Outcome).IsEqualTo(AvailabilityReasonOutcome.Rejected);
    }

    [Test]
    public async Task DecisionsAndTraceAreInvariantToAllObservationPermutationsAndCulture()
    {
        string? baseline = null;
        foreach (var permutation in Permutations(HealthyThree()))
        {
            foreach (var cultureName in new[] { "en-US", "tr-TR", "ar-SA" })
            {
                var original = CultureInfo.CurrentCulture;
                try
                {
                    CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(cultureName);
                    var decision = Evaluate(Policy(3, 2, 2, 1, domains: 2),
                        new MaintainReplicaChange(new("replica-a")), permutation);
                    var serialized = Serialize(decision);
                    baseline ??= serialized;
                    await Assert.That(serialized).IsEqualTo(baseline);
                }
                finally
                {
                    CultureInfo.CurrentCulture = original;
                }
            }
        }
    }

    [Test]
    public async Task RequestDefensivelyCopiesObservations()
    {
        var observations = HealthyThree().ToList();
        var request = new AvailabilityEvaluationRequest(
            Policy(3, 2, 2, 1, domains: 2), new MaintainReplicaChange(new("replica-a")),
            ObservationCompleteness.Complete,new AvailabilityGeneration(1),new AvailabilityGeneration(1), observations);
        observations.Clear();

        await Assert.That(request.Observations.Count).IsEqualTo(3);
        await Assert.That(evaluator.Evaluate(request).Admitted).IsTrue();
    }

    [Test]
    public async Task TraceIsClosedNumericAndCannotCarryCallerTextOrSecrets()
    {
        var traceType = typeof(AvailabilityReason);
        var forbidden = new[] { typeof(string), typeof(byte[]), typeof(char[]), typeof(Exception) };
        var decision = Evaluate(Policy(3, 2, 2, 1, domains: 2),
            new MaintainReplicaChange(new("replica-a")), HealthyThree());

        await Assert.That(traceType.GetProperties().Any(property => forbidden.Contains(property.PropertyType))).IsFalse();
        await Assert.That(traceType.GetConstructors().SelectMany(constructor => constructor.GetParameters())
            .Any(parameter => forbidden.Contains(parameter.ParameterType))).IsFalse();
        await Assert.That(Serialize(decision)).DoesNotContain("secret");
        await Assert.That(decision.Trace.Select(reason => reason.Code).SequenceEqual(Enum.GetValues<AvailabilityReasonCode>())).IsTrue();
    }

    [Test]
    public async Task UnknownEnumsAndNoncanonicalIdentitiesFailClosed()
    {
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => Policy(3, 2, 2, 1, domains: 2,
            criticality: (ServiceCriticality)0))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => Policy(3, 2, 2, 1, domains: 2,
            reserveDisposition: (ReserveDisposition)999))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() =>
            new ReplicaObservation(new("replica-a"), Service, new("node-a"), new("fd-a"), (ReplicaAvailabilityState)0))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => new AvailabilityEvaluationRequest(
            Policy(3, 2, 2, 1, domains: 2), new MaintainReplicaChange(new("replica-a")),
            (ObservationCompleteness)0, new(1), new(1), HealthyThree()))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => new ReplicaId("secret\nvalue"))).IsTrue();
    }

    private static ServiceId Service { get; } = new("control-service");

    private AvailabilityDecision Evaluate(
        ServiceAvailabilityPolicy policy,
        AvailabilityChange change,
        IEnumerable<ReplicaObservation> observations) => evaluator.Evaluate(new(
            policy, change, ObservationCompleteness.Complete,new AvailabilityGeneration(1),new AvailabilityGeneration(1), observations));

    private static ServiceAvailabilityPolicy Policy(
        ulong desired,
        ulong minimum,
        ulong quorum,
        ulong disruptions,
        ulong domains,
        bool onePerHost = true,
        ResourceVector? reserve = null,
        ReserveDisposition reserveDisposition = ReserveDisposition.Preserve,
        ServiceCriticality criticality = ServiceCriticality.Critical) => new(
        Service, new(desired), new(minimum), new(quorum), new(disruptions), criticality,
        onePerHost, new(domains), reserve ?? ResourceVector.Zero, reserveDisposition);

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

    private static PlaceReplicaChange Place(
        string replica,
        string node,
        string domain,
        ResourceVector requested,
        ResourceVector available) => new(new(replica), new(node), new(domain), requested, available);

    private static ResourceVector Resources(long value) => new(value, value, value, value, value, value, value, value);

    private static ResourceVector ResourceWithOneShortDimension(int index)
    {
        var values = Enumerable.Repeat(5L, 8).ToArray();
        values[index] = 4;
        return new(values[0], values[1], values[2], values[3], values[4], values[5], values[6], values[7]);
    }

    private static AvailabilityReason Reason(AvailabilityDecision decision, AvailabilityReasonCode code) =>
        decision.Trace.Single(reason => reason.Code == code);

    private static IEnumerable<AvailabilityReason> ReserveReasons(AvailabilityDecision decision) =>
        decision.Trace.Where(reason => ReserveCodes.Contains(reason.Code));

    private static IEnumerable<AvailabilityReason> CapacityReasons(AvailabilityDecision decision) =>
        decision.Trace.Where(reason => CapacityCodes.Contains(reason.Code));

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

    private static IEnumerable<ReplicaObservation[]> Permutations(ReplicaObservation[] values)
    {
        for (var first = 0; first < values.Length; first++)
        {
            for (var second = 0; second < values.Length; second++)
            {
                if (first == second)
                {
                    continue;
                }

                yield return [values[first], values[second], values[3 - first - second]];
            }
        }
    }

    private static string Serialize(AvailabilityDecision decision) =>
        $"{decision.Admitted}|{string.Join(';', decision.Trace.Select(reason => $"{reason.Code}:{reason.Outcome}:{reason.Observed}:{reason.Required}"))}";

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
}

