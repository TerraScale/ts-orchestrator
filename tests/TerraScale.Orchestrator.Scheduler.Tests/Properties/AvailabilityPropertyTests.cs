using System.Globalization;
using System.Collections;
using System.Reflection;
using TerraScale.Orchestrator.Scheduler.Availability;

namespace TerraScale.Orchestrator.Scheduler.Tests.Properties;

public sealed class AvailabilityPropertyTests
{
    private readonly AvailabilityPolicyEvaluator evaluator=new();

    [Test]
    public async Task Maintenance_preserves_minimum_quorum_disruption_and_topology_floors_across_one_thousand_seeds()
    {
        for(ulong seed=40_001;seed<40_001+PropertyLimits.FeatureCases;seed++)
        {
            var property=AvailabilityPropertyGenerator.Maintenance(seed);var admitted=Evaluate(property.Policy,property.Maintenance,property.Observations);
            await Assert.That(admitted.Admitted).IsTrue();
            var count=(ulong)property.Observations.Length;
            var minimum=Evaluate(AvailabilityPropertyGenerator.Policy(count,count,count-1,1,count-1,true,ResourceVector.Zero),property.Maintenance,property.Observations);
            var quorum=Evaluate(AvailabilityPropertyGenerator.Policy(count,count-1,count,1,count-1,true,ResourceVector.Zero),property.Maintenance,property.Observations);
            var disruption=Evaluate(AvailabilityPropertyGenerator.Policy(count,count-1,count-1,0,count-1,true,ResourceVector.Zero),property.Maintenance,property.Observations);
            var topology=Evaluate(AvailabilityPropertyGenerator.Policy(count,count-1,count-1,1,count,true,ResourceVector.Zero),property.Maintenance,property.Observations);
            await Rejected(minimum,AvailabilityReasonCode.MinimumAvailable);await Rejected(quorum,AvailabilityReasonCode.Quorum);
            await Rejected(disruption,AvailabilityReasonCode.DisruptionBudget);await Rejected(topology,AvailabilityReasonCode.FailureDomainSpread);
        }
    }

    [Test]
    public async Task Availability_decisions_are_deterministic_permutation_and_culture_invariant()
    {
        for(ulong seed=50_001;seed<50_001+PropertyLimits.FeatureCases;seed++)
        {
            var property=AvailabilityPropertyGenerator.Maintenance(seed);var baseline=PropertySerialization.Availability(Evaluate(property.Policy,property.Maintenance,property.Observations));
            foreach(var observations in new[]{property.Observations.Reverse().ToArray(),property.Observations.Skip(1).Append(property.Observations[0]).ToArray()})
            foreach(var cultureName in new[]{"tr-TR","ar-SA"})
            {
                var original=CultureInfo.CurrentCulture;try{CultureInfo.CurrentCulture=CultureInfo.GetCultureInfo(cultureName);
                    await Assert.That(PropertySerialization.Availability(Evaluate(property.Policy,property.Maintenance,observations))).IsEqualTo(baseline);}
                finally{CultureInfo.CurrentCulture=original;}
            }
        }
    }

    [Test]
    public async Task Placement_enforces_one_per_host_and_exact_reserve_conservation_in_every_dimension()
    {
        var reserveCodes=ReserveCodes;
        for(ulong seed=60_001;seed<60_001+PropertyLimits.FeatureCases;seed++)
        {
            var property=AvailabilityPropertyGenerator.Maintenance(seed);var count=(ulong)property.Observations.Length;var amount=(long)(seed%20+1);
            var requested=Resources(amount);var reserve=Resources(amount+1);var available=SchedulerPropertyGenerator.Add(requested,amount+1);
            var policy=AvailabilityPropertyGenerator.Policy(count+1,count,count,1,count+1,true,reserve);
            var colocated=new PlaceReplicaChange(new($"replica-{count}"),new("node-0"),new($"fd-{count}"),requested,available);
            await Rejected(Evaluate(policy,colocated,property.Observations),AvailabilityReasonCode.OnePerHost);
            var exact=new PlaceReplicaChange(new($"replica-{count}"),new($"node-{count}"),new($"fd-{count}"),requested,available);
            await Assert.That(Evaluate(policy,exact,property.Observations).Admitted).IsTrue();
            var dimension=(int)(seed%8);var shortAvailable=SchedulerPropertyGenerator.WithOneDimension(available,dimension,-1);
            var shortPlacement=new PlaceReplicaChange(new($"replica-{count}"),new($"node-{count}"),new($"fd-{count}"),requested,shortAvailable);
            var shortDecision=Evaluate(policy,shortPlacement,property.Observations);await Rejected(shortDecision,reserveCodes[dimension]);
            await Assert.That(shortDecision.Trace.Where(reason=>ReserveCodes.Contains(reason.Code)&&reason.Code!=reserveCodes[dimension])
                .All(reason=>reason.Outcome==AvailabilityReasonOutcome.Passed)).IsTrue();
        }
    }

    [Test]
    public async Task Incomplete_duplicate_and_conflicting_observation_evidence_holds_before_policy_arithmetic()
    {
        for(ulong seed=70_001;seed<70_001+PropertyLimits.FeatureCases;seed++)
        {
            var property=AvailabilityPropertyGenerator.Maintenance(seed);AvailabilityEvaluationRequest request;
            switch(seed%3)
            {
                case 0:request=new(property.Policy,property.Maintenance,ObservationCompleteness.Incomplete,property.Observations);break;
                case 1:request=new(property.Policy,property.Maintenance,ObservationCompleteness.Complete,property.Observations.Append(property.Observations[0]));break;
                default:
                    var conflict=new ReplicaObservation(property.Observations[0].ReplicaId,property.Observations[0].ServiceId,new("node-conflict"),new("fd-conflict"),ReplicaAvailabilityState.Available);
                    request=new(property.Policy,property.Maintenance,ObservationCompleteness.Complete,property.Observations.Append(conflict));break;
            }
            var decision=evaluator.Evaluate(request);await Assert.That(decision.Admitted).IsFalse();
            await Assert.That(decision.Trace.Take(5).Any(reason=>reason.Outcome==AvailabilityReasonOutcome.Held)).IsTrue();
            await Assert.That(decision.Trace.Skip(5).All(reason=>reason.Outcome is AvailabilityReasonOutcome.Held or AvailabilityReasonOutcome.NotApplicable)).IsTrue();
        }
    }

    [Test]
    public async Task Randomized_invalid_inputs_reject_all_constructor_validation_families()
    {
        var hits=Enum.GetValues<AvailabilityValidatorFamily>().ToDictionary(value=>value,_=>0);
        for(ulong seed=80_001;seed<80_001+PropertyLimits.FeatureCases;seed++)
        {
            var invalid=AvailabilityPropertyGenerator.InvalidValidator(seed);hits[invalid.Family]++;await Assert.That(invalid.Rejected).IsTrue();
        }
        await Assert.That(hits.Values.All(count=>count>=70)).IsTrue();
    }

    [Test]
    public async Task Checked_availability_counts_round_trip_without_creation_or_loss()
    {
        for(ulong seed=85_001;seed<85_001+PropertyLimits.FeatureCases;seed++)
        {
            var left=new AvailabilityCount(seed);var right=new AvailabilityCount(seed%1_000);var total=left.AddChecked(right);
            await Assert.That(total.SubtractChecked(right)).IsEqualTo(left);
        }
    }

    [Test]
    public async Task Availability_outputs_are_construction_closed_and_observable_values_are_closed()
    {
        await Assert.That(typeof(AvailabilityDecision).GetConstructors(BindingFlags.Instance|BindingFlags.Public)).IsEmpty();
        await Assert.That(typeof(AvailabilityReason).GetConstructors(BindingFlags.Instance|BindingFlags.Public)).IsEmpty();
        var property=AvailabilityPropertyGenerator.Maintenance(90_001);var decision=Evaluate(property.Policy,property.Maintenance,property.Observations);
        await Assert.That(decision.Trace.All(reason=>Enum.IsDefined(reason.Code)&&Enum.IsDefined(reason.Outcome))).IsTrue();
        await Assert.That(typeof(AvailabilityDecision).GetProperties().All(propertyInfo=>propertyInfo.SetMethod is null)).IsTrue();
    }

    [Test]
    public async Task Observation_snapshot_accepts_exact_maximum_and_preserves_canonical_evaluation_order()
    {
        var observations=ManyObservations(SchedulerTechnicalInputLimits.MaximumAvailabilityObservationCount);var policy=AvailabilityPropertyGenerator.Policy(
            (ulong)observations.Length,0,0,(ulong)observations.Length,0,false,ResourceVector.Zero);var change=new MaintainReplicaChange(new("replica-0"));
        var forward=evaluator.Evaluate(new(policy,change,ObservationCompleteness.Complete,observations));
        var reverse=evaluator.Evaluate(new(policy,change,ObservationCompleteness.Complete,observations.Reverse()));
        await Assert.That(forward.Admitted).IsTrue();await Assert.That(PropertySerialization.Availability(reverse)).IsEqualTo(PropertySerialization.Availability(forward));
    }

    [Test]
    public async Task Observation_snapshot_rejects_maximum_plus_one_infinite_and_hostile_iterators_secret_safely()
    {
        var policy=AvailabilityPropertyGenerator.Policy(1,0,0,1,0,false,ResourceVector.Zero);var change=new MaintainReplicaChange(new("replica-0"));
        var oversized=Capture(()=>new AvailabilityEvaluationRequest(policy,change,ObservationCompleteness.Complete,ManyObservations(SchedulerTechnicalInputLimits.MaximumAvailabilityObservationCount+1)));
        var infinite=Capture(()=>new AvailabilityEvaluationRequest(policy,change,ObservationCompleteness.Complete,InfiniteObservations()));
        await Assert.That(oversized).IsTypeOf<ArgumentException>();await Assert.That(infinite).IsTypeOf<ArgumentException>();
        const string secret="observation-iterator-secret";var values=ManyObservations(3);
        foreach(var mode in Enum.GetValues<ObservationThrowMode>())
        {
            var failure=Capture(()=>new AvailabilityEvaluationRequest(policy,change,ObservationCompleteness.Complete,new ThrowingObservations(values,mode,secret)));
            await Assert.That(failure).IsTypeOf<ArgumentException>();await Assert.That(failure!.Message).DoesNotContain(secret);
        }
    }

    [Test]
    public async Task Observation_snapshot_is_defensive_against_source_mutation_on_dispose()
    {
        var values=ManyObservations(3).ToList();var policy=AvailabilityPropertyGenerator.Policy(3,0,0,3,0,false,ResourceVector.Zero);
        var request=new AvailabilityEvaluationRequest(policy,new MaintainReplicaChange(new("replica-0")),ObservationCompleteness.Complete,new ClearingObservations(values));
        await Assert.That(values).IsEmpty();await Assert.That(request.Observations.Count).IsEqualTo(3);await Assert.That(evaluator.Evaluate(request).Admitted).IsTrue();
    }

    private AvailabilityDecision Evaluate(ServiceAvailabilityPolicy policy,AvailabilityChange change,IEnumerable<ReplicaObservation> observations)=>
        evaluator.Evaluate(new(policy,change,ObservationCompleteness.Complete,observations));
    private static async Task Rejected(AvailabilityDecision decision,AvailabilityReasonCode code)=>
        await Assert.That(decision.Trace.Single(reason=>reason.Code==code).Outcome).IsEqualTo(AvailabilityReasonOutcome.Rejected);
    private static AvailabilityReasonCode[] ReserveCodes { get; }=
    [
        AvailabilityReasonCode.ReserveCpu,AvailabilityReasonCode.ReserveMemory,AvailabilityReasonCode.ReserveBlockIo,
        AvailabilityReasonCode.ReserveEphemeralDisk,AvailabilityReasonCode.ReserveBandwidth,AvailabilityReasonCode.ReservePids,
        AvailabilityReasonCode.ReserveFileDescriptors,AvailabilityReasonCode.ReserveHugePages,
    ];
    private static ResourceVector Resources(long value)=>new(value,value,value,value,value,value,value,value);
    private static ReplicaObservation[] ManyObservations(int count)=>Enumerable.Range(0,count).Select(index=>new ReplicaObservation(new($"replica-{index}"),
        AvailabilityPropertyGenerator.Service,new($"node-{index}"),new($"fd-{index}"),ReplicaAvailabilityState.Available)).ToArray();
    private static IEnumerable<ReplicaObservation> InfiniteObservations(){var index=0;while(true)yield return new(new($"replica-{index}"),AvailabilityPropertyGenerator.Service,new($"node-{index}"),new($"fd-{index++}"),ReplicaAvailabilityState.Available);}
    private static Exception? Capture(Action action){try{action();return null;}catch(Exception exception){return exception;}}
    private enum ObservationThrowMode{GetEnumerator,MoveNextBeforeValue,MoveNextAfterValue,Current,Dispose}
    private sealed class ThrowingObservations(ReplicaObservation[] values,ObservationThrowMode mode,string detail):IEnumerable<ReplicaObservation>
    {
        public IEnumerator<ReplicaObservation> GetEnumerator()=>mode==ObservationThrowMode.GetEnumerator?throw new InvalidOperationException(detail):new Enumerator(values,mode,detail);
        IEnumerator IEnumerable.GetEnumerator()=>GetEnumerator();
        private sealed class Enumerator(ReplicaObservation[] values,ObservationThrowMode mode,string detail):IEnumerator<ReplicaObservation>
        {
            private int index=-1;public ReplicaObservation Current=>mode==ObservationThrowMode.Current?throw new InvalidOperationException(detail):values[index];object IEnumerator.Current=>Current;
            public bool MoveNext(){if(mode==ObservationThrowMode.MoveNextBeforeValue&&index<0)throw new InvalidOperationException(detail);if(mode==ObservationThrowMode.MoveNextAfterValue&&index==0)throw new InvalidOperationException(detail);index++;return index<values.Length;}
            public void Reset()=>throw new NotSupportedException();public void Dispose(){if(mode==ObservationThrowMode.Dispose)throw new InvalidOperationException(detail);}
        }
    }
    private sealed class ClearingObservations(List<ReplicaObservation> values):IEnumerable<ReplicaObservation>
    {
        public IEnumerator<ReplicaObservation> GetEnumerator()=>new Enumerator(values);IEnumerator IEnumerable.GetEnumerator()=>GetEnumerator();
        private sealed class Enumerator(List<ReplicaObservation> values):IEnumerator<ReplicaObservation>
        {
            private readonly IEnumerator<ReplicaObservation> inner=values.GetEnumerator();public ReplicaObservation Current=>inner.Current;object IEnumerator.Current=>Current;
            public bool MoveNext()=>inner.MoveNext();public void Reset()=>inner.Reset();public void Dispose(){inner.Dispose();values.Clear();}
        }
    }
}
