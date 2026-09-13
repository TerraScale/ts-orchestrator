using System.Collections;
using System.Reflection;

namespace TerraScale.Orchestrator.Scheduler.Tests.Properties;

public sealed class SchedulerDecisionSurfaceTests
{
    private readonly DeterministicScheduler scheduler=new();

    [Test]
    public async Task Empty_candidate_set_is_canonical_closed_and_unschedulable()
    {
        var property=SchedulerPropertyGenerator.Valid(100_001);var result=scheduler.Schedule(property.Workload,[],property.Policy);
        await Assert.That(result).IsTypeOf<Unschedulable>();await Assert.That(result.Candidates).IsEmpty();
    }

    [Test]
    public async Task Candidate_snapshot_accepts_exact_maximum_and_preserves_canonical_order()
    {
        var property=SchedulerPropertyGenerator.Valid(100_002);var candidates=Candidates(property,SchedulerTechnicalInputLimits.MaximumCandidateCount).Reverse();
        var result=(PlacementSelected)scheduler.Schedule(property.Workload,candidates,property.Policy);
        await Assert.That(result.Candidates.Count).IsEqualTo(SchedulerTechnicalInputLimits.MaximumCandidateCount);
        await Assert.That(result.SelectedCandidateId).IsEqualTo("bounded-0000");
        await Assert.That(result.Candidates.Select(candidate=>candidate.CandidateId).SequenceEqual(result.Candidates.Select(candidate=>candidate.CandidateId).Order(StringComparer.Ordinal))).IsTrue();
    }

    [Test]
    public async Task Candidate_snapshot_rejects_maximum_plus_one_and_infinite_sources_without_partial_scheduling()
    {
        var property=SchedulerPropertyGenerator.Valid(100_003);var oversized=Capture(()=>scheduler.Schedule(property.Workload,Candidates(property,SchedulerTechnicalInputLimits.MaximumCandidateCount+1),property.Policy));
        var infinite=Capture(()=>scheduler.Schedule(property.Workload,Infinite(property),property.Policy));
        await Assert.That(oversized).IsTypeOf<ArgumentException>();await Assert.That(infinite).IsTypeOf<ArgumentException>();
        await Assert.That(oversized!.Message).DoesNotContain("bounded-4096");await Assert.That(infinite!.Message).DoesNotContain("infinite");
    }

    [Test]
    public async Task Maximum_plus_one_is_rejected_before_reading_the_extra_current_value()
    {
        var property=SchedulerPropertyGenerator.Valid(100_008);var source=new ExtraCurrentTrapCandidates(property);
        var failure=Capture(()=>scheduler.Schedule(property.Workload,source,property.Policy));
        await Assert.That(failure).IsTypeOf<ArgumentException>();await Assert.That(source.ExtraCurrentRead).IsFalse();
    }

    [Test]
    public async Task Candidate_snapshot_translates_enumerator_and_dispose_failures_without_exception_text()
    {
        var property=SchedulerPropertyGenerator.Valid(100_004);var secret="iterator-secret-detail";
        foreach(var mode in Enum.GetValues<ThrowMode>())
        {
            var failure=Capture(()=>scheduler.Schedule(property.Workload,new ThrowingCandidates(Candidates(property,3).ToArray(),mode,secret),property.Policy));
            await Assert.That(failure).IsTypeOf<ArgumentException>();await Assert.That(failure!.Message).DoesNotContain(secret);
        }
        await Assert.That(Capture(()=>scheduler.Schedule(property.Workload,new FatalCandidates(),property.Policy))).IsTypeOf<OutOfMemoryException>();
    }

    [Test]
    public async Task Snapshot_is_defensive_and_returned_trace_collections_are_read_only()
    {
        var property=SchedulerPropertyGenerator.Valid(100_005);var source=Candidates(property,2).ToList();
        var result=scheduler.Schedule(property.Workload,new ClearingCandidates(source),property.Policy);
        await Assert.That(source).IsEmpty();await Assert.That(result.Candidates.Count).IsEqualTo(2);
        var collection=(IList)result.Candidates;var mutation=Capture(()=>collection.Add(result.Candidates[0]));
        var reasons=(IList)result.Candidates[0].Reasons;var reasonMutation=Capture(()=>reasons.Add(result.Candidates[0].Reasons[0]));
        await Assert.That(mutation).IsTypeOf<NotSupportedException>();await Assert.That(reasonMutation).IsTypeOf<NotSupportedException>();
    }

    [Test]
    public async Task Public_schedule_results_are_non_authorizing_dtos_with_closed_observed_enums()
    {
        var property=SchedulerPropertyGenerator.Valid(100_006);var result=scheduler.Schedule(property.Workload,property.Candidates,property.Policy);
        await Assert.That(result.Candidates.SelectMany(candidate=>candidate.Reasons).All(reason=>Enum.IsDefined(reason.Check)&&Enum.IsDefined(reason.Outcome))).IsTrue();
        await Assert.That(typeof(ScheduleResult).GetProperty("IsAuthorized",BindingFlags.Instance|BindingFlags.Public) is null).IsTrue();
        await Assert.That(typeof(PlacementSelected).GetConstructors(BindingFlags.Instance|BindingFlags.Public)).IsNotEmpty();
        await Assert.That(typeof(Unschedulable).GetConstructors(BindingFlags.Instance|BindingFlags.Public)).IsNotEmpty();
    }

    [Test]
    public async Task Nested_scheduler_enumerable_validators_apply_named_technical_bounds()
    {
        var property=SchedulerPropertyGenerator.Valid(100_007);var exactPorts=Enumerable.Range(1,SchedulerTechnicalInputLimits.MaximumPortCount).ToArray();
        var exactFacts=Enumerable.Range(0,SchedulerTechnicalInputLimits.MaximumFactCount).Select(index=>$"fact-{index}").ToArray();
        var exactLabels=Enumerable.Range(0,SchedulerTechnicalInputLimits.MaximumLabelCount).ToDictionary(index=>$"key-{index}",index=>$"value-{index}");
        var node=new NodeCandidate("bounded-node","compute","linux-amd64","fd-a",property.Workload.Resources,exactPorts,exactLabels,exactFacts);
        await Assert.That(node.OccupiedPorts.Count).IsEqualTo(SchedulerTechnicalInputLimits.MaximumPortCount);
        await Assert.That(node.TrustZones.Count).IsEqualTo(SchedulerTechnicalInputLimits.MaximumFactCount);
        await Assert.That(node.Labels.Count).IsEqualTo(SchedulerTechnicalInputLimits.MaximumLabelCount);
        await Assert.That(Capture(()=>new NodeCandidate("node","compute","linux-amd64","fd-a",property.Workload.Resources,
            Enumerable.Range(1,SchedulerTechnicalInputLimits.MaximumPortCount+1)))).IsTypeOf<ArgumentException>();
        await Assert.That(Capture(()=>new WorkloadRequest("workload","linux-amd64",property.Workload.Resources,
            requiredTrustZones:InfiniteStrings()))).IsTypeOf<ArgumentException>();
        await Assert.That(Capture(()=>new LeastWastePolicy(InfiniteScoreDimensions()))).IsTypeOf<ArgumentException>();
        var tooManyLabels=Enumerable.Range(0,SchedulerTechnicalInputLimits.MaximumLabelCount+1).ToDictionary(index=>$"key-{index}",index=>$"value-{index}");
        await Assert.That(Capture(()=>new WorkloadRequest("workload","linux-amd64",property.Workload.Resources,requiredLabels:tooManyLabels))).IsTypeOf<ArgumentException>();
    }

    private static IEnumerable<NodeCandidate> Candidates(SchedulerPropertyCase property,int count)=>Enumerable.Range(0,count).Select(index=>new NodeCandidate(
        $"bounded-{index:D4}","compute","linux-amd64","fd-a",SchedulerPropertyGenerator.Add(property.Workload.Resources,10),[],new Dictionary<string,string>{{"region","gru"}},
        ["trusted"],["product"],["runtime"],["service"],new(0,10_000)));
    private static IEnumerable<NodeCandidate> Infinite(SchedulerPropertyCase property)
    {var index=0;while(true)yield return new($"infinite-{index++:D8}","compute","linux-amd64","fd-a",SchedulerPropertyGenerator.Add(property.Workload.Resources,10));}
    private static IEnumerable<string> InfiniteStrings(){var index=0;while(true)yield return $"fact-{index++}";}
    private static IEnumerable<ScoreDimension> InfiniteScoreDimensions(){var index=0;var dimensions=Enum.GetValues<ResourceDimension>();while(true)yield return new(dimensions[index++%dimensions.Length],1);}
    private static Exception? Capture(Action action){try{action();return null;}catch(Exception exception){return exception;}}

    private enum ThrowMode{GetEnumerator,MoveNextBeforeValue,MoveNextAfterValue,Current,Dispose}
    private sealed class ThrowingCandidates(NodeCandidate[] values,ThrowMode mode,string detail):IEnumerable<NodeCandidate>
    {
        public IEnumerator<NodeCandidate> GetEnumerator()=>mode==ThrowMode.GetEnumerator?throw new InvalidOperationException(detail):new Enumerator(values,mode,detail);
        IEnumerator IEnumerable.GetEnumerator()=>GetEnumerator();
        private sealed class Enumerator(NodeCandidate[] values,ThrowMode mode,string detail):IEnumerator<NodeCandidate>
        {
            private int index=-1;
            public NodeCandidate Current=>mode==ThrowMode.Current?throw new InvalidOperationException(detail):values[index];object IEnumerator.Current=>Current;
            public bool MoveNext(){if(mode==ThrowMode.MoveNextBeforeValue&&index<0)throw new InvalidOperationException(detail);if(mode==ThrowMode.MoveNextAfterValue&&index==0)throw new InvalidOperationException(detail);index++;return index<values.Length;}
            public void Reset()=>throw new NotSupportedException();public void Dispose(){if(mode==ThrowMode.Dispose)throw new InvalidOperationException(detail);}
        }
    }
    private sealed class ClearingCandidates(List<NodeCandidate> values):IEnumerable<NodeCandidate>
    {
        public IEnumerator<NodeCandidate> GetEnumerator()=>new Enumerator(values);IEnumerator IEnumerable.GetEnumerator()=>GetEnumerator();
        private sealed class Enumerator(List<NodeCandidate> values):IEnumerator<NodeCandidate>
        {
            private readonly IEnumerator<NodeCandidate> inner=values.GetEnumerator();public NodeCandidate Current=>inner.Current;object IEnumerator.Current=>Current;
            public bool MoveNext()=>inner.MoveNext();public void Reset()=>inner.Reset();public void Dispose(){inner.Dispose();values.Clear();}
        }
    }
    private sealed class ExtraCurrentTrapCandidates(SchedulerPropertyCase property):IEnumerable<NodeCandidate>
    {
        internal bool ExtraCurrentRead{get;private set;}
        public IEnumerator<NodeCandidate> GetEnumerator()=>new Enumerator(this,property);IEnumerator IEnumerable.GetEnumerator()=>GetEnumerator();
        private sealed class Enumerator(ExtraCurrentTrapCandidates owner,SchedulerPropertyCase property):IEnumerator<NodeCandidate>
        {
            private int index=-1;
            public NodeCandidate Current
            {
                get
                {
                    if(index==SchedulerTechnicalInputLimits.MaximumCandidateCount){owner.ExtraCurrentRead=true;throw new InvalidOperationException("extra-current-must-not-be-read");}
                    return new($"trap-{index:D4}","compute","linux-amd64","fd-a",SchedulerPropertyGenerator.Add(property.Workload.Resources,10));
                }
            }
            object IEnumerator.Current=>Current;public bool MoveNext(){index++;return index<=SchedulerTechnicalInputLimits.MaximumCandidateCount;}
            public void Reset()=>throw new NotSupportedException();public void Dispose(){}
        }
    }
    private sealed class FatalCandidates:IEnumerable<NodeCandidate>
    {
        public IEnumerator<NodeCandidate> GetEnumerator()=>new Enumerator();IEnumerator IEnumerable.GetEnumerator()=>GetEnumerator();
        private sealed class Enumerator:IEnumerator<NodeCandidate>
        {
            private bool moved;public NodeCandidate Current=>throw new OutOfMemoryException("fatal-runtime-failure");object IEnumerator.Current=>Current;
            public bool MoveNext(){if(moved)return false;moved=true;return true;}public void Reset()=>throw new NotSupportedException();public void Dispose(){}
        }
    }
}

