using System.Globalization;
using System.Numerics;
using TerraScale.Orchestrator.Scheduler.Availability;

namespace TerraScale.Orchestrator.Scheduler.Tests.Properties;

internal static class PropertyLimits
{
    internal const int FeatureCases=1_000;
}

internal struct DeterministicSequence
{
    private ulong state;
    internal DeterministicSequence(ulong seed)=>state=seed;
    internal ulong Next()
    {
        state+=0x9E3779B97F4A7C15UL;var value=state;
        value=(value^(value>>30))*0xBF58476D1CE4E5B9UL;value=(value^(value>>27))*0x94D049BB133111EBUL;
        return value^(value>>31);
    }
    internal int Int(int minimumInclusive,int maximumExclusive)=>minimumInclusive+(int)(Next()%(uint)(maximumExclusive-minimumInclusive));
    internal long Long(long minimumInclusive,long maximumExclusive)=>minimumInclusive+(long)(Next()%(ulong)(maximumExclusive-minimumInclusive));
}

internal enum SchedulerViolation{Architecture,NodeClass,Labels,TrustZone,NetworkZone,SecretZone,FailureDomain,Affinity,AntiAffinity,Port,SafetyCap,Veto,Capacity}
internal enum SchedulerValidatorFamily{NegativeResource,AdditionOverflow,SubtractionUnderflow,UnknownVeto,NegativeSafetyCap,NegativeScoreWeight,DuplicateScoreDimension,
    ZeroScorePolicy,NodeIdentity,NodePorts,NodeFacts,NodeLabels,WorkloadIdentity,WorkloadPorts,WorkloadFacts,DuplicateCandidate,NullCandidate,UnknownScoreDimension,WorkloadLabels,NullScheduleInput}
internal enum AvailabilityValidatorFamily{CountOverflow,CountUnderflow,Identity,PolicyNull,PolicyRelation,PolicyEnum,ObservationNull,ObservationEnum,ChangeNull,
    RequestPolicyNull,RequestChangeNull,RequestEnum,RequestObservationNull,EvaluatorNull}
internal sealed record SchedulerPropertyCase(ulong Seed,WorkloadRequest Workload,NodeCandidate[] Candidates,LeastWastePolicy Policy);

internal static class SchedulerPropertyGenerator
{
    internal static SchedulerPropertyCase Valid(ulong seed)
    {
        var sequence=new DeterministicSequence(seed);var requested=Vector(ref sequence,1,40);
        var policy=Policy(ref sequence);var candidates=Enumerable.Range(0,sequence.Int(2,6)).Select(index=>Candidate($"node-{index:D2}",index,requested,ref sequence)).ToArray();
        var workload=new WorkloadRequest($"workload-{seed}","linux-amd64",requested,[8080],"compute",new Dictionary<string,string>{{"region","gru"}},
            ["trusted"],["product"],["runtime"],["fd-a","fd-b","fd-c"],["service"],["noisy"]);
        return new(seed,workload,candidates,policy);
    }

    internal static (SchedulerPropertyCase Case,SchedulerViolation Violation,PlacementCheck Check) Invalid(ulong seed)
    {
        var valid=Valid(seed);var sequence=new DeterministicSequence(seed^0xD1B54A32D192ED03UL);
        var violation=(SchedulerViolation)sequence.Int(0,Enum.GetValues<SchedulerViolation>().Length);
        var candidate=InvalidCandidate("invalid",valid.Workload.Resources,violation,(int)(seed%8));
        return (new(seed,valid.Workload,[candidate],valid.Policy),violation,ToCheck(violation,seed));
    }
    internal static (SchedulerPropertyCase Case,PlacementCheck Check) CapacityInvalid(ulong seed)
    {
        var valid=Valid(seed);var dimension=(int)(seed%8);var candidate=InvalidCandidate("invalid",valid.Workload.Resources,SchedulerViolation.Capacity,dimension);
        return(new(seed,valid.Workload,[candidate],valid.Policy),(PlacementCheck)((int)PlacementCheck.Cpu+dimension));
    }

    internal static NodeCandidate Vetoed(WorkloadRequest workload,CandidateVetoCode code)=>new("vetoed","compute","linux-amd64","fd-a",Add(workload.Resources,20),[],
        new Dictionary<string,string>{{"region","gru"}},["trusted"],["product"],["runtime"],["service"],new(0,100),new(code));
    internal static NodeCandidate[] TiedCandidates(WorkloadRequest workload)=>
    [CandidateWithAvailable("node-z",Add(workload.Resources,10)),CandidateWithAvailable("node-a",Add(workload.Resources,10))];

    internal static (SchedulerValidatorFamily Family,bool Rejected) InvalidValidator(ulong seed)
    {
        var familyCount=(ulong)Enum.GetValues<SchedulerValidatorFamily>().Length;var family=(SchedulerValidatorFamily)(seed%familyCount);var variant=seed/familyCount;
        var property=Valid(seed);var dimensions=Enum.GetValues<ResourceDimension>();
        bool Throws(Func<object?> action){try{_=action();return false;}catch(ArgumentException){return true;}catch(OverflowException){return true;}}
        var rejected=family switch
        {
            SchedulerValidatorFamily.NegativeResource=>Throws(()=>WithOneDimension(ResourceVector.Zero,(int)(variant%8),-1)),
            SchedulerValidatorFamily.AdditionOverflow=>Throws(()=>new ResourceVector(long.MaxValue,0,0,0,0,0,0,0).AddChecked(new(1,0,0,0,0,0,0,0))),
            SchedulerValidatorFamily.SubtractionUnderflow=>Throws(()=>ResourceVector.Zero.SubtractChecked(new(1,0,0,0,0,0,0,0))),
            SchedulerValidatorFamily.UnknownVeto=>Throws(()=>new CandidateVeto((CandidateVetoCode)99)),
            SchedulerValidatorFamily.NegativeSafetyCap=>Throws(()=>variant%2==0?new AllocationSafetyCap(-1,1):new AllocationSafetyCap(0,-1)),
            SchedulerValidatorFamily.NegativeScoreWeight=>Throws(()=>new ScoreDimension(ResourceDimension.Cpu,-1)),
            SchedulerValidatorFamily.DuplicateScoreDimension=>Throws(()=>new LeastWastePolicy(dimensions.Select(dimension=>new ScoreDimension(ResourceDimension.Cpu,1)))),
            SchedulerValidatorFamily.ZeroScorePolicy=>Throws(()=>new LeastWastePolicy(dimensions.Select(dimension=>new ScoreDimension(dimension,0)))),
            SchedulerValidatorFamily.NodeIdentity=>Throws(()=>(variant%4) switch{0=>new NodeCandidate(" ","compute","linux-amd64","fd-a",property.Workload.Resources),
                1=>new NodeCandidate("node"," ","linux-amd64","fd-a",property.Workload.Resources),2=>new NodeCandidate("node","compute"," ","fd-a",property.Workload.Resources),
                _=>new NodeCandidate("node","compute","linux-amd64"," ",property.Workload.Resources)}),
            SchedulerValidatorFamily.NodePorts=>Throws(()=>new NodeCandidate("node","compute","linux-amd64","fd-a",property.Workload.Resources,variant%2==0?[80,80]:[0])),
            SchedulerValidatorFamily.NodeFacts=>Throws(()=>(variant%4) switch{0=>new NodeCandidate("node","compute","linux-amd64","fd-a",property.Workload.Resources,trustZones:["zone","zone"]),
                1=>new NodeCandidate("node","compute","linux-amd64","fd-a",property.Workload.Resources,networkZones:[""]),2=>new NodeCandidate("node","compute","linux-amd64","fd-a",property.Workload.Resources,secretZones:["zone","zone"]),
                _=>new NodeCandidate("node","compute","linux-amd64","fd-a",property.Workload.Resources,affinityFacts:[""])}),
            SchedulerValidatorFamily.NodeLabels=>Throws(()=>new NodeCandidate("node","compute","linux-amd64","fd-a",property.Workload.Resources,labels:new Dictionary<string,string>{{"","value"}})),
            SchedulerValidatorFamily.WorkloadIdentity=>Throws(()=>(variant%3) switch{0=>new WorkloadRequest(" ","linux-amd64",property.Workload.Resources),
                1=>new WorkloadRequest("workload"," ",property.Workload.Resources),_=>new WorkloadRequest("workload","linux-amd64",property.Workload.Resources,requiredNodeClass:"")}),
            SchedulerValidatorFamily.WorkloadPorts=>Throws(()=>new WorkloadRequest("workload","linux-amd64",property.Workload.Resources,variant%2==0?[65_536]:[80,80])),
            SchedulerValidatorFamily.WorkloadFacts=>Throws(()=>(variant%6) switch{0=>new WorkloadRequest("workload","linux-amd64",property.Workload.Resources,requiredTrustZones:["zone","zone"]),
                1=>new WorkloadRequest("workload","linux-amd64",property.Workload.Resources,requiredNetworkZones:[""]),2=>new WorkloadRequest("workload","linux-amd64",property.Workload.Resources,requiredSecretZones:["zone","zone"]),
                3=>new WorkloadRequest("workload","linux-amd64",property.Workload.Resources,allowedFailureDomains:[""]),4=>new WorkloadRequest("workload","linux-amd64",property.Workload.Resources,requiredAffinityFacts:["a","a"]),
                _=>new WorkloadRequest("workload","linux-amd64",property.Workload.Resources,prohibitedAffinityFacts:[""])}),
            SchedulerValidatorFamily.DuplicateCandidate=>Throws(()=>new DeterministicScheduler().Schedule(property.Workload,[property.Candidates[0],property.Candidates[0]],property.Policy)),
            SchedulerValidatorFamily.NullCandidate=>Throws(()=>new DeterministicScheduler().Schedule(property.Workload,[null!],property.Policy)),
            SchedulerValidatorFamily.UnknownScoreDimension=>Throws(()=>new LeastWastePolicy(dimensions.Skip(1).Select(dimension=>new ScoreDimension(dimension,1)).Append(new((ResourceDimension)99,1)))),
            SchedulerValidatorFamily.WorkloadLabels=>Throws(()=>new WorkloadRequest("workload","linux-amd64",property.Workload.Resources,requiredLabels:new Dictionary<string,string>{{"key",""}})),
            SchedulerValidatorFamily.NullScheduleInput=>Throws(()=>(variant%3) switch{0=>new DeterministicScheduler().Schedule(null!,property.Candidates,property.Policy),
                1=>new DeterministicScheduler().Schedule(property.Workload,null!,property.Policy),_=>new DeterministicScheduler().Schedule(property.Workload,property.Candidates,null!)}),
            _=>false
        };
        return(family,rejected);
    }

    private static NodeCandidate InvalidCandidate(string id,ResourceVector requested,SchedulerViolation violation,int capacityDimension)
    {
        var available=violation==SchedulerViolation.Capacity?WithOneDimension(requested,capacityDimension,-1):Add(requested,20);
        return new(id,violation==SchedulerViolation.NodeClass?"storage":"compute",violation==SchedulerViolation.Architecture?"linux-arm64":"linux-amd64",violation==SchedulerViolation.FailureDomain?"fd-z":"fd-a",available,
            violation==SchedulerViolation.Port?[8080]:[],violation==SchedulerViolation.Labels?new Dictionary<string,string>{{"region","sfo"}}:new Dictionary<string,string>{{"region","gru"}},
            violation==SchedulerViolation.TrustZone?[]:["trusted"],violation==SchedulerViolation.NetworkZone?[]:["product"],violation==SchedulerViolation.SecretZone?[]:["runtime"],
            violation==SchedulerViolation.Affinity?[]:violation==SchedulerViolation.AntiAffinity?["service","noisy"]:["service"],
            violation==SchedulerViolation.SafetyCap?new(1,1):new(0,10),violation==SchedulerViolation.Veto?new(CandidateVetoCode.ControllerHold):null);
    }

    private static NodeCandidate Candidate(string id,int index,ResourceVector requested,ref DeterministicSequence sequence,CandidateVeto? veto=null)
        =>new(id,"compute","linux-amd64",$"fd-{(char)('a'+index%3)}",AddRandom(requested,ref sequence),[],new Dictionary<string,string>{{"region","gru"}},
            ["trusted"],["product"],["runtime"],["service"],new(0,100),veto);
    private static NodeCandidate CandidateWithAvailable(string id,ResourceVector available)=>new(id,"compute","linux-amd64","fd-a",available,[],
        new Dictionary<string,string>{{"region","gru"}},["trusted"],["product"],["runtime"],["service"],new(0,100));
    private static LeastWastePolicy Policy(ref DeterministicSequence sequence)
    {
        var dimensions=Enum.GetValues<ResourceDimension>();var offset=sequence.Int(0,dimensions.Length);var scores=new List<ScoreDimension>(dimensions.Length);
        foreach(var dimension in dimensions.Skip(offset).Concat(dimensions.Take(offset)))scores.Add(new(dimension,sequence.Long(1,6)));
        return new(scores);
    }
    private static ResourceVector Vector(ref DeterministicSequence sequence,long minimum,long maximum)=>new(sequence.Long(minimum,maximum),sequence.Long(minimum,maximum),sequence.Long(minimum,maximum),
        sequence.Long(minimum,maximum),sequence.Long(minimum,maximum),sequence.Long(minimum,maximum),sequence.Long(minimum,maximum),sequence.Long(minimum,maximum));
    internal static ResourceVector Add(ResourceVector value,long amount)=>new(checked(value.Cpu+amount),checked(value.Memory+amount),checked(value.BlockIo+amount),checked(value.EphemeralDisk+amount),
        checked(value.Bandwidth+amount),checked(value.Pids+amount),checked(value.FileDescriptors+amount),checked(value.HugePages+amount));
    private static ResourceVector AddRandom(ResourceVector value,ref DeterministicSequence sequence)=>new(checked(value.Cpu+sequence.Long(0,31)),checked(value.Memory+sequence.Long(0,31)),
        checked(value.BlockIo+sequence.Long(0,31)),checked(value.EphemeralDisk+sequence.Long(0,31)),checked(value.Bandwidth+sequence.Long(0,31)),
        checked(value.Pids+sequence.Long(0,31)),checked(value.FileDescriptors+sequence.Long(0,31)),checked(value.HugePages+sequence.Long(0,31)));
    internal static ResourceVector WithOneDimension(ResourceVector value,int index,long delta)
    {
        var values=new[]{value.Cpu,value.Memory,value.BlockIo,value.EphemeralDisk,value.Bandwidth,value.Pids,value.FileDescriptors,value.HugePages};
        values[index]=checked(values[index]+delta);return new(values[0],values[1],values[2],values[3],values[4],values[5],values[6],values[7]);
    }
    private static PlacementCheck ToCheck(SchedulerViolation violation,ulong seed)=>violation switch
    {
        SchedulerViolation.Architecture=>PlacementCheck.Architecture,SchedulerViolation.NodeClass=>PlacementCheck.NodeClass,SchedulerViolation.Labels=>PlacementCheck.Labels,
        SchedulerViolation.TrustZone=>PlacementCheck.TrustZones,SchedulerViolation.NetworkZone=>PlacementCheck.NetworkZones,SchedulerViolation.SecretZone=>PlacementCheck.SecretZones,
        SchedulerViolation.FailureDomain=>PlacementCheck.FailureDomain,SchedulerViolation.Affinity=>PlacementCheck.Affinity,SchedulerViolation.AntiAffinity=>PlacementCheck.AntiAffinity,
        SchedulerViolation.Port=>PlacementCheck.Ports,SchedulerViolation.SafetyCap=>PlacementCheck.SafetyCap,SchedulerViolation.Veto=>PlacementCheck.CallerVeto,
        SchedulerViolation.Capacity=>(PlacementCheck)((int)PlacementCheck.Cpu+(int)(seed%8)),_=>throw new ArgumentOutOfRangeException(nameof(violation))
    };
}

internal sealed record AvailabilityPropertyCase(ulong Seed,ServiceAvailabilityPolicy Policy,ReplicaObservation[] Observations,MaintainReplicaChange Maintenance);
internal static class AvailabilityPropertyGenerator
{
    internal static AvailabilityPropertyCase Maintenance(ulong seed)
    {
        var sequence=new DeterministicSequence(seed);var count=sequence.Int(2,9);var observations=Enumerable.Range(0,count)
            .Select(index=>Observation(index,index,ReplicaAvailabilityState.Available)).ToArray();
        var policy=Policy((ulong)count,(ulong)(count-1),(ulong)(count-1),1,(ulong)(count-1),true,ResourceVector.Zero);
        return new(seed,policy,observations,new(new ReplicaId("replica-0")));
    }
    internal static ServiceAvailabilityPolicy Policy(ulong desired,ulong minimum,ulong quorum,ulong disruptions,ulong domains,bool onePerHost,ResourceVector reserve,
        ReserveDisposition disposition=ReserveDisposition.Preserve)=>new(Service,new(desired),new(minimum),new(quorum),new(disruptions),ServiceCriticality.Critical,onePerHost,new(domains),reserve,disposition);
    internal static ReplicaObservation Observation(int replica,int node,ReplicaAvailabilityState state)=>new(new($"replica-{replica}"),Service,new($"node-{node}"),new($"fd-{node}"),state);
    internal static ServiceId Service{get;}=new("scheduler-service");
    internal static (AvailabilityValidatorFamily Family,bool Rejected) InvalidValidator(ulong seed)
    {
        var familyCount=(ulong)Enum.GetValues<AvailabilityValidatorFamily>().Length;var family=(AvailabilityValidatorFamily)(seed%familyCount);var variant=seed/familyCount;
        var policy=Policy(1,1,1,0,1,true,ResourceVector.Zero);
        var observation=Observation(0,0,ReplicaAvailabilityState.Available);var change=new MaintainReplicaChange(observation.ReplicaId);
        bool Throws(Func<object?> action){try{_=action();return false;}catch(ArgumentException){return true;}catch(OverflowException){return true;}}
        var rejected=family switch
        {
            AvailabilityValidatorFamily.CountOverflow=>Throws(()=>new AvailabilityCount(ulong.MaxValue).AddChecked(new(1))),
            AvailabilityValidatorFamily.CountUnderflow=>Throws(()=>new AvailabilityCount(0).SubtractChecked(new(1))),
            AvailabilityValidatorFamily.Identity=>Throws(()=>(variant%4) switch{0=>new ReplicaId("Not Canonical"),1=>new ServiceId(""),2=>new AvailabilityNodeId("UPPER"),_=>new FailureDomainId("bad_value")}),
            AvailabilityValidatorFamily.PolicyNull=>Throws(()=>(variant%7) switch
            {
                0=>new ServiceAvailabilityPolicy(null!,new(1),new(1),new(1),new(0),ServiceCriticality.Critical,true,new(1),ResourceVector.Zero,ReserveDisposition.Preserve),
                1=>new ServiceAvailabilityPolicy(Service,null!,new(1),new(1),new(0),ServiceCriticality.Critical,true,new(1),ResourceVector.Zero,ReserveDisposition.Preserve),
                2=>new ServiceAvailabilityPolicy(Service,new(1),null!,new(1),new(0),ServiceCriticality.Critical,true,new(1),ResourceVector.Zero,ReserveDisposition.Preserve),
                3=>new ServiceAvailabilityPolicy(Service,new(1),new(1),null!,new(0),ServiceCriticality.Critical,true,new(1),ResourceVector.Zero,ReserveDisposition.Preserve),
                4=>new ServiceAvailabilityPolicy(Service,new(1),new(1),new(1),null!,ServiceCriticality.Critical,true,new(1),ResourceVector.Zero,ReserveDisposition.Preserve),
                5=>new ServiceAvailabilityPolicy(Service,new(1),new(1),new(1),new(0),ServiceCriticality.Critical,true,null!,ResourceVector.Zero,ReserveDisposition.Preserve),
                _=>new ServiceAvailabilityPolicy(Service,new(1),new(1),new(1),new(0),ServiceCriticality.Critical,true,new(1),null!,ReserveDisposition.Preserve)
            }),
            AvailabilityValidatorFamily.PolicyRelation=>Throws(()=>Policy(1,2,1,0,1,true,ResourceVector.Zero)),
            AvailabilityValidatorFamily.PolicyEnum=>Throws(()=>variant%2==0?new ServiceAvailabilityPolicy(Service,new(1),new(1),new(1),new(0),(ServiceCriticality)99,true,new(1),ResourceVector.Zero,ReserveDisposition.Preserve)
                :new ServiceAvailabilityPolicy(Service,new(1),new(1),new(1),new(0),ServiceCriticality.Critical,true,new(1),ResourceVector.Zero,(ReserveDisposition)99)),
            AvailabilityValidatorFamily.ObservationNull=>Throws(()=>variant%2==0?new ReplicaObservation(null!,Service,new("node"),new("fd"),ReplicaAvailabilityState.Available)
                :new ReplicaObservation(new("replica"),null!,new("node"),new("fd"),ReplicaAvailabilityState.Available)),
            AvailabilityValidatorFamily.ObservationEnum=>Throws(()=>new ReplicaObservation(new("replica"),Service,new("node"),new("fd"),(ReplicaAvailabilityState)99)),
            AvailabilityValidatorFamily.ChangeNull=>Throws(()=>(variant%6) switch{0=>new MaintainReplicaChange(null!),1=>new DrainNodeChange(null!),
                2=>new PlaceReplicaChange(null!,new("node"),new("fd"),ResourceVector.Zero,ResourceVector.Zero),3=>new PlaceReplicaChange(new("replica"),null!,new("fd"),ResourceVector.Zero,ResourceVector.Zero),
                4=>new PlaceReplicaChange(new("replica"),new("node"),null!,ResourceVector.Zero,ResourceVector.Zero),_=>new PlaceReplicaChange(new("replica"),new("node"),new("fd"),null!,ResourceVector.Zero)}),
            AvailabilityValidatorFamily.RequestPolicyNull=>Throws(()=>new AvailabilityEvaluationRequest(null!,change,ObservationCompleteness.Complete,[observation])),
            AvailabilityValidatorFamily.RequestChangeNull=>Throws(()=>new AvailabilityEvaluationRequest(policy,null!,ObservationCompleteness.Complete,[observation])),
            AvailabilityValidatorFamily.RequestEnum=>Throws(()=>new AvailabilityEvaluationRequest(policy,change,(ObservationCompleteness)99,[observation])),
            AvailabilityValidatorFamily.RequestObservationNull=>Throws(()=>variant%2==0?new AvailabilityEvaluationRequest(policy,change,ObservationCompleteness.Complete,null!)
                :new AvailabilityEvaluationRequest(policy,change,ObservationCompleteness.Complete,[null!])),
            AvailabilityValidatorFamily.EvaluatorNull=>Throws(()=>new AvailabilityPolicyEvaluator().Evaluate(null!)),
            _=>false
        };
        return(family,rejected);
    }
}

internal static class PropertySerialization
{
    internal static string Schedule(ScheduleResult result)=>result switch
    {
        PlacementSelected selected=>$"selected:{selected.WorkloadId}:{selected.SelectedCandidateId}:{Candidates(selected.Candidates)}",
        Unschedulable rejected=>$"unschedulable:{rejected.WorkloadId}:{Candidates(rejected.Candidates)}",
        _=>throw new ArgumentOutOfRangeException(nameof(result))
    };
    internal static string Availability(AvailabilityDecision decision)=>$"{decision.Admitted}|{string.Join(';',decision.Trace.Select(reason=>$"{(int)reason.Code}:{(int)reason.Outcome}:{reason.Observed}:{reason.Required}"))}";
    private static string Candidates(IEnumerable<CandidateTrace> candidates)=>string.Join('|',candidates.Select(candidate=>$"{candidate.CandidateId}:{candidate.Eligible}:"+
        $"{candidate.Score?.WeightedWaste.ToString(CultureInfo.InvariantCulture)??"-"}:{string.Join(',',candidate.Reasons.Select(reason=>$"{(int)reason.Check}:{(int)reason.Outcome}:{reason.Detail}"))}"));
}

internal sealed record OraclePlacement(string CandidateId,BigInteger WeightedWaste,long[] OrderedRemaining);
internal static class SchedulerIndependentOracle
{
    internal static OraclePlacement Select(SchedulerPropertyCase property)=>property.Candidates.Select(candidate=>Score(candidate,property.Workload,property.Policy))
        .OrderBy(score=>score,OracleComparer.Instance).First();
    internal static bool HasCrossDimensionTradeoff(SchedulerPropertyCase property)
    {
        var remaining=property.Candidates.Select(candidate=>NaturalRemaining(candidate,property.Workload)).ToArray();
        return remaining.SelectMany((left,index)=>remaining.Skip(index+1).Select(right=>(left,right)))
            .Any(pair=>pair.left.Zip(pair.right).Any(values=>values.First<values.Second)&&pair.left.Zip(pair.right).Any(values=>values.First>values.Second));
    }
    internal static long[] Values(ResourceVector value)=>[value.Cpu,value.Memory,value.BlockIo,value.EphemeralDisk,value.Bandwidth,value.Pids,value.FileDescriptors,value.HugePages];
    internal static long[] NaturalRemaining(NodeCandidate candidate,WorkloadRequest workload)
    {
        var available=Values(candidate.Available);var requested=Values(workload.Resources);var remaining=new long[available.Length];
        for(var index=0;index<available.Length;index++)
        {
            var difference=(BigInteger)available[index]-requested[index];
            if(difference<long.MinValue||difference>long.MaxValue)throw new InvalidOperationException("Oracle remainder is not representable.");
            remaining[index]=(long)difference;
        }
        return remaining;
    }
    private static OraclePlacement Score(NodeCandidate candidate,WorkloadRequest workload,LeastWastePolicy policy)
    {
        var natural=NaturalRemaining(candidate,workload);var byDimension=new Dictionary<ResourceDimension,long>
        {{ResourceDimension.Cpu,natural[0]},{ResourceDimension.Memory,natural[1]},{ResourceDimension.BlockIo,natural[2]},
            {ResourceDimension.EphemeralDisk,natural[3]},{ResourceDimension.Bandwidth,natural[4]},{ResourceDimension.Pids,natural[5]},
            {ResourceDimension.FileDescriptors,natural[6]},{ResourceDimension.HugePages,natural[7]}};
        var ordered=policy.Dimensions.Select(dimension=>byDimension[dimension.Dimension]).ToArray();var total=BigInteger.Zero;
        for(var index=0;index<ordered.Length;index++)total+=(BigInteger)ordered[index]*policy.Dimensions[index].Weight;
        return new(candidate.Id,total,ordered);
    }
    private sealed class OracleComparer:IComparer<OraclePlacement>
    {
        internal static OracleComparer Instance{get;}=new();
        public int Compare(OraclePlacement? left,OraclePlacement? right)
        {
            if(ReferenceEquals(left,right))return 0;if(left is null)return-1;if(right is null)return 1;
            var comparison=left.WeightedWaste.CompareTo(right.WeightedWaste);if(comparison!=0)return comparison;
            for(var index=0;index<left.OrderedRemaining.Length;index++){comparison=left.OrderedRemaining[index].CompareTo(right.OrderedRemaining[index]);if(comparison!=0)return comparison;}
            return StringComparer.Ordinal.Compare(left.CandidateId,right.CandidateId);
        }
    }
}
