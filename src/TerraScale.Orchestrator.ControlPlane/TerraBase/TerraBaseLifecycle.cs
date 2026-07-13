namespace TerraScale.Orchestrator.ControlPlane.TerraBase;

public sealed record TerraBaseTopologyEvidence(
    TerraBaseEvidenceScope Scope,TerraBaseMemberKind MemberKind,TerraBaseRole MemberRole,TerraBaseLossCount LossCount,
    TerraBaseProof LeadershipTransferred,TerraBaseProof NoTopologyMutation,
    TerraBaseProof QuorumFloor,TerraBaseProof ReplicationFloor,TerraBaseProof SustainedSignal,
    TerraBaseProof Placement,TerraBaseProof Storage,TerraBaseProof Budget,TerraBaseProof UniqueMember,
    TerraBaseProof TopologyApplied,TerraBaseProof NoDatabaseReference,TerraBaseProof RecoveryPoint,
    TerraBaseProof Retention,TerraBaseProof VolumeDisposition,TerraBaseProof PostChangeReplication,
    TerraBaseReplication Replication,TerraBaseOrdinal ReplicationPosition);

public static class TerraBaseTopologyPlanner
{
    public static TerraBaseDecision PlanAdd(TerraBaseEvidenceScope? expected,TerraBaseTopologyEvidence? evidence)
    {
        var trace=Trace(expected,evidence);
        if(!Scoped(expected,evidence?.Scope))return TerraBaseDecision.Hold(TerraBaseCode.WrongEvidenceScope,trace);
        if(evidence!.MemberKind==TerraBaseMemberKind.Unknown)return TerraBaseDecision.Hold(TerraBaseCode.InvalidInput,trace);
        if(evidence.MemberKind!=TerraBaseMemberKind.Elastic)return TerraBaseDecision.Hold(TerraBaseCode.PermanentMember,trace);
        if(evidence.LossCount==TerraBaseLossCount.Unknown)return TerraBaseDecision.Hold(TerraBaseCode.InvalidInput,trace);
        if(evidence.LossCount==TerraBaseLossCount.TwoOrMore)return TerraBaseDecision.Hold(TerraBaseCode.ReplicationUnsafe,trace);
        if(evidence.LossCount==TerraBaseLossCount.One&&(evidence.QuorumFloor!=TerraBaseProof.Proven||evidence.ReplicationFloor!=TerraBaseProof.Proven))
            return TerraBaseDecision.Hold(TerraBaseCode.ReplicationUnsafe,trace);
        if(evidence.NoTopologyMutation!=TerraBaseProof.Proven)return TerraBaseDecision.Hold(TerraBaseCode.ConflictingTopologyMutation,trace);
        if(evidence.SustainedSignal!=TerraBaseProof.Proven||evidence.Placement!=TerraBaseProof.Proven||evidence.Storage!=TerraBaseProof.Proven||evidence.Budget!=TerraBaseProof.Proven||evidence.UniqueMember!=TerraBaseProof.Proven)
            return TerraBaseDecision.Hold(TerraBaseCode.ProofMissing,trace);
        if(evidence.TopologyApplied!=TerraBaseProof.Proven)return TerraBaseDecision.Emit(TerraBaseAction.Add,TerraBaseTarget.Topology,TerraBaseCode.NextStep,trace!,
            new TerraBaseTopologyIntentSubject(expected!,evidence.MemberKind,evidence.ReplicationPosition));
        if(evidence.Replication==TerraBaseReplication.Conflicting||evidence.Replication==TerraBaseReplication.Future)return TerraBaseDecision.Hold(TerraBaseCode.ReplicationUnsafe,trace);
        if(evidence.Replication!=TerraBaseReplication.CaughtUp)return TerraBaseDecision.Emit(TerraBaseAction.CatchUp,TerraBaseTarget.Member,TerraBaseCode.NextStep,trace!,
            new TerraBaseTopologyIntentSubject(expected!,evidence.MemberKind,evidence.ReplicationPosition));
        if(evidence.PostChangeReplication!=TerraBaseProof.Proven)return TerraBaseDecision.Emit(TerraBaseAction.Observe,TerraBaseTarget.Application,TerraBaseCode.NextStep,trace!);
        return TerraBaseDecision.Emit(TerraBaseAction.Verify,TerraBaseTarget.Member,TerraBaseCode.Completed,trace!);
    }

    public static TerraBaseDecision PlanRemove(TerraBaseEvidenceScope? expected,TerraBaseTopologyEvidence? evidence)
    {
        var trace=Trace(expected,evidence);
        if(!Scoped(expected,evidence?.Scope))return TerraBaseDecision.Hold(TerraBaseCode.WrongEvidenceScope,trace);
        if(evidence!.MemberKind is TerraBaseMemberKind.PermanentA or TerraBaseMemberKind.PermanentB or TerraBaseMemberKind.PermanentC)
            return TerraBaseDecision.Hold(TerraBaseCode.PermanentMember,trace);
        if(evidence.MemberKind!=TerraBaseMemberKind.Elastic)return TerraBaseDecision.Hold(TerraBaseCode.InvalidInput,trace);
        if(evidence.NoTopologyMutation!=TerraBaseProof.Proven)return TerraBaseDecision.Hold(TerraBaseCode.ConflictingTopologyMutation,trace);
        if(evidence.LossCount==TerraBaseLossCount.Unknown)return TerraBaseDecision.Hold(TerraBaseCode.InvalidInput,trace);
        if(evidence.LossCount==TerraBaseLossCount.TwoOrMore)return TerraBaseDecision.Hold(TerraBaseCode.ReplicationUnsafe,trace);
        if(new[]{evidence.SustainedSignal,evidence.QuorumFloor,evidence.ReplicationFloor,evidence.RecoveryPoint,evidence.Retention,evidence.VolumeDisposition}.Any(x=>x!=TerraBaseProof.Proven))
            return TerraBaseDecision.Hold(TerraBaseCode.ProofMissing,trace);
        if(evidence.MemberRole==TerraBaseRole.Unknown)return TerraBaseDecision.Hold(TerraBaseCode.InvalidInput,trace);
        if(evidence.MemberRole==TerraBaseRole.Leader&&evidence.LeadershipTransferred!=TerraBaseProof.Proven)
            return TerraBaseDecision.Emit(TerraBaseAction.Transfer,TerraBaseTarget.Topology,TerraBaseCode.NextStep,trace!,
                new TerraBaseTopologyIntentSubject(expected!,evidence.MemberKind,evidence.ReplicationPosition));
        if(evidence.TopologyApplied!=TerraBaseProof.Proven)return TerraBaseDecision.Emit(TerraBaseAction.Remove,TerraBaseTarget.Topology,TerraBaseCode.NextStep,trace!,
            new TerraBaseTopologyIntentSubject(expected!,evidence.MemberKind,evidence.ReplicationPosition));
        if(evidence.NoDatabaseReference!=TerraBaseProof.Proven||evidence.PostChangeReplication!=TerraBaseProof.Proven)
            return TerraBaseDecision.Emit(TerraBaseAction.Observe,TerraBaseTarget.Application,TerraBaseCode.NextStep,trace!);
        return TerraBaseDecision.Emit(TerraBaseAction.Verify,TerraBaseTarget.Topology,TerraBaseCode.Completed,trace!);
    }

    private static bool Scoped(TerraBaseEvidenceScope? expected,TerraBaseEvidenceScope? actual)=>expected is not null&&expected.Valid&&actual==expected;
    private static TerraBaseTrace? Trace(TerraBaseEvidenceScope? expected,TerraBaseTopologyEvidence? evidence)=>expected is null?null:new(expected,evidence?.ReplicationPosition??default,expected.TopologyGeneration);
}

public sealed class TerraBaseWriterEvidence
{
    private readonly TerraBaseMemberId[] _writers;
    public TerraBaseWriterEvidence(TerraBaseEvidenceScope scope,IEnumerable<TerraBaseMemberId?>? writers,TerraBaseProof inventoryComplete,
        TerraBaseProof exactVolumeIdentity,TerraBaseProof exactFence,TerraBaseProof detached,TerraBaseOrdinal newAuthorityEpoch,int maximum)
    {
        Scope=scope;InventoryComplete=inventoryComplete;ExactVolumeIdentity=exactVolumeIdentity;ExactFence=exactFence;Detached=detached;NewAuthorityEpoch=newAuthorityEpoch;
        var list=writers?.ToArray()??[]; IsValid=scope is not null&&scope.Valid&&maximum>0&&list.Length<=maximum&&list.All(x=>x is not null)&&list.Distinct().Count()==list.Length;
        _writers=list.Where(x=>x is not null).Cast<TerraBaseMemberId>().ToArray();
    }
    public TerraBaseEvidenceScope Scope{get;} public TerraBaseProof InventoryComplete{get;} public TerraBaseProof ExactVolumeIdentity{get;}
    public TerraBaseProof ExactFence{get;} public TerraBaseProof Detached{get;} public TerraBaseOrdinal NewAuthorityEpoch{get;} public bool IsValid{get;}
    public IReadOnlyList<TerraBaseMemberId> Writers=>Array.AsReadOnly(_writers);
}

public static class TerraBaseRetainedVolumePlanner
{
    public static TerraBaseDecision Plan(TerraBaseEvidenceScope expected,TerraBaseWriterEvidence? evidence)
    {
        var trace=new TerraBaseTrace(expected,default,expected.TopologyGeneration);
        if(evidence is null||!evidence.IsValid||evidence.Scope!=expected)return TerraBaseDecision.Hold(TerraBaseCode.WrongEvidenceScope,trace);
        if(evidence.InventoryComplete!=TerraBaseProof.Proven||evidence.Writers.Count!=0)return TerraBaseDecision.Hold(TerraBaseCode.SplitWriter,trace);
        if(evidence.ExactVolumeIdentity!=TerraBaseProof.Proven||evidence.ExactFence!=TerraBaseProof.Proven||evidence.Detached!=TerraBaseProof.Proven)
            return TerraBaseDecision.Hold(TerraBaseCode.ProofMissing,trace);
        if(evidence.NewAuthorityEpoch.Value<=expected.AuthorityEpoch.Value)return TerraBaseDecision.Hold(TerraBaseCode.ProofMissing,trace);
        return TerraBaseDecision.Emit(TerraBaseAction.StartWithRetainedVolume,TerraBaseTarget.Volume,TerraBaseCode.NextStep,
            new(expected,evidence.NewAuthorityEpoch,expected.TopologyGeneration),new TerraBaseRetainedVolumeIntentSubject(expected,evidence.NewAuthorityEpoch));
    }
}

public sealed record TerraBaseUpgradeEvidence(TerraBaseEvidenceScope Scope,TerraBaseReleaseId Current,TerraBaseReleaseId Target,
    TerraBaseUpgradeCompatibility Compatibility,TerraBaseProof NoTopologyMutation,TerraBaseProof OneFailureDomain,
    TerraBaseProof RollbackMaterial,TerraBaseProof LeadershipTransferred,TerraBaseProof UpgradeApplied,TerraBaseProof ProcessHealthy,
    TerraBaseProof Ready,TerraBaseProof CaughtUp,TerraBaseProof RollbackApplied,TerraBaseProof PostRollbackHealthy);
public static class TerraBaseUpgradePlanner
{
    public static TerraBaseDecision Plan(TerraBaseEvidenceScope expected,TerraBaseReleaseId expectedCurrent,
        TerraBaseReleaseId expectedTarget,TerraBaseUpgradeEvidence? e)
    {
        var trace=new TerraBaseTrace(expected,default,expected.TopologyGeneration);
        if(e is null||e.Scope!=expected||e.Current!=expectedCurrent||e.Target!=expectedTarget)return TerraBaseDecision.Hold(TerraBaseCode.WrongEvidenceScope,trace);
        if(expectedCurrent is null||expectedTarget is null||expectedCurrent==expectedTarget)return TerraBaseDecision.Hold(TerraBaseCode.InvalidInput,trace);
        if(e.NoTopologyMutation!=TerraBaseProof.Proven)return TerraBaseDecision.Hold(TerraBaseCode.ConflictingTopologyMutation,trace);
        if(e.Compatibility!=TerraBaseUpgradeCompatibility.CompatibleNAndNMinusOne)return TerraBaseDecision.Hold(TerraBaseCode.CompatibilityRequired,trace);
        if(e.RollbackMaterial!=TerraBaseProof.Proven)return TerraBaseDecision.Hold(TerraBaseCode.RollbackMaterialRequired,trace);
        if(e.OneFailureDomain!=TerraBaseProof.Proven||e.LeadershipTransferred!=TerraBaseProof.Proven)return TerraBaseDecision.Hold(TerraBaseCode.ProofMissing,trace);
        if((e.UpgradeApplied!=TerraBaseProof.Proven&&(e.RollbackApplied==TerraBaseProof.Proven||e.PostRollbackHealthy==TerraBaseProof.Proven))
            ||(e.RollbackApplied!=TerraBaseProof.Proven&&e.PostRollbackHealthy==TerraBaseProof.Proven))
            return TerraBaseDecision.Hold(TerraBaseCode.InvalidInput,trace);
        var subject=new TerraBaseUpgradeIntentSubject(expected,expectedCurrent,expectedTarget);
        if(e.UpgradeApplied!=TerraBaseProof.Proven)return TerraBaseDecision.Emit(TerraBaseAction.Upgrade,TerraBaseTarget.Release,TerraBaseCode.NextStep,trace,subject);
        if(e.ProcessHealthy==TerraBaseProof.Contradicted||e.Ready==TerraBaseProof.Contradicted||e.CaughtUp==TerraBaseProof.Contradicted)
        {
            if(e.RollbackApplied!=TerraBaseProof.Proven)return TerraBaseDecision.Emit(TerraBaseAction.Rollback,TerraBaseTarget.Release,TerraBaseCode.NextStep,trace,subject);
            return e.PostRollbackHealthy==TerraBaseProof.Proven
                ? TerraBaseDecision.Emit(TerraBaseAction.Verify,TerraBaseTarget.Release,TerraBaseCode.RolledBack,trace,subject)
                : TerraBaseDecision.Emit(TerraBaseAction.Observe,TerraBaseTarget.Application,TerraBaseCode.NextStep,trace,subject);
        }
        if(e.RollbackApplied==TerraBaseProof.Proven)return TerraBaseDecision.Hold(TerraBaseCode.InvalidInput,trace);
        if(e.ProcessHealthy!=TerraBaseProof.Proven||e.Ready!=TerraBaseProof.Proven||e.CaughtUp!=TerraBaseProof.Proven)
            return TerraBaseDecision.Emit(TerraBaseAction.Observe,TerraBaseTarget.Application,TerraBaseCode.NextStep,trace);
        return TerraBaseDecision.Emit(TerraBaseAction.Verify,TerraBaseTarget.Release,TerraBaseCode.Completed,trace);
    }
}
