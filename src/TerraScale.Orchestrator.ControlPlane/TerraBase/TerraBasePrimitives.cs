using System.Globalization;

namespace TerraScale.Orchestrator.ControlPlane.TerraBase;

internal static class TerraBaseValueRules
{
    internal static bool Valid(string? value,int maximum)
    {
        if (maximum<=0 || string.IsNullOrEmpty(value) || value.Length>maximum) return false;
        for(var i=0;i<value.Length;i++)
        {
            var c=value[i]; if(char.IsWhiteSpace(c)||char.IsControl(c)) return false;
            if(char.IsHighSurrogate(c)){if(i+1>=value.Length||!char.IsLowSurrogate(value[++i]))return false;}
            else if(char.IsLowSurrogate(c)) return false;
        }
        return true;
    }
}

public abstract record TerraBaseIdentity(string Value){public override string ToString()=>Value;}
public sealed record TerraBaseCellId:TerraBaseIdentity{private TerraBaseCellId(string v):base(v){} public static bool TryCreate(string? v,int m,out TerraBaseCellId? x){x=TerraBaseValueRules.Valid(v,m)?new(v!):null;return x is not null;}}
public sealed record TerraBaseDatabaseId:TerraBaseIdentity{private TerraBaseDatabaseId(string v):base(v){} public static bool TryCreate(string? v,int m,out TerraBaseDatabaseId? x){x=TerraBaseValueRules.Valid(v,m)?new(v!):null;return x is not null;}}
public sealed record TerraBaseMemberId:TerraBaseIdentity{private TerraBaseMemberId(string v):base(v){} public static bool TryCreate(string? v,int m,out TerraBaseMemberId? x){x=TerraBaseValueRules.Valid(v,m)?new(v!):null;return x is not null;}}
public sealed record TerraBaseNodeId:TerraBaseIdentity{private TerraBaseNodeId(string v):base(v){} public static bool TryCreate(string? v,int m,out TerraBaseNodeId? x){x=TerraBaseValueRules.Valid(v,m)?new(v!):null;return x is not null;}}
public sealed record TerraBaseVolumeId:TerraBaseIdentity{private TerraBaseVolumeId(string v):base(v){} public static bool TryCreate(string? v,int m,out TerraBaseVolumeId? x){x=TerraBaseValueRules.Valid(v,m)?new(v!):null;return x is not null;}}
public sealed record TerraBaseBackupId:TerraBaseIdentity{private TerraBaseBackupId(string v):base(v){} public static bool TryCreate(string? v,int m,out TerraBaseBackupId? x){x=TerraBaseValueRules.Valid(v,m)?new(v!):null;return x is not null;}}
public sealed record TerraBaseRestoreId:TerraBaseIdentity{private TerraBaseRestoreId(string v):base(v){} public static bool TryCreate(string? v,int m,out TerraBaseRestoreId? x){x=TerraBaseValueRules.Valid(v,m)?new(v!):null;return x is not null;}}
public sealed record TerraBaseReleaseId:TerraBaseIdentity{private TerraBaseReleaseId(string v):base(v){} public static bool TryCreate(string? v,int m,out TerraBaseReleaseId? x){x=TerraBaseValueRules.Valid(v,m)?new(v!):null;return x is not null;}}
public sealed record TerraBaseOperationId:TerraBaseIdentity{private TerraBaseOperationId(string v):base(v){} public static bool TryCreate(string? v,int m,out TerraBaseOperationId? x){x=TerraBaseValueRules.Valid(v,m)?new(v!):null;return x is not null;}}
public sealed record TerraBaseFenceId:TerraBaseIdentity{private TerraBaseFenceId(string v):base(v){} public static bool TryCreate(string? v,int m,out TerraBaseFenceId? x){x=TerraBaseValueRules.Valid(v,m)?new(v!):null;return x is not null;}}
public sealed record TerraBaseDigestRef:TerraBaseIdentity{private TerraBaseDigestRef(string v):base(v){} public static bool TryCreate(string? v,int m,out TerraBaseDigestRef? x){x=TerraBaseValueRules.Valid(v,m)?new(v!):null;return x is not null;}}
public sealed record TerraBaseObjectRef:TerraBaseIdentity{private TerraBaseObjectRef(string v):base(v){} public static bool TryCreate(string? v,int m,out TerraBaseObjectRef? x){x=TerraBaseValueRules.Valid(v,m)?new(v!):null;return x is not null;}}
public sealed record TerraBaseKeyRef:TerraBaseIdentity{private TerraBaseKeyRef(string v):base(v){} public static bool TryCreate(string? v,int m,out TerraBaseKeyRef? x){x=TerraBaseValueRules.Valid(v,m)?new(v!):null;return x is not null;}}

public readonly record struct TerraBaseOrdinal
{
    private TerraBaseOrdinal(ulong value)=>Value=value; public ulong Value{get;} public bool IsValid=>Value>0;
    public static bool TryCreate(ulong value,out TerraBaseOrdinal x){x=value>0?new(value):default;return x.IsValid;}
    public override string ToString()=>Value.ToString(CultureInfo.InvariantCulture);
}
public readonly record struct TerraBaseBytes
{
    private TerraBaseBytes(ulong value)=>Value=value; public ulong Value{get;} public bool IsValid=>Value>0;
    public static bool TryCreate(ulong value,out TerraBaseBytes x){x=value>0?new(value):default;return x.IsValid;}
}

public enum TerraBaseMemberKind{Unknown=0,PermanentA,PermanentB,PermanentC,Elastic}
public enum TerraBaseRole{Unknown=0,Follower,Leader}
public enum TerraBaseHealth{Unknown=0,Healthy,Degraded,Failed}
public enum TerraBaseProof{Unknown=0,Proven,Contradicted}
public enum TerraBaseReplication{Unknown=0,CaughtUp,Lagging,Conflicting,Future}
public enum TerraBaseUpgradeCompatibility{Unknown=0,CompatibleNAndNMinusOne,Incompatible}
public enum TerraBaseAction{Uninitialized=0,Observe,Add,CatchUp,Transfer,Remove,StartWithRetainedVolume,Backup,Restore,Upgrade,Rollback,Hold,Verify}
public enum TerraBaseTarget{None=0,Member,Topology,Volume,BackupChain,RestoreCandidate,Release,Application}
public enum TerraBaseCode{Uninitialized=0,NextStep,Completed,InvalidInput,WrongEvidenceScope,PermanentMember,ConflictingTopologyMutation,SplitWriter,ProofMissing,ReplicationUnsafe,CompatibilityRequired,RollbackMaterialRequired,ChainGap,DigestProofMissing,ApplicationConsistencyRequired,AntiRollback,SideBySideRequired,PromotionProofMissing}

public sealed record TerraBaseEvidenceScope(TerraBaseCellId Cell,TerraBaseDatabaseId Database,TerraBaseMemberId Member,
    TerraBaseNodeId Node,TerraBaseVolumeId RetainedVolume,TerraBaseFenceId Fence,TerraBaseOrdinal DatabaseGeneration,
    TerraBaseOrdinal TopologyGeneration,TerraBaseOrdinal AuthorityEpoch,TerraBaseOperationId Operation)
{
    internal bool Valid=>Cell is not null&&Database is not null&&Member is not null&&Node is not null&&RetainedVolume is not null
        &&Fence is not null&&DatabaseGeneration.IsValid&&TopologyGeneration.IsValid&&AuthorityEpoch.IsValid&&Operation is not null;
    public override string ToString()=>"<terrabase-evidence-scope>";
}

public sealed record TerraBaseTrace(TerraBaseEvidenceScope Scope,TerraBaseOrdinal Position,TerraBaseOrdinal Generation)
{public override string ToString()=>$"position={Position};generation={Generation}";}
public readonly record struct TerraBaseDecision
{
    private TerraBaseDecision(TerraBaseAction a,TerraBaseTarget t,TerraBaseCode c,TerraBaseTrace? trace){Action=a;Target=t;Code=c;Trace=trace;}
    public TerraBaseAction Action{get;} public TerraBaseTarget Target{get;} public TerraBaseCode Code{get;} public TerraBaseTrace? Trace{get;}
    public bool IsMutationAuthorized=>Action is TerraBaseAction.Add or TerraBaseAction.Remove or TerraBaseAction.StartWithRetainedVolume or TerraBaseAction.Backup or TerraBaseAction.Restore or TerraBaseAction.Upgrade or TerraBaseAction.Rollback;
    internal static TerraBaseDecision Emit(TerraBaseAction a,TerraBaseTarget t,TerraBaseCode c,TerraBaseTrace trace)=>new(a,t,c,trace);
    internal static TerraBaseDecision Hold(TerraBaseCode c,TerraBaseTrace? trace=null)=>new(TerraBaseAction.Hold,TerraBaseTarget.None,c,trace);
}
