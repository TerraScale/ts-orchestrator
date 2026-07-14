using System.Collections.ObjectModel;
using System.Globalization;

namespace TerraScale.Orchestrator.ControlPlane.TerraBase;

/// <summary>Technical caller-input snapshot limits; these are not database membership or backup policy caps.</summary>
public static class TerraBaseTechnicalInputLimits
{
    public const int MaximumWriterEvidenceCount = 4_096;
    public const int MaximumBackupSegmentCount = 4_096;
}

internal static class TerraBaseInputSnapshot
{
    internal static IReadOnlyList<T> Copy<T>(IEnumerable<T> source, int maximum, string parameterName, string inputName)
    {
        ArgumentNullException.ThrowIfNull(source, parameterName);
        var snapshot = new List<T>(Math.Min(maximum, 256));
        try
        {
            using var enumerator = source.GetEnumerator();
            while (enumerator.MoveNext())
            {
                if (snapshot.Count == maximum)
                    throw new ArgumentException($"{inputName} exceeds the technical or caller snapshot bound.", parameterName);
                var current = enumerator.Current;
                if (current is null)
                    throw new ArgumentException($"{inputName} contains a null item.", parameterName);
                snapshot.Add(current);
            }
        }
        catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException and not AccessViolationException)
        {
            throw new ArgumentException($"{inputName} could not be captured within the technical snapshot bound.", parameterName);
        }
        return new ReadOnlyCollection<T>(snapshot.ToArray());
    }
}

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

internal static class TerraBaseEnumRules
{
    internal static bool Defined<TEnum>(TEnum value) where TEnum : struct, Enum => Enum.IsDefined(value);
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
public enum TerraBaseLossCount{Unknown=0,None,One,TwoOrMore}
public enum TerraBaseAction{Uninitialized=0,Observe,Add,CatchUp,Transfer,Remove,StartWithRetainedVolume,Backup,Restore,Upgrade,Rollback,Hold,Verify}
public enum TerraBaseTarget{None=0,Member,Topology,Volume,BackupChain,RestoreCandidate,Release,Application}
public enum TerraBaseCode{Uninitialized=0,NextStep,Completed,InvalidInput,WrongEvidenceScope,PermanentMember,ConflictingTopologyMutation,SplitWriter,ProofMissing,ReplicationUnsafe,CompatibilityRequired,RollbackMaterialRequired,ChainGap,DigestProofMissing,ApplicationConsistencyRequired,AntiRollback,SideBySideRequired,PromotionProofMissing,RolledBack}

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

public abstract record TerraBaseIntentSubject
{
    private protected TerraBaseIntentSubject() { }
    public abstract TerraBaseEvidenceScope Scope { get; }
    public override string ToString()=>"<terrabase-intent-subject>";
}
public sealed record TerraBaseScopedIntentSubject:TerraBaseIntentSubject
{ internal TerraBaseScopedIntentSubject(TerraBaseEvidenceScope scope)=>Scope=scope; public override TerraBaseEvidenceScope Scope{get;} public override string ToString()=>"<terrabase-scoped-intent>"; }
public sealed record TerraBaseTopologyIntentSubject:TerraBaseIntentSubject
{ internal TerraBaseTopologyIntentSubject(TerraBaseEvidenceScope scope,TerraBaseMemberKind kind,TerraBaseOrdinal position){Scope=scope;MemberKind=kind;ReplicationPosition=position;}
  public override TerraBaseEvidenceScope Scope{get;} public TerraBaseMemberKind MemberKind{get;} public TerraBaseOrdinal ReplicationPosition{get;} public override string ToString()=>"<terrabase-topology-intent>"; }
public sealed record TerraBaseRetainedVolumeIntentSubject:TerraBaseIntentSubject
{ internal TerraBaseRetainedVolumeIntentSubject(TerraBaseEvidenceScope scope,TerraBaseOrdinal epoch){Scope=scope;NewAuthorityEpoch=epoch;}
  public override TerraBaseEvidenceScope Scope{get;} public TerraBaseOrdinal NewAuthorityEpoch{get;} public override string ToString()=>"<terrabase-volume-intent>"; }
public sealed record TerraBaseUpgradeIntentSubject:TerraBaseIntentSubject
{ internal TerraBaseUpgradeIntentSubject(TerraBaseEvidenceScope scope,TerraBaseReleaseId current,TerraBaseReleaseId target){Scope=scope;Current=current;Target=target;}
  public override TerraBaseEvidenceScope Scope{get;} public TerraBaseReleaseId Current{get;} public TerraBaseReleaseId Target{get;} public override string ToString()=>"<terrabase-upgrade-intent>"; }
public sealed record TerraBaseBackupRequestIntentSubject:TerraBaseIntentSubject
{ internal TerraBaseBackupRequestIntentSubject(TerraBaseEvidenceScope scope,TerraBaseBackupId backup,TerraBaseOrdinal sequence,
    TerraBaseOrdinal? parent,TerraBaseBackupId? parentBackup,TerraBaseObjectRef destination,TerraBaseKeyRef key){Scope=scope;Backup=backup;Sequence=sequence;ParentSequence=parent;ParentBackup=parentBackup;Destination=destination;EncryptionKey=key;}
  public override TerraBaseEvidenceScope Scope{get;} public TerraBaseBackupId Backup{get;} public TerraBaseOrdinal Sequence{get;}
  public TerraBaseOrdinal? ParentSequence{get;} public TerraBaseBackupId? ParentBackup{get;} public TerraBaseObjectRef Destination{get;} public TerraBaseKeyRef EncryptionKey{get;} public override string ToString()=>"<terrabase-backup-request-intent>"; }

public readonly record struct TerraBaseDecision
{
    private TerraBaseDecision(TerraBaseAction a,TerraBaseTarget t,TerraBaseCode c,TerraBaseTrace? trace,TerraBaseIntentSubject? subject){Action=a;Target=t;Code=c;Trace=trace;Subject=subject;}
    public TerraBaseAction Action{get;} public TerraBaseTarget Target{get;} public TerraBaseCode Code{get;} public TerraBaseTrace? Trace{get;} public TerraBaseIntentSubject? Subject{get;}
    public bool IsMutationAuthorized=>Action is TerraBaseAction.Add or TerraBaseAction.CatchUp or TerraBaseAction.Transfer or TerraBaseAction.Remove
        or TerraBaseAction.StartWithRetainedVolume or TerraBaseAction.Backup or TerraBaseAction.Restore or TerraBaseAction.Upgrade or TerraBaseAction.Rollback;
    internal static TerraBaseDecision Emit(TerraBaseAction a,TerraBaseTarget t,TerraBaseCode c,TerraBaseTrace trace)=>new(a,t,c,trace,new TerraBaseScopedIntentSubject(trace.Scope));
    internal static TerraBaseDecision Emit(TerraBaseAction a,TerraBaseTarget t,TerraBaseCode c,TerraBaseTrace trace,TerraBaseIntentSubject subject)
    {
        var valid=a switch
        {
            TerraBaseAction.Add or TerraBaseAction.CatchUp or TerraBaseAction.Transfer or TerraBaseAction.Remove=>subject is TerraBaseTopologyIntentSubject,
            TerraBaseAction.StartWithRetainedVolume=>subject is TerraBaseRetainedVolumeIntentSubject,
            TerraBaseAction.Upgrade or TerraBaseAction.Rollback=>subject is TerraBaseUpgradeIntentSubject,
            TerraBaseAction.Backup=>subject is TerraBaseBackupRequestIntentSubject,
            TerraBaseAction.Restore=>subject is TerraBaseRestoreIntentSubject,
            _=>true,
        };
        return valid&&subject.Scope==trace.Scope?new(a,t,c,trace,subject):Hold(TerraBaseCode.InvalidInput,trace);
    }
    internal static TerraBaseDecision Hold(TerraBaseCode c,TerraBaseTrace? trace=null)=>new(TerraBaseAction.Hold,TerraBaseTarget.None,c,trace,null);
}
