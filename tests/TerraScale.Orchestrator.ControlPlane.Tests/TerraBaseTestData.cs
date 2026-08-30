using TerraScale.Orchestrator.ControlPlane.TerraBase;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

internal static class TerraBaseTestData
{
    private const int M=64;
    public static TerraBaseRegionCode Region(string value = "GRU")
    {
        if (!TerraBaseRegionCode.TryCreate(value, out var result))
            throw new InvalidOperationException("Invalid test Region code.");
        return result;
    }

    public static TerraBaseDatabaseId Db(string v="db")
    {
        if (!TerraBaseDatabaseId.TryCreate(v, M, out var result)) throw new InvalidOperationException("Invalid test database id.");
        return result;
    }

    public static TerraBaseMemberId Member(string v="d")
    {
        if (!TerraBaseMemberId.TryCreate(v, M, out var result)) throw new InvalidOperationException("Invalid test member id.");
        return result;
    }

    public static TerraBaseNodeId Node(string v="n4")
    {
        if (!TerraBaseNodeId.TryCreate(v, M, out var result)) throw new InvalidOperationException("Invalid test node id.");
        return result;
    }

    public static TerraBaseVolumeId Volume(string v="volume")
    {
        if (!TerraBaseVolumeId.TryCreate(v, M, out var result)) throw new InvalidOperationException("Invalid test volume id.");
        return result;
    }

    public static TerraBaseBackupId Backup(string v="backup")
    {
        if (!TerraBaseBackupId.TryCreate(v, M, out var result)) throw new InvalidOperationException("Invalid test backup id.");
        return result;
    }

    public static TerraBaseRestoreId Restore(string v="restore")
    {
        if (!TerraBaseRestoreId.TryCreate(v, M, out var result)) throw new InvalidOperationException("Invalid test restore id.");
        return result;
    }

    public static TerraBaseReleaseId Release(string v="release")
    {
        if (!TerraBaseReleaseId.TryCreate(v, M, out var result)) throw new InvalidOperationException("Invalid test release id.");
        return result;
    }

    public static TerraBaseOperationId Op(string v="op")
    {
        if (!TerraBaseOperationId.TryCreate(v, M, out var result)) throw new InvalidOperationException("Invalid test operation id.");
        return result;
    }

    public static TerraBaseFenceId Fence(string v="fence")
    {
        if (!TerraBaseFenceId.TryCreate(v, M, out var result)) throw new InvalidOperationException("Invalid test fence id.");
        return result;
    }

    public static TerraBaseDigestRef Digest(string v="digest-secret")
    {
        if (!TerraBaseDigestRef.TryCreate(v, M, out var result)) throw new InvalidOperationException("Invalid test digest reference.");
        return result;
    }

    public static TerraBaseObjectRef Object(string v="object-secret")
    {
        if (!TerraBaseObjectRef.TryCreate(v, M, out var result)) throw new InvalidOperationException("Invalid test object reference.");
        return result;
    }

    public static TerraBaseKeyRef Key(string v="key-secret")
    {
        if (!TerraBaseKeyRef.TryCreate(v, M, out var result)) throw new InvalidOperationException("Invalid test key reference.");
        return result;
    }
    public static TerraBaseOrdinal O(ulong v){TerraBaseOrdinal.TryCreate(v,out var x);return x;}
    public static TerraBaseEvidenceScope Scope()=>new(Region(),Db(),Member(),Node(),Volume(),Fence(),O(4),O(8),O(3),Op());
    public static TerraBaseTopologyEvidence Topology(TerraBaseMemberKind kind=TerraBaseMemberKind.Elastic,TerraBaseEvidenceScope? scope=null,
        TerraBaseReplication replication=TerraBaseReplication.CaughtUp,TerraBaseProof noMutation=TerraBaseProof.Proven,
        TerraBaseProof topologyApplied=TerraBaseProof.Proven,TerraBaseRole role=TerraBaseRole.Follower,
        TerraBaseProof leadership=TerraBaseProof.Proven,TerraBaseLossCount loss=TerraBaseLossCount.None)=>
        new(scope??Scope(),kind,role,loss,leadership,noMutation,TerraBaseProof.Proven,TerraBaseProof.Proven,TerraBaseProof.Proven,TerraBaseProof.Proven,
            TerraBaseProof.Proven,TerraBaseProof.Proven,TerraBaseProof.Proven,topologyApplied,TerraBaseProof.Proven,TerraBaseProof.Proven,
            TerraBaseProof.Proven,TerraBaseProof.Proven,TerraBaseProof.Proven,replication,O(100));
    public static TerraBaseBackupSegment Segment(ulong seq,bool full=false,ulong? parent=null,TerraBaseBackupSubject? subject=null)=>
        new(subject??new(Region(),Db(),O(4),O(8)),Backup($"b{seq}"),O(seq),parent is null?null:O(parent.Value),full,Digest(),Object(),Key());
    public static TerraBaseBackupEvidence Chain(TerraBaseEvidenceScope? scope=null,IEnumerable<TerraBaseBackupSegment?>? segments=null,
        TerraBaseProof application=TerraBaseProof.Proven,TerraBaseProof digest=TerraBaseProof.Proven,TerraBaseProof location=TerraBaseProof.Proven)=>
        new(scope??Scope(),segments??[Segment(1,true),Segment(2,parent:1)],application,digest,location,8);
}
