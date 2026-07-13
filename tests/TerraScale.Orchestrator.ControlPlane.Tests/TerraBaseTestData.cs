using TerraScale.Orchestrator.ControlPlane.TerraBase;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

internal static class TerraBaseTestData
{
    private const int M=64;
    public static TerraBaseCellId Cell(string v="gru"){TerraBaseCellId.TryCreate(v,M,out var x);return x!;}
    public static TerraBaseDatabaseId Db(string v="db"){TerraBaseDatabaseId.TryCreate(v,M,out var x);return x!;}
    public static TerraBaseMemberId Member(string v="d"){TerraBaseMemberId.TryCreate(v,M,out var x);return x!;}
    public static TerraBaseNodeId Node(string v="n4"){TerraBaseNodeId.TryCreate(v,M,out var x);return x!;}
    public static TerraBaseVolumeId Volume(string v="volume"){TerraBaseVolumeId.TryCreate(v,M,out var x);return x!;}
    public static TerraBaseBackupId Backup(string v="backup"){TerraBaseBackupId.TryCreate(v,M,out var x);return x!;}
    public static TerraBaseRestoreId Restore(string v="restore"){TerraBaseRestoreId.TryCreate(v,M,out var x);return x!;}
    public static TerraBaseReleaseId Release(string v="release"){TerraBaseReleaseId.TryCreate(v,M,out var x);return x!;}
    public static TerraBaseOperationId Op(string v="op"){TerraBaseOperationId.TryCreate(v,M,out var x);return x!;}
    public static TerraBaseFenceId Fence(string v="fence"){TerraBaseFenceId.TryCreate(v,M,out var x);return x!;}
    public static TerraBaseDigestRef Digest(string v="digest-secret"){TerraBaseDigestRef.TryCreate(v,M,out var x);return x!;}
    public static TerraBaseObjectRef Object(string v="object-secret"){TerraBaseObjectRef.TryCreate(v,M,out var x);return x!;}
    public static TerraBaseKeyRef Key(string v="key-secret"){TerraBaseKeyRef.TryCreate(v,M,out var x);return x!;}
    public static TerraBaseOrdinal O(ulong v){TerraBaseOrdinal.TryCreate(v,out var x);return x;}
    public static TerraBaseEvidenceScope Scope()=>new(Cell(),Db(),Member(),Node(),Volume(),Fence(),O(4),O(8),O(3),Op());
    public static TerraBaseTopologyEvidence Topology(TerraBaseMemberKind kind=TerraBaseMemberKind.Elastic,TerraBaseEvidenceScope? scope=null,
        TerraBaseReplication replication=TerraBaseReplication.CaughtUp,TerraBaseProof noMutation=TerraBaseProof.Proven,
        TerraBaseProof topologyApplied=TerraBaseProof.Proven)=>
        new(scope??Scope(),kind,noMutation,TerraBaseProof.Proven,TerraBaseProof.Proven,TerraBaseProof.Proven,TerraBaseProof.Proven,
            TerraBaseProof.Proven,TerraBaseProof.Proven,TerraBaseProof.Proven,topologyApplied,TerraBaseProof.Proven,TerraBaseProof.Proven,
            TerraBaseProof.Proven,TerraBaseProof.Proven,TerraBaseProof.Proven,replication,O(100));
    public static TerraBaseBackupSegment Segment(ulong seq,bool full=false,ulong? parent=null,TerraBaseBackupSubject? subject=null)=>
        new(subject??new(Cell(),Db(),O(4),O(8)),Backup($"b{seq}"),O(seq),parent is null?null:O(parent.Value),full,Digest(),Object(),Key());
}
