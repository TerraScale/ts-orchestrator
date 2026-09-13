using TerraScale.Orchestrator.ControlPlane.Storage;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

internal static class StorageTestData
{
    private const int Limit=64;
    public static StorageCellId Cell(string v="gru") => Create(StorageCellId.TryCreate(v, Limit, out var result), result);
    public static VolumeClaimId Claim(string v="claim-a") => Create(VolumeClaimId.TryCreate(v, Limit, out var result), result);
    public static ProviderVolumeId Provider(string v="provider-volume-a") => Create(ProviderVolumeId.TryCreate(v, Limit, out var result), result);
    public static StorageAttachmentId Attachment(string v="attachment-a") => Create(StorageAttachmentId.TryCreate(v, Limit, out var result), result);
    public static StorageNodeId Node(string v="node-a") => Create(StorageNodeId.TryCreate(v, Limit, out var result), result);
    public static StorageWorkloadId Workload(string v="terrabase") => Create(StorageWorkloadId.TryCreate(v, Limit, out var result), result);
    public static StorageMemberId Member(string v="member-a") => Create(StorageMemberId.TryCreate(v, Limit, out var result), result);
    public static FilesystemId Filesystem(string v="filesystem-secret") => Create(FilesystemId.TryCreate(v, Limit, out var result), result);
    public static StorageOperationId Operation(string v="operation-a") => Create(StorageOperationId.TryCreate(v, Limit, out var result), result);
    public static StorageBackupId Backup(string v="backup-a") => Create(StorageBackupId.TryCreate(v, Limit, out var result), result);
    public static StorageFenceId Fence(string v="fence-a") => Create(StorageFenceId.TryCreate(v, Limit, out var result), result);
    public static EncryptionKeyReference Key(string v="key-secret") => Create(EncryptionKeyReference.TryCreate(v, Limit, out var result), result);
    public static StoragePlacementId Placement(string v="ad-1/fd-1") => Create(StoragePlacementId.TryCreate(v, Limit, out var result), result);
    public static StorageDeviceId Device(string v="device-stable-a") => Create(StorageDeviceId.TryCreate(v, Limit, out var result), result);

    public static T Require<T>(T? value) where T : class =>
        value ?? throw new InvalidOperationException("Storage test fixture construction returned no value.");

    private static T Create<T>(bool success, T? value) where T : class =>
        success ? Require(value) : throw new InvalidOperationException("Storage test fixture construction failed.");
    public static StorageBytes B(long v){StorageBytes.TryCreate(v,out var r);return r;}
    public static StorageGeneration Generation(ulong v=4){StorageGeneration.TryCreate(v,out var r);return r;}
    public static StorageWriterEpoch Epoch(ulong v=7){StorageWriterEpoch.TryCreate(v,out var r);return r;}
    public static StorageFormatEvidence Format(StorageProof provider=StorageProof.Proven,
        StorageDeviceClassification classification=StorageDeviceClassification.Blank,StorageProof blank=StorageProof.Proven,
        StorageProof filesystem=StorageProof.Proven,StorageEvidenceScope? scope=null) =>
        new(scope??Scope(),provider,classification,blank,filesystem);
    public static StorageEvidenceScope Scope(ProviderVolumeId? provider=null,StorageOperationId? operation=null,
        StorageFenceId? fence=null,StorageGeneration? generation=null,StorageWriterEpoch? epoch=null,long requested=200,
        StorageRetention retention=StorageRetention.ElasticQuarantine,
        StorageBackupId? backup=null,
        StorageFilesystemType filesystemType=StorageFilesystemType.Xfs, StorageLayout layout=StorageLayout.Lvm,
        long observed=100,long providerBytes=100,long block=100,long filesystem=100,long used=60,long free=40,
        StoragePerformance? performance=null,long forecast=3600) =>
        new(Claim(),provider??Provider(),Attachment(),Cell(),Node(),Workload(),Member(),Device(),Filesystem(),
            filesystemType,layout,B(requested),B(observed),B(providerBytes),B(block),B(filesystem),B(used),B(free),
            performance??new StoragePerformance(StoragePerformanceTier.Balanced,B(10),B(1000),B(200),B(5),B(900),B(180),B(10)),B(forecast),retention,backup??Backup(),
            operation??Operation(),fence??Fence(),generation??Generation(),epoch??Epoch());

    public static StorageVolumeRecord Volume(
        long requested=200,long provider=100,long block=100,long filesystem=100,long used=60,long free=40,
        StorageRetention retention=StorageRetention.ElasticQuarantine, ProviderVolumeId? providerId=null,
        VolumeClaimId? claim=null, StorageCellId? cell=null, StorageWorkloadId? workload=null,
        StorageMemberId? member=null, StorageFenceId? fence=null, StorageGeneration? generation=null,
        StorageWriterEpoch? epoch=null, StoragePerformance? performance=null, long forecast=3600,
        StorageFilesystemType filesystemType=StorageFilesystemType.Xfs, StorageLayout layout=StorageLayout.Lvm,
        long? observed=null, StorageBackupId? backup=null) =>
        new(claim??Claim(),providerId??Provider(),Attachment(),cell??Cell(),Node(),workload??Workload(),member??Member(),
            StorageDomain.TerraBase,Key(),Placement(),Device(),Filesystem(),filesystemType,layout,
            StorageMountPurpose.DatabaseData,B(observed??filesystem),B(requested),B(provider),B(block),B(filesystem),B(used),B(free),
            performance??new StoragePerformance(StoragePerformanceTier.Balanced,B(10),B(1000),B(200),B(5),B(900),B(180),B(10)),
            B(forecast),retention,backup??Backup(),generation??Generation(),fence??Fence(),epoch??Epoch(),Operation());

    public static StorageAuthorityContext Context(
        ProviderVolumeId? provider=null, VolumeClaimId? claim=null, StorageCellId? cell=null,
        StorageWorkloadId? workload=null, StorageMemberId? member=null, StorageFenceId? fence=null,
        StorageGeneration? generation=null, StorageWriterEpoch? epoch=null) =>
        new(claim??Claim(),provider??Provider(),cell??Cell(),workload??Workload(),member??Member(),
            fence??Fence(),generation??Generation(),epoch??Epoch());

    public static StorageExpansionEvidence Expansion(
        StorageProof intent=StorageProof.Unknown,StorageProof prechecks=StorageProof.Unknown,
        StorageProof recovery=StorageProof.Unknown,StorageProof request=StorageProof.Unknown,
        StorageProof providerVerified=StorageProof.Unknown,StorageProof rescan=StorageProof.Unknown,
        StorageProof layout=StorageProof.Unknown,StorageProof grown=StorageProof.Unknown,
        StorageProof sizes=StorageProof.Unknown,StorageProof health=StorageProof.Unknown,
        StorageProof metrics=StorageProof.Unknown,StorageConflictClass conflicts=StorageConflictClass.None,
        StorageEvidenceScope? scope=null,StorageVolumeRecord? volume=null) =>
        new(scope??volume?.EvidenceScope??Scope(),intent,prechecks,recovery,request,providerVerified,rescan,layout,grown,sizes,health,metrics,conflicts);

    public static StorageDeletionEvidence Deletion(
        StorageProof leadership=StorageProof.Proven,StorageProof topology=StorageProof.Proven,
        StorageProof quorum=StorageProof.Proven,StorageProof noReference=StorageProof.Proven,
        StorageProof backup=StorageProof.Proven,StorageProof retention=StorageProof.Proven,
        StorageProof ownerFence=StorageProof.Proven,StorageProof quarantine=StorageProof.Proven,
        StorageProof disposable=StorageProof.Proven,StorageProof auditReady=StorageProof.Proven,
        StorageProof requested=StorageProof.Unknown,StorageProof absent=StorageProof.Unknown,
        StorageProof auditPassed=StorageProof.Unknown,StorageRetention scopeRetention=StorageRetention.ElasticQuarantine,
        StorageEvidenceScope? scope=null) =>
        new(scope??Scope(retention:scopeRetention),leadership,topology,quorum,noReference,backup,retention,ownerFence,quarantine,disposable,auditReady,requested,absent,auditPassed);
}

