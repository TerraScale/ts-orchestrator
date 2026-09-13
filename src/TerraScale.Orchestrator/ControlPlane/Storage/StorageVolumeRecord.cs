namespace TerraScale.Orchestrator.ControlPlane.Storage;

public sealed class StorageVolumeRecord
{
    public StorageVolumeRecord(
        VolumeClaimId claim, ProviderVolumeId providerVolume, StorageAttachmentId attachment,
        StorageCellId cell, StorageNodeId node, StorageWorkloadId workload, StorageMemberId member,
        StorageDomain domain, EncryptionKeyReference encryptionKey, StoragePlacementId placement,
        StorageDeviceId deviceId, FilesystemId filesystemId, StorageFilesystemType filesystemType, StorageLayout layout,
        StorageMountPurpose mountPurpose, StorageBytes observedBytes, StorageBytes requestedBytes,
        StorageBytes providerBytes, StorageBytes blockBytes, StorageBytes filesystemBytes,
        StorageBytes usedBytes, StorageBytes freeBytes, StoragePerformance performance,
        StorageBytes forecastExhaustion,
        StorageRetention retention, StorageBackupId backup, StorageGeneration generation,
        StorageFenceId writerFence, StorageWriterEpoch writerEpoch, StorageOperationId operation)
    {
        Claim = claim; ProviderVolume = providerVolume; Attachment = attachment; Cell = cell; Node = node;
        Workload = workload; Member = member; Domain = domain; EncryptionKey = encryptionKey; Placement = placement; DeviceId = deviceId;
        FilesystemId = filesystemId; FilesystemType = filesystemType; Layout = layout; MountPurpose = mountPurpose;
        ObservedBytes = observedBytes; RequestedBytes = requestedBytes; ProviderBytes = providerBytes; BlockBytes = blockBytes;
        FilesystemBytes = filesystemBytes; UsedBytes = usedBytes; FreeBytes = freeBytes; Performance = performance; ForecastExhaustion = forecastExhaustion;
        Retention = retention; Backup = backup; Generation = generation; WriterFence = writerFence; WriterEpoch = writerEpoch; Operation = operation;
    }
    public VolumeClaimId Claim { get; }
    public ProviderVolumeId ProviderVolume { get; }
    public StorageAttachmentId Attachment { get; }
    public StorageCellId Cell { get; }
    public StorageNodeId Node { get; }
    public StorageWorkloadId Workload { get; }
    public StorageMemberId Member { get; }
    public StorageDomain Domain { get; }
    public EncryptionKeyReference EncryptionKey { get; }
    public StoragePlacementId Placement { get; }
    public StorageDeviceId DeviceId { get; }
    public FilesystemId FilesystemId { get; }
    public StorageFilesystemType FilesystemType { get; }
    public StorageLayout Layout { get; }
    public StorageMountPurpose MountPurpose { get; }
    public StorageBytes ObservedBytes { get; }
    public StorageBytes RequestedBytes { get; }
    public StorageBytes ProviderBytes { get; }
    public StorageBytes BlockBytes { get; }
    public StorageBytes FilesystemBytes { get; }
    public StorageBytes UsedBytes { get; }
    public StorageBytes FreeBytes { get; }
    public StoragePerformance Performance { get; }
    public StorageBytes ForecastExhaustion { get; }
    public StorageRetention Retention { get; }
    public StorageBackupId Backup { get; }
    public StorageGeneration Generation { get; }
    public StorageFenceId WriterFence { get; }
    public StorageWriterEpoch WriterEpoch { get; }
    public StorageOperationId Operation { get; }

    internal bool IsWellFormed => Claim is not null && ProviderVolume is not null && Attachment is not null
        && Cell is not null && Node is not null && Workload is not null && Member is not null
        && Domain is not StorageDomain.Unknown && Enum.IsDefined(Domain)
        && EncryptionKey is not null && Placement is not null && DeviceId is not null && FilesystemId is not null
        && FilesystemType is not StorageFilesystemType.Unknown && Enum.IsDefined(FilesystemType)
        && Layout is not StorageLayout.Unknown && Enum.IsDefined(Layout)
        && MountPurpose is not StorageMountPurpose.Unknown && Enum.IsDefined(MountPurpose)
        && Performance.Tier is not StoragePerformanceTier.Unknown && Enum.IsDefined(Performance.Tier)
        && Retention is not StorageRetention.Unknown && Enum.IsDefined(Retention)
        && Backup is not null && Generation.IsValid && WriterFence is not null && WriterEpoch.IsValid && Operation is not null;

    internal StorageNumericTrace Trace(StorageConflictClass conflicts = StorageConflictClass.None,
        StorageWriterEpoch? authorizedEpoch = null, StorageNodeId? authorizedNode = null) =>
        new(new StorageIntentScope(Claim, ProviderVolume, Attachment, Cell, authorizedNode ?? Node, Workload, Member,
                Domain, EncryptionKey, Placement, DeviceId, FilesystemId, FilesystemType, Layout, MountPurpose,
                Retention, Backup, Operation, WriterFence),
            ObservedBytes, RequestedBytes, ProviderBytes, BlockBytes, FilesystemBytes, UsedBytes, FreeBytes,
            ForecastExhaustion, Generation, authorizedEpoch ?? WriterEpoch, Performance, conflicts);

    public StorageEvidenceScope EvidenceScope => new(Claim, ProviderVolume, Attachment, Cell, Node, Workload, Member, DeviceId,
        FilesystemId, FilesystemType, Layout, RequestedBytes, ObservedBytes, ProviderBytes, BlockBytes, FilesystemBytes,
        UsedBytes, FreeBytes, Performance, ForecastExhaustion, Retention, Backup, Operation, WriterFence, Generation, WriterEpoch);

    public override string ToString() => "<storage-volume-record>";
}

public sealed record StorageEvidenceScope(
    VolumeClaimId Claim, ProviderVolumeId ProviderVolume, StorageAttachmentId Attachment, StorageCellId Cell,
    StorageNodeId Node, StorageWorkloadId Workload, StorageMemberId Member, StorageDeviceId DeviceId,
    FilesystemId FilesystemId, StorageFilesystemType FilesystemType, StorageLayout Layout, StorageBytes RequestedBytes,
    StorageBytes ObservedBytes, StorageBytes ProviderBytes, StorageBytes BlockBytes, StorageBytes FilesystemBytes,
    StorageBytes UsedBytes, StorageBytes FreeBytes, StoragePerformance Performance, StorageBytes ForecastExhaustion,
    StorageRetention Retention, StorageBackupId Backup, StorageOperationId Operation,
    StorageFenceId Fence, StorageGeneration Generation, StorageWriterEpoch WriterEpoch)
{
    internal bool IsWellFormed => Claim is not null && ProviderVolume is not null && Attachment is not null
        && Cell is not null && Node is not null && Workload is not null && Member is not null
        && DeviceId is not null && FilesystemId is not null
        && FilesystemType != StorageFilesystemType.Unknown && Enum.IsDefined(FilesystemType)
        && Layout != StorageLayout.Unknown && Enum.IsDefined(Layout)
        && Performance.Tier != StoragePerformanceTier.Unknown && Enum.IsDefined(Performance.Tier)
        && Retention != StorageRetention.Unknown && Enum.IsDefined(Retention) && Backup is not null
        && Operation is not null && Fence is not null
        && Generation.IsValid && WriterEpoch.IsValid;
    public override string ToString() => "<storage-evidence-scope>";
}

public sealed record StorageIntentScope
{
    internal StorageIntentScope(VolumeClaimId claim, ProviderVolumeId providerVolume,
        StorageAttachmentId attachment, StorageCellId cell, StorageNodeId node, StorageWorkloadId workload,
        StorageMemberId member, StorageDomain domain, EncryptionKeyReference encryptionKey,
        StoragePlacementId placement, StorageDeviceId deviceId, FilesystemId filesystemId,
        StorageFilesystemType filesystemType, StorageLayout layout, StorageMountPurpose mountPurpose,
        StorageRetention retention, StorageBackupId backup, StorageOperationId operation, StorageFenceId fence)
    {
        Claim = claim; ProviderVolume = providerVolume; Attachment = attachment; Cell = cell; Node = node; Workload = workload;
        Member = member; Domain = domain; EncryptionKey = encryptionKey; Placement = placement; DeviceId = deviceId;
        FilesystemId = filesystemId; FilesystemType = filesystemType; Layout = layout; MountPurpose = mountPurpose;
        Retention = retention; Backup = backup;
        Operation = operation; Fence = fence;
    }
    public VolumeClaimId Claim { get; }
    public ProviderVolumeId ProviderVolume { get; }
    public StorageAttachmentId Attachment { get; }
    public StorageCellId Cell { get; }
    public StorageNodeId Node { get; }
    public StorageWorkloadId Workload { get; }
    public StorageMemberId Member { get; }
    public StorageDomain Domain { get; }
    public EncryptionKeyReference EncryptionKey { get; }
    public StoragePlacementId Placement { get; }
    public StorageDeviceId DeviceId { get; }
    public FilesystemId FilesystemId { get; }
    public StorageFilesystemType FilesystemType { get; }
    public StorageLayout Layout { get; }
    public StorageMountPurpose MountPurpose { get; }
    public StorageRetention Retention { get; }
    public StorageBackupId Backup { get; }
    public StorageOperationId Operation { get; }
    public StorageFenceId Fence { get; }
    public override string ToString() => "<storage-intent-scope>";
}

public sealed class StorageAuthorityContext
{
    public StorageAuthorityContext(VolumeClaimId claim, ProviderVolumeId providerVolume, StorageCellId cell,
        StorageWorkloadId workload, StorageMemberId member, StorageFenceId fence,
        StorageGeneration generation, StorageWriterEpoch writerEpoch)
    { Claim = claim; ProviderVolume = providerVolume; Cell = cell; Workload = workload; Member = member; Fence = fence; Generation = generation; WriterEpoch = writerEpoch; }
    public VolumeClaimId Claim { get; }
    public ProviderVolumeId ProviderVolume { get; }
    public StorageCellId Cell { get; }
    public StorageWorkloadId Workload { get; }
    public StorageMemberId Member { get; }
    public StorageFenceId Fence { get; }
    public StorageGeneration Generation { get; }
    public StorageWriterEpoch WriterEpoch { get; }
    internal bool IsWellFormed => Claim is not null && ProviderVolume is not null && Cell is not null
        && Workload is not null && Member is not null && Fence is not null && Generation.IsValid && WriterEpoch.IsValid;
}

internal static class StorageAuthority
{
    public static StorageDecisionCode Validate(StorageVolumeRecord? volume, StorageAuthorityContext? context)
    {
        if (volume is null || !volume.IsWellFormed || context is null || !context.IsWellFormed) return StorageDecisionCode.InvalidInput;
        if (volume.ProviderVolume != context.ProviderVolume) return StorageDecisionCode.WrongProviderVolume;
        if (volume.Claim != context.Claim || volume.Cell != context.Cell || volume.Workload != context.Workload || volume.Member != context.Member)
            return StorageDecisionCode.WrongOwner;
        if (volume.WriterFence != context.Fence) return StorageDecisionCode.WrongFence;
        if (volume.Generation != context.Generation) return StorageDecisionCode.StaleGeneration;
        if (volume.WriterEpoch != context.WriterEpoch) return StorageDecisionCode.StaleWriterEpoch;
        return StorageDecisionCode.Completed;
    }
}

