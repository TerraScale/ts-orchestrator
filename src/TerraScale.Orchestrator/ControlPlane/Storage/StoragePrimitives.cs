using System.Globalization;

namespace TerraScale.Orchestrator.ControlPlane.Storage;

internal static class StorageIdentityRules
{
    public static bool IsValid(string? value, int maximumLength)
    {
        if (maximumLength <= 0 || string.IsNullOrEmpty(value) || value.Length > maximumLength) return false;
        for (var index = 0; index < value.Length; index++)
        {
            var character = value[index];
            if (char.IsWhiteSpace(character) || char.IsControl(character)) return false;
            if (char.IsHighSurrogate(character))
            {
                if (index + 1 >= value.Length || !char.IsLowSurrogate(value[index + 1])) return false;
                index++;
            }
            else if (char.IsLowSurrogate(character)) return false;
        }
        return true;
    }
}

public abstract record StorageIdentity
{
    protected StorageIdentity(string value) => Value = value;
    public string Value { get; }
    public override string ToString() => Value;
}

public sealed record StorageCellId : StorageIdentity
{ private StorageCellId(string v) : base(v) { } public static bool TryCreate(string? v, int m, out StorageCellId? r) { r = StorageIdentityRules.IsValid(v, m) ? new(v!) : null; return r is not null; } }
public sealed record VolumeClaimId : StorageIdentity
{ private VolumeClaimId(string v) : base(v) { } public static bool TryCreate(string? v, int m, out VolumeClaimId? r) { r = StorageIdentityRules.IsValid(v, m) ? new(v!) : null; return r is not null; } }
public sealed record ProviderVolumeId : StorageIdentity
{ private ProviderVolumeId(string v) : base(v) { } public static bool TryCreate(string? v, int m, out ProviderVolumeId? r) { r = StorageIdentityRules.IsValid(v, m) ? new(v!) : null; return r is not null; } }
public sealed record StorageAttachmentId : StorageIdentity
{ private StorageAttachmentId(string v) : base(v) { } public static bool TryCreate(string? v, int m, out StorageAttachmentId? r) { r = StorageIdentityRules.IsValid(v, m) ? new(v!) : null; return r is not null; } }
public sealed record StorageNodeId : StorageIdentity
{ private StorageNodeId(string v) : base(v) { } public static bool TryCreate(string? v, int m, out StorageNodeId? r) { r = StorageIdentityRules.IsValid(v, m) ? new(v!) : null; return r is not null; } }
public sealed record StorageWorkloadId : StorageIdentity
{ private StorageWorkloadId(string v) : base(v) { } public static bool TryCreate(string? v, int m, out StorageWorkloadId? r) { r = StorageIdentityRules.IsValid(v, m) ? new(v!) : null; return r is not null; } }
public sealed record StorageMemberId : StorageIdentity
{ private StorageMemberId(string v) : base(v) { } public static bool TryCreate(string? v, int m, out StorageMemberId? r) { r = StorageIdentityRules.IsValid(v, m) ? new(v!) : null; return r is not null; } }
public sealed record FilesystemId : StorageIdentity
{ private FilesystemId(string v) : base(v) { } public static bool TryCreate(string? v, int m, out FilesystemId? r) { r = StorageIdentityRules.IsValid(v, m) ? new(v!) : null; return r is not null; } }
public sealed record StorageOperationId : StorageIdentity
{ private StorageOperationId(string v) : base(v) { } public static bool TryCreate(string? v, int m, out StorageOperationId? r) { r = StorageIdentityRules.IsValid(v, m) ? new(v!) : null; return r is not null; } }
public sealed record StorageBackupId : StorageIdentity
{ private StorageBackupId(string v) : base(v) { } public static bool TryCreate(string? v, int m, out StorageBackupId? r) { r = StorageIdentityRules.IsValid(v, m) ? new(v!) : null; return r is not null; } }
public sealed record StorageFenceId : StorageIdentity
{ private StorageFenceId(string v) : base(v) { } public static bool TryCreate(string? v, int m, out StorageFenceId? r) { r = StorageIdentityRules.IsValid(v, m) ? new(v!) : null; return r is not null; } }
public sealed record EncryptionKeyReference : StorageIdentity
{ private EncryptionKeyReference(string v) : base(v) { } public static bool TryCreate(string? v, int m, out EncryptionKeyReference? r) { r = StorageIdentityRules.IsValid(v, m) ? new(v!) : null; return r is not null; } }
public sealed record StoragePlacementId : StorageIdentity
{ private StoragePlacementId(string v) : base(v) { } public static bool TryCreate(string? v, int m, out StoragePlacementId? r) { r = StorageIdentityRules.IsValid(v, m) ? new(v!) : null; return r is not null; } }
public sealed record StorageDeviceId : StorageIdentity
{ private StorageDeviceId(string v) : base(v) { } public static bool TryCreate(string? v, int m, out StorageDeviceId? r) { r = StorageIdentityRules.IsValid(v, m) ? new(v!) : null; return r is not null; } }

public readonly record struct StorageBytes
{
    private StorageBytes(long value) => Value = value;
    public long Value { get; }
    public static bool TryCreate(long value, out StorageBytes result) { result = value >= 0 ? new(value) : default; return value >= 0; }
    public override string ToString() => Value.ToString(CultureInfo.InvariantCulture);
}

public readonly record struct StorageGeneration
{
    private StorageGeneration(ulong value) => Value = value;
    public ulong Value { get; }
    public bool IsValid => Value > 0;
    public static bool TryCreate(ulong value, out StorageGeneration result) { result = value > 0 ? new(value) : default; return result.IsValid; }
}

public readonly record struct StorageWriterEpoch
{
    private StorageWriterEpoch(ulong value) => Value = value;
    public ulong Value { get; }
    public bool IsValid => Value > 0;
    public static bool TryCreate(ulong value, out StorageWriterEpoch result) { result = value > 0 ? new(value) : default; return result.IsValid; }
}

public readonly record struct StoragePerformance
{
    public StoragePerformance(StoragePerformanceTier tier, StorageBytes provisionedSetting,
        StorageBytes iops, StorageBytes throughput, StorageBytes latency,
        StorageBytes minimumIops, StorageBytes minimumThroughput, StorageBytes maximumLatency)
    {
        Tier = tier; ProvisionedSetting = provisionedSetting; Iops = iops; Throughput = throughput; Latency = latency;
        MinimumIops = minimumIops; MinimumThroughput = minimumThroughput; MaximumLatency = maximumLatency;
    }
    public StoragePerformanceTier Tier { get; }
    public StorageBytes ProvisionedSetting { get; }
    public StorageBytes Iops { get; }
    public StorageBytes Throughput { get; }
    public StorageBytes Latency { get; }
    public StorageBytes MinimumIops { get; }
    public StorageBytes MinimumThroughput { get; }
    public StorageBytes MaximumLatency { get; }
}

public enum StoragePerformanceTier { Unknown = 0, Economy, Balanced, HighPerformance, Custom }
public enum StorageFilesystemType { Unknown = 0, Ext4, Xfs }
public enum StorageLayout { Unknown = 0, WholeDevice, Partition, Lvm }
public enum StorageDomain { Unknown = 0, Boot, TerraBase, ProductJetStream, ControlJetStream, Observability, CiCache }
public enum StorageMountPurpose { Unknown = 0, Boot, DatabaseData, MessagingStore, TelemetryData, BuildCache }
public enum StorageRetention { Unknown = 0, Permanent, ElasticQuarantine, ExplicitDisposable }
public enum StorageProof { Unknown = 0, Proven, Contradicted }
public enum StorageDeviceClassification { Unknown = 0, Blank, Recognized }
public enum StorageAction { Uninitialized = 0, Observe, Create, Attach, Classify, Format, Mount, Rescan, Extend, Grow, Verify, Detach, Delete, Hold }
public enum StorageIntentTarget { None = 0, ProviderVolume, ProviderAttachment, DeviceIdentity, StorageLayout, Filesystem, Application, MetricsAndCost, PostDeleteAudit }

[Flags]
public enum StorageConflictClass
{
    None = 0, BackupRestore = 1, Topology = 2, MemberScaling = 4, Upgrade = 8,
    CertificateReplacement = 16, DetachReattach = 32, StorageOperation = 64,
}

public enum StorageDecisionCode
{
    Uninitialized = 0, NextStep, Completed, InvalidInput, WrongOwner, WrongProviderVolume, WrongFence,
    StaleGeneration, StaleWriterEpoch, BlankProofRequired, RecognizedVolumeNeverFormats,
    DualWriter, ReattachProofMissing, NewWriterEpochRequired, HealthVerificationRequired,
    ConflictingOperation, ShrinkForbidden, NoGrowthRequested, ArithmeticOverflow, SizeDisagreement,
    StepContradicted, ProviderConvergencePending, PermanentRetention, DeletionProofMissing,
    QuarantineProofMissing, DisposableProofMissing, PostDeleteAuditRequired,
    ConflictingObservation,
    WrongEvidenceScope,
}

public sealed record StorageNumericTrace
{
    internal StorageNumericTrace(StorageIntentScope scope, StorageBytes observed, StorageBytes requested, StorageBytes provider, StorageBytes block,
        StorageBytes filesystem, StorageBytes used, StorageBytes free, StorageBytes forecastExhaustion, StorageGeneration generation,
        StorageWriterEpoch epoch, StoragePerformance performance, StorageConflictClass conflicts)
    { Scope = scope; Observed = observed; Requested = requested; Provider = provider; Block = block; Filesystem = filesystem; Used = used; Free = free; ForecastExhaustion = forecastExhaustion; Generation = generation; Epoch = epoch; Performance = performance; Conflicts = conflicts; }
    public StorageIntentScope Scope { get; }
    public StorageBytes Observed { get; }
    public StorageBytes Requested { get; }
    public StorageBytes Provider { get; }
    public StorageBytes Block { get; }
    public StorageBytes Filesystem { get; }
    public StorageBytes Used { get; }
    public StorageBytes Free { get; }
    public StorageBytes ForecastExhaustion { get; }
    public StorageGeneration Generation { get; }
    public StorageWriterEpoch Epoch { get; }
    public StoragePerformance Performance { get; }
    public StorageConflictClass Conflicts { get; }
    public override string ToString() => string.Create(CultureInfo.InvariantCulture,
        $"observed={Observed.Value};requested={Requested.Value};provider={Provider.Value};block={Block.Value};filesystem={Filesystem.Value};used={Used.Value};free={Free.Value};forecast={ForecastExhaustion.Value};tier={(int)Performance.Tier};setting={Performance.ProvisionedSetting.Value};iops={Performance.Iops.Value};throughput={Performance.Throughput.Value};latency={Performance.Latency.Value};sloIops={Performance.MinimumIops.Value};sloThroughput={Performance.MinimumThroughput.Value};sloLatency={Performance.MaximumLatency.Value};generation={Generation.Value};epoch={Epoch.Value};conflicts={(int)Conflicts}");
}

public readonly record struct StorageDecision
{
    private StorageDecision(StorageAction action, StorageIntentTarget target, StorageDecisionCode code, StorageNumericTrace? trace)
    { Action = action; Target = target; Code = code; Trace = trace; }
    public StorageAction Action { get; }
    public StorageIntentTarget Target { get; }
    public StorageDecisionCode Code { get; }
    public StorageNumericTrace? Trace { get; }
    public StorageIntentScope? Scope => Trace?.Scope;
    public bool IsMutationAuthorized => Action is StorageAction.Create or StorageAction.Attach or StorageAction.Format
        or StorageAction.Mount or StorageAction.Rescan or StorageAction.Extend or StorageAction.Grow or StorageAction.Detach or StorageAction.Delete;
    internal static StorageDecision Emit(StorageAction action, StorageIntentTarget target, StorageDecisionCode code, StorageNumericTrace trace) => new(action, target, code, trace);
    internal static StorageDecision Hold(StorageDecisionCode code, StorageNumericTrace? trace = null) => new(StorageAction.Hold, StorageIntentTarget.None, code, trace);
    public override string ToString() => Trace is null ? $"action={Action};target={Target};code={Code}" : $"action={Action};target={Target};code={Code};trace=[{Trace}]";
}
