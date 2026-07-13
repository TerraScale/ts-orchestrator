using System.Collections.ObjectModel;
using System.Text.RegularExpressions;

namespace TerraScale.Orchestrator.ControlPlane.Runtime;

internal static partial class RuntimeIdentity
{
    public static string Token(string value, string name)
    {
        ArgumentNullException.ThrowIfNull(value, name);
        if (value.Length is < 1 or > 128 || !TokenPattern().IsMatch(value)) throw new ArgumentException("Runtime identity must be a bounded canonical token.", name);
        return value;
    }
    public static string Digest(string value, string name)
    {
        ArgumentNullException.ThrowIfNull(value, name);
        if (value.Length != 64 || value.Any(c => c is not (>= '0' and <= '9') and not (>= 'a' and <= 'f'))) throw new ArgumentException("Digest must be canonical SHA-256.", name);
        return value;
    }
    [GeneratedRegex("^[a-z0-9][a-z0-9]*(?:[.-][a-z0-9]+)*$", RegexOptions.CultureInvariant)]
    private static partial Regex TokenPattern();
}

public abstract record RuntimeToken { internal RuntimeToken(string value, string name) => Value = RuntimeIdentity.Token(value, name); public string Value { get; } public sealed override string ToString() => Value; }
public sealed record RuntimeWorkloadId : RuntimeToken { public RuntimeWorkloadId(string value) : base(value, nameof(value)) { } }
public sealed record RuntimeAllocationId : RuntimeToken { public RuntimeAllocationId(string value) : base(value, nameof(value)) { } }
public sealed record RuntimeNodeId : RuntimeToken { public RuntimeNodeId(string value) : base(value, nameof(value)) { } }
public sealed record RuntimeArtifactId : RuntimeToken { public RuntimeArtifactId(string value) : base(value, nameof(value)) { } }
public sealed record RuntimeSignatureId : RuntimeToken { public RuntimeSignatureId(string value) : base(value, nameof(value)) { } }
public sealed record RuntimeSigningProfileId : RuntimeToken { public RuntimeSigningProfileId(string value) : base(value, nameof(value)) { } }
public sealed record RuntimeHostImageId : RuntimeToken { public RuntimeHostImageId(string value) : base(value, nameof(value)) { } }
public sealed record RuntimeVersionId : RuntimeToken { public RuntimeVersionId(string value) : base(value, nameof(value)) { } }
public sealed record RuntimeConfigId : RuntimeToken { public RuntimeConfigId(string value) : base(value, nameof(value)) { } }
public sealed record RuntimeSecretVersionId : RuntimeToken { public RuntimeSecretVersionId(string value) : base(value, nameof(value)) { } }
public sealed record RuntimeVolumeId : RuntimeToken { public RuntimeVolumeId(string value) : base(value, nameof(value)) { } }
public sealed record RuntimeHealthId : RuntimeToken { public RuntimeHealthId(string value) : base(value, nameof(value)) { } }
public sealed record RuntimeReleaseId : RuntimeToken { public RuntimeReleaseId(string value) : base(value, nameof(value)) { } }
public sealed record RuntimeOperationId : RuntimeToken { public RuntimeOperationId(string value) : base(value, nameof(value)) { } }

public sealed record RuntimeDigest { public RuntimeDigest(string sha256) => Sha256 = RuntimeIdentity.Digest(sha256, nameof(sha256)); public string Sha256 { get; } }
public abstract record PositiveRuntimeNumber { internal PositiveRuntimeNumber(ulong value, string name) => Value = value > 0 ? value : throw new ArgumentOutOfRangeException(name); public ulong Value { get; } }
public sealed record RuntimeGeneration : PositiveRuntimeNumber { public RuntimeGeneration(ulong value) : base(value, nameof(value)) { } }
public sealed record RuntimeEpoch : PositiveRuntimeNumber { public RuntimeEpoch(ulong value) : base(value, nameof(value)) { } }
public sealed record RuntimeAttempt : PositiveRuntimeNumber { public RuntimeAttempt(ulong value) : base(value, nameof(value)) { } }
public sealed record RuntimeDurationSeconds : PositiveRuntimeNumber { public RuntimeDurationSeconds(ulong value) : base(value, nameof(value)) { } }
public sealed record RuntimePort { public RuntimePort(ushort value) => Value = value > 0 ? value : throw new ArgumentOutOfRangeException(nameof(value)); public ushort Value { get; } }

public enum RuntimeDriver { NativeSystemd = 1, OciContainer = 2 }
public enum RuntimeArchitecture { LinuxArm64 = 1, LinuxX64 = 2 }
public enum RuntimeRole { Orchestrator = 1, TerraBase = 2, Api = 3, Authentication = 4, Dashboard = 5, NatsServer = 6, Telemetry = 7, Grafana = 8, TrustedCi = 9 }
public enum NativeUnitDescriptor { Orchestrator = 1, TerraBase = 2, NatsServer = 3, Telemetry = 4 }
public enum OciRuntimeDescriptor { Api = 1, Authentication = 2, Dashboard = 3, TerraBase = 4, Telemetry = 5, Grafana = 6, TrustedCi = 7 }
public enum VolumeRetention { Retained = 1, Ephemeral = 2 }
public enum HealthDimension { Startup = 1, Liveness = 2, LocalReadiness = 3, DependencyReadiness = 4, DrainReadiness = 5, RolloutVerification = 6 }
public enum HealthStatus { Ready = 1, NotReady = 2, Failed = 3, Unknown = 4 }
public enum ProcessStatus { Absent = 1, Running = 2, ExitedSuccessfully = 3, Failed = 4, Unknown = 5 }
public enum LifecyclePhase { None = 1, ArtifactFetched = 2, ArtifactVerified = 3, Staged = 4, Mounted = 5, Started = 6, Serving = 7, Draining = 8, Stopped = 9, Cleaned = 10 }
public enum LifecycleAction { Converge = 1, Drain = 2, Stop = 3, Cleanup = 4 }
public enum ExecutorCallStatus { NotCalled = 1, Accepted = 2, ResponseLost = 3, Completed = 4 }
public enum UpdateSlot { A = 1, B = 2 }
public enum UpdatePhase { UpgradePlanned = 1, ArtifactVerified = 2, InactiveSlotStaged = 3, RollbackTimerArmed = 4, ProcessRestarted = 5, LocalHealthVerified = 6, RegionalCompatibilityVerified = 7, SlotCommitted = 8, OldSlotRetainedUntilSoak = 9, RollingBack = 10, RolledBack = 11, RollbackFailed = 12 }
public enum CompatibilityStatus { Compatible = 1, Incompatible = 2, Missing = 3, Unknown = 4 }
public enum ArtifactAvailability { Available = 1, Missing = 2, Conflicting = 3, Unknown = 4 }
public enum ArtifactVerificationStatus { Verified = 1, Failed = 2, Missing = 3, Unknown = 4 }
public enum EvidenceCompleteness { Complete = 1, Incomplete = 2, Unknown = 3 }
public enum UpdateCompatibilityWindow { NAndNMinusOne = 1 }
public enum UpdateRollbackPolicy { LocalKnownGoodOnHealthOrCompatibilityFailure = 1 }

internal static class RuntimeEnums
{
    public static T Defined<T>(T value, string name) where T : struct, Enum => Enum.IsDefined(value) ? value : throw new ArgumentOutOfRangeException(name);
    public static IReadOnlyList<T> CopyDistinct<T>(IEnumerable<T> source, string name) where T : struct, Enum
    {
        ArgumentNullException.ThrowIfNull(source, name); var values = source.ToArray();
        if (values.Any(v => !Enum.IsDefined(v))) throw new ArgumentOutOfRangeException(name);
        if (values.Length != values.Distinct().Count()) throw new ArgumentException("Duplicate catalog value.", name);
        return new ReadOnlyCollection<T>(values.Order().ToArray());
    }
    public static IReadOnlyList<T> Copy<T>(IEnumerable<T> source, string name) where T : notnull
    {
        ArgumentNullException.ThrowIfNull(source, name); var values = source.ToArray();
        if (values.Any(v => v is null)) throw new ArgumentException("Null runtime evidence.", name);
        return new ReadOnlyCollection<T>(values);
    }
}

public abstract record RuntimePayload
{
    internal RuntimePayload(RuntimeArtifactId artifactId, RuntimeDigest digest, RuntimeSignatureId signatureId, RuntimeSigningProfileId signingProfileId, RuntimeHostImageId hostImageId, RuntimeVersionId runtimeVersionId, RuntimeArchitecture architecture)
    { ArtifactId = artifactId ?? throw new ArgumentNullException(nameof(artifactId)); Digest = digest ?? throw new ArgumentNullException(nameof(digest)); SignatureId = signatureId ?? throw new ArgumentNullException(nameof(signatureId)); SigningProfileId = signingProfileId ?? throw new ArgumentNullException(nameof(signingProfileId)); HostImageId = hostImageId ?? throw new ArgumentNullException(nameof(hostImageId)); RuntimeVersionId = runtimeVersionId ?? throw new ArgumentNullException(nameof(runtimeVersionId)); Architecture = RuntimeEnums.Defined(architecture, nameof(architecture)); }
    public RuntimeArtifactId ArtifactId { get; }
    public RuntimeDigest Digest { get; }
    public RuntimeSignatureId SignatureId { get; }
    public RuntimeSigningProfileId SigningProfileId { get; }
    public RuntimeHostImageId HostImageId { get; }
    public RuntimeVersionId RuntimeVersionId { get; }
    public RuntimeArchitecture Architecture { get; }
    public abstract RuntimeDriver Driver { get; }
    public abstract RuntimeDigest ActivationDigest { get; }
}
public sealed record NativeRuntimePayload : RuntimePayload
{
    public NativeRuntimePayload(RuntimeArtifactId artifactId, RuntimeDigest digest, RuntimeSignatureId signatureId, RuntimeSigningProfileId signingProfileId, RuntimeHostImageId hostImageId, RuntimeVersionId runtimeVersionId, RuntimeArchitecture architecture, NativeUnitDescriptor descriptor) : base(artifactId, digest, signatureId, signingProfileId, hostImageId, runtimeVersionId, architecture) => Descriptor = RuntimeEnums.Defined(descriptor, nameof(descriptor));
    public NativeUnitDescriptor Descriptor { get; }
    public override RuntimeDriver Driver => RuntimeDriver.NativeSystemd;
    public override RuntimeDigest ActivationDigest => Digest;
}
public sealed record OciRuntimePayload : RuntimePayload
{
    public OciRuntimePayload(RuntimeArtifactId artifactId, RuntimeDigest manifestDigest, RuntimeDigest imageDigest, RuntimeSignatureId signatureId, RuntimeSigningProfileId signingProfileId, RuntimeHostImageId hostImageId, RuntimeVersionId runtimeVersionId, RuntimeArchitecture architecture, OciRuntimeDescriptor descriptor) : base(artifactId, manifestDigest, signatureId, signingProfileId, hostImageId, runtimeVersionId, architecture)
    { ImageDigest = imageDigest ?? throw new ArgumentNullException(nameof(imageDigest)); Descriptor = RuntimeEnums.Defined(descriptor, nameof(descriptor)); }
    public RuntimeDigest ImageDigest { get; }
    public OciRuntimeDescriptor Descriptor { get; }
    public override RuntimeDriver Driver => RuntimeDriver.OciContainer;
    public override RuntimeDigest ActivationDigest => ImageDigest;
}

public sealed record RuntimeVolumeBinding
{
    public RuntimeVolumeBinding(RuntimeVolumeId volumeId, VolumeRetention retention) { VolumeId = volumeId ?? throw new ArgumentNullException(nameof(volumeId)); Retention = RuntimeEnums.Defined(retention, nameof(retention)); }
    public RuntimeVolumeId VolumeId { get; }
    public VolumeRetention Retention { get; }
}

public sealed record WorkloadRuntimeSpec
{
    public WorkloadRuntimeSpec(RuntimeWorkloadId workloadId, RuntimeAllocationId allocationId, RuntimeNodeId nodeId, RuntimeRole role, RuntimeGeneration generation, RuntimeConfigId configId, RuntimePayload payload, IEnumerable<RuntimeSecretVersionId> secretVersions, IEnumerable<RuntimeVolumeBinding> volumes, IEnumerable<RuntimePort> ports, IEnumerable<HealthDimension> requiredHealth)
    {
        WorkloadId = workloadId ?? throw new ArgumentNullException(nameof(workloadId)); AllocationId = allocationId ?? throw new ArgumentNullException(nameof(allocationId)); NodeId = nodeId ?? throw new ArgumentNullException(nameof(nodeId));
        Role = RuntimeEnums.Defined(role, nameof(role)); Generation = generation ?? throw new ArgumentNullException(nameof(generation)); ConfigId = configId ?? throw new ArgumentNullException(nameof(configId)); Payload = payload ?? throw new ArgumentNullException(nameof(payload));
        SecretVersions = RuntimeEnums.Copy(secretVersions, nameof(secretVersions)).OrderBy(v => v.Value, StringComparer.Ordinal).ToArray();
        Volumes = RuntimeEnums.Copy(volumes, nameof(volumes)).OrderBy(v => v.VolumeId.Value, StringComparer.Ordinal).ToArray();
        Ports = RuntimeEnums.Copy(ports, nameof(ports)).OrderBy(v => v.Value).ToArray();
        RequiredHealth = RuntimeEnums.CopyDistinct(requiredHealth, nameof(requiredHealth));
        if (SecretVersions.Count != SecretVersions.Distinct().Count() || Volumes.Select(v => v.VolumeId).Distinct().Count() != Volumes.Count || Ports.Distinct().Count() != Ports.Count) throw new ArgumentException("Duplicate runtime binding.");
        if (!RequiredHealth.Contains(HealthDimension.Liveness) || !RequiredHealth.Contains(HealthDimension.LocalReadiness) || !RequiredHealth.Contains(HealthDimension.DependencyReadiness)) throw new ArgumentException("Liveness, local readiness, and dependency readiness are mandatory.", nameof(requiredHealth));
    }
    public RuntimeWorkloadId WorkloadId { get; }
    public RuntimeAllocationId AllocationId { get; }
    public RuntimeNodeId NodeId { get; }
    public RuntimeRole Role { get; }
    public RuntimeGeneration Generation { get; }
    public RuntimeConfigId ConfigId { get; }
    public RuntimePayload Payload { get; }
    public IReadOnlyList<RuntimeSecretVersionId> SecretVersions { get; }
    public IReadOnlyList<RuntimeVolumeBinding> Volumes { get; }
    public IReadOnlyList<RuntimePort> Ports { get; }
    public IReadOnlyList<HealthDimension> RequiredHealth { get; }
}

public sealed record RuntimeAdmission
{
    public RuntimeAdmission(RuntimeRole role, RuntimeDriver driver, RuntimeArchitecture architecture, RuntimeGeneration policyGeneration)
    { Role = RuntimeEnums.Defined(role, nameof(role)); Driver = RuntimeEnums.Defined(driver, nameof(driver)); Architecture = RuntimeEnums.Defined(architecture, nameof(architecture)); PolicyGeneration = policyGeneration ?? throw new ArgumentNullException(nameof(policyGeneration)); }
    public RuntimeRole Role { get; }
    public RuntimeDriver Driver { get; }
    public RuntimeArchitecture Architecture { get; }
    public RuntimeGeneration PolicyGeneration { get; }
}

public sealed record RuntimeHealthEvidence
{
    public RuntimeHealthEvidence(RuntimeHealthId id, RuntimeOperationId operationId, RuntimeAllocationId allocationId, RuntimeGeneration generation, HealthDimension dimension, HealthStatus status)
    { Id = id ?? throw new ArgumentNullException(nameof(id)); OperationId = operationId ?? throw new ArgumentNullException(nameof(operationId)); AllocationId = allocationId ?? throw new ArgumentNullException(nameof(allocationId)); Generation = generation ?? throw new ArgumentNullException(nameof(generation)); Dimension = RuntimeEnums.Defined(dimension, nameof(dimension)); Status = RuntimeEnums.Defined(status, nameof(status)); }
    public RuntimeHealthId Id { get; }
    public RuntimeOperationId OperationId { get; }
    public RuntimeAllocationId AllocationId { get; }
    public RuntimeGeneration Generation { get; }
    public HealthDimension Dimension { get; }
    public HealthStatus Status { get; }
}

public sealed record RuntimeObservation
{
    public RuntimeObservation(RuntimeOperationId operationId, RuntimeAllocationId allocationId, RuntimeEpoch epoch, RuntimeGeneration generation, LifecyclePhase phase, RuntimeDigest artifactDigest, ProcessStatus processStatus, ExecutorCallStatus callStatus)
    { OperationId = operationId ?? throw new ArgumentNullException(nameof(operationId)); AllocationId = allocationId ?? throw new ArgumentNullException(nameof(allocationId)); Epoch = epoch ?? throw new ArgumentNullException(nameof(epoch)); Generation = generation ?? throw new ArgumentNullException(nameof(generation)); Phase = RuntimeEnums.Defined(phase, nameof(phase)); ArtifactDigest = artifactDigest ?? throw new ArgumentNullException(nameof(artifactDigest)); ProcessStatus = RuntimeEnums.Defined(processStatus, nameof(processStatus)); CallStatus = RuntimeEnums.Defined(callStatus, nameof(callStatus)); }
    public RuntimeOperationId OperationId { get; }
    public RuntimeAllocationId AllocationId { get; }
    public RuntimeEpoch Epoch { get; }
    public RuntimeGeneration Generation { get; }
    public LifecyclePhase Phase { get; }
    public RuntimeDigest ArtifactDigest { get; }
    public ProcessStatus ProcessStatus { get; }
    public ExecutorCallStatus CallStatus { get; }
}

public sealed record RuntimeConflictEvidence
{
    public RuntimeConflictEvidence(RuntimeAllocationId allocationId, RuntimeNodeId nodeId, IEnumerable<RuntimePort> ports, IEnumerable<RuntimeVolumeId> volumes)
    { AllocationId = allocationId ?? throw new ArgumentNullException(nameof(allocationId)); NodeId = nodeId ?? throw new ArgumentNullException(nameof(nodeId)); Ports = RuntimeEnums.Copy(ports, nameof(ports)); Volumes = RuntimeEnums.Copy(volumes, nameof(volumes)); }
    public RuntimeAllocationId AllocationId { get; }
    public RuntimeNodeId NodeId { get; }
    public IReadOnlyList<RuntimePort> Ports { get; }
    public IReadOnlyList<RuntimeVolumeId> Volumes { get; }
}

public sealed record RuntimeInventoryEvidence
{
    public RuntimeInventoryEvidence(RuntimeOperationId operationId, RuntimeNodeId nodeId, RuntimeGeneration generation, EvidenceCompleteness completeness, IEnumerable<RuntimeConflictEvidence> allocations)
    { OperationId = operationId ?? throw new ArgumentNullException(nameof(operationId)); NodeId = nodeId ?? throw new ArgumentNullException(nameof(nodeId)); Generation = generation ?? throw new ArgumentNullException(nameof(generation)); Completeness = RuntimeEnums.Defined(completeness, nameof(completeness)); Allocations = RuntimeEnums.Copy(allocations, nameof(allocations)); if (Allocations.Select(a => a.AllocationId).Distinct().Count() != Allocations.Count) throw new ArgumentException("Duplicate allocation inventory.", nameof(allocations)); if (Allocations.Any(a => a.NodeId != NodeId)) throw new ArgumentException("Allocation inventory must belong to its scoped node.", nameof(allocations)); }
    public RuntimeOperationId OperationId { get; }
    public RuntimeNodeId NodeId { get; }
    public RuntimeGeneration Generation { get; }
    public EvidenceCompleteness Completeness { get; }
    public IReadOnlyList<RuntimeConflictEvidence> Allocations { get; }
}

public sealed record RuntimeLifecycleRequest
{
    public RuntimeLifecycleRequest(RuntimeOperationId operationId, RuntimeEpoch epoch, RuntimeEpoch currentEpoch, RuntimeGeneration currentGeneration, RuntimeGeneration admissionPolicyGeneration, RuntimeDurationSeconds healthTimeout, WorkloadRuntimeSpec spec, RuntimeAdmission admission, LifecycleAction action, RuntimeObservation observation, IEnumerable<RuntimeHealthEvidence> health, RuntimeInventoryEvidence inventory)
    { OperationId = operationId ?? throw new ArgumentNullException(nameof(operationId)); Epoch = epoch ?? throw new ArgumentNullException(nameof(epoch)); CurrentEpoch = currentEpoch ?? throw new ArgumentNullException(nameof(currentEpoch)); CurrentGeneration = currentGeneration ?? throw new ArgumentNullException(nameof(currentGeneration)); AdmissionPolicyGeneration = admissionPolicyGeneration ?? throw new ArgumentNullException(nameof(admissionPolicyGeneration)); HealthTimeout = healthTimeout ?? throw new ArgumentNullException(nameof(healthTimeout)); Spec = spec ?? throw new ArgumentNullException(nameof(spec)); Admission = admission ?? throw new ArgumentNullException(nameof(admission)); Action = RuntimeEnums.Defined(action, nameof(action)); Observation = observation ?? throw new ArgumentNullException(nameof(observation)); Health = RuntimeEnums.Copy(health, nameof(health)); Inventory = inventory ?? throw new ArgumentNullException(nameof(inventory)); }
    public RuntimeOperationId OperationId { get; }
    public RuntimeEpoch Epoch { get; }
    public RuntimeEpoch CurrentEpoch { get; }
    public RuntimeGeneration CurrentGeneration { get; }
    public RuntimeGeneration AdmissionPolicyGeneration { get; }
    public RuntimeDurationSeconds HealthTimeout { get; }
    public WorkloadRuntimeSpec Spec { get; }
    public RuntimeAdmission Admission { get; }
    public LifecycleAction Action { get; }
    public RuntimeObservation Observation { get; }
    public IReadOnlyList<RuntimeHealthEvidence> Health { get; }
    public RuntimeInventoryEvidence Inventory { get; }
}

public sealed record UpdateArtifactSubject
{
    public UpdateArtifactSubject(RuntimeReleaseId releaseId, RuntimeArtifactId artifactId, RuntimeDigest digest, RuntimeSignatureId signatureId, RuntimeSigningProfileId signingProfileId, RuntimeArchitecture architecture, RuntimeGeneration generation)
    { ReleaseId = releaseId ?? throw new ArgumentNullException(nameof(releaseId)); ArtifactId = artifactId ?? throw new ArgumentNullException(nameof(artifactId)); Digest = digest ?? throw new ArgumentNullException(nameof(digest)); SignatureId = signatureId ?? throw new ArgumentNullException(nameof(signatureId)); SigningProfileId = signingProfileId ?? throw new ArgumentNullException(nameof(signingProfileId)); Architecture = RuntimeEnums.Defined(architecture, nameof(architecture)); Generation = generation ?? throw new ArgumentNullException(nameof(generation)); }
    public RuntimeReleaseId ReleaseId { get; }
    public RuntimeArtifactId ArtifactId { get; }
    public RuntimeDigest Digest { get; }
    public RuntimeSignatureId SignatureId { get; }
    public RuntimeSigningProfileId SigningProfileId { get; }
    public RuntimeArchitecture Architecture { get; }
    public RuntimeGeneration Generation { get; }
}

public sealed record UpdateArtifactEvidence
{
    public UpdateArtifactEvidence(RuntimeReleaseId releaseId, RuntimeArtifactId artifactId, RuntimeDigest digest, RuntimeSignatureId signatureId, RuntimeSigningProfileId signingProfileId, RuntimeArchitecture architecture, RuntimeGeneration generation, ArtifactAvailability availability, ArtifactVerificationStatus verification)
    { ReleaseId = releaseId ?? throw new ArgumentNullException(nameof(releaseId)); ArtifactId = artifactId ?? throw new ArgumentNullException(nameof(artifactId)); Digest = digest ?? throw new ArgumentNullException(nameof(digest)); SignatureId = signatureId ?? throw new ArgumentNullException(nameof(signatureId)); SigningProfileId = signingProfileId ?? throw new ArgumentNullException(nameof(signingProfileId)); Architecture = RuntimeEnums.Defined(architecture, nameof(architecture)); Generation = generation ?? throw new ArgumentNullException(nameof(generation)); Availability = RuntimeEnums.Defined(availability, nameof(availability)); Verification = RuntimeEnums.Defined(verification, nameof(verification)); }
    public RuntimeReleaseId ReleaseId { get; }
    public RuntimeArtifactId ArtifactId { get; }
    public RuntimeDigest Digest { get; }
    public RuntimeSignatureId SignatureId { get; }
    public RuntimeSigningProfileId SigningProfileId { get; }
    public RuntimeArchitecture Architecture { get; }
    public RuntimeGeneration Generation { get; }
    public ArtifactAvailability Availability { get; }
    public ArtifactVerificationStatus Verification { get; }
}

public sealed record UpdateCompatibilityEvidence
{
    public UpdateCompatibilityEvidence(RuntimeOperationId operationId, RuntimeGeneration currentGeneration, RuntimeGeneration targetGeneration, RuntimeGeneration protocolGeneration, RuntimeGeneration schemaGeneration, CompatibilityStatus nToNMinusOne, CompatibilityStatus status)
    { OperationId = operationId ?? throw new ArgumentNullException(nameof(operationId)); CurrentGeneration = currentGeneration ?? throw new ArgumentNullException(nameof(currentGeneration)); TargetGeneration = targetGeneration ?? throw new ArgumentNullException(nameof(targetGeneration)); ProtocolGeneration = protocolGeneration ?? throw new ArgumentNullException(nameof(protocolGeneration)); SchemaGeneration = schemaGeneration ?? throw new ArgumentNullException(nameof(schemaGeneration)); NToNMinusOne = RuntimeEnums.Defined(nToNMinusOne, nameof(nToNMinusOne)); Status = RuntimeEnums.Defined(status, nameof(status)); }
    public RuntimeOperationId OperationId { get; }
    public RuntimeGeneration CurrentGeneration { get; }
    public RuntimeGeneration TargetGeneration { get; }
    public RuntimeGeneration ProtocolGeneration { get; }
    public RuntimeGeneration SchemaGeneration { get; }
    public CompatibilityStatus NToNMinusOne { get; }
    public CompatibilityStatus Status { get; }
}

public sealed record SelfUpdateObservation
{
    public SelfUpdateObservation(RuntimeOperationId operationId, RuntimeNodeId nodeId, RuntimeEpoch epoch, RuntimeGeneration targetGeneration, UpdatePhase phase, UpdateSlot activeSlot, UpdateSlot inactiveSlot, ExecutorCallStatus callStatus)
    { OperationId = operationId ?? throw new ArgumentNullException(nameof(operationId)); NodeId = nodeId ?? throw new ArgumentNullException(nameof(nodeId)); Epoch = epoch ?? throw new ArgumentNullException(nameof(epoch)); TargetGeneration = targetGeneration ?? throw new ArgumentNullException(nameof(targetGeneration)); Phase = RuntimeEnums.Defined(phase, nameof(phase)); ActiveSlot = RuntimeEnums.Defined(activeSlot, nameof(activeSlot)); InactiveSlot = RuntimeEnums.Defined(inactiveSlot, nameof(inactiveSlot)); CallStatus = RuntimeEnums.Defined(callStatus, nameof(callStatus)); if (activeSlot == inactiveSlot) throw new ArgumentException("A/B slots must be distinct."); }
    public RuntimeOperationId OperationId { get; }
    public RuntimeNodeId NodeId { get; }
    public RuntimeEpoch Epoch { get; }
    public RuntimeGeneration TargetGeneration { get; }
    public UpdatePhase Phase { get; }
    public UpdateSlot ActiveSlot { get; }
    public UpdateSlot InactiveSlot { get; }
    public ExecutorCallStatus CallStatus { get; }
}

public sealed record SelfUpdateRequest
{
    public SelfUpdateRequest(RuntimeOperationId operationId, RuntimeNodeId nodeId, RuntimeAllocationId allocationId, RuntimeEpoch epoch, RuntimeEpoch currentEpoch, RuntimeArchitecture architecture, RuntimeGeneration currentGeneration, RuntimeGeneration targetGeneration, RuntimeGeneration currentProtocolGeneration, RuntimeGeneration currentSchemaGeneration, RuntimeDurationSeconds healthTimeout, RuntimeDurationSeconds soakDuration, UpdateCompatibilityWindow compatibilityWindow, UpdateRollbackPolicy rollbackPolicy, UpdateSlot expectedActiveSlot, UpdateSlot expectedInactiveSlot, UpdateArtifactSubject expectedForwardArtifact, UpdateArtifactSubject expectedRollbackArtifact, UpdateArtifactEvidence forwardArtifact, UpdateArtifactEvidence rollbackArtifact, UpdateCompatibilityEvidence compatibility, SelfUpdateObservation observation, IEnumerable<RuntimeHealthEvidence> health)
    { OperationId = operationId ?? throw new ArgumentNullException(nameof(operationId)); NodeId = nodeId ?? throw new ArgumentNullException(nameof(nodeId)); AllocationId = allocationId ?? throw new ArgumentNullException(nameof(allocationId)); Epoch = epoch ?? throw new ArgumentNullException(nameof(epoch)); CurrentEpoch = currentEpoch ?? throw new ArgumentNullException(nameof(currentEpoch)); Architecture = RuntimeEnums.Defined(architecture, nameof(architecture)); CurrentGeneration = currentGeneration ?? throw new ArgumentNullException(nameof(currentGeneration)); TargetGeneration = targetGeneration ?? throw new ArgumentNullException(nameof(targetGeneration)); CurrentProtocolGeneration = currentProtocolGeneration ?? throw new ArgumentNullException(nameof(currentProtocolGeneration)); CurrentSchemaGeneration = currentSchemaGeneration ?? throw new ArgumentNullException(nameof(currentSchemaGeneration)); HealthTimeout = healthTimeout ?? throw new ArgumentNullException(nameof(healthTimeout)); SoakDuration = soakDuration ?? throw new ArgumentNullException(nameof(soakDuration)); CompatibilityWindow = RuntimeEnums.Defined(compatibilityWindow, nameof(compatibilityWindow)); RollbackPolicy = RuntimeEnums.Defined(rollbackPolicy, nameof(rollbackPolicy)); ExpectedActiveSlot = RuntimeEnums.Defined(expectedActiveSlot, nameof(expectedActiveSlot)); ExpectedInactiveSlot = RuntimeEnums.Defined(expectedInactiveSlot, nameof(expectedInactiveSlot)); if (ExpectedActiveSlot == ExpectedInactiveSlot) throw new ArgumentException("Expected A/B slots must be distinct."); ExpectedForwardArtifact = expectedForwardArtifact ?? throw new ArgumentNullException(nameof(expectedForwardArtifact)); ExpectedRollbackArtifact = expectedRollbackArtifact ?? throw new ArgumentNullException(nameof(expectedRollbackArtifact)); ForwardArtifact = forwardArtifact ?? throw new ArgumentNullException(nameof(forwardArtifact)); RollbackArtifact = rollbackArtifact ?? throw new ArgumentNullException(nameof(rollbackArtifact)); Compatibility = compatibility ?? throw new ArgumentNullException(nameof(compatibility)); Observation = observation ?? throw new ArgumentNullException(nameof(observation)); Health = RuntimeEnums.Copy(health, nameof(health)); }
    public RuntimeOperationId OperationId { get; }
    public RuntimeNodeId NodeId { get; }
    public RuntimeAllocationId AllocationId { get; }
    public RuntimeEpoch Epoch { get; }
    public RuntimeEpoch CurrentEpoch { get; }
    public RuntimeArchitecture Architecture { get; }
    public RuntimeGeneration CurrentGeneration { get; }
    public RuntimeGeneration TargetGeneration { get; }
    public RuntimeGeneration CurrentProtocolGeneration { get; }
    public RuntimeGeneration CurrentSchemaGeneration { get; }
    public RuntimeDurationSeconds HealthTimeout { get; }
    public RuntimeDurationSeconds SoakDuration { get; }
    public UpdateCompatibilityWindow CompatibilityWindow { get; }
    public UpdateRollbackPolicy RollbackPolicy { get; }
    public UpdateSlot ExpectedActiveSlot { get; }
    public UpdateSlot ExpectedInactiveSlot { get; }
    public UpdateArtifactSubject ExpectedForwardArtifact { get; }
    public UpdateArtifactSubject ExpectedRollbackArtifact { get; }
    public UpdateArtifactEvidence ForwardArtifact { get; }
    public UpdateArtifactEvidence RollbackArtifact { get; }
    public UpdateCompatibilityEvidence Compatibility { get; }
    public SelfUpdateObservation Observation { get; }
    public IReadOnlyList<RuntimeHealthEvidence> Health { get; }
}

public enum RuntimeDecisionCode { EvidenceComplete = 1, EvidenceUnique = 2, EvidenceConsistent = 3, OperationExact = 4, EpochCurrent = 5, GenerationCurrent = 6, AdmissionExact = 7, ArchitectureExact = 8, ArtifactExact = 9, PortConflictFree = 10, VolumeConflictFree = 11, HealthExact = 12, ReadinessComplete = 13, CallSafe = 14, SlotDistinct = 15, ForwardAvailable = 16, RollbackAvailable = 17, CompatibilityExact = 18, PhaseResumable = 19, RollbackPossible = 20, ProcessConsistent = 21 }
public enum RuntimeDecisionOutcome { Passed = 1, Rejected = 2, Held = 3, NotApplicable = 4 }
public sealed record RuntimeDecisionReason { internal RuntimeDecisionReason(RuntimeDecisionCode code, RuntimeDecisionOutcome outcome, ulong observed, ulong required) { Code = code; Outcome = outcome; Observed = observed; Required = required; } public RuntimeDecisionCode Code { get; } public RuntimeDecisionOutcome Outcome { get; } public ulong Observed { get; } public ulong Required { get; } }

public abstract record RuntimeIntent { internal RuntimeIntent(RuntimeOperationId operationId) => OperationId = operationId; public RuntimeOperationId OperationId { get; } }
public sealed record FetchRuntimeArtifactIntent : RuntimeIntent { internal FetchRuntimeArtifactIntent(RuntimeLifecycleRequest r) : base(r.OperationId) => Request = r; public RuntimeLifecycleRequest Request { get; } }
public sealed record VerifyRuntimeArtifactIntent : RuntimeIntent { internal VerifyRuntimeArtifactIntent(RuntimeLifecycleRequest r) : base(r.OperationId) => Request = r; public RuntimeLifecycleRequest Request { get; } }
public sealed record StageRuntimeIntent : RuntimeIntent { internal StageRuntimeIntent(RuntimeLifecycleRequest r) : base(r.OperationId) => Request = r; public RuntimeLifecycleRequest Request { get; } }
public sealed record MountRuntimeIntent : RuntimeIntent { internal MountRuntimeIntent(RuntimeLifecycleRequest r) : base(r.OperationId) => Request = r; public RuntimeLifecycleRequest Request { get; } }
public sealed record StartRuntimeIntent : RuntimeIntent { internal StartRuntimeIntent(RuntimeLifecycleRequest r) : base(r.OperationId) => Request = r; public RuntimeLifecycleRequest Request { get; } }
public sealed record CheckRuntimeHealthIntent : RuntimeIntent { internal CheckRuntimeHealthIntent(RuntimeOperationId operationId, RuntimeAllocationId allocationId) : base(operationId) => AllocationId = allocationId; public RuntimeAllocationId AllocationId { get; } }
public sealed record DrainRuntimeIntent : RuntimeIntent { internal DrainRuntimeIntent(RuntimeLifecycleRequest r) : base(r.OperationId) => Request = r; public RuntimeLifecycleRequest Request { get; } }
public sealed record StopRuntimeIntent : RuntimeIntent { internal StopRuntimeIntent(RuntimeLifecycleRequest r) : base(r.OperationId) => Request = r; public RuntimeLifecycleRequest Request { get; } }
public sealed record CleanupRuntimeIntent : RuntimeIntent { internal CleanupRuntimeIntent(RuntimeLifecycleRequest r) : base(r.OperationId) => EphemeralVolumes = r.Spec.Volumes.Where(v => v.Retention == VolumeRetention.Ephemeral).Select(v => v.VolumeId).ToArray(); public IReadOnlyList<RuntimeVolumeId> EphemeralVolumes { get; } }
public sealed record ObserveExecutorIntent : RuntimeIntent { internal ObserveExecutorIntent(RuntimeOperationId operationId, RuntimeAllocationId allocationId) : base(operationId) => AllocationId = allocationId; public RuntimeAllocationId AllocationId { get; } }
public sealed record VerifyUpdateArtifactIntent : RuntimeIntent { internal VerifyUpdateArtifactIntent(SelfUpdateRequest r) : base(r.OperationId) => Request = r; public SelfUpdateRequest Request { get; } }
public sealed record StageInactiveSlotIntent : RuntimeIntent { internal StageInactiveSlotIntent(SelfUpdateRequest r) : base(r.OperationId) => Request = r; public SelfUpdateRequest Request { get; } }
public sealed record ArmRollbackIntent : RuntimeIntent { internal ArmRollbackIntent(SelfUpdateRequest r) : base(r.OperationId) => Request = r; public SelfUpdateRequest Request { get; } }
public sealed record SwitchUpdateSlotIntent : RuntimeIntent { internal SwitchUpdateSlotIntent(SelfUpdateRequest r) : base(r.OperationId) => Request = r; public SelfUpdateRequest Request { get; } }
public sealed record ObserveUpdateIntent : RuntimeIntent { internal ObserveUpdateIntent(SelfUpdateRequest r) : base(r.OperationId) => Request = r; public SelfUpdateRequest Request { get; } }
public sealed record VerifyRegionalCompatibilityIntent : RuntimeIntent { internal VerifyRegionalCompatibilityIntent(SelfUpdateRequest r) : base(r.OperationId) => Request = r; public SelfUpdateRequest Request { get; } }
public sealed record CommitUpdateSlotIntent : RuntimeIntent { internal CommitUpdateSlotIntent(SelfUpdateRequest r) : base(r.OperationId) => Request = r; public SelfUpdateRequest Request { get; } }
public sealed record RollbackUpdateIntent : RuntimeIntent { internal RollbackUpdateIntent(SelfUpdateRequest r) : base(r.OperationId) => Request = r; public SelfUpdateRequest Request { get; } }
public sealed record RetainOldUpdateSlotIntent : RuntimeIntent { internal RetainOldUpdateSlotIntent(SelfUpdateRequest r) : base(r.OperationId) => Request = r; public SelfUpdateRequest Request { get; } }
public sealed record CompleteSelfUpdateIntent : RuntimeIntent { internal CompleteSelfUpdateIntent(SelfUpdateRequest r) : base(r.OperationId) => Request = r; public SelfUpdateRequest Request { get; } }
public sealed record HoldRuntimeIntent : RuntimeIntent { internal HoldRuntimeIntent(RuntimeOperationId operationId) : base(operationId) { } }
public sealed record RuntimeDecision { internal RuntimeDecision(bool authorized, IReadOnlyList<RuntimeDecisionReason> trace, RuntimeIntent intent) { Authorized = authorized; Trace = trace; Intent = intent; } public bool Authorized { get; } public IReadOnlyList<RuntimeDecisionReason> Trace { get; } public RuntimeIntent Intent { get; } }
