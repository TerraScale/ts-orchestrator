// Port of src/TerraScale.Orchestrator/ControlPlane/Runtime/RuntimeModels.cs
package control

import (
	"regexp"
	"sort"
)

var runtimeIdentityTokenPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9]*(?:[.-][a-z0-9]+)*$`)

// runtimeIdentity ports the internal RuntimeIdentity helpers.
var runtimeIdentity runtimeIdentityStatic

type runtimeIdentityStatic struct{}

func (runtimeIdentityStatic) Token(value, name string) (string, error) {
	if len(value) < 1 || len(value) > 128 || !runtimeIdentityTokenPattern.MatchString(value) {
		return "", invalidArgument("Runtime identity must be a bounded canonical token.")
	}
	return value, nil
}

func (runtimeIdentityStatic) Digest(value, name string) (string, error) {
	if len(value) != 64 {
		return "", invalidArgument("Digest must be canonical SHA-256.")
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", invalidArgument("Digest must be canonical SHA-256.")
		}
	}
	return value, nil
}

// RuntimeToken is the Go form of the abstract RuntimeToken record.
type RuntimeToken struct {
	Value string
}

func newRuntimeToken(value, name string) (RuntimeToken, error) {
	token, err := runtimeIdentity.Token(value, name)
	if err != nil {
		return RuntimeToken{}, err
	}
	return RuntimeToken{Value: token}, nil
}

type RuntimeWorkloadId struct{ RuntimeToken }

func NewRuntimeWorkloadId(value string) (RuntimeWorkloadId, error) {
	token, err := newRuntimeToken(value, "value")
	return RuntimeWorkloadId{token}, err
}

type RuntimeAllocationId struct{ RuntimeToken }

func NewRuntimeAllocationId(value string) (RuntimeAllocationId, error) {
	token, err := newRuntimeToken(value, "value")
	return RuntimeAllocationId{token}, err
}

type RuntimeNodeId struct{ RuntimeToken }

func NewRuntimeNodeId(value string) (RuntimeNodeId, error) {
	token, err := newRuntimeToken(value, "value")
	return RuntimeNodeId{token}, err
}

type RuntimeArtifactId struct{ RuntimeToken }

func NewRuntimeArtifactId(value string) (RuntimeArtifactId, error) {
	token, err := newRuntimeToken(value, "value")
	return RuntimeArtifactId{token}, err
}

type RuntimeSignatureId struct{ RuntimeToken }

func NewRuntimeSignatureId(value string) (RuntimeSignatureId, error) {
	token, err := newRuntimeToken(value, "value")
	return RuntimeSignatureId{token}, err
}

type RuntimeSigningProfileId struct{ RuntimeToken }

func NewRuntimeSigningProfileId(value string) (RuntimeSigningProfileId, error) {
	token, err := newRuntimeToken(value, "value")
	return RuntimeSigningProfileId{token}, err
}

type RuntimeHostImageId struct{ RuntimeToken }

func NewRuntimeHostImageId(value string) (RuntimeHostImageId, error) {
	token, err := newRuntimeToken(value, "value")
	return RuntimeHostImageId{token}, err
}

type RuntimeVersionId struct{ RuntimeToken }

func NewRuntimeVersionId(value string) (RuntimeVersionId, error) {
	token, err := newRuntimeToken(value, "value")
	return RuntimeVersionId{token}, err
}

type RuntimeConfigId struct{ RuntimeToken }

func NewRuntimeConfigId(value string) (RuntimeConfigId, error) {
	token, err := newRuntimeToken(value, "value")
	return RuntimeConfigId{token}, err
}

type RuntimeSecretVersionId struct{ RuntimeToken }

func NewRuntimeSecretVersionId(value string) (RuntimeSecretVersionId, error) {
	token, err := newRuntimeToken(value, "value")
	return RuntimeSecretVersionId{token}, err
}

type RuntimeVolumeId struct{ RuntimeToken }

func NewRuntimeVolumeId(value string) (RuntimeVolumeId, error) {
	token, err := newRuntimeToken(value, "value")
	return RuntimeVolumeId{token}, err
}

type RuntimeHealthId struct{ RuntimeToken }

func NewRuntimeHealthId(value string) (RuntimeHealthId, error) {
	token, err := newRuntimeToken(value, "value")
	return RuntimeHealthId{token}, err
}

type RuntimeReleaseId struct{ RuntimeToken }

func NewRuntimeReleaseId(value string) (RuntimeReleaseId, error) {
	token, err := newRuntimeToken(value, "value")
	return RuntimeReleaseId{token}, err
}

type RuntimeOperationId struct{ RuntimeToken }

func NewRuntimeOperationId(value string) (RuntimeOperationId, error) {
	token, err := newRuntimeToken(value, "value")
	return RuntimeOperationId{token}, err
}

type RuntimeDigest struct{ Sha256 string }

func NewRuntimeDigest(sha256 string) (RuntimeDigest, error) {
	value, err := runtimeIdentity.Digest(sha256, "sha256")
	return RuntimeDigest{Sha256: value}, err
}

func (d RuntimeDigest) Equal(other RuntimeDigest) bool { return d.Sha256 == other.Sha256 }

// PositiveRuntimeNumber is the Go form of the abstract record.
type PositiveRuntimeNumber struct {
	Value uint64
}

func newPositiveRuntimeNumber(value uint64) (PositiveRuntimeNumber, error) {
	if value == 0 {
		return PositiveRuntimeNumber{}, argumentOutOfRange("value")
	}
	return PositiveRuntimeNumber{Value: value}, nil
}

type RuntimeGeneration struct{ PositiveRuntimeNumber }

func NewRuntimeGeneration(value uint64) (RuntimeGeneration, error) {
	number, err := newPositiveRuntimeNumber(value)
	return RuntimeGeneration{number}, err
}

type RuntimeEpoch struct{ PositiveRuntimeNumber }

func NewRuntimeEpoch(value uint64) (RuntimeEpoch, error) {
	number, err := newPositiveRuntimeNumber(value)
	return RuntimeEpoch{number}, err
}

type RuntimeAttempt struct{ PositiveRuntimeNumber }

func NewRuntimeAttempt(value uint64) (RuntimeAttempt, error) {
	number, err := newPositiveRuntimeNumber(value)
	return RuntimeAttempt{number}, err
}

type RuntimeDurationSeconds struct{ PositiveRuntimeNumber }

func NewRuntimeDurationSeconds(value uint64) (RuntimeDurationSeconds, error) {
	number, err := newPositiveRuntimeNumber(value)
	return RuntimeDurationSeconds{number}, err
}

type RuntimePort struct {
	Value uint16
}

func NewRuntimePort(value uint16) (RuntimePort, error) {
	if value == 0 {
		return RuntimePort{}, argumentOutOfRange("value")
	}
	return RuntimePort{Value: value}, nil
}

type RuntimeDriver int

const (
	RuntimeDriverNativeSystemd RuntimeDriver = 1
	RuntimeDriverOciContainer  RuntimeDriver = 2
)

func runtimeDriverIsDefined(value RuntimeDriver) bool {
	return value == RuntimeDriverNativeSystemd || value == RuntimeDriverOciContainer
}

type RuntimeArchitecture int

const (
	RuntimeArchitectureLinuxArm64 RuntimeArchitecture = 1
	RuntimeArchitectureLinuxX64   RuntimeArchitecture = 2
)

func runtimeArchitectureIsDefined(value RuntimeArchitecture) bool {
	return value == RuntimeArchitectureLinuxArm64 || value == RuntimeArchitectureLinuxX64
}

type RuntimeRole int

const (
	RuntimeRoleOrchestrator   RuntimeRole = 1
	RuntimeRoleTerraBase      RuntimeRole = 2
	RuntimeRolePlatform       RuntimeRole = 3
	RuntimeRoleAuthentication RuntimeRole = 4
	RuntimeRoleDashboard      RuntimeRole = 5
	RuntimeRoleNatsServer     RuntimeRole = 6
	RuntimeRoleTelemetry      RuntimeRole = 7
	RuntimeRoleGrafana        RuntimeRole = 8
	RuntimeRoleTrustedCi      RuntimeRole = 9
)

func runtimeRoleIsDefined(value RuntimeRole) bool {
	return value >= RuntimeRoleOrchestrator && value <= RuntimeRoleTrustedCi
}

type NativeUnitDescriptor int

const (
	NativeUnitDescriptorOrchestrator NativeUnitDescriptor = 1
	NativeUnitDescriptorTerraBase    NativeUnitDescriptor = 2
	NativeUnitDescriptorNatsServer   NativeUnitDescriptor = 3
	NativeUnitDescriptorTelemetry    NativeUnitDescriptor = 4
)

func nativeUnitDescriptorIsDefined(value NativeUnitDescriptor) bool {
	return value >= NativeUnitDescriptorOrchestrator && value <= NativeUnitDescriptorTelemetry
}

type OciRuntimeDescriptor int

const (
	OciRuntimeDescriptorPlatform       OciRuntimeDescriptor = 1
	OciRuntimeDescriptorAuthentication OciRuntimeDescriptor = 2
	OciRuntimeDescriptorDashboard      OciRuntimeDescriptor = 3
	OciRuntimeDescriptorTerraBase      OciRuntimeDescriptor = 4
	OciRuntimeDescriptorTelemetry      OciRuntimeDescriptor = 5
	OciRuntimeDescriptorGrafana        OciRuntimeDescriptor = 6
	OciRuntimeDescriptorTrustedCi      OciRuntimeDescriptor = 7
)

func ociRuntimeDescriptorIsDefined(value OciRuntimeDescriptor) bool {
	return value >= OciRuntimeDescriptorPlatform && value <= OciRuntimeDescriptorTrustedCi
}

type VolumeRetention int

const (
	VolumeRetentionRetained   VolumeRetention = 1
	VolumeRetentionEphemeral  VolumeRetention = 2
)

func volumeRetentionIsDefined(value VolumeRetention) bool {
	return value == VolumeRetentionRetained || value == VolumeRetentionEphemeral
}

type HealthDimension int

const (
	HealthDimensionStartup             HealthDimension = 1
	HealthDimensionLiveness            HealthDimension = 2
	HealthDimensionLocalReadiness      HealthDimension = 3
	HealthDimensionDependencyReadiness HealthDimension = 4
	HealthDimensionDrainReadiness      HealthDimension = 5
	HealthDimensionRolloutVerification HealthDimension = 6
)

func healthDimensionIsDefined(value HealthDimension) bool {
	return value >= HealthDimensionStartup && value <= HealthDimensionRolloutVerification
}

type HealthStatus int

const (
	HealthStatusReady   HealthStatus = 1
	HealthStatusNotReady HealthStatus = 2
	HealthStatusFailed  HealthStatus = 3
	HealthStatusUnknown HealthStatus = 4
)

func healthStatusIsDefined(value HealthStatus) bool {
	return value >= HealthStatusReady && value <= HealthStatusUnknown
}

type ProcessStatus int

const (
	ProcessStatusAbsent            ProcessStatus = 1
	ProcessStatusRunning           ProcessStatus = 2
	ProcessStatusExitedSuccessfully ProcessStatus = 3
	ProcessStatusFailed            ProcessStatus = 4
	ProcessStatusUnknown           ProcessStatus = 5
)

func processStatusIsDefined(value ProcessStatus) bool {
	return value >= ProcessStatusAbsent && value <= ProcessStatusUnknown
}

type LifecyclePhase int

const (
	LifecyclePhaseNone             LifecyclePhase = 1
	LifecyclePhaseArtifactFetched  LifecyclePhase = 2
	LifecyclePhaseArtifactVerified LifecyclePhase = 3
	LifecyclePhaseStaged           LifecyclePhase = 4
	LifecyclePhaseMounted          LifecyclePhase = 5
	LifecyclePhaseStarted          LifecyclePhase = 6
	LifecyclePhaseServing          LifecyclePhase = 7
	LifecyclePhaseDraining         LifecyclePhase = 8
	LifecyclePhaseStopped          LifecyclePhase = 9
	LifecyclePhaseCleaned          LifecyclePhase = 10
)

func lifecyclePhaseIsDefined(value LifecyclePhase) bool {
	return value >= LifecyclePhaseNone && value <= LifecyclePhaseCleaned
}

type LifecycleAction int

const (
	LifecycleActionConverge LifecycleAction = 1
	LifecycleActionDrain    LifecycleAction = 2
	LifecycleActionStop     LifecycleAction = 3
	LifecycleActionCleanup  LifecycleAction = 4
)

func lifecycleActionIsDefined(value LifecycleAction) bool {
	return value >= LifecycleActionConverge && value <= LifecycleActionCleanup
}

type ExecutorCallStatus int

const (
	ExecutorCallStatusNotCalled    ExecutorCallStatus = 1
	ExecutorCallStatusAccepted     ExecutorCallStatus = 2
	ExecutorCallStatusResponseLost ExecutorCallStatus = 3
	ExecutorCallStatusCompleted    ExecutorCallStatus = 4
)

func executorCallStatusIsDefined(value ExecutorCallStatus) bool {
	return value >= ExecutorCallStatusNotCalled && value <= ExecutorCallStatusCompleted
}

type UpdateSlot int

const (
	UpdateSlotA UpdateSlot = 1
	UpdateSlotB UpdateSlot = 2
)

func updateSlotIsDefined(value UpdateSlot) bool {
	return value == UpdateSlotA || value == UpdateSlotB
}

type UpdatePhase int

const (
	UpdatePhaseUpgradePlanned              UpdatePhase = 1
	UpdatePhaseArtifactVerified            UpdatePhase = 2
	UpdatePhaseInactiveSlotStaged          UpdatePhase = 3
	UpdatePhaseRollbackTimerArmed          UpdatePhase = 4
	UpdatePhaseProcessRestarted            UpdatePhase = 5
	UpdatePhaseLocalHealthVerified         UpdatePhase = 6
	UpdatePhaseRegionalCompatibilityVerified UpdatePhase = 7
	UpdatePhaseSlotCommitted               UpdatePhase = 8
	UpdatePhaseOldSlotRetainedUntilSoak    UpdatePhase = 9
	UpdatePhaseRollingBack                 UpdatePhase = 10
	UpdatePhaseRolledBack                  UpdatePhase = 11
	UpdatePhaseRollbackFailed              UpdatePhase = 12
)

func updatePhaseIsDefined(value UpdatePhase) bool {
	return value >= UpdatePhaseUpgradePlanned && value <= UpdatePhaseRollbackFailed
}

type CompatibilityStatus int

const (
	CompatibilityStatusCompatible   CompatibilityStatus = 1
	CompatibilityStatusIncompatible CompatibilityStatus = 2
	CompatibilityStatusMissing      CompatibilityStatus = 3
	CompatibilityStatusUnknown      CompatibilityStatus = 4
)

func compatibilityStatusIsDefined(value CompatibilityStatus) bool {
	return value >= CompatibilityStatusCompatible && value <= CompatibilityStatusUnknown
}

type ArtifactAvailability int

const (
	ArtifactAvailabilityAvailable  ArtifactAvailability = 1
	ArtifactAvailabilityMissing    ArtifactAvailability = 2
	ArtifactAvailabilityConflicting ArtifactAvailability = 3
	ArtifactAvailabilityUnknown    ArtifactAvailability = 4
)

func artifactAvailabilityIsDefined(value ArtifactAvailability) bool {
	return value >= ArtifactAvailabilityAvailable && value <= ArtifactAvailabilityUnknown
}

type ArtifactVerificationStatus int

const (
	ArtifactVerificationStatusVerified ArtifactVerificationStatus = 1
	ArtifactVerificationStatusFailed    ArtifactVerificationStatus = 2
	ArtifactVerificationStatusMissing  ArtifactVerificationStatus = 3
	ArtifactVerificationStatusUnknown  ArtifactVerificationStatus = 4
)

func artifactVerificationStatusIsDefined(value ArtifactVerificationStatus) bool {
	return value >= ArtifactVerificationStatusVerified && value <= ArtifactVerificationStatusUnknown
}

type EvidenceCompleteness int

const (
	EvidenceCompletenessComplete   EvidenceCompleteness = 1
	EvidenceCompletenessIncomplete EvidenceCompleteness = 2
	EvidenceCompletenessUnknown    EvidenceCompleteness = 3
)

func evidenceCompletenessIsDefined(value EvidenceCompleteness) bool {
	return value >= EvidenceCompletenessComplete && value <= EvidenceCompletenessUnknown
}

type UpdateCompatibilityWindow int

const UpdateCompatibilityWindowNAndNMinusOne UpdateCompatibilityWindow = 1

type UpdateRollbackPolicy int

const UpdateRollbackPolicyLocalKnownGoodOnHealthOrCompatibilityFailure UpdateRollbackPolicy = 1

// runtimeInputSnapshotCopy ports the internal RuntimeInputSnapshot.Copy.
func runtimeInputSnapshotCopy[T any](source []T, maximum int, parameterName string) ([]T, error) {
	if source == nil {
		return nil, argumentNil(parameterName)
	}
	if len(source) > maximum {
		return nil, invalidArgument("Runtime input exceeds the technical item limit.")
	}
	result := make([]T, len(source))
	copy(result, source)
	return result, nil
}

// runtimeEnums ports the internal RuntimeEnums helpers.
var runtimeEnums runtimeEnumsStatic

type runtimeEnumsStatic struct{}

func runtimeEnumsCopy[T any](source []T, name string) ([]T, error) {
	return runtimeInputSnapshotCopy(source, RuntimeTechnicalLimitsMaximumCapturedItems, name)
}

func runtimeEnumsCopyDistinctEnum[T ~int](source []T, name string, isDefined func(T) bool) ([]T, error) {
	values, err := runtimeEnumsCopy(source, name)
	if err != nil {
		return nil, err
	}
	seen := make(map[T]struct{}, len(values))
	for _, value := range values {
		if !isDefined(value) {
			return nil, argumentOutOfRange(name)
		}
		if _, duplicate := seen[value]; duplicate {
			return nil, invalidArgument("Duplicate catalog value.")
		}
		seen[value] = struct{}{}
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	return values, nil
}

// RuntimePayload is the Go form of the abstract RuntimePayload record.
type RuntimePayload interface {
	runtimePayloadCommon() *runtimePayloadBase
	Driver() RuntimeDriver
	ActivationDigest() RuntimeDigest
}

type runtimePayloadBase struct {
	ArtifactId       RuntimeArtifactId
	Digest           RuntimeDigest
	SignatureId      RuntimeSignatureId
	SigningProfileId RuntimeSigningProfileId
	HostImageId      RuntimeHostImageId
	RuntimeVersionId RuntimeVersionId
	Architecture     RuntimeArchitecture
}

func (b *runtimePayloadBase) runtimePayloadCommon() *runtimePayloadBase { return b }

type NativeRuntimePayload struct {
	runtimePayloadBase
	Descriptor NativeUnitDescriptor
}

func NewNativeRuntimePayload(artifactId RuntimeArtifactId, digest RuntimeDigest, signatureId RuntimeSignatureId,
	signingProfileId RuntimeSigningProfileId, hostImageId RuntimeHostImageId, runtimeVersionId RuntimeVersionId,
	architecture RuntimeArchitecture, descriptor NativeUnitDescriptor) (NativeRuntimePayload, error) {
	if !runtimeArchitectureIsDefined(architecture) {
		return NativeRuntimePayload{}, argumentOutOfRange("architecture")
	}
	if !nativeUnitDescriptorIsDefined(descriptor) {
		return NativeRuntimePayload{}, argumentOutOfRange("descriptor")
	}
	return NativeRuntimePayload{runtimePayloadBase{artifactId, digest, signatureId, signingProfileId,
		hostImageId, runtimeVersionId, architecture}, descriptor}, nil
}

func (p NativeRuntimePayload) Driver() RuntimeDriver { return RuntimeDriverNativeSystemd }

func (p NativeRuntimePayload) ActivationDigest() RuntimeDigest { return p.Digest }

type OciRuntimePayload struct {
	runtimePayloadBase
	ImageDigest RuntimeDigest
	Descriptor  OciRuntimeDescriptor
}

func NewOciRuntimePayload(artifactId RuntimeArtifactId, manifestDigest RuntimeDigest, imageDigest RuntimeDigest,
	signatureId RuntimeSignatureId, signingProfileId RuntimeSigningProfileId, hostImageId RuntimeHostImageId,
	runtimeVersionId RuntimeVersionId, architecture RuntimeArchitecture, descriptor OciRuntimeDescriptor) (OciRuntimePayload, error) {
	if !runtimeArchitectureIsDefined(architecture) {
		return OciRuntimePayload{}, argumentOutOfRange("architecture")
	}
	if !ociRuntimeDescriptorIsDefined(descriptor) {
		return OciRuntimePayload{}, argumentOutOfRange("descriptor")
	}
	return OciRuntimePayload{runtimePayloadBase{artifactId, manifestDigest, signatureId, signingProfileId,
		hostImageId, runtimeVersionId, architecture}, imageDigest, descriptor}, nil
}

func (p OciRuntimePayload) Driver() RuntimeDriver { return RuntimeDriverOciContainer }

func (p OciRuntimePayload) ActivationDigest() RuntimeDigest { return p.ImageDigest }

type RuntimeVolumeBinding struct {
	VolumeId  RuntimeVolumeId
	Retention VolumeRetention
}

func NewRuntimeVolumeBinding(volumeId RuntimeVolumeId, retention VolumeRetention) (RuntimeVolumeBinding, error) {
	if !volumeRetentionIsDefined(retention) {
		return RuntimeVolumeBinding{}, argumentOutOfRange("retention")
	}
	return RuntimeVolumeBinding{VolumeId: volumeId, Retention: retention}, nil
}

type WorkloadRuntimeSpec struct {
	WorkloadId     RuntimeWorkloadId
	AllocationId   RuntimeAllocationId
	NodeId         RuntimeNodeId
	Role           RuntimeRole
	Generation     RuntimeGeneration
	ConfigId       RuntimeConfigId
	Payload        RuntimePayload
	SecretVersions []RuntimeSecretVersionId
	Volumes        []RuntimeVolumeBinding
	Ports          []RuntimePort
	RequiredHealth []HealthDimension
}

func NewWorkloadRuntimeSpec(workloadId RuntimeWorkloadId, allocationId RuntimeAllocationId, nodeId RuntimeNodeId,
	role RuntimeRole, generation RuntimeGeneration, configId RuntimeConfigId, payload RuntimePayload,
	secretVersions []RuntimeSecretVersionId, volumes []RuntimeVolumeBinding, ports []RuntimePort,
	requiredHealth []HealthDimension) (WorkloadRuntimeSpec, error) {
	if !runtimeRoleIsDefined(role) {
		return WorkloadRuntimeSpec{}, argumentOutOfRange("role")
	}
	if payload == nil {
		return WorkloadRuntimeSpec{}, argumentNil("payload")
	}
	secrets, err := runtimeEnumsCopy(secretVersions, "secretVersions")
	if err != nil {
		return WorkloadRuntimeSpec{}, err
	}
	sort.Slice(secrets, func(i, j int) bool { return secrets[i].Value < secrets[j].Value })
	volumeBindings, err := runtimeEnumsCopy(volumes, "volumes")
	if err != nil {
		return WorkloadRuntimeSpec{}, err
	}
	sort.Slice(volumeBindings, func(i, j int) bool {
		return volumeBindings[i].VolumeId.Value < volumeBindings[j].VolumeId.Value
	})
	portCopy, err := runtimeEnumsCopy(ports, "ports")
	if err != nil {
		return WorkloadRuntimeSpec{}, err
	}
	sort.Slice(portCopy, func(i, j int) bool { return portCopy[i].Value < portCopy[j].Value })
	health, err := runtimeEnumsCopyDistinctEnum(requiredHealth, "requiredHealth", healthDimensionIsDefined)
	if err != nil {
		return WorkloadRuntimeSpec{}, err
	}

	seenSecrets := map[string]struct{}{}
	for _, value := range secrets {
		seenSecrets[value.Value] = struct{}{}
	}
	if len(seenSecrets) != len(secrets) {
		return WorkloadRuntimeSpec{}, invalidArgument("Duplicate runtime binding.")
	}
	seenVolumes := map[string]struct{}{}
	for _, binding := range volumeBindings {
		seenVolumes[binding.VolumeId.Value] = struct{}{}
	}
	if len(seenVolumes) != len(volumeBindings) {
		return WorkloadRuntimeSpec{}, invalidArgument("Duplicate runtime binding.")
	}
	seenPorts := map[uint16]struct{}{}
	for _, value := range portCopy {
		seenPorts[value.Value] = struct{}{}
	}
	if len(seenPorts) != len(portCopy) {
		return WorkloadRuntimeSpec{}, invalidArgument("Duplicate runtime binding.")
	}
	mandatory := map[HealthDimension]bool{}
	for _, dimension := range health {
		mandatory[dimension] = true
	}
	if !mandatory[HealthDimensionLiveness] || !mandatory[HealthDimensionLocalReadiness] ||
		!mandatory[HealthDimensionDependencyReadiness] {
		return WorkloadRuntimeSpec{}, invalidArgument(
			"Liveness, local readiness, and dependency readiness are mandatory.")
	}

	return WorkloadRuntimeSpec{workloadId, allocationId, nodeId, role, generation, configId, payload,
		secrets, volumeBindings, portCopy, health}, nil
}

type RuntimeAdmission struct {
	Role             RuntimeRole
	Driver           RuntimeDriver
	Architecture     RuntimeArchitecture
	PolicyGeneration RuntimeGeneration
}

func NewRuntimeAdmission(role RuntimeRole, driver RuntimeDriver, architecture RuntimeArchitecture,
	policyGeneration RuntimeGeneration) (RuntimeAdmission, error) {
	if !runtimeRoleIsDefined(role) {
		return RuntimeAdmission{}, argumentOutOfRange("role")
	}
	if !runtimeDriverIsDefined(driver) {
		return RuntimeAdmission{}, argumentOutOfRange("driver")
	}
	if !runtimeArchitectureIsDefined(architecture) {
		return RuntimeAdmission{}, argumentOutOfRange("architecture")
	}
	return RuntimeAdmission{role, driver, architecture, policyGeneration}, nil
}

type RuntimeHealthEvidence struct {
	Id           RuntimeHealthId
	OperationId  RuntimeOperationId
	AllocationId RuntimeAllocationId
	Generation   RuntimeGeneration
	Dimension    HealthDimension
	Status       HealthStatus
}

func NewRuntimeHealthEvidence(id RuntimeHealthId, operationId RuntimeOperationId, allocationId RuntimeAllocationId,
	generation RuntimeGeneration, dimension HealthDimension, status HealthStatus) (RuntimeHealthEvidence, error) {
	if !healthDimensionIsDefined(dimension) {
		return RuntimeHealthEvidence{}, argumentOutOfRange("dimension")
	}
	if !healthStatusIsDefined(status) {
		return RuntimeHealthEvidence{}, argumentOutOfRange("status")
	}
	return RuntimeHealthEvidence{id, operationId, allocationId, generation, dimension, status}, nil
}

type RuntimeObservation struct {
	OperationId    RuntimeOperationId
	AllocationId   RuntimeAllocationId
	Epoch          RuntimeEpoch
	Generation     RuntimeGeneration
	Phase          LifecyclePhase
	ArtifactDigest RuntimeDigest
	ProcessStatus  ProcessStatus
	CallStatus     ExecutorCallStatus
}

func NewRuntimeObservation(operationId RuntimeOperationId, allocationId RuntimeAllocationId, epoch RuntimeEpoch,
	generation RuntimeGeneration, phase LifecyclePhase, artifactDigest RuntimeDigest, processStatus ProcessStatus,
	callStatus ExecutorCallStatus) (RuntimeObservation, error) {
	if !lifecyclePhaseIsDefined(phase) {
		return RuntimeObservation{}, argumentOutOfRange("phase")
	}
	if !processStatusIsDefined(processStatus) {
		return RuntimeObservation{}, argumentOutOfRange("processStatus")
	}
	if !executorCallStatusIsDefined(callStatus) {
		return RuntimeObservation{}, argumentOutOfRange("callStatus")
	}
	return RuntimeObservation{operationId, allocationId, epoch, generation, phase, artifactDigest,
		processStatus, callStatus}, nil
}

type RuntimeConflictEvidence struct {
	AllocationId RuntimeAllocationId
	NodeId       RuntimeNodeId
	Ports        []RuntimePort
	Volumes      []RuntimeVolumeId
}

func NewRuntimeConflictEvidence(allocationId RuntimeAllocationId, nodeId RuntimeNodeId,
	ports []RuntimePort, volumes []RuntimeVolumeId) (RuntimeConflictEvidence, error) {
	portCopy, err := runtimeEnumsCopy(ports, "ports")
	if err != nil {
		return RuntimeConflictEvidence{}, err
	}
	volumeCopy, err := runtimeEnumsCopy(volumes, "volumes")
	if err != nil {
		return RuntimeConflictEvidence{}, err
	}
	return RuntimeConflictEvidence{allocationId, nodeId, portCopy, volumeCopy}, nil
}

type RuntimeInventoryEvidence struct {
	OperationId  RuntimeOperationId
	NodeId       RuntimeNodeId
	Generation   RuntimeGeneration
	Completeness EvidenceCompleteness
	Allocations  []RuntimeConflictEvidence
}

func NewRuntimeInventoryEvidence(operationId RuntimeOperationId, nodeId RuntimeNodeId, generation RuntimeGeneration,
	completeness EvidenceCompleteness, allocations []RuntimeConflictEvidence) (RuntimeInventoryEvidence, error) {
	if !evidenceCompletenessIsDefined(completeness) {
		return RuntimeInventoryEvidence{}, argumentOutOfRange("completeness")
	}
	allocationCopy, err := runtimeEnumsCopy(allocations, "allocations")
	if err != nil {
		return RuntimeInventoryEvidence{}, err
	}
	seen := map[string]struct{}{}
	for index, allocation := range allocationCopy {
		if _, duplicate := seen[allocation.AllocationId.Value]; duplicate {
			return RuntimeInventoryEvidence{}, invalidArgument("Duplicate allocation inventory.")
		}
		seen[allocation.AllocationId.Value] = struct{}{}
		if allocation.NodeId != nodeId {
			_ = index
			return RuntimeInventoryEvidence{}, invalidArgument("Allocation inventory must belong to its scoped node.")
		}
	}
	return RuntimeInventoryEvidence{operationId, nodeId, generation, completeness, allocationCopy}, nil
}

type RuntimeLifecycleRequest struct {
	OperationId              RuntimeOperationId
	Epoch                    RuntimeEpoch
	CurrentEpoch             RuntimeEpoch
	CurrentGeneration        RuntimeGeneration
	AdmissionPolicyGeneration RuntimeGeneration
	HealthTimeout            RuntimeDurationSeconds
	Spec                     WorkloadRuntimeSpec
	Admission                RuntimeAdmission
	Action                   LifecycleAction
	Observation              RuntimeObservation
	Health                   []RuntimeHealthEvidence
	Inventory                RuntimeInventoryEvidence
}

func NewRuntimeLifecycleRequest(operationId RuntimeOperationId, epoch RuntimeEpoch, currentEpoch RuntimeEpoch,
	currentGeneration RuntimeGeneration, admissionPolicyGeneration RuntimeGeneration,
	healthTimeout RuntimeDurationSeconds, spec WorkloadRuntimeSpec, admission RuntimeAdmission,
	action LifecycleAction, observation RuntimeObservation, health []RuntimeHealthEvidence,
	inventory RuntimeInventoryEvidence) (RuntimeLifecycleRequest, error) {
	if !lifecycleActionIsDefined(action) {
		return RuntimeLifecycleRequest{}, argumentOutOfRange("action")
	}
	healthCopy, err := runtimeEnumsCopy(health, "health")
	if err != nil {
		return RuntimeLifecycleRequest{}, err
	}
	return RuntimeLifecycleRequest{operationId, epoch, currentEpoch, currentGeneration,
		admissionPolicyGeneration, healthTimeout, spec, admission, action, observation, healthCopy,
		inventory}, nil
}

type UpdateArtifactSubject struct {
	ReleaseId       RuntimeReleaseId
	ArtifactId      RuntimeArtifactId
	Digest          RuntimeDigest
	SignatureId     RuntimeSignatureId
	SigningProfileId RuntimeSigningProfileId
	Architecture    RuntimeArchitecture
	Generation      RuntimeGeneration
}

func NewUpdateArtifactSubject(releaseId RuntimeReleaseId, artifactId RuntimeArtifactId, digest RuntimeDigest,
	signatureId RuntimeSignatureId, signingProfileId RuntimeSigningProfileId, architecture RuntimeArchitecture,
	generation RuntimeGeneration) (UpdateArtifactSubject, error) {
	if !runtimeArchitectureIsDefined(architecture) {
		return UpdateArtifactSubject{}, argumentOutOfRange("architecture")
	}
	return UpdateArtifactSubject{releaseId, artifactId, digest, signatureId, signingProfileId,
		architecture, generation}, nil
}

type UpdateArtifactEvidence struct {
	ReleaseId       RuntimeReleaseId
	ArtifactId      RuntimeArtifactId
	Digest          RuntimeDigest
	SignatureId     RuntimeSignatureId
	SigningProfileId RuntimeSigningProfileId
	Architecture    RuntimeArchitecture
	Generation      RuntimeGeneration
	Availability    ArtifactAvailability
	Verification    ArtifactVerificationStatus
}

func NewUpdateArtifactEvidence(releaseId RuntimeReleaseId, artifactId RuntimeArtifactId, digest RuntimeDigest,
	signatureId RuntimeSignatureId, signingProfileId RuntimeSigningProfileId, architecture RuntimeArchitecture,
	generation RuntimeGeneration, availability ArtifactAvailability,
	verification ArtifactVerificationStatus) (UpdateArtifactEvidence, error) {
	if !runtimeArchitectureIsDefined(architecture) {
		return UpdateArtifactEvidence{}, argumentOutOfRange("architecture")
	}
	if !artifactAvailabilityIsDefined(availability) {
		return UpdateArtifactEvidence{}, argumentOutOfRange("availability")
	}
	if !artifactVerificationStatusIsDefined(verification) {
		return UpdateArtifactEvidence{}, argumentOutOfRange("verification")
	}
	return UpdateArtifactEvidence{releaseId, artifactId, digest, signatureId, signingProfileId,
		architecture, generation, availability, verification}, nil
}

type UpdateCompatibilityEvidence struct {
	OperationId      RuntimeOperationId
	CurrentGeneration RuntimeGeneration
	TargetGeneration RuntimeGeneration
	ProtocolGeneration RuntimeGeneration
	SchemaGeneration RuntimeGeneration
	NToNMinusOne     CompatibilityStatus
	Status           CompatibilityStatus
}

func NewUpdateCompatibilityEvidence(operationId RuntimeOperationId, currentGeneration RuntimeGeneration,
	targetGeneration RuntimeGeneration, protocolGeneration RuntimeGeneration, schemaGeneration RuntimeGeneration,
	nToNMinusOne CompatibilityStatus, status CompatibilityStatus) (UpdateCompatibilityEvidence, error) {
	if !compatibilityStatusIsDefined(nToNMinusOne) {
		return UpdateCompatibilityEvidence{}, argumentOutOfRange("nToNMinusOne")
	}
	if !compatibilityStatusIsDefined(status) {
		return UpdateCompatibilityEvidence{}, argumentOutOfRange("status")
	}
	return UpdateCompatibilityEvidence{operationId, currentGeneration, targetGeneration,
		protocolGeneration, schemaGeneration, nToNMinusOne, status}, nil
}

type SelfUpdateObservation struct {
	OperationId      RuntimeOperationId
	NodeId           RuntimeNodeId
	Epoch            RuntimeEpoch
	TargetGeneration RuntimeGeneration
	Phase            UpdatePhase
	ActiveSlot       UpdateSlot
	InactiveSlot     UpdateSlot
	CallStatus       ExecutorCallStatus
}

func NewSelfUpdateObservation(operationId RuntimeOperationId, nodeId RuntimeNodeId, epoch RuntimeEpoch,
	targetGeneration RuntimeGeneration, phase UpdatePhase, activeSlot UpdateSlot, inactiveSlot UpdateSlot,
	callStatus ExecutorCallStatus) (SelfUpdateObservation, error) {
	if !updatePhaseIsDefined(phase) {
		return SelfUpdateObservation{}, argumentOutOfRange("phase")
	}
	if !updateSlotIsDefined(activeSlot) {
		return SelfUpdateObservation{}, argumentOutOfRange("activeSlot")
	}
	if !updateSlotIsDefined(inactiveSlot) {
		return SelfUpdateObservation{}, argumentOutOfRange("inactiveSlot")
	}
	if !executorCallStatusIsDefined(callStatus) {
		return SelfUpdateObservation{}, argumentOutOfRange("callStatus")
	}
	if activeSlot == inactiveSlot {
		return SelfUpdateObservation{}, invalidArgument("A/B slots must be distinct.")
	}
	return SelfUpdateObservation{operationId, nodeId, epoch, targetGeneration, phase, activeSlot,
		inactiveSlot, callStatus}, nil
}

type UpdateSoakEvidence struct {
	OperationId      RuntimeOperationId
	NodeId           RuntimeNodeId
	AllocationId     RuntimeAllocationId
	Epoch            RuntimeEpoch
	TargetGeneration RuntimeGeneration
	ActiveSlot       UpdateSlot
	ObservedDuration RuntimeDurationSeconds
}

func NewUpdateSoakEvidence(operationId RuntimeOperationId, nodeId RuntimeNodeId,
	allocationId RuntimeAllocationId, epoch RuntimeEpoch, targetGeneration RuntimeGeneration,
	activeSlot UpdateSlot, observedDuration RuntimeDurationSeconds) (UpdateSoakEvidence, error) {
	if !updateSlotIsDefined(activeSlot) {
		return UpdateSoakEvidence{}, argumentOutOfRange("activeSlot")
	}
	return UpdateSoakEvidence{operationId, nodeId, allocationId, epoch, targetGeneration, activeSlot,
		observedDuration}, nil
}

type SelfUpdateRequest struct {
	OperationId               RuntimeOperationId
	NodeId                    RuntimeNodeId
	AllocationId              RuntimeAllocationId
	Epoch                     RuntimeEpoch
	CurrentEpoch              RuntimeEpoch
	Architecture              RuntimeArchitecture
	CurrentGeneration         RuntimeGeneration
	TargetGeneration          RuntimeGeneration
	CurrentProtocolGeneration RuntimeGeneration
	CurrentSchemaGeneration   RuntimeGeneration
	HealthTimeout             RuntimeDurationSeconds
	SoakDuration              RuntimeDurationSeconds
	CompatibilityWindow       UpdateCompatibilityWindow
	RollbackPolicy            UpdateRollbackPolicy
	ExpectedActiveSlot        UpdateSlot
	ExpectedInactiveSlot      UpdateSlot
	ExpectedForwardArtifact   UpdateArtifactSubject
	ExpectedRollbackArtifact  UpdateArtifactSubject
	ForwardArtifact           UpdateArtifactEvidence
	RollbackArtifact          UpdateArtifactEvidence
	Compatibility             UpdateCompatibilityEvidence
	Observation               SelfUpdateObservation
	Soak                      *UpdateSoakEvidence
	Health                    []RuntimeHealthEvidence
}

func NewSelfUpdateRequest(operationId RuntimeOperationId, nodeId RuntimeNodeId, allocationId RuntimeAllocationId,
	epoch RuntimeEpoch, currentEpoch RuntimeEpoch, architecture RuntimeArchitecture,
	currentGeneration RuntimeGeneration, targetGeneration RuntimeGeneration,
	currentProtocolGeneration RuntimeGeneration, currentSchemaGeneration RuntimeGeneration,
	healthTimeout RuntimeDurationSeconds, soakDuration RuntimeDurationSeconds,
	compatibilityWindow UpdateCompatibilityWindow, rollbackPolicy UpdateRollbackPolicy,
	expectedActiveSlot UpdateSlot, expectedInactiveSlot UpdateSlot,
	expectedForwardArtifact UpdateArtifactSubject, expectedRollbackArtifact UpdateArtifactSubject,
	forwardArtifact UpdateArtifactEvidence, rollbackArtifact UpdateArtifactEvidence,
	compatibility UpdateCompatibilityEvidence, observation SelfUpdateObservation, soak *UpdateSoakEvidence,
	health []RuntimeHealthEvidence) (SelfUpdateRequest, error) {
	if !runtimeArchitectureIsDefined(architecture) {
		return SelfUpdateRequest{}, argumentOutOfRange("architecture")
	}
	if expectedActiveSlot == expectedInactiveSlot {
		return SelfUpdateRequest{}, invalidArgument("Expected A/B slots must be distinct.")
	}
	healthCopy, err := runtimeEnumsCopy(health, "health")
	if err != nil {
		return SelfUpdateRequest{}, err
	}
	return SelfUpdateRequest{operationId, nodeId, allocationId, epoch, currentEpoch, architecture,
		currentGeneration, targetGeneration, currentProtocolGeneration, currentSchemaGeneration,
		healthTimeout, soakDuration, compatibilityWindow, rollbackPolicy, expectedActiveSlot,
		expectedInactiveSlot, expectedForwardArtifact, expectedRollbackArtifact, forwardArtifact,
		rollbackArtifact, compatibility, observation, soak, healthCopy}, nil
}

type RuntimeDecisionCode int

const (
	RuntimeDecisionCodeEvidenceComplete    RuntimeDecisionCode = 1
	RuntimeDecisionCodeEvidenceUnique      RuntimeDecisionCode = 2
	RuntimeDecisionCodeEvidenceConsistent  RuntimeDecisionCode = 3
	RuntimeDecisionCodeOperationExact      RuntimeDecisionCode = 4
	RuntimeDecisionCodeEpochCurrent        RuntimeDecisionCode = 5
	RuntimeDecisionCodeGenerationCurrent   RuntimeDecisionCode = 6
	RuntimeDecisionCodeAdmissionExact      RuntimeDecisionCode = 7
	RuntimeDecisionCodeArchitectureExact   RuntimeDecisionCode = 8
	RuntimeDecisionCodeArtifactExact       RuntimeDecisionCode = 9
	RuntimeDecisionCodePortConflictFree    RuntimeDecisionCode = 10
	RuntimeDecisionCodeVolumeConflictFree  RuntimeDecisionCode = 11
	RuntimeDecisionCodeHealthExact         RuntimeDecisionCode = 12
	RuntimeDecisionCodeReadinessComplete   RuntimeDecisionCode = 13
	RuntimeDecisionCodeCallSafe            RuntimeDecisionCode = 14
	RuntimeDecisionCodeSlotDistinct        RuntimeDecisionCode = 15
	RuntimeDecisionCodeForwardAvailable    RuntimeDecisionCode = 16
	RuntimeDecisionCodeRollbackAvailable   RuntimeDecisionCode = 17
	RuntimeDecisionCodeCompatibilityExact  RuntimeDecisionCode = 18
	RuntimeDecisionCodePhaseResumable      RuntimeDecisionCode = 19
	RuntimeDecisionCodeRollbackPossible    RuntimeDecisionCode = 20
	RuntimeDecisionCodeProcessConsistent   RuntimeDecisionCode = 21
	RuntimeDecisionCodeSoakComplete        RuntimeDecisionCode = 22
)

type RuntimeDecisionOutcome int

const (
	RuntimeDecisionOutcomePassed      RuntimeDecisionOutcome = 1
	RuntimeDecisionOutcomeRejected    RuntimeDecisionOutcome = 2
	RuntimeDecisionOutcomeHeld        RuntimeDecisionOutcome = 3
	RuntimeDecisionOutcomeNotApplicable RuntimeDecisionOutcome = 4
)

type RuntimeDecisionReason struct {
	Code    RuntimeDecisionCode
	Outcome RuntimeDecisionOutcome
	Observed uint64
	Required uint64
}

// RuntimeIntent is the Go form of the abstract RuntimeIntent record.
type RuntimeIntent interface {
	runtimeIntentCommon() *runtimeIntentBase
}

type runtimeIntentBase struct {
	operationId       RuntimeOperationId
	lifecycleRequest  *RuntimeLifecycleRequest
}

func newRuntimeIntentFromRequest(request *RuntimeLifecycleRequest) runtimeIntentBase {
	return runtimeIntentBase{operationId: request.OperationId, lifecycleRequest: request}
}

func (b *runtimeIntentBase) OperationId() RuntimeOperationId { return b.operationId }

func (b *runtimeIntentBase) RequireLifecycleRequest() *RuntimeLifecycleRequest {
	if b.lifecycleRequest == nil {
		panic(invalidArgument("This intent does not carry a lifecycle request."))
	}
	return b.lifecycleRequest
}

type FetchRuntimeArtifactIntent struct {
	runtimeIntentBase
	Request *RuntimeLifecycleRequest
}

func NewFetchRuntimeArtifactIntent(request *RuntimeLifecycleRequest) *FetchRuntimeArtifactIntent {
	return &FetchRuntimeArtifactIntent{newRuntimeIntentFromRequest(request), request}
}

type VerifyRuntimeArtifactIntent struct {
	runtimeIntentBase
	Request *RuntimeLifecycleRequest
}

func NewVerifyRuntimeArtifactIntent(request *RuntimeLifecycleRequest) *VerifyRuntimeArtifactIntent {
	return &VerifyRuntimeArtifactIntent{newRuntimeIntentFromRequest(request), request}
}

type StageRuntimeIntent struct {
	runtimeIntentBase
	Request *RuntimeLifecycleRequest
}

func NewStageRuntimeIntent(request *RuntimeLifecycleRequest) *StageRuntimeIntent {
	return &StageRuntimeIntent{newRuntimeIntentFromRequest(request), request}
}

type MountRuntimeIntent struct {
	runtimeIntentBase
	Request *RuntimeLifecycleRequest
}

func NewMountRuntimeIntent(request *RuntimeLifecycleRequest) *MountRuntimeIntent {
	return &MountRuntimeIntent{newRuntimeIntentFromRequest(request), request}
}

type StartRuntimeIntent struct {
	runtimeIntentBase
	Request *RuntimeLifecycleRequest
}

func NewStartRuntimeIntent(request *RuntimeLifecycleRequest) *StartRuntimeIntent {
	return &StartRuntimeIntent{newRuntimeIntentFromRequest(request), request}
}

type CheckRuntimeHealthIntent struct {
	runtimeIntentBase
	AllocationId  RuntimeAllocationId
	NodeId        RuntimeNodeId
	Epoch         RuntimeEpoch
	Generation    RuntimeGeneration
	HealthTimeout RuntimeDurationSeconds
	requiredHealth []HealthDimension
}

// NewCheckRuntimeHealthIntent ports the lifecycle-request constructor.
func NewCheckRuntimeHealthIntent(request *RuntimeLifecycleRequest) *CheckRuntimeHealthIntent {
	required := make([]HealthDimension, len(request.Spec.RequiredHealth))
	copy(required, request.Spec.RequiredHealth)
	return &CheckRuntimeHealthIntent{
		runtimeIntentBase: newRuntimeIntentFromRequest(request),
		AllocationId:      request.Spec.AllocationId,
		NodeId:            request.Spec.NodeId,
		Epoch:             request.Epoch,
		Generation:        request.Spec.Generation,
		HealthTimeout:     request.HealthTimeout,
		requiredHealth:    required,
	}
}

// NewCheckRuntimeHealthIntentFromSelfUpdate ports the self-update constructor.
func NewCheckRuntimeHealthIntentFromSelfUpdate(request *SelfUpdateRequest) *CheckRuntimeHealthIntent {
	selfUpdateHealth := []HealthDimension{HealthDimensionLiveness, HealthDimensionLocalReadiness,
		HealthDimensionDependencyReadiness}
	return &CheckRuntimeHealthIntent{
		runtimeIntentBase: runtimeIntentBase{operationId: request.OperationId},
		AllocationId:      request.AllocationId,
		NodeId:            request.NodeId,
		Epoch:             request.Epoch,
		Generation:        request.TargetGeneration,
		HealthTimeout:     request.HealthTimeout,
		requiredHealth:    selfUpdateHealth,
	}
}

func (i *CheckRuntimeHealthIntent) RequiredHealth() []HealthDimension { return i.requiredHealth }

func (i *CheckRuntimeHealthIntent) Equal(other *CheckRuntimeHealthIntent) bool {
	if other == nil {
		return false
	}
	if i.operationId != other.operationId || i.AllocationId != other.AllocationId ||
		i.NodeId != other.NodeId || i.Epoch != other.Epoch || i.Generation != other.Generation ||
		i.HealthTimeout != other.HealthTimeout {
		return false
	}
	if len(i.requiredHealth) != len(other.requiredHealth) {
		return false
	}
	for index, dimension := range i.requiredHealth {
		if dimension != other.requiredHealth[index] {
			return false
		}
	}
	return true
}

type DrainRuntimeIntent struct {
	runtimeIntentBase
	Request *RuntimeLifecycleRequest
}

func NewDrainRuntimeIntent(request *RuntimeLifecycleRequest) *DrainRuntimeIntent {
	return &DrainRuntimeIntent{newRuntimeIntentFromRequest(request), request}
}

type StopRuntimeIntent struct {
	runtimeIntentBase
	Request *RuntimeLifecycleRequest
}

func NewStopRuntimeIntent(request *RuntimeLifecycleRequest) *StopRuntimeIntent {
	return &StopRuntimeIntent{newRuntimeIntentFromRequest(request), request}
}

type CleanupRuntimeIntent struct {
	runtimeIntentBase
	Request          *RuntimeLifecycleRequest
	ephemeralVolumes []RuntimeVolumeId
}

func NewCleanupRuntimeIntent(request *RuntimeLifecycleRequest) *CleanupRuntimeIntent {
	var ephemeral []RuntimeVolumeId
	for _, volume := range request.Spec.Volumes {
		if volume.Retention == VolumeRetentionEphemeral {
			ephemeral = append(ephemeral, volume.VolumeId)
		}
	}
	if ephemeral == nil {
		ephemeral = []RuntimeVolumeId{}
	}
	return &CleanupRuntimeIntent{newRuntimeIntentFromRequest(request), request, ephemeral}
}

func (i *CleanupRuntimeIntent) EphemeralVolumes() []RuntimeVolumeId { return i.ephemeralVolumes }

type ObserveExecutorIntent struct {
	runtimeIntentBase
}

func NewObserveExecutorIntent(request *RuntimeLifecycleRequest) *ObserveExecutorIntent {
	return &ObserveExecutorIntent{newRuntimeIntentFromRequest(request)}
}

func (i *ObserveExecutorIntent) Request() *RuntimeLifecycleRequest { return i.RequireLifecycleRequest() }

func (i *ObserveExecutorIntent) AllocationId() RuntimeAllocationId { return i.Request().Spec.AllocationId }

type VerifyUpdateArtifactIntent struct {
	runtimeIntentBase
	Request *SelfUpdateRequest
}

func NewVerifyUpdateArtifactIntent(request *SelfUpdateRequest) *VerifyUpdateArtifactIntent {
	return &VerifyUpdateArtifactIntent{runtimeIntentBase{operationId: request.OperationId}, request}
}

type StageInactiveSlotIntent struct {
	runtimeIntentBase
	Request *SelfUpdateRequest
}

func NewStageInactiveSlotIntent(request *SelfUpdateRequest) *StageInactiveSlotIntent {
	return &StageInactiveSlotIntent{runtimeIntentBase{operationId: request.OperationId}, request}
}

type ArmRollbackIntent struct {
	runtimeIntentBase
	Request *SelfUpdateRequest
}

func NewArmRollbackIntent(request *SelfUpdateRequest) *ArmRollbackIntent {
	return &ArmRollbackIntent{runtimeIntentBase{operationId: request.OperationId}, request}
}

type SwitchUpdateSlotIntent struct {
	runtimeIntentBase
	Request *SelfUpdateRequest
}

func NewSwitchUpdateSlotIntent(request *SelfUpdateRequest) *SwitchUpdateSlotIntent {
	return &SwitchUpdateSlotIntent{runtimeIntentBase{operationId: request.OperationId}, request}
}

type ObserveUpdateIntent struct {
	runtimeIntentBase
	Request *SelfUpdateRequest
}

func NewObserveUpdateIntent(request *SelfUpdateRequest) *ObserveUpdateIntent {
	return &ObserveUpdateIntent{runtimeIntentBase{operationId: request.OperationId}, request}
}

type VerifyRegionalCompatibilityIntent struct {
	runtimeIntentBase
	Request *SelfUpdateRequest
}

func NewVerifyRegionalCompatibilityIntent(request *SelfUpdateRequest) *VerifyRegionalCompatibilityIntent {
	return &VerifyRegionalCompatibilityIntent{runtimeIntentBase{operationId: request.OperationId}, request}
}

type CommitUpdateSlotIntent struct {
	runtimeIntentBase
	Request *SelfUpdateRequest
}

func NewCommitUpdateSlotIntent(request *SelfUpdateRequest) *CommitUpdateSlotIntent {
	return &CommitUpdateSlotIntent{runtimeIntentBase{operationId: request.OperationId}, request}
}

type RollbackUpdateIntent struct {
	runtimeIntentBase
	Request *SelfUpdateRequest
}

func NewRollbackUpdateIntent(request *SelfUpdateRequest) *RollbackUpdateIntent {
	return &RollbackUpdateIntent{runtimeIntentBase{operationId: request.OperationId}, request}
}

type RetainOldUpdateSlotIntent struct {
	runtimeIntentBase
	Request *SelfUpdateRequest
}

func NewRetainOldUpdateSlotIntent(request *SelfUpdateRequest) *RetainOldUpdateSlotIntent {
	return &RetainOldUpdateSlotIntent{runtimeIntentBase{operationId: request.OperationId}, request}
}

type CompleteSelfUpdateIntent struct {
	runtimeIntentBase
	Request *SelfUpdateRequest
}

func NewCompleteSelfUpdateIntent(request *SelfUpdateRequest) *CompleteSelfUpdateIntent {
	return &CompleteSelfUpdateIntent{runtimeIntentBase{operationId: request.OperationId}, request}
}

type HoldRuntimeIntent struct {
	runtimeIntentBase
}

func NewHoldRuntimeIntent(operationId RuntimeOperationId) *HoldRuntimeIntent {
	return &HoldRuntimeIntent{runtimeIntentBase{operationId: operationId}}
}

type RuntimeDecision struct {
	Authorized bool
	Trace      []RuntimeDecisionReason
	Intent     RuntimeIntent
}
