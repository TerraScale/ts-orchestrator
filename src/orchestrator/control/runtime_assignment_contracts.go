package control

import (
	"sort"
	"time"
)

// RuntimeHostAssignmentV1 is the internal persisted host assignment. It
// contains references to admitted configuration and secret versions, never
// configuration paths, secret material, or a caller-provided host execution
// plan.
type RuntimeHostAssignmentV1 struct {
	SchemaVersion               int
	Cell                        RuntimeLifecycleCellId
	WorkloadId                  RuntimeWorkloadId
	AllocationId                HostRuntimeAllocationId
	Node                        RuntimeNodeId
	AssignmentGeneration        RuntimeGeneration
	WorkloadGeneration          RuntimeGeneration
	WriterEpoch                 RuntimeEpoch
	AcceptedGeneration          RuntimeGeneration
	AcceptedGlobalPlanDigest    RuntimeDigest
	AcceptedHandoffDigest       RuntimeDigest
	AcceptedPayloadDigest       RuntimeDigest
	AcceptanceStreamSequence    uint64
	AcceptanceSignatureDigest   RuntimeDigest
	AcceptanceJournalRevision   uint64
	ConvergenceJournalRevision  uint64
	ConvergenceCheckpointDigest RuntimeDigest
	Role                        HostRole
	Driver                      HostRuntimeDriver
	Architecture                HostArchitecture
	ArtifactDigest              HostArtifactDigest
	Resources                   HostRuntimeResources
	ConfigId                    RuntimeConfigId
	SecretVersions              []RuntimeSecretVersionId
	Volumes                     []RuntimeVolumeBinding
	Ports                       []RuntimePort
	ExpectedPlanFingerprint     RuntimeLifecyclePlanFingerprint
	Authorization               RuntimeAssignmentAuthorizationV1
}

const RuntimeHostAssignmentV1CurrentSchemaVersion = 1

func NewRuntimeHostAssignmentV1(
	schemaVersion int,
	cell RuntimeLifecycleCellId,
	workloadId RuntimeWorkloadId,
	allocationId HostRuntimeAllocationId,
	node RuntimeNodeId,
	assignmentGeneration RuntimeGeneration,
	workloadGeneration RuntimeGeneration,
	writerEpoch RuntimeEpoch,
	acceptedGeneration RuntimeGeneration,
	acceptedGlobalPlanDigest RuntimeDigest,
	acceptedHandoffDigest RuntimeDigest,
	acceptedPayloadDigest RuntimeDigest,
	acceptanceStreamSequence uint64,
	acceptanceSignatureDigest RuntimeDigest,
	acceptanceJournalRevision uint64,
	convergenceJournalRevision uint64,
	convergenceCheckpointDigest RuntimeDigest,
	role HostRole,
	driver HostRuntimeDriver,
	architecture HostArchitecture,
	artifactDigest HostArtifactDigest,
	resources HostRuntimeResources,
	configId RuntimeConfigId,
	secretVersions []RuntimeSecretVersionId,
	volumes []RuntimeVolumeBinding,
	ports []RuntimePort,
	expectedPlanFingerprint RuntimeLifecyclePlanFingerprint,
	authorization RuntimeAssignmentAuthorizationV1) (RuntimeHostAssignmentV1, error) {
	if schemaVersion != RuntimeHostAssignmentV1CurrentSchemaVersion {
		return RuntimeHostAssignmentV1{}, argumentOutOfRange("schemaVersion")
	}
	if acceptanceStreamSequence == 0 {
		return RuntimeHostAssignmentV1{}, argumentOutOfRange("acceptanceStreamSequence")
	}
	if acceptanceJournalRevision == 0 {
		return RuntimeHostAssignmentV1{}, argumentOutOfRange("acceptanceJournalRevision")
	}
	if convergenceJournalRevision == 0 {
		return RuntimeHostAssignmentV1{}, argumentOutOfRange("convergenceJournalRevision")
	}
	if !hostAdmittedRoleIsDefined(role) {
		return RuntimeHostAssignmentV1{}, argumentOutOfRange("role")
	}
	if !(driver == 0 || driver == 1) {
		return RuntimeHostAssignmentV1{}, argumentOutOfRange("driver")
	}
	if !(architecture == 0 || architecture == 1) {
		return RuntimeHostAssignmentV1{}, argumentOutOfRange("architecture")
	}
	secrets, err := runtimeAssignmentCopyDistinct(secretVersions, "secretVersions",
		func(value RuntimeSecretVersionId) string { return value.Value })
	if err != nil {
		return RuntimeHostAssignmentV1{}, err
	}
	volumeBindings, err := runtimeAssignmentCopyDistinct(volumes, "volumes",
		func(value RuntimeVolumeBinding) string { return value.VolumeId.Value })
	if err != nil {
		return RuntimeHostAssignmentV1{}, err
	}
	portCopy, err := runtimeAssignmentCopyDistinct(ports, "ports",
		func(value RuntimePort) uint16 { return value.Value })
	if err != nil {
		return RuntimeHostAssignmentV1{}, err
	}
	return RuntimeHostAssignmentV1{schemaVersion, cell, workloadId, allocationId, node,
		assignmentGeneration, workloadGeneration, writerEpoch, acceptedGeneration,
		acceptedGlobalPlanDigest, acceptedHandoffDigest, acceptedPayloadDigest,
		acceptanceStreamSequence, acceptanceSignatureDigest, acceptanceJournalRevision,
		convergenceJournalRevision, convergenceCheckpointDigest, role, driver, architecture,
		artifactDigest, resources, configId, secrets, volumeBindings, portCopy,
		expectedPlanFingerprint, authorization}, nil
}

func runtimeAssignmentCopyDistinct[T any, K string | uint16](values []T, name string, key func(T) K) ([]T, error) {
	copyValues, err := runtimeInputSnapshotCopy(values, RuntimeTechnicalLimitsMaximumCapturedItems, name)
	if err != nil {
		return nil, err
	}
	seen := make(map[K]struct{}, len(copyValues))
	for _, value := range copyValues {
		seen[key(value)] = struct{}{}
	}
	if len(seen) != len(copyValues) {
		return nil, invalidArgument("Assignment bindings must be non-null and distinct.")
	}
	sort.Slice(copyValues, func(i, j int) bool { return key(copyValues[i]) < key(copyValues[j]) })
	return copyValues, nil
}

// RuntimeAssignmentAuthorizationV1 is persisted evidence accepted by the
// regional assignment authority for one bounded command.
type RuntimeAssignmentAuthorizationV1 struct {
	AuthorizationEvidenceDigest RuntimeDigest
	DeadlineEvidence            RuntimeLifecycleDeadlineEvidence
	ExpiresAt                   time.Time
}

func NewRuntimeAssignmentAuthorizationV1(authorizationEvidenceDigest RuntimeDigest,
	deadlineEvidence RuntimeLifecycleDeadlineEvidence, expiresAt time.Time) (RuntimeAssignmentAuthorizationV1, error) {
	if expiresAt.IsZero() {
		return RuntimeAssignmentAuthorizationV1{}, argumentOutOfRange("expiresAt")
	}
	return RuntimeAssignmentAuthorizationV1{authorizationEvidenceDigest, deadlineEvidence, expiresAt}, nil
}

// RuntimeAssignmentProjectionScopeV1 is the local projector fence. A command
// cannot cross a cell/node/epoch ownership boundary.
type RuntimeAssignmentProjectionScopeV1 struct {
	Cell        RuntimeLifecycleCellId
	Node        RuntimeNodeId
	WriterEpoch RuntimeEpoch
}

func NewRuntimeAssignmentProjectionScopeV1(cell RuntimeLifecycleCellId, node RuntimeNodeId,
	writerEpoch RuntimeEpoch) (RuntimeAssignmentProjectionScopeV1, error) {
	return RuntimeAssignmentProjectionScopeV1{cell, node, writerEpoch}, nil
}
