package control

import (
	"context"
	"strconv"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/runtime"
)

// Host runtime aliases mirroring the C# using aliases.
type (
	HostArchitecture        = runtime.HostArchitecture
	HostArtifactDigest      = runtime.ArtifactDigest
	HostRole                = runtime.AdmittedRole
	HostRuntimeDriver       = runtime.RuntimeDriver
	HostRuntimeAllocationId = runtime.RuntimeAllocationId
	HostRuntimeResources    = runtime.RuntimeResourceLimits
	HostRuntimePlan         = runtime.HostRuntimePlan
)

// RuntimeLifecycleContract ports the versioned, persistence-safe lifecycle
// contract constants. It intentionally contains fingerprints, never host
// execution material.
var RuntimeLifecycleContract runtimeLifecycleContractStatic

type runtimeLifecycleContractStatic struct{}

const (
	RuntimeLifecycleContractSchemaVersion           = 2
	RuntimeLifecycleContractMaximumCasAttempts      = 3
	RuntimeLifecycleContractMaximumCoordinatorSteps = 12
)

type RuntimeLifecyclePhase int

const (
	RuntimeLifecyclePhaseProposed          RuntimeLifecyclePhase = 1
	RuntimeLifecyclePhaseAuthorized        RuntimeLifecyclePhase = 2
	RuntimeLifecyclePhaseDispatchPersisted RuntimeLifecyclePhase = 3
	RuntimeLifecyclePhaseInFlight          RuntimeLifecyclePhase = 4
	RuntimeLifecyclePhaseObservedConverged RuntimeLifecyclePhase = 5
	RuntimeLifecyclePhaseObservedStopped   RuntimeLifecyclePhase = 6
	RuntimeLifecyclePhaseUncertain         RuntimeLifecyclePhase = 7
	RuntimeLifecyclePhaseFailed            RuntimeLifecyclePhase = 8
	RuntimeLifecyclePhaseTerminal          RuntimeLifecyclePhase = 9
)

func runtimeLifecyclePhaseIsDefined(value RuntimeLifecyclePhase) bool {
	return value >= RuntimeLifecyclePhaseProposed && value <= RuntimeLifecyclePhaseTerminal
}

type RuntimeLifecycleCallStatus int

const (
	RuntimeLifecycleCallStatusNotCalled           RuntimeLifecycleCallStatus = 1
	RuntimeLifecycleCallStatusDispatchPersisted   RuntimeLifecycleCallStatus = 2
	RuntimeLifecycleCallStatusInFlight            RuntimeLifecycleCallStatus = 3
	RuntimeLifecycleCallStatusResponseLost        RuntimeLifecycleCallStatus = 4
	RuntimeLifecycleCallStatusObservationRequired RuntimeLifecycleCallStatus = 5
	RuntimeLifecycleCallStatusObserved            RuntimeLifecycleCallStatus = 6
)

func runtimeLifecycleCallStatusIsDefined(value RuntimeLifecycleCallStatus) bool {
	return value >= RuntimeLifecycleCallStatusNotCalled && value <= RuntimeLifecycleCallStatusObserved
}

type RuntimeLifecycleCompensationPolicy int

const (
	RuntimeLifecycleCompensationPolicyNone              RuntimeLifecycleCompensationPolicy = 1
	RuntimeLifecycleCompensationPolicyAuthorizedCleanup RuntimeLifecycleCompensationPolicy = 2
)

func runtimeLifecycleCompensationPolicyIsDefined(value RuntimeLifecycleCompensationPolicy) bool {
	return value == RuntimeLifecycleCompensationPolicyNone || value == RuntimeLifecycleCompensationPolicyAuthorizedCleanup
}

type RuntimeLifecycleTerminalStatus int

const (
	RuntimeLifecycleTerminalStatusNone                   RuntimeLifecycleTerminalStatus = 1
	RuntimeLifecycleTerminalStatusConverged              RuntimeLifecycleTerminalStatus = 2
	RuntimeLifecycleTerminalStatusStopped                RuntimeLifecycleTerminalStatus = 3
	RuntimeLifecycleTerminalStatusReconciliationRequired RuntimeLifecycleTerminalStatus = 4
	RuntimeLifecycleTerminalStatusFailed                 RuntimeLifecycleTerminalStatus = 5
)

func runtimeLifecycleTerminalStatusIsDefined(value RuntimeLifecycleTerminalStatus) bool {
	return value >= RuntimeLifecycleTerminalStatusNone && value <= RuntimeLifecycleTerminalStatusFailed
}

type RuntimeLifecycleErrorCode int

const (
	RuntimeLifecycleErrorCodeNone                   RuntimeLifecycleErrorCode = 1
	RuntimeLifecycleErrorCodeAuthorityUnavailable   RuntimeLifecycleErrorCode = 2
	RuntimeLifecycleErrorCodeAuthorityFenced        RuntimeLifecycleErrorCode = 3
	RuntimeLifecycleErrorCodeIdentityMismatch       RuntimeLifecycleErrorCode = 4
	RuntimeLifecycleErrorCodeJournalUnavailable     RuntimeLifecycleErrorCode = 5
	RuntimeLifecycleErrorCodeJournalAmbiguous       RuntimeLifecycleErrorCode = 6
	RuntimeLifecycleErrorCodeCasExhausted           RuntimeLifecycleErrorCode = 7
	RuntimeLifecycleErrorCodeInvalidCheckpoint      RuntimeLifecycleErrorCode = 8
	RuntimeLifecycleErrorCodeObservationMismatch    RuntimeLifecycleErrorCode = 9
	RuntimeLifecycleErrorCodeExecutorResponseLost   RuntimeLifecycleErrorCode = 10
	RuntimeLifecycleErrorCodeExecutorFailed         RuntimeLifecycleErrorCode = 11
	RuntimeLifecycleErrorCodeCancelledAfterDispatch RuntimeLifecycleErrorCode = 12
	RuntimeLifecycleErrorCodeUnsupportedCleanup     RuntimeLifecycleErrorCode = 13
)

func runtimeLifecycleErrorCodeIsDefined(value RuntimeLifecycleErrorCode) bool {
	return value >= RuntimeLifecycleErrorCodeNone && value <= RuntimeLifecycleErrorCodeUnsupportedCleanup
}

type RuntimeLifecycleAuthorityStatus int

const (
	RuntimeLifecycleAuthorityStatusReadyLeader RuntimeLifecycleAuthorityStatus = 1
	RuntimeLifecycleAuthorityStatusNotReady    RuntimeLifecycleAuthorityStatus = 2
	RuntimeLifecycleAuthorityStatusFollower    RuntimeLifecycleAuthorityStatus = 3
	RuntimeLifecycleAuthorityStatusUnavailable RuntimeLifecycleAuthorityStatus = 4
)

func runtimeLifecycleAuthorityStatusIsDefined(value RuntimeLifecycleAuthorityStatus) bool {
	return value >= RuntimeLifecycleAuthorityStatusReadyLeader && value <= RuntimeLifecycleAuthorityStatusUnavailable
}

type RuntimeLifecycleJournalReadStatus int

const (
	RuntimeLifecycleJournalReadStatusFound       RuntimeLifecycleJournalReadStatus = 1
	RuntimeLifecycleJournalReadStatusMissing     RuntimeLifecycleJournalReadStatus = 2
	RuntimeLifecycleJournalReadStatusAmbiguous   RuntimeLifecycleJournalReadStatus = 3
	RuntimeLifecycleJournalReadStatusUnavailable RuntimeLifecycleJournalReadStatus = 4
)

func runtimeLifecycleJournalReadStatusIsDefined(value RuntimeLifecycleJournalReadStatus) bool {
	return value >= RuntimeLifecycleJournalReadStatusFound && value <= RuntimeLifecycleJournalReadStatusUnavailable
}

type RuntimeLifecycleJournalWriteStatus int

const (
	RuntimeLifecycleJournalWriteStatusApplied     RuntimeLifecycleJournalWriteStatus = 1
	RuntimeLifecycleJournalWriteStatusConflict    RuntimeLifecycleJournalWriteStatus = 2
	RuntimeLifecycleJournalWriteStatusMissing     RuntimeLifecycleJournalWriteStatus = 3
	RuntimeLifecycleJournalWriteStatusAmbiguous   RuntimeLifecycleJournalWriteStatus = 4
	RuntimeLifecycleJournalWriteStatusUnavailable RuntimeLifecycleJournalWriteStatus = 5
)

func runtimeLifecycleJournalWriteStatusIsDefined(value RuntimeLifecycleJournalWriteStatus) bool {
	return value >= RuntimeLifecycleJournalWriteStatusApplied && value <= RuntimeLifecycleJournalWriteStatusUnavailable
}

type RuntimeLifecycleExecutorStatus int

const (
	RuntimeLifecycleExecutorStatusAccepted     RuntimeLifecycleExecutorStatus = 1
	RuntimeLifecycleExecutorStatusCompleted    RuntimeLifecycleExecutorStatus = 2
	RuntimeLifecycleExecutorStatusResponseLost RuntimeLifecycleExecutorStatus = 3
	RuntimeLifecycleExecutorStatusFailed       RuntimeLifecycleExecutorStatus = 4
)

func runtimeLifecycleExecutorStatusIsDefined(value RuntimeLifecycleExecutorStatus) bool {
	return value >= RuntimeLifecycleExecutorStatusAccepted && value <= RuntimeLifecycleExecutorStatusFailed
}

type RuntimeLifecycleObservationStatus int

const (
	RuntimeLifecycleObservationStatusConverged   RuntimeLifecycleObservationStatus = 1
	RuntimeLifecycleObservationStatusStopped     RuntimeLifecycleObservationStatus = 2
	RuntimeLifecycleObservationStatusNotObserved RuntimeLifecycleObservationStatus = 3
	RuntimeLifecycleObservationStatusUnknown     RuntimeLifecycleObservationStatus = 4
)

func runtimeLifecycleObservationStatusIsDefined(value RuntimeLifecycleObservationStatus) bool {
	return value >= RuntimeLifecycleObservationStatusConverged && value <= RuntimeLifecycleObservationStatusUnknown
}

type RuntimeLifecycleCellId struct{ RuntimeToken }

func NewRuntimeLifecycleCellId(value string) (RuntimeLifecycleCellId, error) {
	token, err := newRuntimeToken(value, "value")
	return RuntimeLifecycleCellId{token}, err
}

type RuntimeLifecycleOperationKey struct{ Value string }

func NewRuntimeLifecycleOperationKey(value string) (RuntimeLifecycleOperationKey, error) {
	digest, err := runtimeIdentity.Digest(value, "value")
	return RuntimeLifecycleOperationKey{Value: digest}, err
}

type RuntimeLifecyclePlanFingerprint struct{ Value string }

func NewRuntimeLifecyclePlanFingerprint(value string) (RuntimeLifecyclePlanFingerprint, error) {
	digest, err := runtimeIdentity.Digest(value, "value")
	return RuntimeLifecyclePlanFingerprint{Value: digest}, err
}

type RuntimeLifecycleHostObservationFingerprint struct{ Value string }

func NewRuntimeLifecycleHostObservationFingerprint(value string) (RuntimeLifecycleHostObservationFingerprint, error) {
	digest, err := runtimeIdentity.Digest(value, "value")
	return RuntimeLifecycleHostObservationFingerprint{Value: digest}, err
}

type RuntimeLifecycleDeadlineEvidence struct {
	Digest    RuntimeDigest
	Watermark uint64
}

func NewRuntimeLifecycleDeadlineEvidence(digest RuntimeDigest, watermark uint64) (RuntimeLifecycleDeadlineEvidence, error) {
	if watermark == 0 {
		return RuntimeLifecycleDeadlineEvidence{}, argumentOutOfRange("watermark")
	}
	return RuntimeLifecycleDeadlineEvidence{Digest: digest, Watermark: watermark}, nil
}

type RuntimeLifecycleAuthority struct {
	Status RuntimeLifecycleAuthorityStatus
	Epoch  RuntimeEpoch
}

func NewRuntimeLifecycleAuthority(status RuntimeLifecycleAuthorityStatus, epoch RuntimeEpoch) (RuntimeLifecycleAuthority, error) {
	if !runtimeLifecycleAuthorityStatusIsDefined(status) {
		return RuntimeLifecycleAuthority{}, argumentOutOfRange("status")
	}
	return RuntimeLifecycleAuthority{Status: status, Epoch: epoch}, nil
}

func (a RuntimeLifecycleAuthority) IsExactLeader(expectedEpoch RuntimeEpoch) bool {
	return a.Status == RuntimeLifecycleAuthorityStatusReadyLeader && a.Epoch == expectedEpoch
}

type RuntimeLifecycleOperationRequest struct {
	Cell                        RuntimeLifecycleCellId
	Node                        RuntimeNodeId
	WorkloadGeneration          RuntimeGeneration
	AcceptedConvergenceDigest   RuntimeDigest
	Plan                        HostRuntimePlan
	Action                      LifecycleAction
	WriterEpoch                 RuntimeEpoch
	AuthorizationEvidenceDigest RuntimeDigest
	DeadlineEvidence            RuntimeLifecycleDeadlineEvidence
	CompensationPolicy          RuntimeLifecycleCompensationPolicy
	PlanFingerprint             RuntimeLifecyclePlanFingerprint
	OperationKey                RuntimeLifecycleOperationKey
}

func NewRuntimeLifecycleOperationRequest(
	cell RuntimeLifecycleCellId,
	node RuntimeNodeId,
	workloadGeneration RuntimeGeneration,
	acceptedConvergenceDigest RuntimeDigest,
	plan HostRuntimePlan,
	action LifecycleAction,
	writerEpoch RuntimeEpoch,
	authorizationEvidenceDigest RuntimeDigest,
	deadlineEvidence RuntimeLifecycleDeadlineEvidence,
	compensationPolicy RuntimeLifecycleCompensationPolicy) (RuntimeLifecycleOperationRequest, error) {
	if !lifecycleActionIsDefined(action) {
		return RuntimeLifecycleOperationRequest{}, argumentOutOfRange("action")
	}
	if action == LifecycleActionCleanup {
		return RuntimeLifecycleOperationRequest{}, argumentOutOfRangeError("action",
			"Destructive cleanup is not enabled by this lifecycle contract.")
	}
	if !runtimeLifecycleCompensationPolicyIsDefined(compensationPolicy) {
		return RuntimeLifecycleOperationRequest{}, argumentOutOfRange("compensationPolicy")
	}
	if compensationPolicy != RuntimeLifecycleCompensationPolicyNone {
		return RuntimeLifecycleOperationRequest{}, argumentOutOfRangeError("compensationPolicy",
			"Destructive cleanup is not enabled by this lifecycle contract.")
	}
	planFingerprint, err := RuntimeLifecycleFingerprint.Plan(plan)
	if err != nil {
		return RuntimeLifecycleOperationRequest{}, err
	}
	request := RuntimeLifecycleOperationRequest{Cell: cell, Node: node, WorkloadGeneration: workloadGeneration,
		AcceptedConvergenceDigest: acceptedConvergenceDigest, Plan: plan, Action: action, WriterEpoch: writerEpoch,
		AuthorizationEvidenceDigest: authorizationEvidenceDigest, DeadlineEvidence: deadlineEvidence,
		CompensationPolicy: compensationPolicy, PlanFingerprint: planFingerprint}
	operationKey, err := RuntimeLifecycleFingerprint.Operation(request)
	if err != nil {
		return RuntimeLifecycleOperationRequest{}, err
	}
	request.OperationKey = operationKey
	return request, nil
}

type RuntimeLifecycleCheckpoint struct {
	SchemaVersion               int
	OperationKey                RuntimeLifecycleOperationKey
	Cell                        RuntimeLifecycleCellId
	Node                        RuntimeNodeId
	AllocationId                string
	WorkloadGeneration          RuntimeGeneration
	AcceptedConvergenceDigest   RuntimeDigest
	PlanFingerprint             RuntimeLifecyclePlanFingerprint
	Driver                      HostRuntimeDriver
	Role                        HostRole
	Action                      LifecycleAction
	Phase                       RuntimeLifecyclePhase
	WriterEpoch                 RuntimeEpoch
	AuthorizationEvidenceDigest RuntimeDigest
	ExecutorAttempt             RuntimeAttempt
	DispatchToken               RuntimeDigest
	CallStatus                  RuntimeLifecycleCallStatus
	LastObservationFingerprint  *RuntimeLifecycleHostObservationFingerprint
	LastObservationWatermark    uint64
	DeadlineEvidence            RuntimeLifecycleDeadlineEvidence
	CompensationPolicy          RuntimeLifecycleCompensationPolicy
	JournalRevision             uint64
	PreviousEventDigest         RuntimeDigest
	EventDigest                 RuntimeDigest
	TerminalStatus              RuntimeLifecycleTerminalStatus
	ErrorCode                   RuntimeLifecycleErrorCode
}

// RuntimeLifecycleCheckpointProposed creates the genesis checkpoint for a request.
func RuntimeLifecycleCheckpointProposed(request RuntimeLifecycleOperationRequest) (RuntimeLifecycleCheckpoint, error) {
	genesisDigest, err := NewRuntimeDigest(RuntimeLifecycleFingerprint.Hash("runtime-lifecycle-genesis-v2"))
	if err != nil {
		return RuntimeLifecycleCheckpoint{}, err
	}
	dispatchToken, err := NewRuntimeDigest(RuntimeLifecycleFingerprint.DispatchToken(request))
	if err != nil {
		return RuntimeLifecycleCheckpoint{}, err
	}
	attempt, err := NewRuntimeAttempt(1)
	if err != nil {
		return RuntimeLifecycleCheckpoint{}, err
	}
	checkpoint := RuntimeLifecycleCheckpoint{
		SchemaVersion: RuntimeLifecycleContractSchemaVersion, OperationKey: request.OperationKey,
		Cell: request.Cell, Node: request.Node, AllocationId: request.Plan.AllocationId.Value,
		WorkloadGeneration: request.WorkloadGeneration, AcceptedConvergenceDigest: request.AcceptedConvergenceDigest,
		PlanFingerprint: request.PlanFingerprint, Driver: request.Plan.Driver, Role: request.Plan.Role,
		Action: request.Action, Phase: RuntimeLifecyclePhaseProposed, WriterEpoch: request.WriterEpoch,
		AuthorizationEvidenceDigest: request.AuthorizationEvidenceDigest, ExecutorAttempt: attempt,
		DispatchToken: dispatchToken, CallStatus: RuntimeLifecycleCallStatusNotCalled,
		LastObservationFingerprint: nil, LastObservationWatermark: 0,
		DeadlineEvidence: request.DeadlineEvidence, CompensationPolicy: request.CompensationPolicy,
		JournalRevision: 0, PreviousEventDigest: genesisDigest, EventDigest: genesisDigest,
		TerminalStatus: RuntimeLifecycleTerminalStatusNone, ErrorCode: RuntimeLifecycleErrorCodeNone}
	eventDigest, err := RuntimeLifecycleFingerprint.Event(checkpoint)
	if err != nil {
		return RuntimeLifecycleCheckpoint{}, err
	}
	checkpoint.EventDigest = eventDigest
	return checkpoint, nil
}

func (c RuntimeLifecycleCheckpoint) Matches(request RuntimeLifecycleOperationRequest) bool {
	return c.SchemaVersion == RuntimeLifecycleContractSchemaVersion &&
		c.OperationKey == request.OperationKey && c.Cell == request.Cell && c.Node == request.Node &&
		c.AllocationId == request.Plan.AllocationId.Value && c.WorkloadGeneration == request.WorkloadGeneration &&
		c.AcceptedConvergenceDigest == request.AcceptedConvergenceDigest &&
		c.PlanFingerprint == request.PlanFingerprint && c.Driver == request.Plan.Driver &&
		c.Role == request.Plan.Role && c.Action == request.Action &&
		c.WriterEpoch == request.WriterEpoch &&
		c.AuthorizationEvidenceDigest == request.AuthorizationEvidenceDigest &&
		c.DeadlineEvidence == request.DeadlineEvidence &&
		c.CompensationPolicy == RuntimeLifecycleCompensationPolicyNone
}

type RuntimeLifecycleJournalRead struct {
	Status     RuntimeLifecycleJournalReadStatus
	Checkpoint *RuntimeLifecycleCheckpoint
}

type RuntimeLifecycleJournalWrite struct {
	Status     RuntimeLifecycleJournalWriteStatus
	Checkpoint *RuntimeLifecycleCheckpoint
}

// IRuntimeLifecycleJournal ports the journal interface.
type IRuntimeLifecycleJournal interface {
	ReadAsync(ctx context.Context, operationKey RuntimeLifecycleOperationKey) (RuntimeLifecycleJournalRead, error)
	CompareExchangeAsync(ctx context.Context, operationKey RuntimeLifecycleOperationKey,
		expectedRevision *uint64, checkpoint RuntimeLifecycleCheckpoint) (RuntimeLifecycleJournalWrite, error)
}

// IRuntimeLifecycleAuthorityGate ports the authority gate interface.
type IRuntimeLifecycleAuthorityGate interface {
	ReadAsync(ctx context.Context, cell RuntimeLifecycleCellId) (RuntimeLifecycleAuthority, error)
}

type RuntimeLifecycleExecutionRequest struct {
	OperationKey  RuntimeLifecycleOperationKey
	DispatchToken RuntimeDigest
	Plan          HostRuntimePlan
	Action        LifecycleAction
	WriterEpoch   RuntimeEpoch
}

type RuntimeLifecycleExecutorResponse struct {
	Status RuntimeLifecycleExecutorStatus
}

// RuntimeLifecycleObservationRequest is a transient recovery context. The plan
// is supplied by the exact caller, never retained in the checkpoint.
type RuntimeLifecycleObservationRequest struct {
	OperationKey                 RuntimeLifecycleOperationKey
	Plan                         HostRuntimePlan
	Action                       LifecycleAction
	PlanFingerprint              RuntimeLifecyclePlanFingerprint
	PreviousObservationWatermark uint64
	WriterEpoch                  RuntimeEpoch
	DispatchToken                RuntimeDigest
}

type RuntimeLifecycleObservation struct {
	OperationKey    RuntimeLifecycleOperationKey
	AllocationId    string
	PlanFingerprint RuntimeLifecyclePlanFingerprint
	Action          LifecycleAction
	Fingerprint     RuntimeLifecycleHostObservationFingerprint
	Watermark       uint64
	Status          RuntimeLifecycleObservationStatus
}

// IRuntimeLifecycleHostExecutor ports the host executor interface.
type IRuntimeLifecycleHostExecutor interface {
	ExecuteAsync(ctx context.Context, request RuntimeLifecycleExecutionRequest) (*RuntimeLifecycleExecutorResponse, error)
	ObserveAsync(ctx context.Context, request RuntimeLifecycleObservationRequest) (*RuntimeLifecycleObservation, error)
}

type RuntimeLifecycleResult struct {
	Checkpoint *RuntimeLifecycleCheckpoint
	Status     RuntimeLifecycleTerminalStatus
	ErrorCode  RuntimeLifecycleErrorCode
}

func (r RuntimeLifecycleResult) RequiresReconciliation() bool {
	return r.Status == RuntimeLifecycleTerminalStatusReconciliationRequired
}

// RuntimeLifecycleFingerprint ports the fingerprint static class.
var RuntimeLifecycleFingerprint runtimeLifecycleFingerprint

type runtimeLifecycleFingerprint struct{}

func canonicalStrings(builder *strings.Builder, values []string) {
	for _, value := range values {
		builder.WriteString(strconv.Itoa(v1UTF16CodeUnitCount(value)))
		builder.WriteByte(':')
		builder.WriteString(value)
		builder.WriteByte(';')
	}
}

func fingerprintCanonicalHash(values []string) string {
	var builder strings.Builder
	canonicalStrings(&builder, values)
	return RuntimeLifecycleFingerprint.Hash(builder.String())
}

func fingerprintList(values []string, out []string) []string {
	out = append(out, strconv.Itoa(len(values)))
	return append(out, values...)
}

func fingerprintResources(resources runtime.RuntimeResourceLimits) []string {
	return []string{
		strconv.FormatInt(resources.MemoryMaxBytes, 10),
		strconv.Itoa(resources.TasksMax),
		strconv.Itoa(resources.CpuQuotaPercent),
		strconv.Itoa(resources.CpuWeight),
		strconv.Itoa(resources.IoWeight),
		strconv.Itoa(resources.Nice),
	}
}

func (runtimeLifecycleFingerprint) Plan(plan HostRuntimePlan) (RuntimeLifecyclePlanFingerprint, error) {
	if plan.SchemaVersion != 2 || !hostAdmittedRoleIsDefined(plan.Role) ||
		plan.Driver != runtime.RuntimeDriverNativeSystemd ||
		!(plan.Architecture == runtime.HostArchitectureArm64 || plan.Architecture == runtime.HostArchitectureX64) ||
		plan.Systemd == nil || plan.Oci != nil {
		return RuntimeLifecyclePlanFingerprint{}, invalidArgument("Host runtime plan is not a supported closed plan.")
	}
	fields := []string{"host-runtime-plan-v1", strconv.Itoa(plan.SchemaVersion), strconv.Itoa(int(plan.Role)),
		strconv.Itoa(int(plan.Driver)), plan.AllocationId.Value, plan.ArtifactDigest.Value,
		strconv.Itoa(int(plan.Architecture))}
	fields = append(fields, fingerprintResources(plan.Resources)...)
	if plan.Systemd != nil {
		fields = append(fields, "systemd", plan.Systemd.UnitName, plan.Systemd.Executable)
		fields = fingerprintList(plan.Systemd.Arguments, fields)
		fields = fingerprintList(plan.Systemd.Properties, fields)
	}
	return NewRuntimeLifecyclePlanFingerprint(fingerprintCanonicalHash(fields))
}

func boolDigit(value bool) string {
	if value {
		return "1"
	}
	return "0"
}

func hostAdmittedRoleIsDefined(role runtime.AdmittedRole) bool {
	switch role {
	case runtime.AdmittedRoleTerraBaseMember, runtime.AdmittedRoleNats,
		runtime.AdmittedRoleJournalWriter:
		return true
	default:
		return false
	}
}

func (runtimeLifecycleFingerprint) Operation(request RuntimeLifecycleOperationRequest) (RuntimeLifecycleOperationKey, error) {
	values := []string{"runtime-lifecycle-operation-v1", request.Cell.Value, request.Node.Value,
		request.Plan.AllocationId.Value, strconv.FormatUint(request.WorkloadGeneration.Value, 10),
		request.AcceptedConvergenceDigest.Sha256, strconv.Itoa(int(request.Action)),
		strconv.Itoa(int(request.Plan.Driver)), strconv.Itoa(int(request.Plan.Role)),
		request.PlanFingerprint.Value}
	return NewRuntimeLifecycleOperationKey(fingerprintCanonicalHash(values))
}

func (runtimeLifecycleFingerprint) DispatchToken(request RuntimeLifecycleOperationRequest) string {
	values := []string{"runtime-lifecycle-dispatch-v1", request.OperationKey.Value,
		strconv.FormatUint(request.WriterEpoch.Value, 10), request.AuthorizationEvidenceDigest.Sha256}
	return fingerprintCanonicalHash(values)
}

func (runtimeLifecycleFingerprint) Event(checkpoint RuntimeLifecycleCheckpoint) (RuntimeDigest, error) {
	lastObservation := ""
	if checkpoint.LastObservationFingerprint != nil {
		lastObservation = checkpoint.LastObservationFingerprint.Value
	}
	values := []string{"runtime-lifecycle-event-v1", checkpoint.PreviousEventDigest.Sha256,
		checkpoint.OperationKey.Value, checkpoint.Cell.Value, checkpoint.Node.Value, checkpoint.AllocationId,
		strconv.FormatUint(checkpoint.WorkloadGeneration.Value, 10), checkpoint.AcceptedConvergenceDigest.Sha256,
		checkpoint.PlanFingerprint.Value, strconv.Itoa(int(checkpoint.Driver)), strconv.Itoa(int(checkpoint.Role)),
		strconv.Itoa(int(checkpoint.Action)), strconv.Itoa(int(checkpoint.Phase)),
		strconv.FormatUint(checkpoint.WriterEpoch.Value, 10), checkpoint.AuthorizationEvidenceDigest.Sha256,
		strconv.FormatUint(checkpoint.ExecutorAttempt.Value, 10), checkpoint.DispatchToken.Sha256,
		strconv.Itoa(int(checkpoint.CallStatus)), lastObservation,
		strconv.FormatUint(checkpoint.LastObservationWatermark, 10),
		checkpoint.DeadlineEvidence.Digest.Sha256, strconv.FormatUint(checkpoint.DeadlineEvidence.Watermark, 10),
		strconv.Itoa(int(checkpoint.CompensationPolicy)),
		strconv.FormatUint(checkpoint.JournalRevision, 10),
		strconv.Itoa(int(checkpoint.TerminalStatus)), strconv.Itoa(int(checkpoint.ErrorCode))}
	return NewRuntimeDigest(fingerprintCanonicalHash(values))
}

func (runtimeLifecycleFingerprint) Hash(value string) string {
	return digestHash(value)
}
