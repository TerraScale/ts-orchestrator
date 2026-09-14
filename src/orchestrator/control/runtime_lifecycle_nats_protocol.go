package control

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/protocol"
)

// RuntimeLifecycleNatsProtocol ports the closed, redacted wire contract for
// the private runtime-lifecycle journal bridge. This protocol carries no host
// plan, secret, credential, provider identifier, or exception text.
var RuntimeLifecycleNatsProtocol runtimeLifecycleNatsProtocol

type runtimeLifecycleNatsProtocol struct{}

const (
	RuntimeLifecycleNatsProtocolSchemaVersion          = 2
	RuntimeLifecycleNatsProtocolMaximumCheckpointBytes = 16 * 1024
	RuntimeLifecycleNatsProtocolReadAction             = "runtime-lifecycle-read"
	RuntimeLifecycleNatsProtocolCreateAction           = "runtime-lifecycle-create"
	RuntimeLifecycleNatsProtocolUpdateAction           = "runtime-lifecycle-update"
)

func (runtimeLifecycleNatsProtocol) Subject(cell, operation string) (string, error) {
	required, err := runtimeLifecycleRequireCell(cell)
	if err != nil {
		return "", err
	}
	return protocol.NatsSubjectTaxonomy.RuntimeLifecycleJournalSubject(required, operation)
}

func (runtimeLifecycleNatsProtocol) ReplySubject(cell, callerIdentity, nonce string) (string, error) {
	required, err := runtimeLifecycleRequireCell(cell)
	if err != nil {
		return "", err
	}
	return protocol.NatsSubjectTaxonomy.RuntimeLifecycleJournalReplySubject(required, callerIdentity, nonce)
}

func (runtimeLifecycleNatsProtocol) Key(operationKey RuntimeLifecycleOperationKey) string {
	return "runtime." + operationKey.Value
}

func isAsciiHexDigitString(value string) bool {
	for i := 0; i < len(value); i++ {
		c := value[i]
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') && !(c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

func (runtimeLifecycleNatsProtocol) IsKey(key string) bool {
	return len(key) == 72 && strings.HasPrefix(key, "runtime.") &&
		isAsciiHexDigitString(key[8:])
}

func (runtimeLifecycleNatsProtocol) Serialize(checkpoint RuntimeLifecycleCheckpoint) (string, error) {
	encoded, err := marshalCheckpointJSON(checkpoint)
	if err != nil {
		return "", err
	}
	if len(encoded) > RuntimeLifecycleNatsProtocolMaximumCheckpointBytes {
		return "", invalidArgument("Runtime lifecycle checkpoint exceeds its journal bound.")
	}
	return encoded, nil
}

func (runtimeLifecycleNatsProtocol) TryDeserialize(value string) (RuntimeLifecycleCheckpoint, bool) {
	if isNullOrWhiteSpace(value) || len(value) > RuntimeLifecycleNatsProtocolMaximumCheckpointBytes {
		return RuntimeLifecycleCheckpoint{}, false
	}
	checkpoint, err := unmarshalCheckpointJSON(value)
	if err != nil {
		return RuntimeLifecycleCheckpoint{}, false
	}
	roundTrip, err := marshalCheckpointJSON(checkpoint)
	if err != nil || roundTrip != value {
		return RuntimeLifecycleCheckpoint{}, false
	}
	return checkpoint, true
}

func (runtimeLifecycleNatsProtocol) IsCheckpoint(checkpoint *RuntimeLifecycleCheckpoint, cell, key string, revision uint64) bool {
	if checkpoint == nil || revision == 0 {
		return false
	}
	if checkpoint.SchemaVersion != RuntimeLifecycleContractSchemaVersion ||
		checkpoint.Cell.Value != cell ||
		RuntimeLifecycleNatsProtocol.Key(checkpoint.OperationKey) != key ||
		checkpoint.JournalRevision != revision {
		return false
	}
	if !(checkpoint.Driver == 0 || checkpoint.Driver == 1) ||
		!hostAdmittedRoleIsDefined(checkpoint.Role) ||
		!lifecycleActionIsDefined(checkpoint.Action) ||
		!runtimeLifecyclePhaseIsDefined(checkpoint.Phase) ||
		!runtimeLifecycleCallStatusIsDefined(checkpoint.CallStatus) ||
		!runtimeLifecycleCompensationPolicyIsDefined(checkpoint.CompensationPolicy) ||
		!runtimeLifecycleTerminalStatusIsDefined(checkpoint.TerminalStatus) ||
		!runtimeLifecycleErrorCodeIsDefined(checkpoint.ErrorCode) ||
		checkpoint.CompensationPolicy != RuntimeLifecycleCompensationPolicyNone {
		return false
	}
	eventDigest, err := RuntimeLifecycleFingerprint.Event(*checkpoint)
	if err != nil || checkpoint.EventDigest != eventDigest {
		return false
	}
	return true
}

func (runtimeLifecycleNatsProtocol) IsGenesis(checkpoint RuntimeLifecycleCheckpoint) bool {
	return checkpoint.PreviousEventDigest.Sha256 == RuntimeLifecycleFingerprint.Hash("runtime-lifecycle-genesis-v2") &&
		checkpoint.Phase == RuntimeLifecyclePhaseProposed
}

func (runtimeLifecycleNatsProtocol) IsChained(current, next RuntimeLifecycleCheckpoint) bool {
	return current.JournalRevision < ^uint64(0) && next.PreviousEventDigest == current.EventDigest &&
		next.JournalRevision == current.JournalRevision+1
}

func (runtimeLifecycleNatsProtocol) ProofBinding(action string, schemaVersion int, cell, key string,
	expectedRevision, writerEpoch uint64, requestId string, checkpoint *string) string {
	checkpointText := ""
	if checkpoint != nil {
		checkpointText = *checkpoint
	}
	values := []string{"runtime-lifecycle-nats-proof-v2", action, strconv.Itoa(schemaVersion), cell, key,
		strconv.FormatUint(expectedRevision, 10), strconv.FormatUint(writerEpoch, 10), requestId, checkpointText}
	return RuntimeLifecycleFingerprint.Hash(strings.Join(values, "|"))
}

func (runtimeLifecycleNatsProtocol) IsRequest(schemaVersion int, cell, key, requestId string) bool {
	return schemaVersion == RuntimeLifecycleNatsProtocolSchemaVersion && RuntimeLifecycleNatsProtocol.IsCell(cell) &&
		RuntimeLifecycleNatsProtocol.IsKey(key) && len(requestId) == 32 && isAsciiHexDigitString(requestId)
}

func (runtimeLifecycleNatsProtocol) IsCell(value string) bool {
	if len(value) == 0 || len(value) > 63 {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		isLetterOrDigit := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		if !isLetterOrDigit && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

func runtimeLifecycleRequireCell(value string) (string, error) {
	if !RuntimeLifecycleNatsProtocol.IsCell(value) {
		return "", argumentOutOfRange("value")
	}
	return value, nil
}

type NatsRuntimeLifecycleJournalReadRequest struct {
	SchemaVersion int
	Cell          string
	Key           string
	RequestId     string
	Authority     NatsOperationJournalMutationAuthorityProof
}

func NewNatsRuntimeLifecycleJournalReadRequest(schemaVersion int, cell, key, requestId string,
	authority NatsOperationJournalMutationAuthorityProof) *NatsRuntimeLifecycleJournalReadRequest {
	return &NatsRuntimeLifecycleJournalReadRequest{schemaVersion, cell, key, requestId, authority}
}

type NatsRuntimeLifecycleJournalWriteRequest struct {
	SchemaVersion    int
	Cell             string
	Key              string
	ExpectedRevision uint64
	WriterEpoch      uint64
	Checkpoint       string
	RequestId        string
	Authority        NatsOperationJournalMutationAuthorityProof
}

func NewNatsRuntimeLifecycleJournalWriteRequest(schemaVersion int, cell, key string, expectedRevision,
	writerEpoch uint64, checkpoint, requestId string,
	authority NatsOperationJournalMutationAuthorityProof) *NatsRuntimeLifecycleJournalWriteRequest {
	return &NatsRuntimeLifecycleJournalWriteRequest{schemaVersion, cell, key, expectedRevision, writerEpoch,
		checkpoint, requestId, authority}
}

type NatsRuntimeLifecycleJournalReply struct {
	SchemaVersion int
	Status        int
	Revision      uint64
	Checkpoint    *string
	RequestDigest string
	Signature     string
}

func (r NatsRuntimeLifecycleJournalReply) Payload() string {
	checkpoint := ""
	if r.Checkpoint != nil {
		checkpoint = *r.Checkpoint
	}
	return strings.Join([]string{strconv.Itoa(r.SchemaVersion), strconv.Itoa(r.Status),
		strconv.FormatUint(r.Revision, 10), checkpoint, r.RequestDigest}, "|")
}

// checkpointJSONValue mirrors the .NET source-generated JSON shape for
// RuntimeLifecycleCheckpoint: PascalCase property names, enums as numbers and
// nested single-value records as objects.
type checkpointJSONValue struct {
	Value string `json:"Value"`
}

type digestJSONValue struct {
	Sha256 string `json:"Sha256"`
}

type generationJSONValue struct {
	Value uint64 `json:"Value"`
}

type deadlineJSONValue struct {
	Digest    digestJSONValue `json:"Digest"`
	Watermark uint64          `json:"Watermark"`
}

type observationFingerprintJSONValue struct {
	Value string `json:"Value"`
}

type checkpointJSON struct {
	SchemaVersion               int                              `json:"SchemaVersion"`
	OperationKey                checkpointJSONValue              `json:"OperationKey"`
	Cell                        checkpointJSONValue              `json:"Cell"`
	Node                        checkpointJSONValue              `json:"Node"`
	AllocationId                string                           `json:"AllocationId"`
	WorkloadGeneration          generationJSONValue              `json:"WorkloadGeneration"`
	AcceptedConvergenceDigest   digestJSONValue                  `json:"AcceptedConvergenceDigest"`
	PlanFingerprint             checkpointJSONValue              `json:"PlanFingerprint"`
	Driver                      int                              `json:"Driver"`
	Role                        int                              `json:"Role"`
	Action                      int                              `json:"Action"`
	Phase                       int                              `json:"Phase"`
	WriterEpoch                 generationJSONValue              `json:"WriterEpoch"`
	AuthorizationEvidenceDigest digestJSONValue                  `json:"AuthorizationEvidenceDigest"`
	ExecutorAttempt             generationJSONValue              `json:"ExecutorAttempt"`
	DispatchToken               digestJSONValue                  `json:"DispatchToken"`
	CallStatus                  int                              `json:"CallStatus"`
	LastObservationFingerprint  *observationFingerprintJSONValue `json:"LastObservationFingerprint"`
	LastObservationWatermark    uint64                           `json:"LastObservationWatermark"`
	DeadlineEvidence            deadlineJSONValue                `json:"DeadlineEvidence"`
	CompensationPolicy          int                              `json:"CompensationPolicy"`
	JournalRevision             uint64                           `json:"JournalRevision"`
	PreviousEventDigest         digestJSONValue                  `json:"PreviousEventDigest"`
	EventDigest                 digestJSONValue                  `json:"EventDigest"`
	TerminalStatus              int                              `json:"TerminalStatus"`
	ErrorCode                   int                              `json:"ErrorCode"`
}

func checkpointToJSON(checkpoint RuntimeLifecycleCheckpoint) checkpointJSON {
	var lastObservation *observationFingerprintJSONValue
	if checkpoint.LastObservationFingerprint != nil {
		lastObservation = &observationFingerprintJSONValue{Value: checkpoint.LastObservationFingerprint.Value}
	}
	return checkpointJSON{
		SchemaVersion:               checkpoint.SchemaVersion,
		OperationKey:                checkpointJSONValue{checkpoint.OperationKey.Value},
		Cell:                        checkpointJSONValue{checkpoint.Cell.Value},
		Node:                        checkpointJSONValue{checkpoint.Node.Value},
		AllocationId:                checkpoint.AllocationId,
		WorkloadGeneration:          generationJSONValue{checkpoint.WorkloadGeneration.Value},
		AcceptedConvergenceDigest:   digestJSONValue{checkpoint.AcceptedConvergenceDigest.Sha256},
		PlanFingerprint:             checkpointJSONValue{checkpoint.PlanFingerprint.Value},
		Driver:                      int(checkpoint.Driver),
		Role:                        int(checkpoint.Role),
		Action:                      int(checkpoint.Action),
		Phase:                       int(checkpoint.Phase),
		WriterEpoch:                 generationJSONValue{checkpoint.WriterEpoch.Value},
		AuthorizationEvidenceDigest: digestJSONValue{checkpoint.AuthorizationEvidenceDigest.Sha256},
		ExecutorAttempt:             generationJSONValue{checkpoint.ExecutorAttempt.Value},
		DispatchToken:               digestJSONValue{checkpoint.DispatchToken.Sha256},
		CallStatus:                  int(checkpoint.CallStatus),
		LastObservationFingerprint:  lastObservation,
		LastObservationWatermark:    checkpoint.LastObservationWatermark,
		DeadlineEvidence: deadlineJSONValue{digestJSONValue{checkpoint.DeadlineEvidence.Digest.Sha256},
			checkpoint.DeadlineEvidence.Watermark},
		CompensationPolicy:  int(checkpoint.CompensationPolicy),
		JournalRevision:     checkpoint.JournalRevision,
		PreviousEventDigest: digestJSONValue{checkpoint.PreviousEventDigest.Sha256},
		EventDigest:         digestJSONValue{checkpoint.EventDigest.Sha256},
		TerminalStatus:      int(checkpoint.TerminalStatus),
		ErrorCode:           int(checkpoint.ErrorCode),
	}
}

func checkpointFromJSON(value checkpointJSON) RuntimeLifecycleCheckpoint {
	var lastObservation *RuntimeLifecycleHostObservationFingerprint
	if value.LastObservationFingerprint != nil {
		lastObservation = &RuntimeLifecycleHostObservationFingerprint{Value: value.LastObservationFingerprint.Value}
	}
	return RuntimeLifecycleCheckpoint{
		SchemaVersion:               value.SchemaVersion,
		OperationKey:                RuntimeLifecycleOperationKey{Value: value.OperationKey.Value},
		Cell:                        RuntimeLifecycleCellId{RuntimeToken{Value: value.Cell.Value}},
		Node:                        RuntimeNodeId{RuntimeToken{Value: value.Node.Value}},
		AllocationId:                value.AllocationId,
		WorkloadGeneration:          RuntimeGeneration{PositiveRuntimeNumber{Value: value.WorkloadGeneration.Value}},
		AcceptedConvergenceDigest:   RuntimeDigest{Sha256: value.AcceptedConvergenceDigest.Sha256},
		PlanFingerprint:             RuntimeLifecyclePlanFingerprint{Value: value.PlanFingerprint.Value},
		Driver:                      HostRuntimeDriver(value.Driver),
		Role:                        HostRole(value.Role),
		Action:                      LifecycleAction(value.Action),
		Phase:                       RuntimeLifecyclePhase(value.Phase),
		WriterEpoch:                 RuntimeEpoch{PositiveRuntimeNumber{Value: value.WriterEpoch.Value}},
		AuthorizationEvidenceDigest: RuntimeDigest{Sha256: value.AuthorizationEvidenceDigest.Sha256},
		ExecutorAttempt:             RuntimeAttempt{PositiveRuntimeNumber{Value: value.ExecutorAttempt.Value}},
		DispatchToken:               RuntimeDigest{Sha256: value.DispatchToken.Sha256},
		CallStatus:                  RuntimeLifecycleCallStatus(value.CallStatus),
		LastObservationFingerprint:  lastObservation,
		LastObservationWatermark:    value.LastObservationWatermark,
		DeadlineEvidence: RuntimeLifecycleDeadlineEvidence{Digest: RuntimeDigest{Sha256: value.DeadlineEvidence.Digest.Sha256},
			Watermark: value.DeadlineEvidence.Watermark},
		CompensationPolicy:  RuntimeLifecycleCompensationPolicy(value.CompensationPolicy),
		JournalRevision:     value.JournalRevision,
		PreviousEventDigest: RuntimeDigest{Sha256: value.PreviousEventDigest.Sha256},
		EventDigest:         RuntimeDigest{Sha256: value.EventDigest.Sha256},
		TerminalStatus:      RuntimeLifecycleTerminalStatus(value.TerminalStatus),
		ErrorCode:           RuntimeLifecycleErrorCode(value.ErrorCode),
	}
}

func marshalCheckpointJSON(checkpoint RuntimeLifecycleCheckpoint) (string, error) {
	encoded, err := marshalJSONNoEscape(checkpointToJSON(checkpoint))
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func unmarshalCheckpointJSON(value string) (RuntimeLifecycleCheckpoint, error) {
	decoder := json.NewDecoder(bytes.NewReader([]byte(value)))
	decoder.DisallowUnknownFields()
	var parsed checkpointJSON
	if err := decoder.Decode(&parsed); err != nil {
		return RuntimeLifecycleCheckpoint{}, err
	}
	return checkpointFromJSON(parsed), nil
}

func marshalJSONNoEscape(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buffer.Bytes(), "\n"), nil
}
