package rootoci

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"github.com/TerraScale/ts-orchestrator/internal/rootociwire"
	"strings"
)

const SocketPath = rootociwire.SocketPath

// The existing five MiB public signed chain expands under JSON base64.
const maxFrameBytes = rootociwire.MaxFrameBytes

var (
	ErrInvalid        = errors.New("root OCI request invalid")
	ErrUnavailable    = errors.New("root OCI operation unavailable")
	ErrPending        = errors.New("root OCI operation pending")
	ErrOutcomeUnknown = errors.New("root OCI operation outcome unknown")
)

// The private envelope is a finite operation union, never an exported RPC API.
type wireRequest struct {
	Version   uint64         `json:"version"`
	Operation Operation      `json:"operation"`
	Expected  Expectations   `json:"expected"`
	Payload   jsontext.Value `json:"payload"`
}

type wireResponse struct {
	Version   uint64         `json:"version"`
	Operation Operation      `json:"operation"`
	Status    string         `json:"status"`
	Payload   jsontext.Value `json:"payload,omitempty"`
}

func decodePayload(payload jsontext.Value, destination any) error {
	if len(payload) < 2 || payload[0] != '{' || json.Unmarshal(payload, destination, json.RejectUnknownMembers(true)) != nil {
		return ErrInvalid
	}
	return nil
}

func validExpectations(expected Expectations) bool {
	return (expected.Cell == "" || validSelector(expected.Cell)) &&
		(expected.GrantSHA256 == "" || validDigest(expected.GrantSHA256)) &&
		(expected.OperationID == "" || validSelector(expected.OperationID))
}

func validSelector(value string) bool {
	if value == "" || len(value) > 256 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("-_.:", character) {
			continue
		}
		return false
	}
	return true
}

func validDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if character >= '0' && character <= '9' || character >= 'a' && character <= 'f' {
			continue
		}
		return false
	}
	return true
}

func errorStatus(err error) string {
	switch {
	case errors.Is(err, ErrOutcomeUnknown):
		return "outcome_unknown"
	case err == nil:
		return "ok"
	case errors.Is(err, ErrInvalid):
		return "invalid"
	case errors.Is(err, ErrUnauthorized):
		return "unauthorized"
	case errors.Is(err, ErrPending):
		return "pending"
	default:
		return "unavailable"
	}
}

func statusError(status string) error {
	switch status {
	case "ok":
		return nil
	case "invalid":
		return ErrInvalid
	case "unauthorized":
		return ErrUnauthorized
	case "pending":
		return ErrPending
	case "outcome_unknown":
		return errors.Join(ErrUnavailable, ErrOutcomeUnknown)
	default:
		return ErrUnavailable
	}
}

// observationOnly does not grant the six-operation startup exemption.
func (operation Operation) observationOnly() bool {
	switch operation {
	case OperationObservePoolChild, OperationInspectVolumeMount, OperationObserveTerminatedInstance,
		OperationObserveContainerGeneration, OperationContainerEvidence, OperationContainerAllocation,
		OperationRetainedContainerEvidence, OperationRetainedContainerAllocation,
		OperationNativeRelease, OperationReleaseBinaryChunk, OperationNativeReleaseBinaryChunk, OperationContainerRelease:
		return true
	default:
		return operation.ReadOnly()
	}
}
