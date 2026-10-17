// Package drainwire carries retained execution identities, never execution authority.
package drainwire

import (
	"crypto/sha256"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

type HostSession struct {
	Cell                   string    `json:"cell"`
	HostNode               string    `json:"host_node"`
	RegistrationID         string    `json:"registration_id"`
	InstanceID             string    `json:"instance_id"`
	HostSessionID          string    `json:"host_session_id"`
	RegistrationGeneration uint64    `json:"registration_generation"`
	HostEpoch              uint64    `json:"host_epoch"`
	ExpiresAt              time.Time `json:"expires_at"`
}

type ExecutionHold struct {
	OriginalEpoch uint64 `json:"original_epoch"`
	HostSession
	NodeID             string    `json:"node_id"`
	TaskID             string    `json:"task_id"`
	ServiceID          string    `json:"service_id"`
	TaskSHA256         string    `json:"task_sha256"`
	ExecutionSHA256    string    `json:"execution_sha256"`
	ExecutionSessionID string    `json:"execution_session_id"`
	IssuedAt           time.Time `json:"issued_at"`
}

type SignedHold struct {
	Hold             ExecutionHold `json:"hold"`
	CertificateChain [][]byte      `json:"certificate_chain"`
	Signature        []byte        `json:"signature"`
}

type DrainStopChallenge struct {
	Cell                   string    `json:"cell"`
	HostNode               string    `json:"host_node"`
	RemovalOperationID     string    `json:"removal_operation_id"`
	BirthOperationID       string    `json:"birth_operation_id"`
	InstanceID             string    `json:"instance_id"`
	NodeID                 string    `json:"node_id"`
	RegistrationID         string    `json:"registration_id"`
	HostSessionID          string    `json:"host_session_id"`
	RegistrationGeneration uint64    `json:"registration_generation"`
	Epoch                  uint64    `json:"epoch"`
	HostEpoch              uint64    `json:"host_epoch"`
	OriginalEpoch          uint64    `json:"original_epoch"`
	ExecutionSessionID     string    `json:"execution_session_id"`
	TaskID                 string    `json:"task_id"`
	ServiceID              string    `json:"service_id"`
	TaskSHA256             string    `json:"task_sha256"`
	ExecutionSHA256        string    `json:"execution_sha256"`
	Nonce                  string    `json:"nonce"`
	IssuedAt               time.Time `json:"issued_at"`
	Deadline               time.Time `json:"deadline"`
}

type StopPayload struct {
	Challenge      DrainStopChallenge `json:"challenge"`
	ObservedAt     time.Time          `json:"observed_at"`
	ContainerID    string             `json:"container_id"`
	KernelStart    string             `json:"kernel_start"`
	Cgroup         string             `json:"cgroup"`
	HostPID        int                `json:"host_pid"`
	PIDNamespace   uint64             `json:"pid_namespace"`
	MountNamespace uint64             `json:"mount_namespace"`
}

type SignedStop struct {
	StopPayload
	CertificateChain [][]byte `json:"certificate_chain"`
	Signature        []byte   `json:"signature"`
}

func (h ExecutionHold) Validate() error {
	if h.Cell == "" || h.HostNode == "" || !entityid.Valid(h.RegistrationID) || !entityid.Valid(h.HostSessionID) ||
		h.InstanceID == "" || h.RegistrationGeneration == 0 || h.OriginalEpoch == 0 || h.HostEpoch == 0 || !h.ExpiresAt.After(h.IssuedAt) || !entityid.Valid(h.ExecutionSessionID) ||
		h.NodeID == "" || h.TaskID == "" || h.ServiceID == "" || strings.ContainsAny(h.NodeID+h.TaskID+h.ServiceID, "/\\. \t\r\n") ||
		!digest(h.TaskSHA256) || !digest(h.ExecutionSHA256) || h.IssuedAt.IsZero() {
		return errors.New("generic execution hold is incomplete")
	}
	return nil
}

func (c DrainStopChallenge) Matches(h ExecutionHold) bool {
	return c.Cell == h.Cell && c.HostNode == h.HostNode && c.RegistrationID == h.RegistrationID && c.InstanceID == h.InstanceID &&
		c.NodeID == h.NodeID && c.HostSessionID == h.HostSessionID && c.RegistrationGeneration == h.RegistrationGeneration &&
		c.OriginalEpoch == h.OriginalEpoch && c.HostEpoch == h.HostEpoch && c.ExecutionSessionID == h.ExecutionSessionID && c.TaskID == h.TaskID &&
		c.ServiceID == h.ServiceID && c.TaskSHA256 == h.TaskSHA256 && c.ExecutionSHA256 == h.ExecutionSHA256
}

func (c DrainStopChallenge) Validate(now time.Time) error {
	if !entityid.Valid(c.RemovalOperationID) || !entityid.Valid(c.BirthOperationID) || !digest(c.Nonce) || c.Epoch == 0 ||
		c.HostEpoch == 0 || c.OriginalEpoch == 0 || c.OriginalEpoch > c.Epoch || c.IssuedAt.IsZero() || c.IssuedAt.After(now) ||
		!c.Deadline.After(c.IssuedAt) || c.Deadline.Sub(c.IssuedAt) > 30*time.Minute || !now.Before(c.Deadline) {
		return errors.New("drain stop challenge has no exact current bounded authority")
	}
	return nil
}

func HoldSigningBytes(h ExecutionHold) ([]byte, error) {
	wire, err := json.Marshal(h, json.Deterministic(true))
	return append([]byte("TS-GENERIC-EXECUTION-HOLD-V1\x00"), wire...), err
}

func StopSigningBytes(p StopPayload) ([]byte, error) {
	wire, err := json.Marshal(p, json.Deterministic(true))
	return append([]byte("TS-POOL-DRAIN-STOP-V1\x00"), wire...), err
}

func HoldSHA256(h ExecutionHold) (string, error) {
	wire, err := HoldSigningBytes(h)
	return fmt.Sprintf("%x", sha256.Sum256(wire)), err
}

func digest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

// Session renewal may extend a live source, never an already captured deadline.
func (s HostSession) SameIdentity(other HostSession) bool {
	s.ExpiresAt, other.ExpiresAt = time.Time{}, time.Time{}
	s.InstanceID, other.InstanceID = "", ""
	return s == other
}
