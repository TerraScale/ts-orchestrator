// Package executionwire contains inert stateful host transport values.
package executionwire

import (
	"crypto/sha256"
	"encoding/json/v2"
	"fmt"
	"github.com/moby/swarmkit/v2/api"
	"time"
)

// WorkerIdentity is pinned to the existing authenticated host process and node.
type WorkerIdentity struct {
	Cell                   string `json:"cell"`
	HostNode               string `json:"host_node"`
	NATSUserPublicKey      string `json:"nats_user_public_key"`
	HostPublicKey          string `json:"host_public_key"`
	InstanceID             string `json:"instance_id"`
	NodeID                 string `json:"node_id"`
	HostSessionID          string `json:"host_session_id"`
	RegistrationGeneration uint64 `json:"registration_generation"`
}

type RuntimeEffectQuery struct {
	Action    string             `json:"action"`
	EffectID  string             `json:"effect_id"`
	Nonce     string             `json:"nonce"`
	Task      *api.Task          `json:"task"`
	Identity  WorkerIdentity     `json:"identity"`
	StopProof *SignedRuntimeStop `json:"stop_proof,omitempty"`
}

type WorkerGrantPayload struct {
	Identity      WorkerIdentity      `json:"identity"`
	TaskID        string              `json:"task_id"`
	ServiceID     string              `json:"service_id"`
	TaskSHA256    string              `json:"task_sha256"`
	EffectID      string              `json:"effect_id"`
	Nonce         string              `json:"nonce"`
	Epoch         uint64              `json:"epoch"`
	Revision      uint64              `json:"revision"`
	IssuedAt      time.Time           `json:"issued_at"`
	Deadline      time.Time           `json:"deadline"`
	Material      WorkerGrantMaterial `json:"material"`
	Phase         string              `json:"phase"`
	StopChallenge string              `json:"stop_challenge,omitempty"`
}

// WorkerAdmissionSHA256 binds immutable material; renewal changes no identity.
// Computing this digest grants no authority.
func WorkerAdmissionSHA256(payload WorkerGrantPayload) (string, error) {
	material, err := json.Marshal(payload.Material, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	immutable := struct {
		Identity                                                WorkerIdentity
		TaskID, ServiceID, TaskSHA256, EffectID, MaterialSHA256 string
		Epoch                                                   uint64
	}{
		payload.Identity, payload.TaskID, payload.ServiceID, payload.TaskSHA256, payload.EffectID, fmt.Sprintf("%x", sha256.Sum256(material)), payload.Epoch,
	}
	wire, err := json.Marshal(immutable, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(wire)), nil
}

// RuntimeStopPayload describes a fresh observation of an already stopped writer.
type RuntimeStopPayload struct {
	EffectID       string    `json:"effect_id"`
	TaskSHA256     string    `json:"task_sha256"`
	InstanceID     string    `json:"instance_id"`
	NodeID         string    `json:"node_id"`
	ContainerID    string    `json:"container_id"`
	KernelStart    string    `json:"kernel_start"`
	Cgroup         string    `json:"cgroup"`
	Challenge      string    `json:"challenge"`
	Epoch          uint64    `json:"epoch"`
	Revision       uint64    `json:"revision"`
	PIDNamespace   uint64    `json:"pid_namespace"`
	MountNamespace uint64    `json:"mount_namespace"`
	HostPID        int       `json:"host_pid"`
	Deadline       time.Time `json:"deadline"`
	ObservedAt     time.Time `json:"observed_at"`
}
type SignedRuntimeStop struct {
	Payload          RuntimeStopPayload `json:"payload"`
	CertificateChain [][]byte           `json:"certificate_chain"`
	Signature        []byte             `json:"signature"`
}
