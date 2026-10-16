// Package native runs infrastructure qualification on disposable native image hosts.
// It is test infrastructure, never a production workload admission authority.
package native

import (
	"context"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/release"
)

// Identity combines locally measured component bytes with OCI instance metadata.
// ImageOCID is read from authenticated IMDSv2; the producer independently binds it
// to the imported QCOW2 digest in Candidate.ArtifactSHA256.
type Identity struct {
	Architecture     string `json:"architecture"`
	KernelRelease    string `json:"kernel_release"`
	KernelSHA256     string `json:"kernel_sha256"`
	BinarySHA256     string `json:"binary_sha256"`
	ContainerdSHA256 string `json:"containerd_sha256"`
	RuncSHA256       string `json:"runc_sha256"`
	InstanceID       string `json:"instance_id"`
	ImageOCID        string `json:"image_ocid"`
}

type Host struct {
	OCID             string
	Address          string // Private IPv4 address; SSH and SwarmKit use this same host.
	SSHHostKey       string // OpenSSH authorized-key form, obtained through trusted launch evidence.
	ExpectedIdentity Identity
}

// Request is supplied only after the parent has authenticated confinement and
// disposable host ownership. Run cannot establish that cloud authorization.
type Request struct {
	RunID                 string
	Candidate             release.ProductionExpectation
	ImageOCID             string
	Hosts                 []Host
	SSHUser               string
	PrivateKeyPath        string // Ephemeral local key, owner-only permissions; never retained.
	WorkerPath            string // Same-architecture test-only native-worker executable.
	WorkerSHA256          string
	WorkloadArchivePath   string // Local OCI archive, securely copied before runtime execution.
	WorkloadArchiveSHA256 string
	WorkloadImage         string // Architecture-specific immutable child manifest, providing /bin/sh and nc.
	ContainerdPath        string
	RuncPath              string
}

type HostReport struct {
	WorkerSourceRevision string   `json:"worker_source_revision"`
	OCID                 string   `json:"ocid"`
	Address              string   `json:"address"`
	Observed             Identity `json:"observed"`
	WorkerSHA256         string   `json:"worker_sha256"`
	NodeID               string   `json:"node_id"`
}

type Scenario struct {
	Name             string    `json:"name"`
	Gate             string    `json:"gate"`
	StartedAt        time.Time `json:"started_at"`
	CompletedAt      time.Time `json:"completed_at"`
	HostIDs          []string  `json:"host_ids"`
	Transcript       []byte    `json:"transcript"`
	TranscriptSHA256 string    `json:"transcript_sha256"`
}

type Report struct {
	RunID                 string                        `json:"run_id"`
	Candidate             release.ProductionExpectation `json:"candidate"`
	ImageOCID             string                        `json:"image_ocid"`
	WorkloadImage         string                        `json:"workload_image"`
	WorkloadArchiveSHA256 string                        `json:"workload_archive_sha256"`
	Hosts                 []HostReport                  `json:"hosts"`
	Scenarios             []Scenario                    `json:"scenarios"`
	StartedAt             time.Time                     `json:"started_at"`
	CompletedAt           time.Time                     `json:"completed_at"`
}

type command struct {
	Operation      string            `json:"operation"`
	SourceRevision string            `json:"source_revision,omitempty"`
	RunID          string            `json:"run_id,omitempty"`
	Host           Host              `json:"host,omitzero"`
	Region         string            `json:"region,omitempty"`
	Founder        string            `json:"founder,omitempty"`
	JoinAddress    string            `json:"join_address,omitempty"`
	Token          string            `json:"token,omitempty"`
	NodeID         string            `json:"node_id,omitempty"`
	ServiceID      string            `json:"service_id,omitempty"`
	Image          string            `json:"image,omitempty"`
	ArchiveSHA256  string            `json:"archive_sha256,omitempty"`
	Port           uint32            `json:"port,omitzero"`
	Mode           string            `json:"mode,omitempty"`
	Peers          []string          `json:"peers,omitempty"`
	Addresses      map[string]string `json:"addresses,omitempty"`
	ContainerdPath string            `json:"containerd_path,omitempty"`
	RuncPath       string            `json:"runc_path,omitempty"`
}

type taskState struct {
	ID         string `json:"id"`
	NodeID     string `json:"node_id"`
	PID        uint32 `json:"pid"`
	Containers int    `json:"containers"`
	Secure     bool   `json:"secure"`
}

type response struct {
	WorkerSHA256         string      `json:"worker_sha256,omitempty"`
	WorkerSourceRevision string      `json:"worker_source_revision,omitempty"`
	Error                string      `json:"error,omitempty"`
	Identity             Identity    `json:"identity,omitzero"`
	NodeID               string      `json:"node_id,omitempty"`
	Token                string      `json:"token,omitempty"`
	Leader               string      `json:"leader,omitempty"`
	Managers             int         `json:"managers,omitzero"`
	ServiceID            string      `json:"service_id,omitempty"`
	Tasks                []taskState `json:"tasks,omitempty"`
	Running              uint64      `json:"running,omitzero"`
	Ready                uint64      `json:"ready,omitzero"`
	UpdateState          string      `json:"update_state,omitempty"`
}

type peer interface {
	call(context.Context, command) (response, error)
	close() error
}
