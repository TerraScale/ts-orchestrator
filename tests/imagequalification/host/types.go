// Package host provides disposable-image qualification observations and pinned SSH transport.
// It creates no cloud, workload-admission, or production trust authority.
package host

import (
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/release"
)

// Identity combines locally measured component bytes with OCI instance metadata.
// ImageOCID is observed through OCI IMDSv2 on the pinned SSH host; it is
// not cryptographic instance or boot attestation. The producer independently binds it
// to the imported QCOW2 digest in Candidate.ArtifactSHA256.
// Component file hashes do not attest which containerd or runc process is running.
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
	Address          string // Private IPv4 address of the explicitly approved disposable host.
	SSHHostKey       string // OpenSSH authorized-key form, obtained through trusted launch evidence.
	ExpectedIdentity Identity
}

type HostReport struct {
	Role                 string   `json:"role"`
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
