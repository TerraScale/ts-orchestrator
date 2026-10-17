// Package native runs infrastructure qualification on disposable native image hosts.
// It is test infrastructure, never a production workload admission authority.
package native

import (
	"context"

	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	qualificationhost "github.com/TerraScale/ts-orchestrator/tests/imagequalification/host"
)

type Identity = qualificationhost.Identity
type Host = qualificationhost.Host
type HostReport = qualificationhost.HostReport
type Scenario = qualificationhost.Scenario
type Report = qualificationhost.Report

// Request is supplied only after the parent has authenticated confinement and
// disposable host ownership. Run cannot establish that cloud authorization.
// MaterialFixture identifies existing signed production profile/intent proof
// bytes for one exact qualification phase. It grants no authority by itself.
type MaterialFixture struct {
	Scenario              string
	SignedProfilePath     string
	SignedProfileSHA256   string
	ContainerIntentPath   string
	ContainerIntentSHA256 string
	EvidenceDirectory     string
}

// RequiredMaterialScenarios is the exact ordered authority set bound by the
// parent approval. Rollback reuses the original ready authority.
func RequiredMaterialScenarios() [5]string {
	return [5]string{"ready", "after-loss", "after-partition", "unready", "failed-update"}
}

// ValidateProfileIdentity binds existing root authority to the image candidate;
// it neither verifies signed bytes nor creates a deployment identity.
func ValidateProfileIdentity(candidate release.ProductionExpectation, identity cellspec.Identity) error {
	return qualificationhost.ValidateProfileIdentity(candidate, identity)
}

type Request struct {
	RootCredentialProofs          map[string][]byte
	RootCredentialNamespaceSHA256 string
	Delivery                      Delivery
	MaterialFixtures              []MaterialFixture
	TrustedRoots                  trust.Keyring
	ProfileIdentity               cellspec.Identity
	RunID                         string
	Candidate                     release.ProductionExpectation
	ImageOCID                     string
	Hosts                         []Host
	SSHUser                       string
	PrivateKeyPath                string // Ephemeral local key, owner-only permissions; never retained.
	WorkerPath                    string // Same-architecture test-only native-worker executable.
	WorkerSHA256                  string
	WorkloadArchivePath           string // Local archive identity; delivery uses the authenticated artifact producer.
	WorkloadArchiveSHA256         string
	WorkloadImage                 string // Architecture-specific immutable child manifest, providing /bin/sh and nc.
	ContainerdPath                string
	RuncPath                      string
}

// Delivery uses the parent's authenticated controller client; SSH never supplies authority.
type Delivery interface {
	Apply(context.Context, MaterialFixture) error
}

type command struct {
	RootCredentialProof []byte                       `json:"root_credential_proof,omitempty"`
	Expected            []swarmruntime.ServiceIntent `json:"expected,omitempty"`
	Operation           string                       `json:"operation"`
	SourceRevision      string                       `json:"source_revision,omitempty"`
	RunID               string                       `json:"run_id,omitempty"`
	Host                Host                         `json:"host,omitzero"`
	ServiceID           string                       `json:"service_id,omitempty"`
	Mode                string                       `json:"mode,omitempty"`
	Peers               []string                     `json:"peers,omitempty"`
	Addresses           map[string]string            `json:"addresses,omitempty"`
	ContainerdPath      string                       `json:"containerd_path,omitempty"`
	RuncPath            string                       `json:"runc_path,omitempty"`
}

type taskState struct {
	ID         string `json:"id"`
	NodeID     string `json:"node_id"`
	PID        uint32 `json:"pid"`
	Containers int    `json:"containers"`
	Secure     bool   `json:"secure"`
}

type response struct {
	RootCredentialBoundary *release.RootCredentialBoundaryHost `json:"root_credential_boundary,omitempty"`
	Role                   string                              `json:"role,omitempty"`
	WorkerSHA256           string                              `json:"worker_sha256,omitempty"`
	WorkerSourceRevision   string                              `json:"worker_source_revision,omitempty"`
	Error                  string                              `json:"error,omitempty"`
	Identity               Identity                            `json:"identity,omitzero"`
	NodeID                 string                              `json:"node_id,omitempty"`
	Leader                 string                              `json:"leader,omitempty"`
	Managers               int                                 `json:"managers,omitzero"`
	OperationID            string                              `json:"operation_id,omitempty"`
	ServiceID              string                              `json:"service_id,omitempty"`
	Tasks                  []taskState                         `json:"tasks,omitempty"`
	Running                uint64                              `json:"running,omitzero"`
	Ready                  uint64                              `json:"ready,omitzero"`
	UpdateState            string                              `json:"update_state,omitempty"`
}

type peer interface {
	call(context.Context, command) (response, error)
	probeHTTP(context.Context) error
	close() error
}
