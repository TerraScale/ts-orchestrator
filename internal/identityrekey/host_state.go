package identityrekey

import (
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/host"
)

const (
	HostStateHandoffDomain = "terrascale.identity-rekey.host-state-handoff"
	MaxHostStatePlanBytes  = 512 << 10
	HostStateQuiescence    = 32 * time.Second // Host execution lease plus clock skew.
	hostStateBucket        = "TS_HOST_STATE"
)

var ErrHostStateHandoff = errors.New("host state handoff is invalid")

type HostStateAction = authority.IdentityResetAction

const (
	HostStateDelete     HostStateAction = authority.IdentityResetDeleteKV
	HostStateReplaceKV  HostStateAction = authority.IdentityResetReplaceKV
	HostStateAppendHead HostStateAction = authority.IdentityResetAppendHostHead
)

// HostStatePrecondition is an independently observed leader-backed predecessor.
// Revision zero means absent; tombstones also pin the exact KV-Operation header.
type HostStatePrecondition struct {
	Bucket    string `json:"bucket"`
	Key       string `json:"key"`
	Revision  uint64 `json:"revision"`
	SHA256    string `json:"sha256"`
	Operation string `json:"operation,omitempty"`
}

type HostStateDesired struct {
	Target              host.Desired `json:"target"`
	GenerationFloor     uint64       `json:"generation_floor"`
	AuthorityEpochFloor uint64       `json:"authority_epoch_floor"`
}

// HostStateVolume pins an existing mount and local consumption marker. Neither
// is a mutation target: this plan can only recreate a CLOSED confirmation.
type HostStateVolume struct {
	VolumeID             string `json:"volume_id"`
	UUID                 string `json:"uuid"`
	FileSystemType       string `json:"filesystem_type"`
	DataPath             string `json:"data_path"`
	NativeClusterID      string `json:"native_cluster_id"`
	StateRoot            string `json:"state_root"`
	ConsumedMarkerSHA256 string `json:"consumed_marker_sha256"`
	Mounted              bool   `json:"mounted"`
}

// HostStateHost includes inactive registrations as well as running hosts.
// Registration and desired targets are independently verified current facts,
// never decoded from the obsolete predecessor bytes.
// A retired static orphan may omit instance/request evidence; it receives no grant.
type HostStateHost struct {
	InstanceOCID                string             `json:"instance_ocid"`
	Registration                host.Registration  `json:"registration"`
	RegistrationGenerationFloor uint64             `json:"registration_generation_floor"`
	Retired                     bool               `json:"retired"`
	EnrollmentRequest           []byte             `json:"enrollment_request"`
	Desired                     []HostStateDesired `json:"desired"`
	Volume                      *HostStateVolume   `json:"volume,omitempty"`
}

// HostStateObservation must inventory every host registration/desired head and
// host/enrollment KV key in this cell, including absence at new destinations.
// The installer establishes inventory completeness and writer shutdown before
// supplying these facts; a signed plan cannot establish either by itself.
type HostStateObservation struct {
	OperationID         string                  `json:"operation_id"`
	DeploymentID        string                  `json:"deployment_id"`
	ClusterID           string                  `json:"cluster_id"`
	Cell                string                  `json:"cell"`
	Environment         string                  `json:"environment"`
	CheckpointSHA256    string                  `json:"checkpoint_sha256"`
	EpochFloor          uint64                  `json:"epoch_floor"`
	Epoch               uint64                  `json:"epoch"`
	PreviousResponseKey string                  `json:"previous_response_key"`
	ResponseKey         string                  `json:"response_key"`
	AgentsStoppedAt     time.Time               `json:"agents_stopped_at"`
	ObservedAt          time.Time               `json:"observed_at"`
	Hosts               []HostStateHost         `json:"hosts"`
	Preconditions       []HostStatePrecondition `json:"preconditions"`
}

// HostStateRecord supplies typed root pins and exact successor bytes.
type HostStateRecord struct {
	Action HostStateAction               `json:"action"`
	Pin    authority.IdentityResetRecord `json:"pin"`
	Value  []byte                        `json:"value,omitempty"`
}

type HostStateHandoffPlan struct {
	Version     int                  `json:"version"`
	Observation HostStateObservation `json:"observation"`
	Records     []HostStateRecord    `json:"records"`
}

// VerifiedHostStateHandoffPlan exposes no caller-editable mutation authority.
type VerifiedHostStateHandoffPlan struct {
	plan        HostStateHandoffPlan
	fingerprint string
	verified    bool
}
