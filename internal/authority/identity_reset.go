package authority

type IdentityResetAction string

const (
	IdentityResetDeleteKV       IdentityResetAction = "delete"
	IdentityResetReplaceKV      IdentityResetAction = "replace-kv"
	IdentityResetAppendHostHead IdentityResetAction = "append-host-head"
	maxIdentityResetBytes                           = 512 << 10
	maxIdentityResetRecords                         = 4096
)

// IdentityReset replaces the current lease without interpreting obsolete
// identity bytes. The root binds their exact digest and the observed log floor.
type IdentityReset struct {
	Version             int                       `json:"version"`
	OperationID         string                    `json:"operation_id"`
	DeploymentID        string                    `json:"deployment_id"`
	ClusterID           string                    `json:"cluster_id"`
	Scope               string                    `json:"scope"`
	Environment         string                    `json:"environment"`
	CheckpointSHA256    string                    `json:"checkpoint_sha256"`
	HostStatePlanSHA256 string                    `json:"host_state_plan_sha256"`
	LastSequence        uint64                    `json:"last_sequence"`
	PreviousSequence    uint64                    `json:"previous_sequence"`
	PreviousSHA256      string                    `json:"previous_sha256"`
	EpochFloor          uint64                    `json:"epoch_floor"`
	Epoch               uint64                    `json:"epoch"`
	GlobalLease         *IdentityResetGlobalLease `json:"global_lease,omitempty"`
	Records             []IdentityResetRecord     `json:"records"`
}

// IdentityResetRecord root-pins a closed typed destination and its opaque
// predecessor. Delete requires this operation's tombstone, never absence.
type IdentityResetRecord struct {
	Action            IdentityResetAction `json:"action"`
	Bucket            string              `json:"bucket"`
	Key               string              `json:"key"`
	PreviousRevision  uint64              `json:"previous_revision"`
	PreviousSHA256    string              `json:"previous_sha256"`
	PreviousOperation string              `json:"previous_operation,omitempty"`
	SHA256            string              `json:"sha256"`
}

// IdentityResetTarget comes from verified replacement acceptance, independently
// of the reset envelope. Replicas is the existing stream's required quorum.
type IdentityResetTarget struct {
	OperationID         string
	DeploymentID        string
	ClusterID           string
	Scope               string
	Environment         string
	CheckpointSHA256    string
	HostStatePlanSHA256 string
	Replicas            int
}
