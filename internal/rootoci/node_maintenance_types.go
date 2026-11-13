package rootoci

import (
	"time"
)

type NodeMaintenanceNode struct {
	InstanceID string  `json:"instance_id"`
	Node       string  `json:"node"`
	State      string  `json:"state"`
	OCPUs      float32 `json:"ocpus"`
	MemoryGB   float32 `json:"memory_gb"`
}

type NodeMaintenanceRequest struct {
	OperationID     string `json:"operation_id"`
	RequestSHA256   string `json:"request_sha256"`
	RequestRevision uint64 `json:"request_revision"`
}

type NodeMaintenanceStep string

const ()

// Step narrows the original operation; it cannot authorize another action.
type NodeMaintenanceAdvanceRequest struct {
	NodeMaintenanceRequest
	Step NodeMaintenanceStep `json:"step"`
}

// NodeMaintenanceView is descriptive and cannot grant provider authority.
type NodeMaintenanceView struct {
	OperationID      string    `json:"operation_id"`
	RequestSHA256    string    `json:"request_sha256"`
	RequestRevision  uint64    `json:"request_revision"`
	Node             string    `json:"node"`
	From             string    `json:"from,omitempty"`
	InstanceID       string    `json:"instance_id"`
	State            string    `json:"state"`
	OCPUs            float32   `json:"ocpus"`
	MemoryGB         float32   `json:"memory_gb"`
	BackupID         string    `json:"backup_id,omitempty"`
	OriginalDeadline time.Time `json:"original_deadline"`
	ObservedAt       time.Time `json:"observed_at"`
	ExpiresAt        time.Time `json:"expires_at"`
}
