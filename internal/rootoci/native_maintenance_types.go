package rootoci

import "time"

const OperationReconcileOrchestratorMaintenance Operation = "reconcile_orchestrator_maintenance"

// OrchestratorMaintenanceRequest narrows the root-derived target to one unit.
type OrchestratorMaintenanceRequest struct {
	Unit string `json:"unit"`
}

// OrchestratorMaintenanceReceipt describes protected progress, never permission
// for a later effect. ExpiresAt bounds this response's original phase admission.
type OrchestratorMaintenanceReceipt struct {
	Unit         string    `json:"unit"`
	OperationID  string    `json:"operation_id"`
	SourceSHA256 string    `json:"source_sha256"`
	InstanceID   string    `json:"instance_id"`
	FromDigest   string    `json:"from_digest"`
	ToDigest     string    `json:"to_digest"`
	Phase        string    `json:"phase"`
	DrainedAt    time.Time `json:"drained_at,omitzero"`
	DispatchedAt time.Time `json:"dispatched_at,omitzero"`
	ObservedAt   time.Time `json:"observed_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}
