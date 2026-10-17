package rootoci

import (
	"context"
	"time"
)

const OperationReconcileNodeOperation Operation = "reconcile_node_operation"

// NodeOperations derives every effect from the original signed action and its
// protected progress. The caller selects an operation, never a provider payload.
type NodeOperations interface {
	ReconcileNodeOperation(context.Context, Call, NodeOperationRequest) (NodeOperationReceipt, error)
}

type NodeOperationRequest struct {
	OperationID string `json:"operation_id"`
}

// NodeOperationReceipt describes protected progress; mirroring it grants no
// follow-up effects. Complete covers compute dispatch, not restart readiness.
type NodeOperationReceipt struct {
	OperationID   string    `json:"operation_id"`
	RequestSHA256 string    `json:"request_sha256"`
	InstanceID    string    `json:"instance_id,omitempty"`
	BackupID      string    `json:"backup_id,omitempty"`
	Phase         string    `json:"phase"`
	Session       string    `json:"session,omitempty"`
	ActedAt       time.Time `json:"acted_at,omitzero"`
	ObservedAt    time.Time `json:"observed_at"`
	ExpiresAt     time.Time `json:"expires_at"`
}
