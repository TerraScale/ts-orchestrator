package rootoci

import (
	"context"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
)

const OperationReconcileTaskTraffic Operation = "reconcile_task_traffic"

// Role selects current signed backend sets; no caller-selected backend crosses IPC.
type TaskTrafficRequest struct {
	Role string `json:"role"`
}

type TaskTrafficReceipt struct {
	Role         string    `json:"role"`
	OperationIDs []string  `json:"operationIds"`
	ObservedAt   time.Time `json:"observedAt"`
	ExpiresAt    time.Time `json:"expiresAt"`
}

func (client *Client) ReconcileTaskTraffic(ctx context.Context, request TaskTrafficRequest) (TaskTrafficReceipt, error) {
	var result TaskTrafficReceipt
	err := client.invoke(ctx, OperationReconcileTaskTraffic, request, &result)
	return result, err
}

func validTaskTrafficReceipt(receipt TaskTrafficReceipt, role string, call Call) bool {
	now := time.Now()
	if receipt.Role != role || receipt.ObservedAt.IsZero() || receipt.ObservedAt.After(now) ||
		!receipt.ObservedAt.Before(receipt.ExpiresAt) || !validResponseExpiry(receipt.ExpiresAt, call) ||
		len(receipt.OperationIDs) == 0 || len(receipt.OperationIDs) > cellspec.MaxFencedSets {
		return false
	}
	seen := make(map[string]bool, len(receipt.OperationIDs))
	for _, operation := range receipt.OperationIDs {
		if !validSelector(operation) || seen[operation] {
			return false
		}
		seen[operation] = true
	}
	return true
}
