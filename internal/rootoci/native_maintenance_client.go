package rootoci

import (
	"context"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

func (client *Client) ReconcileOrchestratorMaintenance(ctx context.Context, request OrchestratorMaintenanceRequest) (OrchestratorMaintenanceReceipt, error) {
	var receipt OrchestratorMaintenanceReceipt
	err := client.invoke(ctx, OperationReconcileOrchestratorMaintenance, request, &receipt)
	if err == nil && !validOrchestratorMaintenanceReceipt(receipt, request, time.Now()) {
		return OrchestratorMaintenanceReceipt{}, ErrOutcomeUnknown
	}
	return receipt, err
}

func validOrchestratorMaintenanceReceipt(receipt OrchestratorMaintenanceReceipt, request OrchestratorMaintenanceRequest, now time.Time) bool {
	if !validSelector(request.Unit) || receipt.Unit != request.Unit || !entityid.Valid(receipt.OperationID) ||
		!validDigest(receipt.SourceSHA256) || !validDigest(receipt.FromDigest) || !validDigest(receipt.ToDigest) || receipt.FromDigest == receipt.ToDigest ||
		!strings.HasPrefix(receipt.InstanceID, "ocid1.instance.") || len(receipt.InstanceID) <= len("ocid1.instance.") ||
		len(receipt.InstanceID) > 512 || strings.ContainsAny(receipt.InstanceID, " \t\r\n") ||
		!receipt.ObservedAt.After(time.Unix(0, 0)) || receipt.ObservedAt.After(now) || !now.Before(receipt.ExpiresAt) ||
		receipt.DrainedAt.After(receipt.ObservedAt) || receipt.DispatchedAt.After(receipt.ObservedAt) {
		return false
	}
	for _, event := range []time.Time{receipt.DrainedAt, receipt.DispatchedAt} {
		if !event.IsZero() && !event.After(time.Unix(0, 0)) {
			return false
		}
	}
	if !receipt.DispatchedAt.IsZero() && (receipt.DrainedAt.IsZero() || receipt.DispatchedAt.Before(receipt.DrainedAt)) {
		return false
	}
	switch receipt.Phase {
	case "pending":
		return receipt.DrainedAt.IsZero() && receipt.DispatchedAt.IsZero()
	case "drained":
		return !receipt.DrainedAt.IsZero()
	case "ambiguous":
		return true
	case "complete":
		return !receipt.DrainedAt.IsZero() && !receipt.DispatchedAt.IsZero()
	default:
		return false
	}
}
