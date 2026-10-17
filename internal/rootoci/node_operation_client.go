package rootoci

import (
	"context"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

func (client *Client) ReconcileNodeOperation(ctx context.Context, request NodeOperationRequest) (NodeOperationReceipt, error) {
	var response NodeOperationReceipt
	err := client.invoke(ctx, OperationReconcileNodeOperation, request, &response)
	if err == nil && !validNodeOperationReceipt(response, request, time.Now()) {
		return NodeOperationReceipt{}, ErrOutcomeUnknown
	}
	return response, err
}

func validNodeOperationReceipt(receipt NodeOperationReceipt, request NodeOperationRequest, now time.Time) bool {
	if !entityid.Valid(request.OperationID) || receipt.OperationID != request.OperationID || !validDigest(receipt.RequestSHA256) ||
		receipt.ObservedAt.IsZero() || receipt.ObservedAt.After(now) || !now.Before(receipt.ExpiresAt) ||
		!receipt.ObservedAt.Before(receipt.ExpiresAt) || receipt.ActedAt.After(receipt.ObservedAt) || len(receipt.Session) > 256 {
		return false
	}
	for _, id := range []struct{ value, prefix string }{
		{receipt.InstanceID, "ocid1.instance."}, {receipt.BackupID, "ocid1.bootvolumebackup."},
	} {
		if id.value != "" && (!strings.HasPrefix(id.value, id.prefix) || len(id.value) > 512 || strings.ContainsAny(id.value, " \t\r\n")) {
			return false
		}
	}
	switch receipt.Phase {
	case "pending", "ambiguous":
		return true
	case "complete":
		return receipt.InstanceID != "" && !receipt.ActedAt.IsZero()
	default:
		return false
	}
}
