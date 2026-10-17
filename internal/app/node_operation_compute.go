package app

import (
	"context"
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

func (o *nodeOps) reconcileCompute(ctx context.Context, op *nodeOp) error {
	original, err := o.originalRequest(ctx, *op)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithDeadline(ctx, original.ExpiresAt)
	defer cancel()
	if !time.Now().Before(original.ExpiresAt) {
		return rootoci.ErrUnauthorized
	}
	api, err := o.instances(ctx)
	if err != nil {
		return err
	}
	receipt, err := api.ReconcileNodeOperation(ctx, rootoci.NodeOperationRequest{OperationID: op.ID})
	if err != nil {
		return err
	}
	return mirrorNodeComputeReceipt(op, receipt, original.ExpiresAt, time.Now())
}

// The original request and previously mirrored facts can only narrow a receipt.
// Pending outcomes retain descriptive IDs but never advance restart readiness.
func mirrorNodeComputeReceipt(op *nodeOp, receipt rootoci.NodeOperationReceipt, deadline, now time.Time) error {
	if op == nil || receipt.OperationID != op.ID || receipt.RequestSHA256 != op.RequestSHA256 ||
		receipt.ExpiresAt.After(deadline) || !now.Before(receipt.ExpiresAt) || receipt.ObservedAt.IsZero() ||
		receipt.ObservedAt.After(now) || !receipt.ObservedAt.Before(receipt.ExpiresAt) || receipt.ActedAt.After(receipt.ObservedAt) ||
		op.Instance != "" && op.Instance != receipt.InstanceID || op.Backup != "" && op.Backup != receipt.BackupID ||
		op.Session != "" && op.Session != receipt.Session || !op.ActedAt.IsZero() && !op.ActedAt.Equal(receipt.ActedAt) {
		return errors.New("root node operation receipt differs from its original request or protected progress")
	}
	switch receipt.Phase {
	case "pending", "ambiguous":
	case "complete":
		if receipt.InstanceID == "" || receipt.ActedAt.IsZero() || op.Op == nodeOpRetire && receipt.BackupID == "" {
			return errors.New("completed root node operation lacks protected dispatch evidence")
		}
	default:
		return errors.New("root node operation receipt has an unknown phase")
	}
	op.Instance, op.Backup, op.Session = receipt.InstanceID, receipt.BackupID, receipt.Session
	switch receipt.Phase {
	case "pending":
		return rootoci.ErrPending
	case "ambiguous":
		return rootoci.ErrOutcomeUnknown
	default:
		op.ActedAt = receipt.ActedAt
		return nil
	}
}
