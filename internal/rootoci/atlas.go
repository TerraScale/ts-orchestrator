package rootoci

import (
	"context"
	"time"
)

const OperationReconcileAtlasTopology Operation = "reconcile_atlas_topology"

const (
	AtlasTopologyPublished    = "published"
	AtlasTopologyUnconfigured = "unconfigured"
)

// AtlasTopology derives and publishes one admitted topology. The caller cannot
// choose signing bytes, a destination or a secret reference.
type AtlasTopology interface {
	ReconcileAtlasTopology(context.Context, Call) (AtlasTopologyReceipt, error)
}

type AtlasTopologyReceipt struct {
	State     string
	ExpiresAt time.Time
}

func (client *Client) ReconcileAtlasTopology(ctx context.Context) (AtlasTopologyReceipt, error) {
	var receipt AtlasTopologyReceipt
	err := client.invoke(ctx, OperationReconcileAtlasTopology, struct{}{}, &receipt)
	if err != nil {
		return AtlasTopologyReceipt{}, err
	}
	if ctx.Err() != nil || !time.Now().Before(receipt.ExpiresAt) ||
		(receipt.State != AtlasTopologyPublished && receipt.State != AtlasTopologyUnconfigured) {
		return AtlasTopologyReceipt{}, outcomeError(OperationReconcileAtlasTopology)
	}
	return receipt, nil
}
