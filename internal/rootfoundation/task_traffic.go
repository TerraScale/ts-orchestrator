package rootfoundation

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

type TaskTrafficScope struct {
	Foundation    rootoci.FoundationReceipt
	OCIRegion     string
	CompartmentID string
	ExpiresAt     time.Time
}

// TaskTrafficFoundation reads an already reconciled foundation; task traffic
// cannot create foundation resources or acquire a replacement writer lease.
func (b *Backend) TaskTrafficFoundation(ctx context.Context, call rootoci.Call) (TaskTrafficScope, error) {
	if b == nil || call.Operation() != rootoci.OperationReconcileTaskTraffic || !time.Now().Before(call.Deadline()) {
		return TaskTrafficScope{}, ErrScope
	}
	ctx, cancel := context.WithDeadline(ctx, call.Deadline())
	defer cancel()
	ctx = ociclient.WithRequestGuard(ctx, call.Guard)
	resolver, err := b.current(ctx, call)
	if err != nil {
		return TaskTrafficScope{}, err
	}
	footprint, expires, err := resolver.Footprint.AuthorizedRegionsUntil(ctx)
	if err != nil {
		return TaskTrafficScope{}, err
	}
	record, _, err := resolver.Store.Load(ctx, b.cell)
	if err != nil {
		return TaskTrafficScope{}, err
	}
	if record.Cell != b.cell || record.Stage != "reconciled" || record.LeaseID != "" || record.Epoch == 0 || record.GrantSHA256 != footprint.GrantSHA256 || !strings.HasPrefix(record.ResourceIDs["network_compartment"], "ocid1.compartment.") {
		return TaskTrafficScope{}, ErrScope
	}
	found := false
	for _, intent := range footprint.Regions {
		if intent.Plan["cell"] != b.cell {
			continue
		}
		digest, err := region.FoundationIntentDigest(intent)
		operation := entityid.Derive("regional-foundation", footprint.TenancyID, b.cell, fmt.Sprint(intent.Generation))
		if err != nil || record.Generation != intent.Generation || record.IntentDigest != digest || record.OperationID != operation || record.OCIRegion != intent.Plan["region"] {
			return TaskTrafficScope{}, errors.Join(ErrScope, err)
		}
		found = true
	}
	if !found {
		return TaskTrafficScope{}, ErrScope
	}
	receipt := rootoci.FoundationReceipt{Cell: record.Cell, GrantDigest: record.GrantSHA256, OperationID: record.OperationID,
		Generation: record.Generation, Epoch: record.Epoch, Stage: record.Stage}
	if err := checkCall(ctx, call, rootoci.OperationReconcileTaskTraffic, rootoci.Expectations{
		Cell: receipt.Cell, GrantSHA256: receipt.GrantDigest, OperationID: receipt.OperationID, Epoch: receipt.Epoch,
	}); err != nil {
		return TaskTrafficScope{}, err
	}
	current, currentExpires, err := resolver.Footprint.AuthorizedRegionsUntil(ctx)
	if err != nil || current.GrantSHA256 != receipt.GrantDigest || !currentExpires.Equal(expires) || !time.Now().Before(expires) {
		return TaskTrafficScope{}, errors.Join(ErrScope, err)
	}
	if err := b.guard(ctx, call); err != nil {
		return TaskTrafficScope{}, err
	}
	return TaskTrafficScope{Foundation: receipt, OCIRegion: record.OCIRegion, CompartmentID: record.ResourceIDs["network_compartment"], ExpiresAt: expires}, nil
}
