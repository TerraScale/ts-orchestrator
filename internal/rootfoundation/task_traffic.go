package rootfoundation

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/foundationbinding"
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
	return b.operationFoundation(ctx, call, rootoci.OperationReconcileTaskTraffic)
}

func (b *Backend) operationFoundation(ctx context.Context, call rootoci.Call, operation rootoci.Operation) (TaskTrafficScope, error) {
	if ctx == nil || b == nil || call.Operation() != operation || !time.Now().Before(call.Deadline()) {
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
	if !time.Now().Before(expires) {
		return TaskTrafficScope{}, ErrScope
	}
	ctx, stopFootprint := context.WithDeadline(ctx, expires)
	defer stopFootprint()
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
	if err := checkCall(ctx, call, operation, rootoci.Expectations{
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

// NodeOperationScope narrows existing resource roles; it never launches or adopts
// a node and never changes foundation reconciliation state.
type NodeOperationScope struct {
	Foundation            rootoci.FoundationReceipt
	OCIRegion             string
	ControlCompartmentID  string
	WorkloadCompartmentID string
	ExpiresAt             time.Time
	bindings              foundationbinding.VerifiedBindings
	source                context.Context
	call                  rootoci.Call
	deadline              time.Time
}

func (s NodeOperationScope) Revalidate(ctx context.Context) error {
	if ctx == nil || s.source == nil || s.source.Err() != nil || !time.Now().Before(s.deadline) {
		return ErrScope
	}
	ctx, cancel := context.WithDeadline(ctx, s.deadline)
	defer cancel()
	stop := context.AfterFunc(s.source, cancel)
	defer stop()
	ctx = ociclient.WithRequestGuard(ctx, s.call.Guard)
	if err := s.call.Guard(ctx); err != nil {
		return err
	}
	if err := s.bindings.Revalidate(ctx); err != nil {
		return err
	}
	if s.source.Err() != nil || ctx.Err() != nil || !time.Now().Before(s.deadline) {
		return ErrScope
	}
	return s.call.Guard(ctx)
}

func (b *Backend) NodeOperationFoundation(ctx context.Context, call rootoci.Call) (NodeOperationScope, error) {
	if ctx == nil {
		return NodeOperationScope{}, ErrScope
	}
	original := ctx
	ctx, stopCall := context.WithDeadline(ctx, call.Deadline())
	defer stopCall()
	ctx = ociclient.WithRequestGuard(ctx, call.Guard)
	current, err := b.operationFoundation(ctx, call, rootoci.OperationReconcileNodeOperation)
	if err != nil {
		return NodeOperationScope{}, err
	}
	ctx, cancel := context.WithDeadline(ctx, current.ExpiresAt)
	defer cancel()
	resolver, err := b.current(ctx, call)
	if err != nil {
		return NodeOperationScope{}, err
	}
	bindings, err := resolver.ResourceBindingsFor(ctx, b.cell, "control_compartment", "workload_compartment")
	if err != nil {
		return NodeOperationScope{}, err
	}
	if bindings.GrantSHA256() != current.Foundation.GrantDigest || bindings.Cell() != b.cell {
		return NodeOperationScope{}, ErrScope
	}
	controlRef, err := region.FoundationResourceReference(b.cell, "control_compartment")
	if err != nil {
		return NodeOperationScope{}, err
	}
	control, err := bindings.Resolve(controlRef)
	if err != nil {
		return NodeOperationScope{}, err
	}
	workloadRef, err := region.FoundationResourceReference(b.cell, "workload_compartment")
	if err != nil {
		return NodeOperationScope{}, err
	}
	workload, err := bindings.Resolve(workloadRef)
	if err != nil {
		return NodeOperationScope{}, err
	}
	if !strings.HasPrefix(control, "ocid1.compartment.") || !strings.HasPrefix(workload, "ocid1.compartment.") {
		return NodeOperationScope{}, ErrScope
	}
	expires := current.ExpiresAt
	if call.Deadline().Before(expires) {
		expires = call.Deadline()
	}
	if until, ok := original.Deadline(); ok && until.Before(expires) {
		expires = until
	}
	if bindings.ExpiresAt().Before(expires) {
		expires = bindings.ExpiresAt()
	}
	if !time.Now().Before(expires) {
		return NodeOperationScope{}, ErrScope
	}
	ctx, stopBindings := context.WithDeadline(ctx, expires)
	defer stopBindings()
	if err := b.guard(ctx, call); err != nil {
		return NodeOperationScope{}, err
	}
	return NodeOperationScope{Foundation: current.Foundation, OCIRegion: current.OCIRegion,
		ControlCompartmentID: control, WorkloadCompartmentID: workload,
		ExpiresAt: expires, bindings: bindings, source: original, call: call, deadline: expires}, nil
}
