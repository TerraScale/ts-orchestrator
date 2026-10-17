package rootfoundation

import (
	"context"
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

// RuntimeCreationPermit combines the concrete source capability with root's
// typed actual-node genesis commit. Only the neutral capability enters fixtures.
type RuntimeCreationPermit struct {
	backend *Backend
	call    rootoci.Call
	permit  *region.RuntimeCreationPermit
}

func (b *Backend) PrepareRuntimeCreation(ctx context.Context, reader *bootstrapstart.CurrentFounderAuthorityReader, accepted bootstrapstart.AcceptedIdentity) (*RuntimeCreationPermit, error) {
	if b == nil || accepted.Cell != b.cell {
		return nil, ErrScope
	}
	call, err := rootoci.RootCall(ctx)
	if err != nil {
		return nil, err
	}
	if err := b.guard(ctx, call); err != nil {
		return nil, err
	}
	ctx = ociclient.WithRequestGuard(ctx, call.Guard)
	permit, err := region.PrepareRuntimeCreation(ctx, b.factory, reader, accepted)
	if err != nil || permit == nil {
		return nil, err
	}
	return &RuntimeCreationPermit{backend: b, call: call, permit: permit}, nil
}

func (permit *RuntimeCreationPermit) CreationPermit() *region.RuntimeCreationPermit {
	if permit == nil {
		return nil
	}
	return permit.permit
}

func (permit *RuntimeCreationPermit) GuardCreate(ctx context.Context) error {
	if permit == nil || permit.permit == nil || permit.backend == nil {
		return errors.New("runtime has no protected original creation permit")
	}
	if err := permit.backend.guard(ctx, permit.call); err != nil {
		return err
	}
	return permit.permit.GuardCreate(ctx)
}

func (permit *RuntimeCreationPermit) Commit(ctx context.Context, proof swarmruntime.VerifiedRuntimeGenesis) error {
	if permit == nil || permit.permit == nil || permit.backend == nil {
		return ErrScope
	}
	expires := permit.permit.ExpiresAt()
	if proof.ExpiresAt().Before(expires) {
		expires = proof.ExpiresAt()
	}
	if permit.call.Deadline().Before(expires) {
		expires = permit.call.Deadline()
	}
	ctx, cancel := context.WithDeadline(ctx, expires)
	defer cancel()
	if err := permit.backend.guard(ctx, permit.call); err != nil {
		return err
	}
	if err := permit.permit.GuardStarted(ctx); err != nil {
		return err
	}
	if err := proof.Revalidate(ctx); err != nil {
		return err
	}
	info, original := proof.Info(), permit.permit.Creation()
	if info.HostID != original.HostID || info.InstanceID != original.InstanceID || info.Region != permit.backend.anchor.Anchor().OCIRegion || info.StartedAt.Before(original.StartedAt) {
		return errors.New("actual runtime genesis differs from protected original creation")
	}
	resolver, err := permit.backend.current(ctx, permit.call)
	if err != nil {
		return err
	}
	approved, err := resolver.Resolve(ctx, permit.backend.cell)
	if err != nil {
		return err
	}
	record, etag, err := resolver.Store.Load(ctx, permit.backend.cell)
	if err != nil {
		return err
	}
	if record.Generation != approved.Generation || record.GrantSHA256 != approved.GrantSHA256 || record.OperationID != approved.OperationID || record.IntentDigest != approved.IntentDigest || record.Stage != "reconciled" || record.LeaseID != "" || record.RuntimeLineage == nil || record.RuntimeLineage.Creation == nil || *record.RuntimeLineage.Creation != original {
		return errors.New("protected original runtime creation changed or completed")
	}
	lineage := *record.RuntimeLineage
	creation := *lineage.Creation
	lineage.Creation = nil
	if lineage != permit.permit.Origin() {
		return errors.New("protected original runtime foundation changed")
	}
	creation.Genesis = &region.RuntimeSwarmGenesis{ClusterID: info.ClusterID, NodeID: info.NodeID, RootCASHA256: info.RootCASHA256,
		StartedAt: info.StartedAt, Version: info.Version, Term: info.Term, Leader: info.Leader}
	lineage.Creation = &creation
	record.RuntimeLineage, record.UpdatedAt = &lineage, time.Now().UTC()
	ctx = ociclient.WithRequestGuard(ctx, func(ctx context.Context) error {
		if err := permit.call.Guard(ctx); err != nil {
			return err
		}
		return proof.Revalidate(ctx)
	})
	ctx = ociclient.WithAuthority(ctx, permit.permit.ValidateSource)
	if _, err := resolver.Store.CompareAndSwap(ctx, record, etag); err != nil {
		return err
	}
	if err := proof.Revalidate(ctx); err != nil {
		return err
	}
	return permit.permit.ValidateSource(ctx)
}
