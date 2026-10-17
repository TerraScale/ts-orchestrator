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

// VerifiedRuntimeCreation binds the actual original manager to a fresh bounded
// read of its protected committed origin, never broker or role history.
type VerifiedRuntimeCreation struct {
	ctx     context.Context
	backend *Backend
	call    rootoci.Call
	node    swarmruntime.VerifiedRuntimeGenesis
	source  region.VerifiedRuntimeCreationSource
	expires time.Time
}

func (b *Backend) ReadRuntimeCreation(ctx context.Context, node swarmruntime.VerifiedRuntimeGenesis, reader *bootstrapstart.CurrentFounderAuthorityReader, accepted bootstrapstart.AcceptedIdentity) (VerifiedRuntimeCreation, error) {
	expires := time.Now().UTC().Add(30 * time.Second)
	if b == nil || reader == nil || accepted.Cell != b.cell || ctx.Err() != nil {
		return VerifiedRuntimeCreation{}, ErrScope
	}
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(expires) {
		expires = deadline
	}
	if node.ExpiresAt().Before(expires) {
		expires = node.ExpiresAt()
	}
	call, err := rootoci.RootCall(ctx)
	if err != nil {
		return VerifiedRuntimeCreation{}, err
	}
	if call.Deadline().Before(expires) {
		expires = call.Deadline()
	}
	ctx = ociclient.WithRequestGuard(ctx, call.Guard)
	operation, cancel := context.WithDeadline(ctx, expires)
	defer cancel()
	if err := b.guard(operation, call); err != nil {
		return VerifiedRuntimeCreation{}, err
	}
	source, err := region.ReadRuntimeCreationSource(ctx, b.factory, reader, accepted)
	if err != nil {
		return VerifiedRuntimeCreation{}, err
	}
	if source.ExpiresAt().Before(expires) {
		expires = source.ExpiresAt()
	}
	proof := VerifiedRuntimeCreation{ctx: ctx, backend: b, call: call, node: node, source: source, expires: expires}
	if err := proof.Revalidate(operation); err != nil {
		return VerifiedRuntimeCreation{}, err
	}
	return proof, nil
}

func (proof VerifiedRuntimeCreation) Info() swarmruntime.RuntimeGenesisInfo { return proof.node.Info() }
func (proof VerifiedRuntimeCreation) ExpiresAt() time.Time                  { return proof.expires }

func (proof VerifiedRuntimeCreation) Revalidate(ctx context.Context) error {
	if proof.ctx == nil || proof.backend == nil || !time.Now().Before(proof.expires) {
		return errors.New("original protected runtime read is absent or expired")
	}
	if err := proof.ctx.Err(); err != nil {
		return err
	}
	ctx, cancel := context.WithDeadline(ctx, proof.expires)
	defer cancel()
	stop := context.AfterFunc(proof.ctx, cancel)
	defer stop()
	ctx = ociclient.WithRequestGuard(ctx, proof.call.Guard)
	if err := proof.backend.guard(ctx, proof.call); err != nil {
		return err
	}
	if err := proof.node.Revalidate(ctx); err != nil {
		return err
	}
	if err := proof.source.Revalidate(ctx); err != nil {
		return err
	}
	info, creation, genesis := proof.node.Info(), proof.source.Creation(), proof.source.Genesis()
	if info.Region != proof.backend.anchor.Anchor().OCIRegion || info.HostID != creation.HostID || info.InstanceID != creation.InstanceID ||
		info.ClusterID != genesis.ClusterID || info.NodeID != genesis.NodeID || info.RootCASHA256 != genesis.RootCASHA256 ||
		!info.StartedAt.Equal(genesis.StartedAt) || info.Version < genesis.Version || info.Term != genesis.Term || info.Leader != genesis.Leader {
		return errors.New("actual original manager differs from protected committed genesis")
	}
	if err := proof.node.Revalidate(ctx); err != nil {
		return err
	}
	if err := proof.call.Guard(ctx); err != nil {
		return err
	}
	return ctx.Err()
}
