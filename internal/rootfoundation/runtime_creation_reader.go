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

// VerifiedRuntimeCreation binds the original manager process to its protected
// before-create source. It does not certify broker or role history.
type VerifiedRuntimeCreation struct {
	ctx      context.Context
	backend  *Backend
	call     rootoci.Call
	reader   *bootstrapstart.CurrentFounderAuthorityReader
	accepted bootstrapstart.AcceptedIdentity
	node     swarmruntime.VerifiedRuntimeGenesis
	origin   region.RuntimeLineageRecord
	creation region.RuntimeCreation
	genesis  region.RuntimeSwarmGenesis
	expires  time.Time
}

func (b *Backend) ReadRuntimeCreation(ctx context.Context, node swarmruntime.VerifiedRuntimeGenesis, reader *bootstrapstart.CurrentFounderAuthorityReader, accepted bootstrapstart.AcceptedIdentity) (VerifiedRuntimeCreation, error) {
	if b == nil || reader == nil || accepted.Cell != b.cell || ctx.Err() != nil {
		return VerifiedRuntimeCreation{}, ErrScope
	}
	expires := time.Now().UTC().Add(30 * time.Second)
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
	operation, cancel := context.WithDeadline(ctx, expires)
	defer cancel()
	proof := VerifiedRuntimeCreation{ctx: ctx, backend: b, call: call, reader: reader, accepted: accepted.Clone(), node: node, expires: expires}
	origin, creation, genesis, authorityExpires, err := proof.read(operation)
	if err != nil {
		return VerifiedRuntimeCreation{}, err
	}
	proof.origin, proof.creation, proof.genesis = origin, creation, genesis
	if creation.ExpiresAt.Before(proof.expires) {
		proof.expires = creation.ExpiresAt
	}
	if authorityExpires.Before(proof.expires) {
		proof.expires = authorityExpires
	}
	if err := proof.Revalidate(operation); err != nil {
		return VerifiedRuntimeCreation{}, err
	}
	return proof, nil
}

func (proof VerifiedRuntimeCreation) Info() swarmruntime.RuntimeGenesisInfo { return proof.node.Info() }
func (proof VerifiedRuntimeCreation) ExpiresAt() time.Time                  { return proof.expires }

func (proof VerifiedRuntimeCreation) Revalidate(ctx context.Context) error {
	if proof.ctx == nil || proof.backend == nil || proof.reader == nil || !time.Now().Before(proof.expires) {
		return errors.New("original protected runtime creation is absent or expired")
	}
	if err := proof.ctx.Err(); err != nil {
		return err
	}
	ctx, cancel := context.WithDeadline(ctx, proof.expires)
	defer cancel()
	stop := context.AfterFunc(proof.ctx, cancel)
	defer stop()
	origin, creation, genesis, _, err := proof.read(ctx)
	if err != nil {
		return err
	}
	if origin != proof.origin || creation != proof.creation || genesis != proof.genesis {
		return errors.New("original protected runtime creation changed")
	}
	if err := proof.ctx.Err(); err != nil {
		return err
	}
	return ctx.Err()
}

func (proof VerifiedRuntimeCreation) read(ctx context.Context) (region.RuntimeLineageRecord, region.RuntimeCreation, region.RuntimeSwarmGenesis, time.Time, error) {
	fail := func(err error) (region.RuntimeLineageRecord, region.RuntimeCreation, region.RuntimeSwarmGenesis, time.Time, error) {
		return region.RuntimeLineageRecord{}, region.RuntimeCreation{}, region.RuntimeSwarmGenesis{}, time.Time{}, err
	}
	ctx = ociclient.WithRequestGuard(ctx, proof.call.Guard)
	if err := proof.backend.guard(ctx, proof.call); err != nil {
		return fail(err)
	}
	if err := proof.node.Revalidate(ctx); err != nil {
		return fail(err)
	}
	authority, err := proof.reader.ReadRuntimeAuthority(ctx, proof.accepted, time.Now().UTC())
	if err != nil {
		return fail(err)
	}
	identity := authority.Identity()
	resolver, err := proof.backend.current(ctx, proof.call)
	if err != nil {
		return fail(err)
	}
	approved, err := resolver.Resolve(ctx, proof.backend.cell)
	if err != nil {
		return fail(err)
	}
	record, _, err := resolver.Store.Load(ctx, proof.backend.cell)
	if err != nil {
		return fail(err)
	}
	if record.Generation != approved.Generation || record.GrantSHA256 != approved.GrantSHA256 || record.OperationID != approved.OperationID || record.IntentDigest != approved.IntentDigest || record.Stage != "reconciled" || record.LeaseID != "" || record.RuntimeLineage == nil || record.RuntimeLineage.Creation == nil || record.RuntimeLineage.Creation.Genesis == nil {
		return fail(errors.New("runtime has no current protected original creation"))
	}
	origin, creation := *record.RuntimeLineage, *record.RuntimeLineage.Creation
	genesis := *creation.Genesis
	origin, creation.Genesis = origin.Original(), nil
	digest, err := proof.accepted.AcceptanceSHA256()
	if err != nil {
		return fail(err)
	}
	info := proof.node.Info()
	if !time.Now().Before(creation.ExpiresAt) || identity.Cell != proof.backend.cell || identity.OCIRegion != info.Region ||
		identity.DeploymentID != creation.DeploymentID || identity.ClusterID != creation.SignedClusterID || identity.Environment != creation.Environment ||
		identity.Slot != creation.HostID || identity.Slot != identity.SeedSlot || identity.InstanceID != creation.InstanceID || digest != creation.AcceptanceSHA256 || authority.Anchor().Digest() != creation.AnchorSHA256 ||
		info.HostID != creation.HostID || info.InstanceID != creation.InstanceID || info.ClusterID != genesis.ClusterID || info.NodeID != genesis.NodeID || info.RootCASHA256 != genesis.RootCASHA256 ||
		!info.StartedAt.Equal(genesis.StartedAt) || info.Version < genesis.Version || info.Term != genesis.Term || info.Leader != genesis.Leader {
		return fail(errors.New("actual runtime genesis differs from its original protected source"))
	}
	if err := proof.backend.guard(ctx, proof.call); err != nil {
		return fail(err)
	}
	if err := proof.node.Revalidate(ctx); err != nil {
		return fail(err)
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	return origin, creation, genesis, authority.ExpiresAt(), nil
}
