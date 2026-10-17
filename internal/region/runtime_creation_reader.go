package region

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
)

// VerifiedRuntimeCreationSource is a read-only protected original source fact.
// The actual manager must independently bind its own opaque genesis and replay;
// this type grants no create permission or broker/role history certification.
type VerifiedRuntimeCreationSource struct {
	ctx      context.Context
	home     *HomeIAMAuthority
	reader   *bootstrapstart.CurrentFounderAuthorityReader
	accepted bootstrapstart.AcceptedIdentity
	identity bootstrapstart.RuntimeIdentity
	origin   RuntimeLineageRecord
	creation RuntimeCreation
	genesis  RuntimeSwarmGenesis
	expires  time.Time
}

func ReadRuntimeCreationSource(ctx context.Context, factory *ociclient.Factory, reader *bootstrapstart.CurrentFounderAuthorityReader, accepted bootstrapstart.AcceptedIdentity) (VerifiedRuntimeCreationSource, error) {
	expires := time.Now().UTC().Add(30 * time.Second)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(expires) {
		expires = deadline
	}
	if os.Geteuid() != 0 || factory == nil || reader == nil || ctx.Err() != nil {
		return VerifiedRuntimeCreationSource{}, errors.New("original runtime source requires current concrete root authority")
	}
	operation, cancel := context.WithDeadline(ctx, expires)
	defer cancel()
	authority, err := reader.ReadRuntimeAuthority(operation, accepted, time.Now().UTC())
	if err != nil {
		return VerifiedRuntimeCreationSource{}, err
	}
	identity := authority.Identity()
	if factory.Region() != identity.OCIRegion {
		return VerifiedRuntimeCreationSource{}, errors.New("original runtime source names another OCI region")
	}
	resolver, err := DiscoverCurrentFoundation(operation, factory)
	if err != nil {
		return VerifiedRuntimeCreationSource{}, err
	}
	home, err := NewRuntimeHomeIAMAuthority(operation, reader, accepted, resolver)
	if err != nil {
		return VerifiedRuntimeCreationSource{}, err
	}
	proof := VerifiedRuntimeCreationSource{ctx: ctx, home: home, reader: reader, accepted: accepted.Clone(), identity: identity, expires: expires}
	origin, creation, genesis, sourceExpiry, err := proof.read(operation)
	if err != nil {
		return VerifiedRuntimeCreationSource{}, err
	}
	proof.origin, proof.creation, proof.genesis = origin, creation, genesis
	if creation.ExpiresAt.Before(proof.expires) {
		proof.expires = creation.ExpiresAt
	}
	if sourceExpiry.Before(proof.expires) {
		proof.expires = sourceExpiry
	}
	if err := proof.Revalidate(operation); err != nil {
		return VerifiedRuntimeCreationSource{}, err
	}
	return proof, nil
}

func (proof VerifiedRuntimeCreationSource) Creation() RuntimeCreation {
	creation := proof.creation
	if proof.genesis.ClusterID != "" {
		creation.Genesis = new(proof.genesis)
	}
	return creation
}

func (proof VerifiedRuntimeCreationSource) Genesis() RuntimeSwarmGenesis { return proof.genesis }
func (proof VerifiedRuntimeCreationSource) Origin() RuntimeLineageRecord { return proof.origin }
func (proof VerifiedRuntimeCreationSource) ExpiresAt() time.Time         { return proof.expires }

func (proof VerifiedRuntimeCreationSource) Revalidate(ctx context.Context) error {
	if proof.ctx == nil || proof.home == nil || proof.reader == nil || !time.Now().Before(proof.expires) {
		return errors.New("original protected runtime source is absent or expired")
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
		return errors.New("original protected runtime source changed")
	}
	if err := proof.ctx.Err(); err != nil {
		return err
	}
	return ctx.Err()
}

func (proof VerifiedRuntimeCreationSource) read(ctx context.Context) (RuntimeLineageRecord, RuntimeCreation, RuntimeSwarmGenesis, time.Time, error) {
	fail := func(err error) (RuntimeLineageRecord, RuntimeCreation, RuntimeSwarmGenesis, time.Time, error) {
		return RuntimeLineageRecord{}, RuntimeCreation{}, RuntimeSwarmGenesis{}, time.Time{}, err
	}
	if err := proof.home.VerifyFoundationWriter(ctx); err != nil {
		return fail(err)
	}
	authority, err := proof.reader.ReadRuntimeAuthority(ctx, proof.accepted, time.Now().UTC())
	if err != nil {
		return fail(err)
	}
	if authority.Identity() != proof.identity {
		return fail(errors.New("original runtime accepted authority changed"))
	}
	resolver, err := discoverCurrentFoundation(ctx, proof.home.objects, proof.home.tenancyID, proof.home.currentGenesis)
	if err != nil {
		return fail(err)
	}
	approved, err := resolver.Resolve(ctx, proof.identity.Cell)
	if err != nil {
		return fail(err)
	}
	record, _, err := resolver.Store.Load(ctx, proof.identity.Cell)
	if err != nil {
		return fail(err)
	}
	if !sameRuntimeFoundation(record, approved) || record.RuntimeLineage == nil || record.RuntimeLineage.Creation == nil || record.RuntimeLineage.Creation.Genesis == nil {
		return fail(errors.New("runtime has no retained original protected genesis"))
	}
	origin, creation := record.RuntimeLineage.Original(), *record.RuntimeLineage.Creation
	genesis := *creation.Genesis
	creation.Genesis = nil
	acceptance, err := proof.accepted.AcceptanceSHA256()
	if err != nil {
		return fail(err)
	}
	identity := proof.identity
	if !time.Now().Before(creation.ExpiresAt) || creation.DeploymentID != identity.DeploymentID || creation.SignedClusterID != identity.ClusterID || creation.Environment != identity.Environment ||
		creation.HostID != identity.Slot || identity.Slot != identity.SeedSlot || creation.InstanceID != identity.InstanceID || creation.AcceptanceSHA256 != acceptance || creation.AnchorSHA256 != authority.Anchor().Digest() {
		return fail(errors.New("protected runtime genesis differs from original current source"))
	}
	if err := proof.home.VerifyFoundationWriter(ctx); err != nil {
		return fail(err)
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	return origin, creation, genesis, authority.ExpiresAt(), nil
}
