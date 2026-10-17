package region

import (
	"context"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/identityrekey"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
)

// RuntimeCreationPermit is minted from current signed source and the actual
// protected SDK record. Neither payloads nor callback-backed stores mint it.
type RuntimeCreationPermit struct {
	mu       sync.Mutex
	used     bool
	ctx      context.Context
	factory  *ociclient.Factory
	home     *HomeIAMAuthority
	reader   *bootstrapstart.CurrentFounderAuthorityReader
	accepted bootstrapstart.AcceptedIdentity
	identity bootstrapstart.RuntimeIdentity
	creation RuntimeCreation
	origin   RuntimeLineageRecord
	expires  time.Time
}

func PrepareRuntimeCreation(ctx context.Context, factory *ociclient.Factory, reader *bootstrapstart.CurrentFounderAuthorityReader, accepted bootstrapstart.AcceptedIdentity) (*RuntimeCreationPermit, error) {
	if os.Geteuid() != 0 || factory == nil || reader == nil || ctx.Err() != nil {
		return nil, errors.New("runtime creation requires current root-owned production source")
	}
	expires := time.Now().UTC().Add(30 * time.Second)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(expires) {
		expires = deadline
	}
	operation, cancel := context.WithDeadline(ctx, expires)
	defer cancel()
	authority, err := reader.ReadRuntimeAuthority(operation, accepted, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	identity := authority.Identity()
	if factory.Region() != identity.OCIRegion {
		return nil, errors.New("runtime creation OCI source names another region")
	}
	if identity.Slot != identity.SeedSlot || accepted.Origin != identityrekey.AcceptanceOriginInitial {
		return nil, nil
	}
	resolver, err := DiscoverCurrentFoundation(operation, factory)
	if err != nil {
		return nil, err
	}
	home, err := NewRuntimeHomeIAMAuthority(operation, reader, accepted, resolver)
	if err != nil {
		return nil, err
	}
	factory, _, err = home.GuardedFactory(operation)
	if err != nil {
		return nil, err
	}
	approved, err := resolver.Resolve(operation, identity.Cell)
	if err != nil {
		return nil, err
	}
	record, etag, err := resolver.Store.Load(operation, identity.Cell)
	if err != nil {
		return nil, err
	}
	if !sameRuntimeFoundation(record, approved) {
		return nil, ErrFoundationBusy
	}
	if record.RuntimeLineage == nil || record.RuntimeLineage.Creation != nil {
		return nil, nil
	}
	acceptance, err := accepted.AcceptanceSHA256()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	creation := RuntimeCreation{OperationID: entityid.Derive("runtime-genesis", record.RuntimeLineage.FoundationOperationID),
		DeploymentID: identity.DeploymentID, SignedClusterID: identity.ClusterID, Environment: identity.Environment,
		HostID: identity.Slot, InstanceID: identity.InstanceID, AcceptanceSHA256: acceptance,
		AnchorSHA256: authority.Anchor().Digest(), StartedAt: now}
	if authority.ExpiresAt().Before(expires) {
		expires = authority.ExpiresAt()
	}
	permit := &RuntimeCreationPermit{ctx: ctx, factory: factory, home: home, reader: reader, accepted: accepted.Clone(),
		identity: identity, creation: creation, origin: *record.RuntimeLineage, expires: expires}
	if err := permit.ValidateSource(operation); err != nil {
		return nil, err
	}
	lineage := *record.RuntimeLineage
	lineage.Creation = new(creation)
	record.RuntimeLineage, record.UpdatedAt = &lineage, now
	if _, err := resolver.Store.CompareAndSwap(operation, record, etag); err != nil {
		return nil, err
	}
	if err := permit.current(operation); err != nil {
		return nil, err
	}
	return permit, nil
}

func (permit *RuntimeCreationPermit) Creation() RuntimeCreation {
	if permit == nil {
		return RuntimeCreation{}
	}
	return permit.creation
}

func (permit *RuntimeCreationPermit) Origin() RuntimeLineageRecord {
	if permit == nil {
		return RuntimeLineageRecord{}
	}
	return permit.origin
}

func (permit *RuntimeCreationPermit) ExpiresAt() time.Time {
	if permit == nil {
		return time.Time{}
	}
	return permit.expires
}

func (permit *RuntimeCreationPermit) GuardCreate(ctx context.Context) error {
	if permit == nil {
		return errors.New("runtime has no protected original creation permit")
	}
	return permit.GuardCreateFor(ctx, permit.reader, permit.accepted)
}

// GuardCreateFor binds the concrete accepted caller before consuming the
// one-shot permit under the actual founder's node.lock.
func (permit *RuntimeCreationPermit) GuardCreateFor(ctx context.Context, reader *bootstrapstart.CurrentFounderAuthorityReader, accepted bootstrapstart.AcceptedIdentity) error {
	if permit == nil {
		return errors.New("runtime has no protected original creation permit")
	}
	permit.mu.Lock()
	defer permit.mu.Unlock()
	ctx, cancel, err := permit.bound(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	digest, err := accepted.AcceptanceSHA256()
	if err != nil || reader != permit.reader || digest != permit.creation.AcceptanceSHA256 {
		return errors.New("runtime creation permit names another accepted source")
	}
	if permit.used {
		return errors.New("original runtime creation permit was already consumed")
	}
	if err := permit.current(ctx); err != nil {
		return err
	}
	permit.used = true
	return nil
}

func (permit *RuntimeCreationPermit) GuardStarted(ctx context.Context) error {
	if permit == nil {
		return errors.New("runtime has no protected original creation permit")
	}
	permit.mu.Lock()
	defer permit.mu.Unlock()
	ctx, cancel, err := permit.bound(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	if !permit.used {
		return errors.New("runtime genesis did not consume its original creation permit")
	}
	return permit.current(ctx)
}

func (permit *RuntimeCreationPermit) ValidateSource(ctx context.Context) error {
	if permit == nil || permit.factory == nil || permit.home == nil || permit.reader == nil || permit.ctx == nil || !time.Now().Before(permit.expires) {
		return errors.New("runtime original creation authority is absent or expired")
	}
	if err := permit.ctx.Err(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	ctx, cancel, err := permit.bound(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	if err := permit.home.VerifyFoundationWriter(ctx); err != nil {
		return err
	}
	authority, err := permit.reader.ReadRuntimeAuthority(ctx, permit.accepted, time.Now().UTC())
	if err != nil {
		return err
	}
	if authority.Identity() != permit.identity || authority.Anchor().Digest() != permit.creation.AnchorSHA256 {
		return errors.New("runtime original accepted source changed before genesis")
	}
	if err := permit.ctx.Err(); err != nil {
		return err
	}
	return ctx.Err()
}

func (permit *RuntimeCreationPermit) bound(ctx context.Context) (context.Context, func(), error) {
	if permit == nil || permit.ctx == nil || permit.ctx.Err() != nil || !time.Now().Before(permit.expires) {
		return nil, nil, errors.New("original runtime creation lifetime ended")
	}
	ctx, cancel := context.WithDeadline(ctx, permit.expires)
	stop := context.AfterFunc(permit.ctx, cancel)
	return ctx, func() { stop(); cancel() }, nil
}

func (permit *RuntimeCreationPermit) current(ctx context.Context) error {
	if err := permit.ValidateSource(ctx); err != nil {
		return err
	}
	resolver, err := DiscoverCurrentFoundation(ctx, permit.factory)
	if err != nil {
		return err
	}
	approved, err := resolver.Resolve(ctx, permit.identity.Cell)
	if err != nil {
		return err
	}
	record, _, err := resolver.Store.Load(ctx, permit.identity.Cell)
	if err != nil {
		return err
	}
	lineage := record.RuntimeLineage
	if !sameRuntimeFoundation(record, approved) || lineage == nil || lineage.Creation == nil || *lineage.Creation != permit.creation {
		return errors.New("protected original runtime creation changed or completed")
	}
	origin := *lineage
	origin.Creation = nil
	if origin != permit.origin {
		return errors.New("protected original runtime foundation changed")
	}
	return nil
}

func sameRuntimeFoundation(record, approved FoundationRecord) bool {
	return record.Stage == "reconciled" && record.LeaseID == "" && record.Generation == approved.Generation && record.GrantSHA256 == approved.GrantSHA256 && record.OperationID == approved.OperationID && record.IntentDigest == approved.IntentDigest
}
