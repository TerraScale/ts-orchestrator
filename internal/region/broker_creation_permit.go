package region

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/identityrekey"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// BrokerCreationPermit protects the original writer's local broker only.
// It cannot certify the other brokers or any regional role's retained history.
type BrokerCreationPermit struct {
	mu       sync.Mutex
	used     bool
	ctx      context.Context
	home     *HomeIAMAuthority
	reader   *bootstrapstart.CurrentFounderAuthorityReader
	accepted bootstrapstart.AcceptedIdentity
	identity bootstrapstart.RuntimeIdentity
	origin   RuntimeLineageRecord
	creation RuntimeBrokerCreation
	floor    RuntimeTrustFloor
	chain    []byte
	expires  time.Time
}

func PrepareBrokerCreation(ctx context.Context, factory *ociclient.Factory, reader *bootstrapstart.CurrentFounderAuthorityReader, accepted bootstrapstart.AcceptedIdentity) (*BrokerCreationPermit, error) {
	expires := time.Now().UTC().Add(30 * time.Second)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(expires) {
		expires = deadline
	}
	if os.Geteuid() != 0 || factory == nil || reader == nil || ctx.Err() != nil {
		return nil, errors.New("broker creation requires current root-owned production source")
	}
	operation, cancel := context.WithDeadline(ctx, expires)
	defer cancel()
	authority, err := reader.ReadRuntimeAuthority(operation, accepted, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	identity := authority.Identity()
	if identity.Slot != identity.SeedSlot || accepted.Origin != identityrekey.AcceptanceOriginInitial {
		return nil, nil
	}
	if factory.Region() != identity.OCIRegion {
		return nil, errors.New("broker creation source names another OCI region")
	}
	resolver, err := DiscoverCurrentFoundation(operation, factory)
	if err != nil {
		return nil, err
	}
	home, err := NewRuntimeHomeIAMAuthority(operation, reader, accepted, resolver)
	if err != nil {
		return nil, err
	}
	if err := home.VerifyFoundationWriter(operation); err != nil {
		return nil, err
	}
	factory, operation, err = home.GuardedFactory(operation)
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
	if record.RuntimeLineage == nil || record.RuntimeLineage.Broker != nil || record.RuntimeLineage.TrustFloor != nil {
		return nil, nil
	}
	baked, err := bootstrapstart.LoadBakedInputs()
	if err != nil {
		return nil, err
	}
	if baked.Identity.DeploymentID != identity.DeploymentID || string(baked.Identity.Cell) != identity.Cell || baked.Identity.Environment != identity.Environment {
		return nil, errors.New("broker root source differs from current accepted installation")
	}
	roots, err := trust.VerifyRootChain(baked.Genesis, baked.Identity.ChainIdentity(), baked.Chain)
	if err != nil {
		return nil, err
	}
	chain, err := trust.EncodeRootChain(baked.Chain)
	if err != nil {
		return nil, err
	}
	acceptance, err := accepted.AcceptanceSHA256()
	if err != nil {
		return nil, err
	}
	if authority.ExpiresAt().Before(expires) {
		expires = authority.ExpiresAt()
	}
	now := time.Now().UTC()
	creation := RuntimeBrokerCreation{OperationID: entityid.Derive("broker-genesis", record.RuntimeLineage.FoundationOperationID),
		DeploymentID: identity.DeploymentID, SignedClusterID: identity.ClusterID, Environment: identity.Environment,
		HostID: identity.Slot, InstanceID: identity.InstanceID, AcceptanceSHA256: acceptance, AnchorSHA256: authority.Anchor().Digest(),
		Broker: accepted.Broker, Store: accepted.Store, StartedAt: now, ExpiresAt: expires}
	floor := RuntimeTrustFloor{OperationID: creation.OperationID, RootSequence: roots.Sequence, RootHead: roots.Head, RootChainSHA256: brokerSourceDigest(chain), UpdatedAt: now}
	permit := &BrokerCreationPermit{ctx: ctx, home: home, reader: reader, accepted: accepted.Clone(), identity: identity,
		origin: record.RuntimeLineage.Original(), creation: creation, floor: floor, chain: bytes.Clone(chain), expires: expires}
	operation, finish, err := permit.bound(operation)
	if err != nil {
		return nil, err
	}
	defer finish()
	if err := permit.validateSource(operation); err != nil {
		return nil, err
	}
	lineage := *record.RuntimeLineage
	lineage.Broker, lineage.TrustFloor = new(creation), new(floor)
	record.RuntimeLineage, record.UpdatedAt = &lineage, now
	operation = ociclient.WithAuthority(operation, permit.validateSource)
	if _, err := resolver.Store.CompareAndSwap(operation, record, etag); err != nil {
		return nil, err
	}
	if _, _, err := permit.current(operation, nil); err != nil {
		return nil, err
	}
	return permit, nil
}

func (permit *BrokerCreationPermit) ExpiresAt() time.Time {
	if permit == nil {
		return time.Time{}
	}
	return permit.expires
}

// Start consumes the protected reservation itself; callers cannot replace its
// guard with a callback or attach a payload to an already running broker.
func (permit *BrokerCreationPermit) Start(ctx context.Context, cfg natscell.Config) (*natscell.Runtime, VerifiedBrokerCreation, error) {
	if permit == nil {
		return nil, VerifiedBrokerCreation{}, errors.New("broker has no protected original creation permit")
	}
	permit.mu.Lock()
	defer permit.mu.Unlock()
	operation, finish, err := permit.bound(ctx)
	if err != nil {
		return nil, VerifiedBrokerCreation{}, err
	}
	defer finish()
	if permit.used {
		return nil, VerifiedBrokerCreation{}, errors.New("original broker creation permit was already consumed")
	}
	if _, _, err := permit.current(operation, nil); err != nil {
		return nil, VerifiedBrokerCreation{}, err
	}
	installed, err := natscell.ObserveInstalledIdentity(cfg)
	if err != nil || !brokerInstallationMatches(installed, permit.creation) || cfg.Cell != strings.ToLower(permit.identity.Cell) || cfg.Instance != permit.identity.Slot {
		return nil, VerifiedBrokerCreation{}, errors.Join(errors.New("original broker configuration differs from protected accepted source"), err)
	}
	permit.used = true
	// This context remains live after Start returns; the creation observation
	// retains its original cap rather than a deferred-canceled helper context.
	started, cancel := context.WithDeadline(ctx, permit.expires)
	stop := context.AfterFunc(permit.ctx, cancel)
	context.AfterFunc(started, func() { stop() })
	runtime, actual, err := natscell.StartOriginalBroker(started, cfg)
	if err != nil {
		cancel()
		return nil, VerifiedBrokerCreation{}, err
	}
	proof, err := permit.commit(operation, actual)
	if err != nil {
		cancel()
		_ = runtime.Close()
		return nil, VerifiedBrokerCreation{}, err
	}
	return runtime, proof, nil
}

func (permit *BrokerCreationPermit) bound(ctx context.Context) (context.Context, func(), error) {
	if permit == nil || permit.ctx == nil || permit.ctx.Err() != nil || !time.Now().Before(permit.expires) {
		return nil, nil, errors.New("original broker creation lifetime ended")
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	expires := permit.expires
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(expires) {
		expires = deadline
	}
	bound, cancel := context.WithDeadline(permit.ctx, expires)
	stop := context.AfterFunc(ctx, cancel)
	return bound, func() { stop(); cancel() }, nil
}

func (permit *BrokerCreationPermit) validateSource(ctx context.Context) error {
	if permit == nil || permit.ctx == nil || permit.home == nil || permit.reader == nil || !time.Now().Before(permit.expires) {
		return errors.New("original broker source is absent or expired")
	}
	if err := permit.ctx.Err(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := permit.home.VerifyFoundationWriter(ctx); err != nil {
		return err
	}
	authority, err := permit.reader.ReadRuntimeAuthority(ctx, permit.accepted, time.Now().UTC())
	if err != nil {
		return err
	}
	if authority.Identity() != permit.identity || authority.Anchor().Digest() != permit.creation.AnchorSHA256 {
		return errors.New("original broker signed source changed")
	}
	return permit.ctx.Err()
}

func (permit *BrokerCreationPermit) current(ctx context.Context, genesis *RuntimeBrokerGenesis) (FoundationRecord, string, error) {
	if err := permit.validateSource(ctx); err != nil {
		return FoundationRecord{}, "", err
	}
	resolver, err := discoverCurrentFoundation(ctx, permit.home.objects, permit.home.tenancyID, permit.home.currentGenesis)
	if err != nil {
		return FoundationRecord{}, "", err
	}
	approved, err := resolver.Resolve(ctx, permit.identity.Cell)
	if err != nil {
		return FoundationRecord{}, "", err
	}
	record, etag, err := resolver.Store.Load(ctx, permit.identity.Cell)
	if err != nil {
		return FoundationRecord{}, "", err
	}
	lineage := record.RuntimeLineage
	if !sameRuntimeFoundation(record, approved) || lineage == nil || lineage.Original() != permit.origin || lineage.Broker == nil || lineage.TrustFloor == nil || lineage.TrustFloor.OperationID != permit.floor.OperationID || genesis == nil && *lineage.TrustFloor != permit.floor {
		return FoundationRecord{}, "", errors.New("original broker protected source changed")
	}
	creation := *lineage.Broker
	actualGenesis := creation.Genesis
	creation.Genesis = nil
	if creation != permit.creation || genesis == nil && actualGenesis != nil || genesis != nil && (actualGenesis == nil || *actualGenesis != *genesis) {
		return FoundationRecord{}, "", errors.New("original broker creation changed or completed")
	}
	return record, etag, nil
}

func brokerInstallationMatches(installed natscell.InstallationIdentity, source RuntimeBrokerCreation) bool {
	return installed.Directory == source.Store.Directory && installed.ServerName == source.Store.ServerName && installed.RaftNodeID == source.Store.RaftNodeID &&
		installed.ServerNameSHA256 == source.Store.ServerNameSHA256 && installed.NodeIdentitySHA256 == source.Store.NodeIdentitySHA256 &&
		installed.Operator == source.Broker.Operator && installed.SystemAccount == source.Broker.SystemAccount && installed.CellAccount == source.Broker.CellAccount &&
		installed.HostSigner == source.Broker.HostSigner && installed.RoleSigner == source.Broker.RoleSigner && installed.AccountSigner == source.Broker.AccountSigner && installed.InterRegionAccount == source.Broker.InterRegionAccount
}

func brokerSourceDigest(wire []byte) string {
	digest := sha256.Sum256(wire)
	return hex.EncodeToString(digest[:])
}
