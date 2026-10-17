package region

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// RegionalTrustFloorInfo exposes public retained facts, never write authority.
type RegionalTrustFloorInfo struct {
	Cell   string
	Origin RuntimeLineageRecord
	Broker RuntimeBrokerCreation
	Floor  RuntimeTrustFloor
}

// VerifiedRegionalTrustFloor is a finite read-only observation of the protected
// original broker and its adopted public source. It cannot initialize lineage.
type VerifiedRegionalTrustFloor struct {
	ctx     context.Context
	factory *ociclient.Factory
	genesis trust.Keyring
	info    RegionalTrustFloorInfo
	expires time.Time
}

// OpenRegionalTrustFloor authenticates the signed regional scope and existing
// protected original source without inventing a manager AcceptedIdentity.
func OpenRegionalTrustFloor(ctx context.Context, factory *ociclient.Factory, genesis trust.Keyring, cell string) (VerifiedRegionalTrustFloor, error) {
	return OpenRegionalTrustFloorForOperation(ctx, ctx, time.Now().UTC().Add(30*time.Second), factory, genesis, cell)
}

// OpenRegionalTrustFloorForOperation bounds acquisition separately from the
// original reader and material lifetime retained by the read-only proof.
func OpenRegionalTrustFloorForOperation(ctx, original context.Context, retainedUntil time.Time, factory *ociclient.Factory, genesis trust.Keyring, cell string) (VerifiedRegionalTrustFloor, error) {
	if factory == nil || len(genesis) == 0 || !catalog.IsCell(cell) {
		return VerifiedRegionalTrustFloor{}, errors.New("regional trust floor requires authenticated OCI and independent roots")
	}
	operation, cancel, expires, err := regionalTrustFloorReadContext(ctx, original, retainedUntil)
	if err != nil {
		return VerifiedRegionalTrustFloor{}, err
	}
	defer cancel()
	genesis = maps.Clone(genesis)
	for id, key := range genesis {
		genesis[id] = bytes.Clone(key)
	}
	info, sourceExpiry, err := readRegionalTrustFloor(operation, factory, genesis, cell)
	if err != nil {
		return VerifiedRegionalTrustFloor{}, err
	}
	if sourceExpiry.Before(expires) {
		expires = sourceExpiry
	}
	operation, stopSource := context.WithDeadline(operation, expires)
	defer stopSource()
	proof := VerifiedRegionalTrustFloor{ctx: original, factory: factory, genesis: genesis, info: info, expires: expires}
	if err := proof.Guard(operation); err != nil {
		return VerifiedRegionalTrustFloor{}, err
	}
	return proof, nil
}

func regionalTrustFloorReadContext(ctx, original context.Context, retainedUntil time.Time) (context.Context, context.CancelFunc, time.Time, error) {
	if ctx == nil || original == nil || retainedUntil.IsZero() || !time.Now().Before(retainedUntil) {
		return nil, nil, time.Time{}, errors.New("regional trust floor requires its original current reader and material lifetime")
	}
	if err := errors.Join(ctx.Err(), original.Err()); err != nil {
		return nil, nil, time.Time{}, err
	}
	expires := time.Now().UTC().Add(30 * time.Second)
	if retainedUntil.Before(expires) {
		expires = retainedUntil
	}
	if deadline, ok := original.Deadline(); ok && deadline.Before(expires) {
		expires = deadline
	}
	operation, cancel := context.WithDeadline(ctx, expires)
	stop := context.AfterFunc(original, cancel)
	return operation, func() { stop(); cancel() }, expires, nil
}

func (proof VerifiedRegionalTrustFloor) Info() RegionalTrustFloorInfo {
	info := proof.info
	if info.Broker.Genesis != nil {
		info.Broker.Genesis = new(*info.Broker.Genesis)
	}
	return info
}

func (proof VerifiedRegionalTrustFloor) ExpiresAt() time.Time { return proof.expires }

func (proof VerifiedRegionalTrustFloor) Guard(ctx context.Context) error {
	if ctx == nil || proof.ctx == nil || proof.factory == nil || !time.Now().Before(proof.expires) {
		return errors.New("regional trust floor observation is absent or expired")
	}
	if err := proof.ctx.Err(); err != nil {
		return err
	}
	operation, cancel := context.WithDeadline(ctx, proof.expires)
	defer cancel()
	stop := context.AfterFunc(proof.ctx, cancel)
	defer stop()
	current, _, err := readRegionalTrustFloor(operation, proof.factory, proof.genesis, proof.info.Cell)
	if err != nil {
		return err
	}
	if !sameRegionalTrustFloor(current, proof.info) {
		return errors.New("protected regional trust floor changed after observation")
	}
	if err := proof.ctx.Err(); err != nil {
		return err
	}
	return operation.Err()
}

// CheckAdoptedSources permits historical signature verification only for the
// exact two already adopted public records. It grants no adoption authority.
func (proof VerifiedRegionalTrustFloor) CheckAdoptedSources(ctx context.Context, rootCreated time.Time, rootRevision uint64, rootWire []byte, specCreated time.Time, specRevision uint64, specWire []byte) error {
	if err := proof.Guard(ctx); err != nil {
		return err
	}
	floor := proof.info.Floor
	if floor.RootRevision == 0 || floor.SpecRevision == 0 ||
		!floor.RootStreamCreated.Equal(rootCreated) || floor.RootRevision != rootRevision || floor.RootChainSHA256 != brokerSourceDigest(rootWire) ||
		!floor.SpecStreamCreated.Equal(specCreated) || floor.SpecRevision != specRevision || floor.SpecSHA256 != brokerSourceDigest(specWire) {
		return errors.New("public root or spec differs from the exact protected adopted source")
	}
	return proof.Guard(ctx)
}

func sameRegionalTrustFloor(a, b RegionalTrustFloorInfo) bool {
	if a.Cell != b.Cell || a.Origin != b.Origin || a.Floor != b.Floor || a.Broker.Genesis == nil || b.Broker.Genesis == nil || *a.Broker.Genesis != *b.Broker.Genesis {
		return false
	}
	a.Broker.Genesis, b.Broker.Genesis = nil, nil
	return a.Broker == b.Broker
}

func readRegionalTrustFloor(ctx context.Context, factory *ociclient.Factory, genesis trust.Keyring, cell string) (RegionalTrustFloorInfo, time.Time, error) {
	client, tenancy, err := foundationHomeClient(factory)
	if err != nil {
		return RegionalTrustFloorInfo{}, time.Time{}, err
	}
	resolver, err := discoverCurrentFoundation(ctx, client, tenancy, genesis)
	if err != nil {
		return RegionalTrustFloorInfo{}, time.Time{}, err
	}
	purposeExpiry, err := regionalControlPurposeExpiry(ctx, resolver, cell)
	if err != nil {
		return RegionalTrustFloorInfo{}, time.Time{}, err
	}
	ctx, cancel := context.WithDeadline(ctx, purposeExpiry)
	defer cancel()
	record, err := resolver.Resolve(ctx, cell)
	if err != nil {
		return RegionalTrustFloorInfo{}, time.Time{}, err
	}
	material, err := resolver.BootstrapMaterial(ctx, cell)
	if err != nil {
		return RegionalTrustFloorInfo{}, time.Time{}, err
	}
	lineage := record.RuntimeLineage
	if lineage == nil || lineage.Broker == nil || lineage.Broker.Genesis == nil || lineage.TrustFloor == nil || lineage.TrustFloor.RootRevision == 0 || record.FoundationWriter == nil || record.FoundationWriter.InstanceID != lineage.Broker.InstanceID {
		return RegionalTrustFloorInfo{}, time.Time{}, errors.New("regional trust floor has no retained original broker and published root source")
	}
	config := material.Config()
	if lineage.Broker.DeploymentID != config.DeploymentID || lineage.Broker.SignedClusterID != config.ClusterID || lineage.Broker.Environment != config.Environment {
		return RegionalTrustFloorInfo{}, time.Time{}, errors.New("protected broker differs from signed regional installation")
	}
	broker := *lineage.Broker
	broker.Genesis = new(*broker.Genesis)
	expires := material.ExpiresAt()
	if purposeExpiry.Before(expires) {
		expires = purposeExpiry
	}
	if !time.Now().Before(expires) {
		return RegionalTrustFloorInfo{}, time.Time{}, errors.New("regional trust floor signed source expired during observation")
	}
	return RegionalTrustFloorInfo{Cell: cell, Origin: lineage.Original(), Broker: broker, Floor: *lineage.TrustFloor}, expires, ctx.Err()
}

func regionalControlPurposeExpiry(ctx context.Context, resolver FoundationResolver, cell string) (time.Time, error) {
	reader, ok := resolver.Footprint.(*SignedFootprint)
	if !ok || reader == nil {
		return time.Time{}, errors.New("regional control lineage requires its signed foundation scope")
	}
	ctx, cancel := context.WithDeadline(ctx, reader.expires)
	defer cancel()
	footprint, expires, err := reader.authorizedRegions(ctx)
	if err != nil {
		return time.Time{}, err
	}
	for _, intent := range footprint.Regions {
		if intent.Plan["cell"] == cell {
			if err := intent.validateControlLineagePurpose(); err != nil {
				return time.Time{}, err
			}
			return expires, ociclient.LimitAdmission(ctx, expires)
		}
	}
	return time.Time{}, errors.New("signed regional-control-lineage purpose is absent or differs")
}
