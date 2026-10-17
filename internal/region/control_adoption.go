package region

import (
	"context"
	"encoding/json/v2"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// AdoptRegionalControlSources reads the two actual broker keys and advances
// only an existing protected floor under current original-writer authority.
// Public DTOs and caller verification callbacks cannot authorize this CAS.
func AdoptRegionalControlSources(ctx context.Context, factory *ociclient.Factory, reader *bootstrapstart.CurrentFounderAuthorityReader, accepted bootstrapstart.AcceptedIdentity, runtime *natscell.Runtime) error {
	if ctx == nil || os.Geteuid() != 0 || factory == nil || reader == nil || runtime == nil {
		return errors.New("regional control adoption requires concrete current root source and broker")
	}
	expires := time.Now().UTC().Add(30 * time.Second)
	operation, cancel := context.WithDeadline(ctx, expires)
	defer cancel()
	authority, err := reader.ReadRuntimeAuthority(operation, accepted, time.Now().UTC())
	if err != nil {
		return err
	}
	if authority.ExpiresAt().Before(expires) {
		expires = authority.ExpiresAt()
	}
	operation, stop := context.WithDeadline(operation, expires)
	defer stop()
	identity := authority.Identity()
	if factory.Region() != identity.OCIRegion {
		return errors.New("regional control writer names another OCI region")
	}
	resolver, err := DiscoverCurrentFoundation(operation, factory)
	if err != nil {
		return err
	}
	purposeExpiry, err := regionalControlPurposeExpiry(operation, resolver, identity.Cell)
	if err != nil {
		return err
	}
	operation, stopPurpose := context.WithDeadline(operation, purposeExpiry)
	defer stopPurpose()
	home, err := NewRuntimeHomeIAMAuthority(operation, reader, accepted, resolver)
	if err != nil {
		return err
	}
	if err := home.VerifyFoundationWriter(operation); err != nil {
		return err
	}
	approved, err := resolver.Resolve(operation, identity.Cell)
	if err != nil {
		return err
	}
	record, etag, err := resolver.Store.Load(operation, identity.Cell)
	if err != nil {
		return err
	}
	if !sameRuntimeFoundation(record, approved) || record.RuntimeLineage == nil || record.RuntimeLineage.Broker == nil || record.RuntimeLineage.Broker.Genesis == nil || record.RuntimeLineage.TrustFloor == nil {
		return errors.New("regional control adoption has no original protected broker genesis")
	}
	before := *record.RuntimeLineage.TrustFloor
	if before.RootRevision == 0 || before.RootStreamCreated.IsZero() || before.SpecStreamCreated.IsZero() {
		return errors.New("regional control adoption cannot initialize an unpublished root or unreserved spec stream")
	}
	creation := *record.RuntimeLineage.Broker
	acceptance, err := accepted.AcceptanceSHA256()
	if err != nil {
		return err
	}
	if creation.DeploymentID != identity.DeploymentID || creation.SignedClusterID != identity.ClusterID || creation.Environment != identity.Environment ||
		creation.HostID != identity.Slot || identity.Slot != identity.SeedSlot || creation.InstanceID != identity.InstanceID || creation.AcceptanceSHA256 != acceptance || creation.AnchorSHA256 != authority.Anchor().Digest() {
		return errors.New("regional control adoption differs from original accepted writer source")
	}
	storage, err := runtime.ObserveBrokerStorage(operation)
	if err != nil {
		return err
	}
	if err := matchControlBrokerStorage(storage.Info(), creation); err != nil {
		return err
	}
	if storage.Info().Cell != strings.ToLower(identity.Cell) || storage.Info().Instance != identity.Slot {
		return errors.New("actual broker storage names another regional writer slot")
	}
	operation, stopStorage := context.WithDeadline(operation, storage.ExpiresAt())
	defer stopStorage()
	baked, err := bootstrapstart.LoadBakedInputs()
	if err != nil {
		return err
	}
	if baked.Identity.DeploymentID != identity.DeploymentID || string(baked.Identity.Cell) != identity.Cell || baked.Identity.Environment != identity.Environment {
		return errors.New("regional control verification roots name another installation")
	}
	root, err := observeControlSource(operation, runtime, controlRootsBucket, controlRootsKey)
	if err != nil {
		return err
	}
	spec, err := observeControlSource(operation, runtime, controlSpecBucket, controlSpecKey)
	if err != nil {
		return err
	}
	id := cellspec.Identity{DeploymentID: identity.DeploymentID, Environment: identity.Environment, Cell: strings.ToLower(identity.Cell)}
	next, err := verifiedControlAdvance(before, root, spec, baked.Genesis, id, time.Now().UTC())
	if err != nil {
		return err
	}
	sourceExpiry, err := controlAdmissionExpiry(before, root, spec)
	if err != nil {
		return err
	}
	if !sourceExpiry.IsZero() {
		var stopSource context.CancelFunc
		operation, stopSource = context.WithDeadline(operation, sourceExpiry)
		defer stopSource()
	}
	guard := func(ctx context.Context) error {
		if err := home.VerifyFoundationWriter(ctx); err != nil {
			return err
		}
		currentAuthority, err := reader.ReadRuntimeAuthority(ctx, accepted, time.Now().UTC())
		if err != nil {
			return err
		}
		if currentAuthority.Identity() != identity || currentAuthority.Anchor().Digest() != creation.AnchorSHA256 || !time.Now().Before(expires) {
			return errors.New("regional control accepted writer source changed or expired")
		}
		ctx, stopAuthority := context.WithDeadline(ctx, currentAuthority.ExpiresAt())
		defer stopAuthority()
		if err := storage.RevalidateRuntime(ctx, runtime); err != nil {
			return err
		}
		currentResolver, err := discoverCurrentFoundation(ctx, home.objects, home.tenancyID, home.currentGenesis)
		if err != nil {
			return err
		}
		purposeExpiry, err := regionalControlPurposeExpiry(ctx, currentResolver, identity.Cell)
		if err != nil {
			return err
		}
		ctx, stopPurpose := context.WithDeadline(ctx, purposeExpiry)
		defer stopPurpose()
		currentApproved, err := currentResolver.Resolve(ctx, identity.Cell)
		if err != nil {
			return err
		}
		current, held, err := currentResolver.Store.Load(ctx, identity.Cell)
		if err != nil {
			return err
		}
		if !sameRuntimeFoundation(current, currentApproved) || held != etag || current.RuntimeLineage == nil || current.RuntimeLineage.Original() != record.RuntimeLineage.Original() ||
			current.RuntimeLineage.TrustFloor == nil || *current.RuntimeLineage.TrustFloor != before || current.RuntimeLineage.Broker == nil || !sameControlBroker(*current.RuntimeLineage.Broker, creation) {
			return ErrFoundationConflict
		}
		actualRoot, err := observeControlSource(ctx, runtime, controlRootsBucket, controlRootsKey)
		if err != nil {
			return err
		}
		actualSpec, err := observeControlSource(ctx, runtime, controlSpecBucket, controlSpecKey)
		if err != nil {
			return err
		}
		if !actualRoot.same(root) || !actualSpec.same(spec) {
			return errors.New("regional public source changed before protected adoption")
		}
		if _, err := verifiedControlAdvance(before, actualRoot, actualSpec, baked.Genesis, id, time.Now().UTC()); err != nil {
			return err
		}
		if err := storage.RevalidateRuntime(ctx, runtime); err != nil {
			return err
		}
		if err := ociclient.LimitAdmission(ctx, currentAuthority.ExpiresAt()); err != nil {
			return err
		}
		if err := ociclient.LimitAdmission(ctx, storage.ExpiresAt()); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if !sourceExpiry.IsZero() {
			return ociclient.LimitAdmission(ctx, sourceExpiry)
		}
		return nil
	}
	if err := guard(operation); err != nil {
		return err
	}
	if next == before {
		return nil
	}
	now := time.Now().UTC()
	lineage := *record.RuntimeLineage
	next.UpdatedAt = now
	lineage.TrustFloor = new(next)
	record.RuntimeLineage, record.UpdatedAt = &lineage, now
	writeCtx := ociclient.WithAuthority(operation, guard)
	writeCtx = ociclient.WithAdmission(writeCtx, func(ctx context.Context) (func(), error) {
		if err := guard(ctx); err != nil {
			return nil, err
		}
		return func() {}, nil
	})
	if _, err := resolver.Store.CompareAndSwap(writeCtx, record, etag); err != nil {
		return err
	}
	saved, _, err := resolver.Store.Load(operation, identity.Cell)
	if err != nil {
		return err
	}
	if saved.RuntimeLineage == nil || saved.RuntimeLineage.Original() != lineage.Original() || saved.RuntimeLineage.Broker == nil || !sameControlBroker(*saved.RuntimeLineage.Broker, creation) ||
		saved.RuntimeLineage.TrustFloor == nil || *saved.RuntimeLineage.TrustFloor != next {
		return errors.New("regional control floor checkpoint was not retained exactly")
	}
	actualRoot, err := observeControlSource(operation, runtime, controlRootsBucket, controlRootsKey)
	if err != nil {
		return err
	}
	actualSpec, err := observeControlSource(operation, runtime, controlSpecBucket, controlSpecKey)
	if err != nil {
		return err
	}
	if !actualRoot.same(root) || !actualSpec.same(spec) {
		return errors.New("regional public source changed after protected adoption")
	}
	if err := home.VerifyFoundationWriter(operation); err != nil {
		return err
	}
	currentResolver, err := discoverCurrentFoundation(operation, home.objects, home.tenancyID, home.currentGenesis)
	if err != nil {
		return err
	}
	purposeExpiry, err = regionalControlPurposeExpiry(operation, currentResolver, identity.Cell)
	if err != nil {
		return err
	}
	operation, stopFinalPurpose := context.WithDeadline(operation, purposeExpiry)
	defer stopFinalPurpose()
	return storage.RevalidateRuntime(operation, runtime)
}

func sameControlBroker(a, b RuntimeBrokerCreation) bool {
	if a.Genesis == nil || b.Genesis == nil || *a.Genesis != *b.Genesis {
		return false
	}
	a.Genesis, b.Genesis = nil, nil
	return a == b
}

func matchControlBrokerStorage(info natscell.BrokerStorageInfo, creation RuntimeBrokerCreation) error {
	genesis := creation.Genesis
	if genesis == nil || !brokerInstallationMatches(info.Installation, creation) || info.RaftNodeID != creation.Store.RaftNodeID ||
		!info.StartedAt.Equal(genesis.StartedAt) || info.Device != genesis.Device || info.Inode != genesis.Inode || info.UID != genesis.UID ||
		info.OperatorSHA256 != genesis.OperatorSHA256 || info.SystemJWTSHA256 != genesis.SystemJWTSHA256 || info.CellJWTSHA256 != genesis.CellJWTSHA256 ||
		info.MarkerSHA256 != genesis.MarkerSHA256 || info.MarkerInode != genesis.MarkerInode {
		return errors.New("actual broker storage differs from its protected original incarnation")
	}
	return nil
}

func verifiedControlAdvance(before RuntimeTrustFloor, root, spec controlSource, genesis trust.Keyring, id cellspec.Identity, now time.Time) (RuntimeTrustFloor, error) {
	if before.RootRevision == 0 || root.revision == 0 || spec.revision == 0 ||
		!before.RootStreamCreated.Equal(root.created) || !before.SpecStreamCreated.Equal(spec.created) || root.revision < before.RootRevision || spec.revision < before.SpecRevision {
		return RuntimeTrustFloor{}, errors.New("regional control source is missing, recreated or behind its protected revision")
	}
	chain, err := trust.DecodeRootChain(root.wire)
	if err != nil {
		return RuntimeTrustFloor{}, err
	}
	verified, err := trust.VerifyRootChain(genesis, trust.ChainIdentity{DeploymentID: id.DeploymentID, Environment: id.Environment, Cell: id.Cell}, chain)
	if err != nil {
		return RuntimeTrustFloor{}, err
	}
	if verified.Sequence < before.RootSequence {
		return RuntimeTrustFloor{}, errors.New("regional root chain rolls back protected sequence")
	}
	prefix := trust.RootChain{Version: chain.Version, Rotations: chain.Rotations[:before.RootSequence]}
	prefixWire, err := trust.EncodeRootChain(prefix)
	if err != nil || brokerSourceDigest(prefixWire) != before.RootChainSHA256 {
		return RuntimeTrustFloor{}, errors.New("regional root chain does not extend the exact protected prefix")
	}
	oldRoots, err := trust.VerifyRootChain(genesis, trust.ChainIdentity{DeploymentID: id.DeploymentID, Environment: id.Environment, Cell: id.Cell}, prefix)
	if err != nil || oldRoots.Head != before.RootHead {
		return RuntimeTrustFloor{}, errors.New("regional root chain differs from protected rotation head")
	}
	for _, rotation := range chain.Rotations[before.RootSequence:] {
		if err := trust.RotationCurrent(rotation, now); err != nil {
			return RuntimeTrustFloor{}, err
		}
	}
	var adopted cellspec.Verified
	if before.SpecRevision != 0 && before.SpecSHA256 == brokerSourceDigest(spec.wire) {
		adopted, err = cellspec.VerifyHistorical(spec.wire, verified.Historical, id)
	} else {
		adopted, err = cellspec.VerifyCurrent(spec.wire, verified.Current, id, now)
	}
	if err != nil {
		return RuntimeTrustFloor{}, err
	}
	next := before
	next.RootSequence, next.RootHead, next.RootChainSHA256, next.RootRevision = verified.Sequence, verified.Head, brokerSourceDigest(root.wire), root.revision
	next.SpecGeneration, next.SpecSHA256, next.SpecRevision = adopted.Generation, brokerSourceDigest(spec.wire), spec.revision
	if err := retainBrokerLineage(&RuntimeLineageRecord{TrustFloor: &before}, &RuntimeLineageRecord{TrustFloor: &next}); err != nil {
		return RuntimeTrustFloor{}, err
	}
	return next, nil
}

func controlAdmissionExpiry(before RuntimeTrustFloor, root, spec controlSource) (time.Time, error) {
	var expires time.Time
	retain := func(deadline time.Time) {
		if expires.IsZero() || deadline.Before(expires) {
			expires = deadline
		}
	}
	chain, err := trust.DecodeRootChain(root.wire)
	if err != nil {
		return time.Time{}, err
	}
	if uint64(len(chain.Rotations)) < before.RootSequence {
		return time.Time{}, errors.New("regional control admission lost its protected root prefix")
	}
	for _, rotation := range chain.Rotations[before.RootSequence:] {
		for _, envelope := range rotation.Signatures {
			retain(envelope.ExpiresAt)
		}
	}
	if before.SpecRevision != 0 && before.SpecSHA256 == brokerSourceDigest(spec.wire) {
		return expires, nil
	}
	var signed cellspec.Signed
	if err := json.Unmarshal(spec.wire, &signed); err != nil {
		return time.Time{}, err
	}
	for _, wire := range [][]byte{signed.Spec, signed.Delegation} {
		if len(wire) == 0 {
			continue
		}
		envelope, err := trust.DecodeEnvelope(wire)
		if err != nil {
			return time.Time{}, err
		}
		retain(envelope.ExpiresAt)
	}
	return expires, nil
}
