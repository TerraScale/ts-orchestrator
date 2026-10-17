package region

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
)

// VerifiedBrokerCreation is original local broker provenance bound to its
// actual protected before-start source. It does not prove regional role absence.
type VerifiedBrokerCreation struct {
	permit  *BrokerCreationPermit
	actual  natscell.VerifiedBrokerGenesis
	genesis RuntimeBrokerGenesis
}

func (proof VerifiedBrokerCreation) Info() natscell.BrokerGenesisInfo { return proof.actual.Info() }

func (proof VerifiedBrokerCreation) ExpiresAt() time.Time {
	expires := proof.permit.ExpiresAt()
	if proof.actual.ExpiresAt().Before(expires) {
		expires = proof.actual.ExpiresAt()
	}
	return expires
}

func (proof VerifiedBrokerCreation) Revalidate(ctx context.Context) error {
	ctx, finish, err := proof.permit.bound(ctx)
	if err != nil {
		return err
	}
	defer finish()
	if err := proof.actual.Revalidate(ctx); err != nil {
		return err
	}
	if _, _, err := proof.permit.current(ctx, &proof.genesis); err != nil {
		return err
	}
	return proof.actual.Revalidate(ctx)
}

// InitialRootChain returns only the exact authenticated chain reserved before
// broker creation; the ordinary registry receives no cloud or genesis authority.
func (proof VerifiedBrokerCreation) InitialRootChain(ctx context.Context) ([]byte, error) {
	if err := proof.Revalidate(ctx); err != nil {
		return nil, err
	}
	record, _, err := proof.permit.current(ctx, &proof.genesis)
	if err != nil {
		return nil, err
	}
	floor := record.RuntimeLineage.TrustFloor
	if floor.RootSequence != proof.permit.floor.RootSequence || floor.RootHead != proof.permit.floor.RootHead || floor.RootChainSHA256 != proof.permit.floor.RootChainSHA256 {
		return nil, errors.New("original root chain has been superseded by an adopted successor")
	}
	return bytes.Clone(proof.permit.chain), nil
}

func (permit *BrokerCreationPermit) commit(ctx context.Context, actual natscell.VerifiedBrokerGenesis) (VerifiedBrokerCreation, error) {
	if err := actual.Revalidate(ctx); err != nil {
		return VerifiedBrokerCreation{}, err
	}
	info := actual.Info()
	if !brokerInstallationMatches(info.Installation, permit.creation) || info.Cell != strings.ToLower(permit.identity.Cell) || info.Instance != permit.creation.HostID ||
		info.RaftNodeID != permit.creation.Store.RaftNodeID || info.StartedAt.Before(permit.creation.StartedAt) || !info.StartedAt.Before(permit.expires) {
		return VerifiedBrokerCreation{}, errors.New("actual broker differs from protected original creation")
	}
	genesis := RuntimeBrokerGenesis{ServerID: info.ServerID, StartedAt: info.StartedAt, Device: info.Device, Inode: info.Inode, UID: info.UID,
		OperatorSHA256: info.OperatorSHA256, SystemJWTSHA256: info.SystemJWTSHA256, CellJWTSHA256: info.CellJWTSHA256, MarkerSHA256: info.MarkerSHA256, MarkerInode: info.MarkerInode}
	record, etag, err := permit.current(ctx, nil)
	if err != nil {
		return VerifiedBrokerCreation{}, err
	}
	lineage := *record.RuntimeLineage
	creation := *lineage.Broker
	creation.Genesis = new(genesis)
	lineage.Broker = &creation
	record.RuntimeLineage, record.UpdatedAt = &lineage, time.Now().UTC()
	ctx = ociclient.WithAuthority(ctx, func(ctx context.Context) error {
		if err := permit.validateSource(ctx); err != nil {
			return err
		}
		return actual.Revalidate(ctx)
	})
	resolver, err := discoverCurrentFoundation(ctx, permit.home.objects, permit.home.tenancyID, permit.home.currentGenesis)
	if err != nil {
		return VerifiedBrokerCreation{}, err
	}
	if _, err := resolver.Store.CompareAndSwap(ctx, record, etag); err != nil {
		return VerifiedBrokerCreation{}, err
	}
	proof := VerifiedBrokerCreation{permit: permit, actual: actual, genesis: genesis}
	if err := proof.Revalidate(ctx); err != nil {
		return VerifiedBrokerCreation{}, err
	}
	return proof, nil
}
