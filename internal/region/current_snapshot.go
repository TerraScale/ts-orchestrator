package region

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// CurrentFoundationSnapshot retains one authenticated discovery attempt. Its
// currentness guard never adopts a successor or replaces the original lifetime.
type CurrentFoundationSnapshot struct {
	resolver       FoundationResolver
	documents      RetainedFoundation
	genesis        trust.Keyring
	roots          trust.Keyring
	anchor         bootstrap.VerifiedBootstrapAnchor
	head           string
	expires        time.Time
	ctx            context.Context
	floorDirectory string
	floor          foundationFloor
}

// DiscoverCurrentFoundationSnapshot returns both halves of the same discovery;
// existing material and resource-binding verification still applies to its resolver.
func DiscoverCurrentFoundationSnapshot(ctx context.Context, factory *ociclient.Factory) (*CurrentFoundationSnapshot, error) {
	return DiscoverCurrentFoundationSnapshotForOperation(ctx, ctx, factory)
}

// DiscoverCurrentFoundationSnapshotForOperation uses one bounded discovery while
// retaining the original source lifecycle independently of the read budget.
func DiscoverCurrentFoundationSnapshotForOperation(ctx, originalCtx context.Context, factory *ociclient.Factory) (*CurrentFoundationSnapshot, error) {
	if ctx == nil || originalCtx == nil || ctx.Err() != nil || originalCtx.Err() != nil {
		return nil, errors.New("current foundation requires a live original context")
	}
	genesis, err := trust.DiscoveryGenesis()
	if err != nil {
		return nil, err
	}
	client, tenancy, err := foundationHomeClient(factory)
	if err != nil {
		return nil, err
	}
	snapshot, err := discoverCurrentFoundationSnapshotForOperation(ctx, originalCtx, client, tenancy, genesis)
	if err == nil {
		snapshot.resolver.Footprint.(*SignedFootprint).factory = factory
	}
	return snapshot, err
}

func discoverCurrentFoundationSnapshot(ctx context.Context, client foundationDiscoveryObjects, tenancy string, genesis trust.Keyring) (*CurrentFoundationSnapshot, error) {
	return discoverCurrentFoundationSnapshotForOperation(ctx, ctx, client, tenancy, genesis)
}

func discoverCurrentFoundationSnapshotForOperation(ctx, originalCtx context.Context, client foundationDiscoveryObjects, tenancy string, genesis trust.Keyring) (*CurrentFoundationSnapshot, error) {
	if ctx == nil || originalCtx == nil || ctx.Err() != nil || originalCtx.Err() != nil || client == nil {
		return nil, errors.New("current foundation requires authenticated discovery and a live original context")
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(originalCtx, cancel)
	defer func() { stop(); cancel() }()
	if deadline, ok := originalCtx.Deadline(); ok {
		var cancelDeadline context.CancelFunc
		ctx, cancelDeadline = context.WithDeadline(ctx, deadline)
		defer cancelDeadline()
	}
	directory, err := os.UserConfigDir()
	if err != nil {
		return nil, err
	}
	resolver, documents, err := resolveCurrentFoundation(ctx, client, tenancy, genesis, nil)
	if err != nil {
		return nil, err
	}
	source := resolver.Footprint.(*SignedFootprint)
	chain, err := trust.DecodeRootChain(documents.RootChainWire)
	if err != nil {
		return nil, err
	}
	roots, err := trust.VerifyRootChain(genesis, foundationChainIdentity(source.home.DeploymentID), chain)
	if err != nil {
		return nil, err
	}
	_, expires, err := source.verifyGrant(documents.GrantWire)
	if err != nil {
		return nil, err
	}
	envelope, err := trust.DecodeEnvelope(documents.AnchorWire)
	if err != nil {
		return nil, err
	}
	anchorDigest := sha256.Sum256(envelope.Payload)
	snapshot := &CurrentFoundationSnapshot{
		resolver: resolver, documents: documents.clone(), genesis: cloneFoundationRoots(genesis),
		roots: cloneFoundationRoots(roots.Current), anchor: source.bootstrapAnchor, head: roots.Head,
		expires: expires, ctx: originalCtx, floorDirectory: directory,
		floor: foundationFloor{Version: 1, TenancyID: tenancy, InstallationID: source.home.InstallationID,
			DeploymentID: source.home.DeploymentID, ClusterID: source.home.ClusterID,
			ChainWire: bytes.Clone(documents.RootChainWire), Generation: source.home.GrantGeneration,
			GrantSHA256: source.home.GrantSHA256, AnchorSHA256: hex.EncodeToString(anchorDigest[:])},
	}
	if err := snapshot.checkLifetime(ctx); err != nil {
		return nil, err
	}
	if err := snapshot.checkFloor(); err != nil {
		return nil, err
	}
	if err := snapshot.checkLifetime(ctx); err != nil {
		return nil, err
	}
	return snapshot, nil
}

func (s *CurrentFoundationSnapshot) Resolver() FoundationResolver              { return s.resolver }
func (s *CurrentFoundationSnapshot) Documents() RetainedFoundation             { return s.documents.clone() }
func (s *CurrentFoundationSnapshot) Roots() trust.Keyring                      { return cloneFoundationRoots(s.roots) }
func (s *CurrentFoundationSnapshot) Anchor() bootstrap.VerifiedBootstrapAnchor { return s.anchor }

// ExpiresAt is the original HOME grant expiry. A material's shorter independent
// expiry still applies when the resolver verifies that material.
func (s *CurrentFoundationSnapshot) ExpiresAt() time.Time     { return s.expires }
func (s *CurrentFoundationSnapshot) Context() context.Context { return s.ctx }

// Guard revalidates the exact fixed current documents and existing HOME floor.
// It does not replace the resolver's independent resource-binding checks.
func (s *CurrentFoundationSnapshot) Guard(ctx context.Context) error {
	if err := s.checkLifetime(ctx); err != nil {
		return err
	}
	deadline := s.expires
	if s.anchor.ExpiresAt().Before(deadline) {
		deadline = s.anchor.ExpiresAt()
	}
	if original, ok := s.ctx.Deadline(); ok && original.Before(deadline) {
		deadline = original
	}
	readCtx, cancel := context.WithDeadline(ctx, deadline)
	stop := context.AfterFunc(s.ctx, cancel)
	defer func() { stop(); cancel() }()
	if err := s.checkFloor(); err != nil {
		return err
	}
	source := s.resolver.Footprint.(*SignedFootprint)
	anchorWire, err := readDiscoveryObject(readCtx, source.client, s.documents.Namespace, foundationDiscoveryObject, bootstrap.MaxBootstrapAnchorBytes)
	if err != nil {
		return err
	}
	chainWire, err := readDiscoveryObject(readCtx, source.client, s.documents.Namespace, foundationRootChainObject, trust.MaxRootChainBytes)
	if err != nil {
		return err
	}
	grantWire, err := source.readGrant(readCtx)
	if err != nil {
		return err
	}
	chain, err := trust.DecodeRootChain(chainWire)
	if err != nil {
		return err
	}
	roots, err := trust.VerifyRootChain(s.genesis, foundationChainIdentity(s.floor.DeploymentID), chain)
	if err != nil {
		return err
	}
	anchor, err := verifyDiscoveryAnchor(anchorWire, roots.Current, s.documents.TenancyID, s.documents.Namespace)
	if err != nil {
		return err
	}
	current, err := newSignedFootprint(source.client, anchor, roots.Current, s.documents.TenancyID)
	if err != nil {
		return err
	}
	_, expires, err := current.verifyGrant(grantWire)
	if err != nil {
		return err
	}
	if roots.Head != s.head || !expires.Equal(s.expires) || !anchor.ExpiresAt().Equal(s.anchor.ExpiresAt()) ||
		!bytes.Equal(anchorWire, s.documents.AnchorWire) || !bytes.Equal(chainWire, s.documents.RootChainWire) ||
		!bytes.Equal(grantWire, s.documents.GrantWire) {
		return errors.New("current foundation differs from the original discovery attempt")
	}
	if err := s.checkFloor(); err != nil {
		return err
	}
	return s.checkLifetime(readCtx)
}

func (s *CurrentFoundationSnapshot) checkLifetime(ctx context.Context) error {
	if s == nil || s.ctx == nil || ctx == nil || !s.anchor.IsVerified() || s.expires.IsZero() {
		return errors.New("current foundation snapshot is absent")
	}
	if err := s.ctx.Err(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	now := time.Now()
	for _, lifetime := range []context.Context{s.ctx, ctx} {
		if deadline, ok := lifetime.Deadline(); ok && !now.Before(deadline) {
			return context.DeadlineExceeded
		}
	}
	if !now.Before(s.expires) || !now.Before(s.anchor.ExpiresAt()) {
		return errors.New("original foundation snapshot expired")
	}
	return nil
}

func (s *CurrentFoundationSnapshot) checkFloor() error {
	directory, err := openFoundationFloorDirectoryAt(s.floorDirectory, false)
	if err != nil {
		return fmt.Errorf("open original foundation floor: %w", err)
	}
	defer directory.Close()
	digest := sha256.Sum256([]byte(s.documents.TenancyID))
	floor, found, err := readFoundationFloor(int(directory.Fd()), hex.EncodeToString(digest[:])+".json", s.documents.TenancyID, s.genesis)
	if err != nil {
		return err
	}
	if !found || floor.InstallationID != s.floor.InstallationID || floor.DeploymentID != s.floor.DeploymentID ||
		floor.ClusterID != s.floor.ClusterID || floor.Generation != s.floor.Generation ||
		floor.GrantSHA256 != s.floor.GrantSHA256 || floor.AnchorSHA256 != s.floor.AnchorSHA256 ||
		!bytes.Equal(floor.ChainWire, s.floor.ChainWire) {
		return errors.New("original foundation floor is missing or changed")
	}
	return nil
}

func cloneFoundationRoots(roots trust.Keyring) trust.Keyring {
	cloned := make(trust.Keyring, len(roots))
	for key, public := range roots {
		cloned[key] = bytes.Clone(public)
	}
	return cloned
}
