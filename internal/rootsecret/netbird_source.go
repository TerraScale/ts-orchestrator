package rootsecret

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"net"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/naming"
	"github.com/TerraScale/ts-orchestrator/internal/netbird"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/region"
)

// NetBirdBrokerSource holds independently authenticated public startup inputs.
// Neither Vault content nor a controller's local installation supplies trust.
type NetBirdBrokerSource struct {
	source    bootstrap.VerifiedRegionalSource
	startup   bootstrap.DerivedStartupAuthority
	resolver  region.FoundationResolver
	snapshot  *region.CurrentFoundationSnapshot
	objects   bootstrap.ObjectStorageClient
	record    bootstrapmaterial.Record
	endpoints []NetBirdBrokerEndpoint
	expires   time.Time
}

func (s NetBirdBrokerSource) Source() bootstrap.VerifiedRegionalSource   { return s.source }
func (s NetBirdBrokerSource) Startup() bootstrap.DerivedStartupAuthority { return s.startup }
func (s NetBirdBrokerSource) Resolver() region.FoundationResolver        { return s.resolver }

// ExpiresAt is the shortest retained original and authenticated source lifetime.
func (s NetBirdBrokerSource) ExpiresAt() time.Time {
	if s.snapshot == nil {
		return time.Time{}
	}
	deadline := minDeadline(s.expires, minDeadline(s.snapshot.ExpiresAt(), minDeadline(s.snapshot.Anchor().ExpiresAt(), minDeadline(s.source.ExpiresAt(), s.startup.ExpiresAt()))))
	if until, ok := s.snapshot.Context().Deadline(); ok {
		deadline = minDeadline(deadline, until)
	}
	return deadline
}

func netBirdReadContext(ctx, original context.Context, deadline time.Time) (context.Context, context.CancelFunc) {
	if until, ok := original.Deadline(); ok {
		deadline = minDeadline(deadline, until)
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	stop := context.AfterFunc(original, cancel)
	if original.Err() != nil {
		cancel()
	}
	return ctx, func() { stop(); cancel() }
}

func (s NetBirdBrokerSource) readContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return netBirdReadContext(ctx, s.snapshot.Context(), minDeadline(s.ExpiresAt(), time.Now().Add(30*time.Second)))
}

func (s NetBirdBrokerSource) Guard(ctx context.Context) error {
	if ctx == nil || s.snapshot == nil {
		return ErrDelivery
	}
	ctx, cancel := s.readContext(ctx)
	defer cancel()
	if s.guardPublicSource(ctx) != nil {
		return ErrDelivery
	}
	for index, slot := range s.source.Manifest().ControllerSlots {
		ip, err := netbird.BrokerRoute(ctx, netBirdControllerPeerName(string(s.source.Manifest().Cell), slot))
		if err != nil || index >= len(s.endpoints) || s.endpoints[index] != (NetBirdBrokerEndpoint{Address: "tls://" + net.JoinHostPort(ip.String(), "4222"), ServerName: slot}) {
			return ErrDelivery
		}
	}
	return ctx.Err()
}

// guardPublicSource authenticates the retained source without mesh locators.
func (s NetBirdBrokerSource) guardPublicSource(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || s.snapshot == nil || !s.source.IsVerified() || !s.startup.IsVerified() {
		return ErrDelivery
	}
	ctx, cancel := s.readContext(ctx)
	defer cancel()
	if err := s.snapshot.Guard(ctx); err != nil {
		return ErrDelivery
	}
	if err := s.source.VerifyCurrent(ctx, time.Now().UTC()); err != nil {
		return ErrDelivery
	}
	if err := s.startup.VerifyCurrent(ctx, time.Now().UTC()); err != nil {
		return ErrDelivery
	}
	return ctx.Err()
}

// LoadNetBirdBrokerSource uses fixed authenticated HOME discovery and one signed
// regional slot. An empty slot selects the source's original seed slot.
func LoadNetBirdBrokerSource(ctx context.Context, factory *ociclient.Factory, cell, slot string) (NetBirdBrokerSource, error) {
	if ctx == nil {
		return NetBirdBrokerSource{}, ErrDelivery
	}
	readCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return LoadNetBirdBrokerSourceForOperation(readCtx, ctx, factory, cell, slot)
}

// LoadNetBirdBrokerSourceForOperation retains the original lifecycle while all
// discovery reads use the caller's independently bounded operation context.
func LoadNetBirdBrokerSourceForOperation(ctx, originalCtx context.Context, factory *ociclient.Factory, cell, slot string) (NetBirdBrokerSource, error) {
	if ctx == nil || originalCtx == nil {
		return NetBirdBrokerSource{}, ErrDelivery
	}
	ctx, cancelOperation := netBirdReadContext(ctx, originalCtx, time.Now().Add(30*time.Second))
	defer cancelOperation()
	result, err := loadNetBirdPublicSourceForOperation(ctx, originalCtx, factory, cell, slot)
	if err != nil {
		return NetBirdBrokerSource{}, err
	}
	ctx, cancel := result.readContext(ctx)
	defer cancel()
	for _, controller := range result.source.Manifest().ControllerSlots {
		ip, err := netbird.BrokerRoute(ctx, netBirdControllerPeerName(cell, controller))
		if err != nil {
			return NetBirdBrokerSource{}, ErrDelivery
		}
		result.endpoints = append(result.endpoints, NetBirdBrokerEndpoint{Address: "tls://" + net.JoinHostPort(ip.String(), "4222"), ServerName: controller})
	}
	if len(result.endpoints) == 0 || result.Guard(ctx) != nil {
		return NetBirdBrokerSource{}, ErrDelivery
	}
	return result, nil
}

// The early journal source reuses these authenticated inputs before the mesh
// exists. Only the later broker source may resolve overlay addresses.
func loadNetBirdPublicSourceForOperation(ctx, originalCtx context.Context, factory *ociclient.Factory, cell, slot string) (NetBirdBrokerSource, error) {
	var result NetBirdBrokerSource
	if factory == nil || ctx == nil || originalCtx == nil || ctx.Err() != nil || originalCtx.Err() != nil || cell != strings.ToUpper(cell) {
		return result, ErrDelivery
	}
	ctx, cancelOriginal := netBirdReadContext(ctx, originalCtx, time.Now().Add(30*time.Second))
	defer cancelOriginal()
	snapshot, err := region.DiscoverCurrentFoundationSnapshotForOperation(ctx, originalCtx, factory)
	if err != nil {
		return result, ErrDelivery
	}
	result.snapshot = snapshot
	result.resolver = snapshot.Resolver()
	ctx, cancelSnapshot := context.WithDeadline(ctx, minDeadline(snapshot.ExpiresAt(), snapshot.Anchor().ExpiresAt()))
	defer cancelSnapshot()
	documents := snapshot.Documents()
	anchor := snapshot.Anchor()
	home, err := anchor.FoundationScope()
	if err != nil || home.TenancyID != documents.TenancyID || home.StorageDomain.Namespace != documents.Namespace {
		return result, ErrDelivery
	}
	material, err := result.resolver.BootstrapMaterialForOperation(ctx, originalCtx, cell)
	if err != nil || !bytes.Equal(material.FoundationGrantWire(), documents.GrantWire) {
		return result, ErrDelivery
	}
	ctx, cancelMaterial := context.WithDeadline(ctx, material.ExpiresAt())
	defer cancelMaterial()
	template, err := bootstrap.VerifyBoundRegionalStartupTemplateForOperation(ctx, originalCtx, factory, documents.GrantWire, snapshot.Roots(), anchor, oci.Region(cell), time.Now().UTC())
	if err != nil || template.Template().ControllerConfigDerivation != bootstrap.ControllerConfigDerivationV2 {
		return result, ErrDelivery
	}
	ctx, cancelTemplate := context.WithDeadline(ctx, template.ExpiresAt())
	defer cancelTemplate()
	result.expires = minDeadline(material.ExpiresAt(), template.ExpiresAt())
	homeFactory, err := factory.ForRegion(home.OCIRegion)
	if err != nil {
		return result, ErrDelivery
	}
	objects, err := homeFactory.ObjectStorage()
	if err != nil {
		return result, ErrDelivery
	}
	result.objects = &objects
	result.source, err = bootstrap.LoadRegionalSource(ctx, template, result.objects, time.Now().UTC())
	if err != nil {
		return result, ErrDelivery
	}
	ctx, cancelSource := context.WithDeadline(ctx, result.source.ExpiresAt())
	defer cancelSource()
	if slot == "" {
		slot = template.Template().SeedSlot
	}
	result.startup, err = bootstrap.LoadDerivedStartupAuthority(ctx, template, &objects, slot, time.Now().UTC())
	if err != nil || !bytes.Equal(result.source.MaterialRecord(), result.startup.MaterialRecord()) ||
		json.Unmarshal(result.source.MaterialRecord(), &result.record, json.RejectUnknownMembers(true)) != nil {
		return NetBirdBrokerSource{}, ErrDelivery
	}
	ctx, cancelStartup := context.WithDeadline(ctx, result.startup.ExpiresAt())
	defer cancelStartup()
	if wire := result.startup.LinkMaterialRecord(); len(wire) != 0 {
		var link struct {
			ExpiresAt time.Time `json:"expiresAt"`
		}
		if json.Unmarshal(wire, &link) != nil || link.ExpiresAt.IsZero() {
			return NetBirdBrokerSource{}, ErrDelivery
		}
		result.expires = minDeadline(result.expires, link.ExpiresAt)
	}
	ctx, cancelMaterialLifetime := context.WithDeadline(ctx, result.ExpiresAt())
	defer cancelMaterialLifetime()
	if result.guardPublicSource(ctx) != nil {
		return NetBirdBrokerSource{}, ErrDelivery
	}
	return result, nil
}

// ForStartupSlot authenticates another original slot under this same frozen
// snapshot, template and source. The slot string conveys no authority.
func (s NetBirdBrokerSource) ForStartupSlot(ctx context.Context, slot string) (NetBirdBrokerSource, error) {
	if ctx == nil || s.snapshot == nil || s.objects == nil {
		return NetBirdBrokerSource{}, ErrDelivery
	}
	ctx, cancel := s.readContext(ctx)
	defer cancel()
	if s.Guard(ctx) != nil {
		return NetBirdBrokerSource{}, ErrDelivery
	}
	startup, err := bootstrap.LoadDerivedStartupAuthority(ctx, s.source.Template(), s.objects, slot, time.Now().UTC())
	if err != nil {
		return NetBirdBrokerSource{}, ErrDelivery
	}
	ctx, cancelStartup := context.WithDeadline(ctx, startup.ExpiresAt())
	defer cancelStartup()
	if startup.TemplateDigest() != s.startup.TemplateDigest() || startup.AnchorDigest() != s.startup.AnchorDigest() ||
		startup.SourceSHA256() != s.startup.SourceSHA256() || startup.MaterialSHA256() != s.startup.MaterialSHA256() ||
		!bytes.Equal(startup.MaterialRecord(), s.source.MaterialRecord()) || s.Guard(ctx) != nil {
		return NetBirdBrokerSource{}, ErrDelivery
	}
	s.expires = minDeadline(s.ExpiresAt(), startup.ExpiresAt())
	s.startup = startup
	if s.Guard(ctx) != nil {
		return NetBirdBrokerSource{}, ErrDelivery
	}
	return s, nil
}

func netBirdDigest(wire []byte) string { sum := sha256.Sum256(wire); return hex.EncodeToString(sum[:]) }

func netBirdControllerPeerName(cell, slot string) string {
	if naming.IsNode(slot, strings.ToLower(cell)) {
		return slot
	}
	return strings.ToLower(cell) + "-1-" + slot
}
