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
}

func (s NetBirdBrokerSource) Source() bootstrap.VerifiedRegionalSource   { return s.source }
func (s NetBirdBrokerSource) Startup() bootstrap.DerivedStartupAuthority { return s.startup }
func (s NetBirdBrokerSource) Resolver() region.FoundationResolver        { return s.resolver }
func (s NetBirdBrokerSource) Guard(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || s.snapshot == nil || !s.source.IsVerified() || !s.startup.IsVerified() {
		return ErrDelivery
	}
	if err := s.snapshot.Guard(ctx); err != nil {
		return ErrDelivery
	}
	if err := s.source.VerifyCurrent(ctx, time.Now().UTC()); err != nil {
		return ErrDelivery
	}
	if err := s.startup.VerifyCurrent(ctx, time.Now().UTC()); err != nil {
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

// LoadNetBirdBrokerSource uses fixed authenticated HOME discovery and one signed
// regional slot. An empty slot selects the source's original seed slot.
func LoadNetBirdBrokerSource(ctx context.Context, factory *ociclient.Factory, cell, slot string) (NetBirdBrokerSource, error) {
	var result NetBirdBrokerSource
	if factory == nil || ctx == nil || ctx.Err() != nil || cell != strings.ToUpper(cell) {
		return result, ErrDelivery
	}
	snapshot, err := region.DiscoverCurrentFoundationSnapshot(ctx, factory)
	if err != nil {
		return result, ErrDelivery
	}
	result.snapshot = snapshot
	result.resolver = snapshot.Resolver()
	documents := snapshot.Documents()
	anchor := snapshot.Anchor()
	home, err := anchor.FoundationScope()
	if err != nil || home.TenancyID != documents.TenancyID || home.StorageDomain.Namespace != documents.Namespace {
		return result, ErrDelivery
	}
	material, err := result.resolver.BootstrapMaterial(ctx, cell)
	if err != nil || !bytes.Equal(material.FoundationGrantWire(), documents.GrantWire) {
		return result, ErrDelivery
	}
	template, err := bootstrap.VerifyBoundRegionalStartupTemplate(ctx, factory, documents.GrantWire, snapshot.Roots(), anchor, oci.Region(cell), time.Now().UTC())
	if err != nil || template.Template().ControllerConfigDerivation != bootstrap.ControllerConfigDerivationV2 {
		return result, ErrDelivery
	}
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
	if slot == "" {
		slot = template.Template().SeedSlot
	}
	result.startup, err = bootstrap.LoadDerivedStartupAuthority(ctx, template, &objects, slot, time.Now().UTC())
	if err != nil || !bytes.Equal(result.source.MaterialRecord(), result.startup.MaterialRecord()) ||
		json.Unmarshal(result.source.MaterialRecord(), &result.record, json.RejectUnknownMembers(true)) != nil {
		return NetBirdBrokerSource{}, ErrDelivery
	}
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

// ForStartupSlot authenticates another original slot under this same frozen
// snapshot, template and source. The slot string conveys no authority.
func (s NetBirdBrokerSource) ForStartupSlot(ctx context.Context, slot string) (NetBirdBrokerSource, error) {
	if s.Guard(ctx) != nil || s.objects == nil {
		return NetBirdBrokerSource{}, ErrDelivery
	}
	startup, err := bootstrap.LoadDerivedStartupAuthority(ctx, s.source.Template(), s.objects, slot, time.Now().UTC())
	if err != nil || startup.TemplateDigest() != s.startup.TemplateDigest() || startup.AnchorDigest() != s.startup.AnchorDigest() ||
		startup.SourceSHA256() != s.startup.SourceSHA256() || startup.MaterialSHA256() != s.startup.MaterialSHA256() ||
		!bytes.Equal(startup.MaterialRecord(), s.source.MaterialRecord()) || s.Guard(ctx) != nil {
		return NetBirdBrokerSource{}, ErrDelivery
	}
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
