package region

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// RetainedFoundation carries public signed discovery documents. Its locators
// are untrusted until VerifyRetainedFoundation binds them to the signed scope.
type RetainedFoundation struct {
	TenancyID     string `json:"tenancyId"`
	Namespace     string `json:"namespace"`
	RootChainWire []byte `json:"rootChainWire"`
	AnchorWire    []byte `json:"anchorWire"`
	GrantWire     []byte `json:"grantWire"`
}

func (r RetainedFoundation) clone() RetainedFoundation {
	r.RootChainWire = bytes.Clone(r.RootChainWire)
	r.AnchorWire = bytes.Clone(r.AnchorWire)
	r.GrantWire = bytes.Clone(r.GrantWire)
	return r
}

// ExportCurrentFoundation authenticates read-only OCI discovery and durably
// adopts its current lineage before returning exact public document bytes.
func ExportCurrentFoundation(ctx context.Context, factory *ociclient.Factory) (RetainedFoundation, error) {
	genesis, err := trust.DiscoveryGenesis()
	if err != nil {
		return RetainedFoundation{}, err
	}
	client, tenancy, err := foundationHomeClient(factory)
	if err != nil {
		return RetainedFoundation{}, err
	}
	_, snapshot, err := resolveCurrentFoundation(ctx, client, tenancy, genesis, nil)
	return snapshot, err
}

// VerifyRetainedFoundation verifies current signatures and the same durable
// per-tenancy lineage floors as online discovery. It constructs no OCI client;
// the returned resolver exposes signed scope/material only and has no store.
func VerifyRetainedFoundation(ctx context.Context, snapshot RetainedFoundation) (FoundationResolver, error) {
	genesis, err := trust.DiscoveryGenesis()
	if err != nil {
		return FoundationResolver{}, err
	}
	return verifyRetainedFoundation(ctx, snapshot, genesis)
}

func verifyRetainedFoundation(ctx context.Context, snapshot RetainedFoundation, genesis trust.Keyring) (FoundationResolver, error) {
	if !strings.HasPrefix(snapshot.TenancyID, "ocid1.tenancy.") || len(snapshot.TenancyID) > 512 ||
		snapshot.Namespace == "" || len(snapshot.Namespace) > 255 || strings.ContainsAny(snapshot.Namespace, "/\\\r\n") ||
		len(snapshot.RootChainWire) == 0 || len(snapshot.RootChainWire) > trust.MaxRootChainBytes ||
		len(snapshot.AnchorWire) == 0 || len(snapshot.AnchorWire) > bootstrap.MaxBootstrapAnchorBytes ||
		len(snapshot.GrantWire) == 0 || len(snapshot.GrantWire) > foundationRecordLimit {
		return FoundationResolver{}, errors.New("retained foundation has invalid locators or document bounds")
	}
	resolver, _, err := resolveCurrentFoundation(ctx, nil, snapshot.TenancyID, genesis, &snapshot)
	return resolver, err
}

func readCurrentFoundation(ctx context.Context, client foundationDiscoveryObjects, tenancy string) (RetainedFoundation, error) {
	namespace, err := discoveryNamespace(ctx, client, tenancy)
	if err != nil {
		return RetainedFoundation{}, err
	}
	anchor, err := readDiscoveryObject(ctx, client, namespace, foundationDiscoveryObject, bootstrap.MaxBootstrapAnchorBytes)
	if err != nil {
		return RetainedFoundation{}, fmt.Errorf("%w: read current home anchor: %w", ErrFoundationDiscoveryPending, err)
	}
	chain, err := readDiscoveryObject(ctx, client, namespace, foundationRootChainObject, trust.MaxRootChainBytes)
	if err != nil {
		return RetainedFoundation{}, fmt.Errorf("%w: read current root chain: %w", ErrFoundationDiscoveryPending, err)
	}
	return RetainedFoundation{TenancyID: tenancy, Namespace: namespace, RootChainWire: chain, AnchorWire: anchor}, nil
}

// VerifiedBootstrapIntent is read-only evidence of the signed startup recipe.
// Logical resources remain unresolved; this type grants no credential creation,
// OCI resource binding, source installation or founder authority.
type VerifiedBootstrapIntent struct {
	intent     BootstrapMaterialIntent
	generation uint64
	expires    time.Time
	image      release.VerifiedImage
	grantWire  []byte
}

func (v VerifiedBootstrapIntent) IsVerified() bool            { return v.generation > 0 }
func (v VerifiedBootstrapIntent) Generation() uint64          { return v.generation }
func (v VerifiedBootstrapIntent) ExpiresAt() time.Time        { return v.expires }
func (v VerifiedBootstrapIntent) FoundationGrantWire() []byte { return bytes.Clone(v.grantWire) }
func (v VerifiedBootstrapIntent) Config() bootstrapmaterial.Config {
	config := v.intent.Config
	config.Slots = slices.Clone(config.Slots)
	return config
}
func (v VerifiedBootstrapIntent) Startup() (BootstrapStartupIntent, error) {
	if !v.IsVerified() || !time.Now().Before(v.expires) || v.intent.Startup == nil || !v.image.IsVerified() {
		return BootstrapStartupIntent{}, errors.New("signed bootstrap intent is absent or expired")
	}
	return v.intent.Startup.Clone(), nil
}
func (v VerifiedBootstrapIntent) Image() (release.VerifiedImage, error) {
	if _, err := v.Startup(); err != nil {
		return release.VerifiedImage{}, err
	}
	return v.image, nil
}

// BootstrapIntent verifies public release evidence without resolving logical
// resources or returning the production material/installation authority type.
func (r FoundationResolver) BootstrapIntent(ctx context.Context, cell string) (VerifiedBootstrapIntent, error) {
	reader, ok := r.Footprint.(*SignedFootprint)
	if !ok {
		return VerifiedBootstrapIntent{}, errors.New("bootstrap intent requires authenticated signed footprint")
	}
	intent, _, err := reader.bootstrapIntent(ctx, cell)
	return intent, err
}
