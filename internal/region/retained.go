package region

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
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
	return verifyRetainedFoundationWith(ctx, snapshot, genesis, nil)
}

func verifyRetainedFoundationWith(ctx context.Context, snapshot RetainedFoundation, genesis trust.Keyring, memo *foundationVerificationMemo) (FoundationResolver, error) {
	if !strings.HasPrefix(snapshot.TenancyID, "ocid1.tenancy.") || len(snapshot.TenancyID) > 512 ||
		snapshot.Namespace == "" || len(snapshot.Namespace) > 255 || strings.ContainsAny(snapshot.Namespace, "/\\\r\n") ||
		len(snapshot.RootChainWire) == 0 || len(snapshot.RootChainWire) > trust.MaxRootChainBytes ||
		len(snapshot.AnchorWire) == 0 || len(snapshot.AnchorWire) > bootstrap.MaxBootstrapAnchorBytes ||
		len(snapshot.GrantWire) == 0 || len(snapshot.GrantWire) > foundationGrantLimit {
		return FoundationResolver{}, errors.New("retained foundation has invalid locators or document bounds")
	}
	resolver, _, err := resolveCurrentFoundationWith(ctx, nil, snapshot.TenancyID, genesis, &snapshot, memo)
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
