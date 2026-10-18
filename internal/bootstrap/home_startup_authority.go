package bootstrap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json/v2"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// VerifyRegionalStartupTemplate derives one regional identity from the exact
// foundation grant pinned by the real local anchor. It manufactures no anchor.
func VerifyRegionalStartupTemplate(wire []byte, roots trust.Keyring, anchor VerifiedBootstrapAnchor, requestedCell oci.Region, now time.Time) (VerifiedStartupTemplate, error) {
	return verifyRegionalStartupTemplateBindings(wire, roots, anchor, requestedCell, nil, now)
}

// VerifyBoundRegionalStartupTemplate independently resolves the selected cell's
// schema-2 resources from the same original protected foundation grant.
func VerifyBoundRegionalStartupTemplate(ctx context.Context, factory *ociclient.Factory, wire []byte, roots trust.Keyring, anchor VerifiedBootstrapAnchor, requestedCell oci.Region, now time.Time) (VerifiedStartupTemplate, error) {
	bindings, err := verifyStartupBindings(ctx, factory, wire, roots, anchor, string(requestedCell), now)
	if err != nil {
		return VerifiedStartupTemplate{}, err
	}
	verified, err := verifyRegionalStartupTemplateBindings(wire, roots, anchor, requestedCell, bindings, now)
	if err != nil {
		return VerifiedStartupTemplate{}, err
	}
	if err := ctx.Err(); err != nil {
		return VerifiedStartupTemplate{}, err
	}
	return verified, nil
}

func verifyRegionalStartupTemplateBindings(wire []byte, roots trust.Keyring, anchor VerifiedBootstrapAnchor, requestedCell oci.Region, bindings *startupBindings, now time.Time) (VerifiedStartupTemplate, error) {
	ociRegion, regionErr := requestedCell.OCIRegion()
	if !anchor.IsVerified() || regionErr != nil || now.IsZero() || len(wire) == 0 || len(wire) > 1<<20 {
		return VerifiedStartupTemplate{}, ErrManifestInvalid
	}
	local := anchor.Anchor()
	anchorEnvelope, err := trust.DecodeEnvelope(anchor.Wire())
	if err != nil {
		return VerifiedStartupTemplate{}, err
	}
	// A same-region request must retain any baked ledger signer pin. A signed
	// registration for a new source cannot replace that existing authority.
	if requestedCell == local.Cell {
		return verifyStartupTemplateForIdentityBindings(wire, roots, anchor, local, bindings, now)
	}
	anchor, err = VerifyBootstrapAnchor(anchorEnvelope, roots, BootstrapAnchorExpectation{DeploymentID: local.DeploymentID, Environment: local.Environment, Cell: local.Cell}, now, BootstrapAnchorTrustPolicy())
	if err != nil {
		return VerifiedStartupTemplate{}, err
	}
	home, err := anchor.FoundationScope()
	if err != nil || digestBytes(wire) != home.GrantSHA256 {
		return VerifiedStartupTemplate{}, ErrManifestInvalid
	}
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil {
		return VerifiedStartupTemplate{}, err
	}
	payload, err := trust.VerifyCurrent(envelope, trust.Scope{Domain: "terrascale.foundation.scope", DeploymentID: home.DeploymentID,
		Cell: string(oci.RegionGRU), Environment: local.Environment, Role: "foundation", Slot: home.ClusterID}, roots, now, BootstrapAnchorTrustPolicy())
	if err != nil || envelope.ExpiresAt.After(anchor.ExpiresAt()) {
		return VerifiedStartupTemplate{}, ErrManifestInvalid
	}
	var grant struct {
		SchemaVersion  int    `json:"schemaVersion"`
		InstallationID string `json:"installationId"`
		Generation     uint64 `json:"generation"`
		TenancyID      string `json:"tenancyId"`
		Regions        []struct {
			Generation uint64 `json:"generation"`
			Plan       struct {
				Cell   string `json:"cell"`
				Region string `json:"region"`
			} `json:"plan"`
			BootstrapMaterial *struct {
				InstallationID     string                     `json:"installationId"`
				PlanSHA256         string                     `json:"planSha256"`
				Startup            *StartupTemplate           `json:"startup"`
				SourceRegistration *InitialSourceRegistration `json:"sourceRegistration"`
			} `json:"bootstrapMaterial"`
		} `json:"regions"`
	}
	if json.Unmarshal(payload, &grant) != nil || (grant.SchemaVersion != 1 || bindings != nil) && ((grant.SchemaVersion != 2 && grant.SchemaVersion != 3) || bindings == nil) || grant.InstallationID != home.InstallationID || grant.Generation != home.GrantGeneration || grant.TenancyID != home.TenancyID {
		return VerifiedStartupTemplate{}, ErrManifestInvalid
	}
	var identity BootstrapAnchor
	for _, region := range grant.Regions {
		if region.Plan.Cell != string(requestedCell) {
			continue
		}
		material := region.BootstrapMaterial
		if identity.Cell != "" || region.Generation != grant.Generation || region.Plan.Region != ociRegion || material == nil || material.InstallationID != home.InstallationID || material.Startup == nil || material.SourceRegistration == nil {
			return VerifiedStartupTemplate{}, ErrManifestInvalid
		}
		if bindings == nil && material.Startup.Validate() != nil || bindings != nil && material.Startup.ValidateFoundation(string(requestedCell)) != nil {
			return VerifiedStartupTemplate{}, ErrManifestInvalid
		}
		registration := material.SourceRegistration.Clone()
		if registration.Validate() != nil || registration.InstallationID != home.InstallationID || registration.Environment != local.Environment || registration.Cell != requestedCell || registration.Generation != home.GrantGeneration || registration.PlanSHA256 != material.PlanSHA256 || registration.SeedSlot != material.Startup.SeedSlot {
			return VerifiedStartupTemplate{}, ErrManifestInvalid
		}
		if requestedCell == oci.RegionGRU && (registration.DeploymentID != home.DeploymentID || registration.ClusterID != home.ClusterID || registration.StorageDomain != home.StorageDomain || ociRegion != home.OCIRegion) {
			return VerifiedStartupTemplate{}, ErrManifestInvalid
		}
		intentWire := material.Startup.ControllerFiles[0].Bytes
		intent, err := canonicalRegionIntent(intentWire)
		if err != nil {
			return VerifiedStartupTemplate{}, err
		}
		identity = BootstrapAnchor{SchemaVersion: BootstrapAnchorSchemaVersion, DeploymentID: registration.DeploymentID,
			Environment: local.Environment, ClusterID: registration.ClusterID, Cell: requestedCell, OCIRegion: ociRegion,
			StorageDomain: registration.StorageDomain, FoundationScope: new(home), InitialSourceRegistration: new(registration),
			ControllerSlots: registration.ControllerSlots, InitialRegionIntentGeneration: intent.Generation,
			InitialRegionIntentSHA256: digestBytes(intentWire), InitialRegionIntentWire: bytes.Clone(intentWire)}
	}
	if identity.Validate() != nil {
		return VerifiedStartupTemplate{}, ErrManifestInvalid
	}
	return verifyStartupTemplateForIdentityBindings(wire, roots, anchor, identity, bindings, now)
}

// VerifyHomeStartupTemplate additionally binds GRU to the baked home identity
// and storage domain in FoundationScope, without fabricating a home anchor.
func VerifyHomeStartupTemplate(wire []byte, roots trust.Keyring, anchor VerifiedBootstrapAnchor, now time.Time) (VerifiedStartupTemplate, error) {
	return VerifyRegionalStartupTemplate(wire, roots, anchor, oci.RegionGRU, now)
}

// LoadRegionalStartupAuthority reads one exact registered recipient's public
// startup proof. Source escrow and caller-selected object locators are absent.
func LoadRegionalStartupAuthority(ctx context.Context, grantWire []byte, anchor VerifiedBootstrapAnchor, roots trust.Keyring, client ObjectStorageClient, cell oci.Region, slot string, now time.Time) (DerivedStartupAuthority, error) {
	template, err := VerifyRegionalStartupTemplate(grantWire, roots, anchor, cell, now)
	if err != nil {
		return DerivedStartupAuthority{}, err
	}
	return LoadDerivedStartupAuthority(ctx, template, client, slot, now)
}

// LoadHomeStartupAuthority reads only the authenticated home's public source
// object. It neither recovers founder escrow nor needs a Vault client.
func LoadHomeStartupAuthority(ctx context.Context, grantWire []byte, anchor VerifiedBootstrapAnchor, roots trust.Keyring, client ObjectStorageClient, now time.Time) (DerivedStartupAuthority, error) {
	template, err := VerifyHomeStartupTemplate(grantWire, roots, anchor, now)
	if err != nil {
		return DerivedStartupAuthority{}, err
	}
	return LoadDerivedStartupAuthority(ctx, template, client, template.Template().SeedSlot, now)
}

// ControllerResponsePublicKey returns the public key from verified source
// inventory, never a response payload or a source-local NATS mirror. Callers
// recheck VerifyCurrent before spending and retain their reservation floors.
func (authority DerivedStartupAuthority) ControllerResponsePublicKey() (ed25519.PublicKey, error) {
	if !authority.IsVerified() {
		return nil, ErrManifestInvalid
	}
	var record struct {
		Public struct {
			ControllerResponsePublicKey string `json:"controllerResponsePublicKey"`
		} `json:"public"`
	}
	if json.Unmarshal(authority.binding.MaterialRecord, &record) != nil {
		return nil, ErrManifestInvalid
	}
	key, err := base64.StdEncoding.Strict().DecodeString(record.Public.ControllerResponsePublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize || strings.TrimSpace(record.Public.ControllerResponsePublicKey) != record.Public.ControllerResponsePublicKey {
		return nil, ErrManifestInvalid
	}
	return ed25519.PublicKey(key), nil
}
