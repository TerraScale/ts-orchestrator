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
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// VerifyHomeStartupTemplate derives the home identity from the exact foundation
// grant pinned by the real local anchor. It does not manufacture a home anchor.
func VerifyHomeStartupTemplate(wire []byte, roots trust.Keyring, anchor VerifiedBootstrapAnchor, now time.Time) (VerifiedStartupTemplate, error) {
	if !anchor.IsVerified() || now.IsZero() || len(wire) == 0 || len(wire) > 1<<20 {
		return VerifiedStartupTemplate{}, ErrManifestInvalid
	}
	local := anchor.Anchor()
	anchorEnvelope, err := trust.DecodeEnvelope(anchor.Wire())
	if err != nil {
		return VerifiedStartupTemplate{}, err
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
	if json.Unmarshal(payload, &grant) != nil || grant.SchemaVersion != 1 || grant.InstallationID != home.InstallationID || grant.Generation != home.GrantGeneration || grant.TenancyID != home.TenancyID {
		return VerifiedStartupTemplate{}, ErrManifestInvalid
	}
	var identity BootstrapAnchor
	for _, region := range grant.Regions {
		if region.Plan.Cell != string(oci.RegionGRU) {
			continue
		}
		material := region.BootstrapMaterial
		if identity.Cell != "" || region.Generation != grant.Generation || region.Plan.Region != home.OCIRegion || material == nil || material.InstallationID != home.InstallationID || material.Startup == nil || material.Startup.Validate() != nil || material.SourceRegistration == nil {
			return VerifiedStartupTemplate{}, ErrManifestInvalid
		}
		registration := material.SourceRegistration.Clone()
		if registration.Validate() != nil || registration.InstallationID != home.InstallationID || registration.DeploymentID != home.DeploymentID || registration.Environment != local.Environment || registration.ClusterID != home.ClusterID || registration.Cell != oci.RegionGRU || registration.Generation != home.GrantGeneration || registration.PlanSHA256 != material.PlanSHA256 || registration.StorageDomain != home.StorageDomain || registration.SeedSlot != material.Startup.SeedSlot {
			return VerifiedStartupTemplate{}, ErrManifestInvalid
		}
		intentWire := material.Startup.ControllerFiles[0].Bytes
		intent, err := canonicalRegionIntent(intentWire)
		if err != nil {
			return VerifiedStartupTemplate{}, err
		}
		identity = BootstrapAnchor{SchemaVersion: BootstrapAnchorSchemaVersion, DeploymentID: home.DeploymentID,
			Environment: local.Environment, ClusterID: home.ClusterID, Cell: oci.RegionGRU, OCIRegion: home.OCIRegion,
			StorageDomain: home.StorageDomain, FoundationScope: new(home), InitialSourceRegistration: new(registration),
			ControllerSlots: registration.ControllerSlots, InitialRegionIntentGeneration: intent.Generation,
			InitialRegionIntentSHA256: digestBytes(intentWire), InitialRegionIntentWire: bytes.Clone(intentWire)}
	}
	if identity.Validate() != nil {
		return VerifiedStartupTemplate{}, ErrManifestInvalid
	}
	return verifyStartupTemplateForIdentity(wire, roots, anchor, identity, now)
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
