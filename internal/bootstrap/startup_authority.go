package bootstrap

import (
	"bytes"
	"encoding/json/v2"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// VerifiedStartupTemplate is a startup recipe verified in the original signed
// foundation grant. It grants no authority to install arbitrary config bytes.
type VerifiedStartupTemplate struct {
	template                                                StartupTemplate
	anchor                                                  VerifiedBootstrapAnchor
	grantWire                                               []byte
	grantDigest, templateDigest, planDigest, installationID string
	generation                                              uint64
	issuedAt, expiresAt                                     time.Time
	image                                                   release.VerifiedImage
	vault                                                   StartupVaultTarget
}

// StartupVaultTarget is the exact regional host-publication destination from
// the root-signed owned foundation record, distinct from founder source escrow.
type StartupVaultTarget struct {
	CompartmentOCID string
	VaultOCID       string
	KMSKeyOCID      string
}

func (verified VerifiedStartupTemplate) IsVerified() bool {
	return verified.grantDigest != "" && verified.anchor.IsVerified() && verified.image.IsVerified()
}
func (verified VerifiedStartupTemplate) Template() StartupTemplate       { return verified.template.Clone() }
func (verified VerifiedStartupTemplate) GrantWire() []byte               { return bytes.Clone(verified.grantWire) }
func (verified VerifiedStartupTemplate) GrantDigest() string             { return verified.grantDigest }
func (verified VerifiedStartupTemplate) TemplateDigest() string          { return verified.templateDigest }
func (verified VerifiedStartupTemplate) PlanDigest() string              { return verified.planDigest }
func (verified VerifiedStartupTemplate) InstallationID() string          { return verified.installationID }
func (verified VerifiedStartupTemplate) Generation() uint64              { return verified.generation }
func (verified VerifiedStartupTemplate) ExpiresAt() time.Time            { return verified.expiresAt }
func (verified VerifiedStartupTemplate) IssuedAt() time.Time             { return verified.issuedAt }
func (verified VerifiedStartupTemplate) Image() release.VerifiedImage    { return verified.image }
func (verified VerifiedStartupTemplate) VaultTarget() StartupVaultTarget { return verified.vault }

// ManifestFor returns render-only structural inputs. It cannot be passed to a
// materializer or admission gate as a verified signed manifest.
func (verified VerifiedStartupTemplate) ManifestFor(slot string, refs []SecretReference) (Manifest, error) {
	if !verified.IsVerified() || !slices.Contains(verified.anchor.Anchor().ControllerSlots, slot) {
		return Manifest{}, ErrManifestInvalid
	}
	anchor := verified.anchor.Anchor()
	template := verified.template.Clone()
	manifest := Manifest{SchemaVersion: ManifestSchemaVersion, DeploymentID: anchor.DeploymentID,
		Environment: anchor.Environment, ClusterID: anchor.ClusterID, Cell: anchor.Cell, OCIRegion: anchor.OCIRegion,
		IntentGeneration: anchor.InitialRegionIntentGeneration, IntentSHA256: anchor.InitialRegionIntentSHA256,
		ControllerRole: "controller", Slot: slot, SeedSlot: template.SeedSlot, ControllerSlots: slices.Clone(anchor.ControllerSlots),
		Profiles: template.Profiles, ImageOCID: template.ImageOCID, ImageArchitecture: template.ImageArchitecture,
		ReleaseImageReceiptWire: template.ReleaseImageReceiptWire, ReleaseDelegationWire: template.ReleaseDelegationWire,
		ReleaseReceiptSHA256: digestBytes(template.ReleaseImageReceiptWire), StorageDomain: anchor.StorageDomain,
		Secrets: slices.Clone(refs), ControllerFiles: template.ControllerFiles, ManagedMaterial: template.ManagedMaterial}
	for _, ref := range refs {
		if ref.validate(manifest) != nil {
			return Manifest{}, ErrManifestInvalid
		}
	}
	return manifest, nil
}

// VerifyStartupTemplate independently checks the same footprint signature and
// exact grant pin used by OCI. No per-manifest signature or new root is minted.
func VerifyStartupTemplate(wire []byte, roots trust.Keyring, anchor VerifiedBootstrapAnchor, now time.Time) (VerifiedStartupTemplate, error) {
	if !anchor.IsVerified() || now.IsZero() || !now.Before(anchor.ExpiresAt()) || len(wire) == 0 || len(wire) > 1<<20 {
		return VerifiedStartupTemplate{}, ErrManifestInvalid
	}
	home, err := anchor.FoundationScope()
	if err != nil || digestBytes(wire) != home.GrantSHA256 {
		return VerifiedStartupTemplate{}, ErrManifestInvalid
	}
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil {
		return VerifiedStartupTemplate{}, err
	}
	identity := anchor.Anchor()
	payload, err := trust.VerifyCurrent(envelope, trust.Scope{Domain: "terrascale.foundation.scope", DeploymentID: home.DeploymentID,
		Cell: "GRU", Environment: identity.Environment, Role: "foundation", Slot: home.ClusterID}, roots, now, BootstrapAnchorTrustPolicy())
	if err != nil || envelope.ExpiresAt.After(anchor.ExpiresAt()) {
		return VerifiedStartupTemplate{}, ErrManifestInvalid
	}
	var grant struct {
		InstallationID string `json:"installationId"`
		SchemaVersion  int    `json:"schemaVersion"`
		Generation     uint64 `json:"generation"`
		TenancyID      string `json:"tenancyId"`
		Regions        []struct {
			Generation uint64 `json:"generation"`
			Plan       struct {
				Cell        string            `json:"cell"`
				Region      string            `json:"region"`
				ResourceIDs map[string]string `json:"resource_ids"`
			} `json:"plan"`
			BootstrapMaterial *struct {
				InstallationID string `json:"installationId"`
				PlanSHA256     string `json:"planSha256"`
				Config         struct {
					DeploymentID string `json:"deploymentId"`
					Environment  string `json:"environment"`
					ClusterID    string `json:"clusterId"`
					Cell         string `json:"cell"`
					Region       string `json:"region"`
					Slots        []struct {
						Name string `json:"name"`
					} `json:"slots"`
				} `json:"config"`
				Startup *StartupTemplate `json:"startup"`
			} `json:"bootstrapMaterial"`
		} `json:"regions"`
	}
	if json.Unmarshal(payload, &grant) != nil || grant.SchemaVersion != 1 || grant.Generation != home.GrantGeneration || grant.InstallationID != home.InstallationID || grant.TenancyID != home.TenancyID {
		return VerifiedStartupTemplate{}, ErrManifestInvalid
	}
	for _, region := range grant.Regions {
		if region.Plan.Cell != string(identity.Cell) {
			continue
		}
		material := region.BootstrapMaterial
		if material == nil || material.Startup == nil || material.Startup.Validate() != nil || material.InstallationID != home.InstallationID ||
			!sha256RE.MatchString(material.PlanSHA256) || region.Generation != grant.Generation || region.Plan.Region != identity.OCIRegion {
			return VerifiedStartupTemplate{}, ErrManifestInvalid
		}
		cfg := material.Config
		if cfg.DeploymentID != identity.DeploymentID || cfg.Environment != identity.Environment || cfg.ClusterID != identity.ClusterID || cfg.Cell != strings.ToLower(string(identity.Cell)) || cfg.Region != identity.OCIRegion || len(cfg.Slots) != len(identity.ControllerSlots) {
			return VerifiedStartupTemplate{}, ErrManifestInvalid
		}
		for index, slot := range cfg.Slots {
			if slot.Name != identity.ControllerSlots[index] {
				return VerifiedStartupTemplate{}, ErrManifestInvalid
			}
		}
		template := material.Startup.Clone()
		if len(template.Profiles) != len(identity.ControllerSlots) || !bytes.Equal(template.ControllerFiles[0].Bytes, identity.InitialRegionIntentWire) || template.ControllerFiles[0].SHA256 != identity.InitialRegionIntentSHA256 {
			return VerifiedStartupTemplate{}, ErrManifestInvalid
		}
		for _, slot := range identity.ControllerSlots {
			if !slices.ContainsFunc(template.Profiles, func(profile LaunchProfile) bool { return profile.Slot == slot }) {
				return VerifiedStartupTemplate{}, ErrManifestInvalid
			}
		}
		image, imageErr := release.VerifyImageCurrent(template.ReleaseImageReceiptWire, template.ReleaseDelegationWire, roots,
			release.ImageExpectation{Environment: identity.Environment, LogicalRegion: string(identity.Cell), OCIImageOCID: template.ImageOCID, Architecture: strings.TrimPrefix(template.ImageArchitecture, "linux-")}, now)
		if imageErr != nil {
			return VerifiedStartupTemplate{}, fmt.Errorf("verify startup image: %w", imageErr)
		}
		templateWire, err := json.Marshal(template, json.Deterministic(true))
		if err != nil {
			return VerifiedStartupTemplate{}, err
		}
		vault := StartupVaultTarget{CompartmentOCID: region.Plan.ResourceIDs["control_compartment"], VaultOCID: region.Plan.ResourceIDs["vault"], KMSKeyOCID: region.Plan.ResourceIDs["key"]}
		if !isOCID(vault.CompartmentOCID, "compartment") || !strings.HasPrefix(vault.VaultOCID, "ocid1.vault.oc1."+identity.OCIRegion+".") || !strings.HasPrefix(vault.KMSKeyOCID, "ocid1.key.oc1."+identity.OCIRegion+".") {
			return VerifiedStartupTemplate{}, ErrManifestInvalid
		}
		expires := envelope.ExpiresAt
		if image.ExpiresAt().Before(expires) {
			expires = image.ExpiresAt()
		}
		return VerifiedStartupTemplate{template: template, anchor: anchor, grantWire: bytes.Clone(wire), grantDigest: digestBytes(wire), templateDigest: digestBytes(templateWire),
			planDigest: material.PlanSHA256, installationID: material.InstallationID, generation: grant.Generation, issuedAt: envelope.IssuedAt, expiresAt: expires, image: image, vault: vault}, nil
	}
	return VerifiedStartupTemplate{}, ErrManifestInvalid
}
