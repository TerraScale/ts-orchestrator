package bootstrap

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"net/netip"
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
	identity                                                BootstrapAnchor
	roots                                                   trust.Keyring
	grantWire                                               []byte
	grantDigest, templateDigest, planDigest, installationID string
	generation                                              uint64
	issuedAt, expiresAt                                     time.Time
	image                                                   release.VerifiedImage
	vault, escrow                                           StartupVaultTarget
	slotIPs                                                 map[string]string
}

// StartupVaultTarget is the exact regional host-publication destination from
// the root-signed owned foundation record, distinct from founder source escrow.
type StartupVaultTarget struct {
	CompartmentOCID string `json:"compartmentOcid"`
	VaultOCID       string `json:"vaultOcid"`
	KMSKeyOCID      string `json:"kmsKeyOcid"`
}

func (verified VerifiedStartupTemplate) IsVerified() bool {
	return verified.grantDigest != "" && verified.anchor.IsVerified() && verified.image.IsVerified()
}
func (verified VerifiedStartupTemplate) startupIdentity() BootstrapAnchor {
	return cloneBootstrapAnchor(verified.identity)
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

func (verified VerifiedStartupTemplate) SlotPrivateIP(slot string) (string, error) {
	if !verified.IsVerified() || verified.slotIPs[slot] == "" {
		return "", ErrManifestInvalid
	}
	return verified.slotIPs[slot], nil
}

// ValidateProjection checks the shared manifest structure with derived receipt
// provenance and exact signed recipe inputs, before any source CAS mutation.
func (verified VerifiedStartupTemplate) ValidateProjection(manifest Manifest) error {
	if manifest.validateStructure(true) != nil {
		return ErrManifestInvalid
	}
	expected, err := verified.ManifestFor(manifest.Slot, manifest.Secrets)
	if err != nil {
		return err
	}
	expected.ControllerConfig, expected.ControllerConfigSHA256 = bytes.Clone(manifest.ControllerConfig), manifest.ControllerConfigSHA256
	want, _ := json.Marshal(expected, json.Deterministic(true))
	actual, _ := json.Marshal(manifest, json.Deterministic(true))
	if !bytes.Equal(want, actual) {
		return ErrManifestInvalid
	}
	return nil
}

func (verified VerifiedStartupTemplate) VerifyCurrent(now time.Time) error {
	if !verified.IsVerified() {
		return ErrManifestInvalid
	}
	identity := verified.anchor.Anchor()
	envelope, err := trust.DecodeEnvelope(verified.anchor.Wire())
	if err != nil {
		return err
	}
	anchor, err := VerifyBootstrapAnchor(envelope, verified.roots, BootstrapAnchorExpectation{DeploymentID: identity.DeploymentID, Environment: identity.Environment, Cell: identity.Cell}, now, BootstrapAnchorTrustPolicy())
	if err != nil {
		return err
	}
	_, err = verifyStartupTemplateForIdentity(verified.grantWire, verified.roots, anchor, verified.startupIdentity(), now)
	return err
}

// ManifestFor returns render-only structural inputs. It cannot be passed to a
// materializer or admission gate as a verified signed manifest.
func (verified VerifiedStartupTemplate) ManifestFor(slot string, refs []SecretReference) (Manifest, error) {
	if !verified.IsVerified() || !slices.Contains(verified.startupIdentity().ControllerSlots, slot) {
		return Manifest{}, ErrManifestInvalid
	}
	anchor := verified.startupIdentity()
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
	return verifyStartupTemplateForIdentity(wire, roots, anchor, anchor.Anchor(), now)
}

func verifyStartupTemplateForIdentity(wire []byte, roots trust.Keyring, anchor VerifiedBootstrapAnchor, identity BootstrapAnchor, now time.Time) (VerifiedStartupTemplate, error) {
	if !anchor.IsVerified() || identity.Validate() != nil || now.IsZero() || !now.Before(anchor.ExpiresAt()) || len(wire) == 0 || len(wire) > 1<<20 {
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
				InstallationID     string                     `json:"installationId"`
				PlanSHA256         string                     `json:"planSha256"`
				Config             jsontext.Value             `json:"config"`
				SourceVaultTarget  StartupVaultTarget         `json:"sourceVaultTarget"`
				Startup            *StartupTemplate           `json:"startup"`
				SourceRegistration *InitialSourceRegistration `json:"sourceRegistration"`
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
		var cfg struct {
			DeploymentID string `json:"deploymentId"`
			Environment  string `json:"environment"`
			ClusterID    string `json:"clusterId"`
			Cell         string `json:"cell"`
			Region       string `json:"region"`
			SubnetCIDR   string `json:"subnetCidr"`
			Slots        []struct {
				Name      string `json:"name"`
				PrivateIP string `json:"privateIp"`
			} `json:"slots"`
		}
		if json.Unmarshal(material.Config, &cfg) != nil || digestBytes(material.Config) != material.PlanSHA256 {
			return VerifiedStartupTemplate{}, ErrManifestInvalid
		}
		escrow := material.SourceVaultTarget
		if !isOCID(escrow.CompartmentOCID, "compartment") || !strings.HasPrefix(escrow.VaultOCID, "ocid1.vault.oc1.sa-saopaulo-1.") || escrow.KMSKeyOCID != home.StorageDomain.HeadKMSKeyOCID {
			return VerifiedStartupTemplate{}, ErrManifestInvalid
		}
		if cfg.DeploymentID != identity.DeploymentID || cfg.Environment != identity.Environment || cfg.ClusterID != identity.ClusterID || cfg.Cell != strings.ToLower(string(identity.Cell)) || cfg.Region != identity.OCIRegion || len(cfg.Slots) != len(identity.ControllerSlots) {
			return VerifiedStartupTemplate{}, ErrManifestInvalid
		}
		prefix, prefixErr := netip.ParsePrefix(cfg.SubnetCIDR)
		if prefixErr != nil || !prefix.Addr().Is4() || !prefix.Addr().IsPrivate() || prefix.Masked() != prefix {
			return VerifiedStartupTemplate{}, ErrManifestInvalid
		}
		slotIPs := make(map[string]string, len(cfg.Slots))
		seenIPs := make(map[string]bool, len(cfg.Slots))
		for index, slot := range cfg.Slots {
			address, addressErr := netip.ParseAddr(slot.PrivateIP)
			if slot.Name != identity.ControllerSlots[index] || addressErr != nil || !address.Is4() || !prefix.Contains(address) || address == prefix.Addr() || address == prefix.Addr().Next() || seenIPs[slot.PrivateIP] {
				return VerifiedStartupTemplate{}, ErrManifestInvalid
			}
			slotIPs[slot.Name], seenIPs[slot.PrivateIP] = slot.PrivateIP, true
		}
		template := material.Startup.Clone()
		if identity.InitialSourceRegistration != nil {
			registration := material.SourceRegistration
			want, _ := json.Marshal(identity.InitialSourceRegistration, json.Deterministic(true))
			actual, _ := json.Marshal(registration, json.Deterministic(true))
			if registration == nil || registration.Validate() != nil || !bytes.Equal(want, actual) || registration.InstallationID != material.InstallationID || registration.PlanSHA256 != material.PlanSHA256 || registration.SeedSlot != template.SeedSlot {
				return VerifiedStartupTemplate{}, ErrManifestInvalid
			}
		} else if material.SourceRegistration != nil {
			return VerifiedStartupTemplate{}, ErrManifestInvalid
		}
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
		if template.FounderResources != nil && (template.FounderResources.LaunchDeadline.After(envelope.ExpiresAt) || template.FounderResources.LaunchDeadline.After(image.ExpiresAt())) {
			return VerifiedStartupTemplate{}, ErrFounderPlanInvalid
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
		clonedRoots := make(trust.Keyring, len(roots))
		for keyID, key := range roots {
			clonedRoots[keyID] = bytes.Clone(key)
		}
		return VerifiedStartupTemplate{template: template, anchor: anchor, identity: cloneBootstrapAnchor(identity), roots: clonedRoots, grantWire: bytes.Clone(wire), grantDigest: digestBytes(wire), templateDigest: digestBytes(templateWire),
			planDigest: material.PlanSHA256, installationID: material.InstallationID, generation: grant.Generation, issuedAt: envelope.IssuedAt, expiresAt: expires, image: image, vault: vault, escrow: escrow, slotIPs: slotIPs}, nil
	}
	return VerifiedStartupTemplate{}, ErrManifestInvalid
}
