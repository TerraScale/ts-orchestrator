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

// startupTemplateEvidence contains checked signed data and no current authority.
type startupTemplateEvidence struct {
	template                                                StartupTemplate
	identity                                                BootstrapAnchor
	roots                                                   trust.Keyring
	grantWire                                               []byte
	grantDigest, templateDigest, planDigest, installationID string
	generation                                              uint64
	issuedAt, expiresAt, authorityExpiresAt                 time.Time
	vault, escrow                                           StartupVaultTarget
	slotIPs                                                 map[string]string
}

func (proof startupTemplateEvidence) sourceDomain() StorageDomain {
	return proof.identity.FoundationScope.StorageDomain
}

func (proof startupTemplateEvidence) sourceKey() string {
	scope := digestBytes([]byte(proof.installationID + "\x00" + strings.ToLower(string(proof.identity.Cell))))
	return proof.sourceDomain().Prefix + "/bootstrap/v2/material-source/" + scope + ".json"
}

func verifyHistoricalStartupTemplate(wire []byte, roots trust.Keyring, anchor HistoricalBootstrapAnchor, instant time.Time) (startupTemplateEvidence, error) {
	return verifyHistoricalStartupTemplateForIdentity(wire, roots, anchor, anchor.Anchor(), instant)
}

func verifyHistoricalStartupTemplateForIdentity(wire []byte, roots trust.Keyring, anchor HistoricalBootstrapAnchor, identity BootstrapAnchor, instant time.Time) (startupTemplateEvidence, error) {
	if !anchor.IsVerified() {
		return startupTemplateEvidence{}, ErrManifestInvalid
	}
	envelope, err := trust.DecodeEnvelope(anchor.Wire())
	if err != nil {
		return startupTemplateEvidence{}, err
	}
	proof, err := decodeStartupTemplateEvidence(wire, roots, anchor.Anchor(), envelope.ExpiresAt, identity, nil, instant)
	if err != nil {
		return startupTemplateEvidence{}, err
	}
	if instant.Before(proof.issuedAt) {
		return startupTemplateEvidence{}, ErrManifestInvalid
	}
	template := proof.template
	image, err := release.VerifyImageHistorical(template.ReleaseImageReceiptWire, template.ReleaseDelegationWire, roots,
		release.ImageExpectation{Environment: proof.identity.Environment, LogicalRegion: string(proof.identity.Cell), OCIImageOCID: template.ImageOCID, Architecture: strings.TrimPrefix(template.ImageArchitecture, "linux-")})
	if err != nil || instant.Before(image.IssuedAt()) || !instant.Before(image.ExpiresAt()) {
		return startupTemplateEvidence{}, fmt.Errorf("%w: historical startup image interval: %v", ErrManifestInvalid, err)
	}
	receipt := image.Receipt()
	if receipt.Production == nil {
		return startupTemplateEvidence{}, ErrManifestInvalid
	}
	if _, err := release.VerifyProductionCurrent(receipt.Production.Qualification, receipt.Production.Delegation, roots,
		release.ProductionExpectation{SourceRevision: receipt.SourceRevision, ArtifactSHA256: receipt.ImageSHA256, QualificationSHA256: receipt.QualificationSHA256,
			Cell: receipt.OCIRegion, Environment: proof.identity.Environment, Runtime: release.ProductionRuntime, Architecture: receipt.Architecture, Role: "orchestrator"}, instant); err != nil {
		return startupTemplateEvidence{}, err
	}
	expires := minTimeLink(proof.expiresAt, image.ExpiresAt())
	for _, wire := range [][]byte{template.ReleaseDelegationWire, receipt.Production.Qualification, receipt.Production.Delegation} {
		if len(wire) == 0 {
			continue
		}
		envelope, err := trust.DecodeEnvelope(wire)
		if err != nil || instant.Before(envelope.IssuedAt) || !instant.Before(envelope.ExpiresAt) {
			return startupTemplateEvidence{}, ErrManifestInvalid
		}
		expires = minTimeLink(expires, envelope.ExpiresAt)
	}
	if template.FounderResources != nil && template.FounderResources.LaunchDeadline.After(expires) {
		return startupTemplateEvidence{}, ErrFounderPlanInvalid
	}
	proof.expiresAt, proof.authorityExpiresAt = expires, expires
	return proof, nil
}

func decodeStartupTemplateEvidence(wire []byte, roots trust.Keyring, anchor BootstrapAnchor, anchorExpiry time.Time, identity BootstrapAnchor, bindings *startupBindings, now time.Time) (startupTemplateEvidence, error) {
	if identity.Validate() != nil || now.IsZero() || !now.Before(anchorExpiry) || len(wire) == 0 || len(wire) > 1<<20 {
		return startupTemplateEvidence{}, ErrManifestInvalid
	}
	home := anchor.FoundationScope
	if home == nil || home.Validate() != nil || digestBytes(wire) != home.GrantSHA256 {
		return startupTemplateEvidence{}, ErrManifestInvalid
	}
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil {
		return startupTemplateEvidence{}, err
	}
	payload, err := trust.VerifyCurrent(envelope, trust.Scope{Domain: "terrascale.foundation.scope", DeploymentID: home.DeploymentID,
		Cell: "GRU", Environment: identity.Environment, Role: "foundation", Slot: home.ClusterID}, roots, now, BootstrapAnchorTrustPolicy())
	if err != nil || envelope.ExpiresAt.After(anchorExpiry) {
		return startupTemplateEvidence{}, ErrManifestInvalid
	}
	var grant struct {
		InstallationID string `json:"installationId"`
		SchemaVersion  int    `json:"schemaVersion"`
		Generation     uint64 `json:"generation"`
		TenancyID      string `json:"tenancyId"`
		Regions        []struct {
			Generation uint64 `json:"generation"`
			Plan       struct {
				Cell        string             `json:"cell"`
				Region      string             `json:"region"`
				ResourceIDs startupResourceIDs `json:"resource_ids"`
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
	if json.Unmarshal(payload, &grant) != nil || (grant.SchemaVersion != 1 || bindings != nil) && (grant.SchemaVersion != 2 || bindings == nil) || grant.Generation != home.GrantGeneration || grant.InstallationID != home.InstallationID || grant.TenancyID != home.TenancyID {
		return startupTemplateEvidence{}, ErrManifestInvalid
	}
	for _, region := range grant.Regions {
		if region.Plan.Cell != string(identity.Cell) {
			continue
		}
		material := region.BootstrapMaterial
		if material == nil || material.Startup == nil || material.InstallationID != home.InstallationID ||
			!sha256RE.MatchString(material.PlanSHA256) || region.Generation != grant.Generation || region.Plan.Region != identity.OCIRegion {
			return startupTemplateEvidence{}, ErrManifestInvalid
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
			return startupTemplateEvidence{}, ErrManifestInvalid
		}
		escrow := material.SourceVaultTarget
		if !isOCID(escrow.CompartmentOCID, "compartment") || !strings.HasPrefix(escrow.VaultOCID, "ocid1.vault.oc1.sa-saopaulo-1.") || escrow.KMSKeyOCID != home.StorageDomain.HeadKMSKeyOCID {
			return startupTemplateEvidence{}, ErrManifestInvalid
		}
		if cfg.DeploymentID != identity.DeploymentID || cfg.Environment != identity.Environment || cfg.ClusterID != identity.ClusterID || cfg.Cell != strings.ToLower(string(identity.Cell)) || cfg.Region != identity.OCIRegion || len(cfg.Slots) != len(identity.ControllerSlots) {
			return startupTemplateEvidence{}, ErrManifestInvalid
		}
		prefix, prefixErr := netip.ParsePrefix(cfg.SubnetCIDR)
		if prefixErr != nil || !prefix.Addr().Is4() || !prefix.Addr().IsPrivate() || prefix.Masked() != prefix {
			return startupTemplateEvidence{}, ErrManifestInvalid
		}
		slotIPs := make(map[string]string, len(cfg.Slots))
		seenIPs := make(map[string]bool, len(cfg.Slots))
		for index, slot := range cfg.Slots {
			address, addressErr := netip.ParseAddr(slot.PrivateIP)
			if slot.Name != identity.ControllerSlots[index] || addressErr != nil || !address.Is4() || !prefix.Contains(address) || address == prefix.Addr() || address == prefix.Addr().Next() || seenIPs[slot.PrivateIP] {
				return startupTemplateEvidence{}, ErrManifestInvalid
			}
			slotIPs[slot.Name], seenIPs[slot.PrivateIP] = slot.PrivateIP, true
		}
		template := material.Startup.Clone()
		templateWire, err := json.Marshal(template, json.Deterministic(true))
		if err != nil {
			return startupTemplateEvidence{}, err
		}
		if bindings != nil {
			if bindings.logical != nil && (bindings.logical.GrantSHA256() != digestBytes(wire) || bindings.logical.Generation() != grant.Generation || bindings.logical.Cell() != string(identity.Cell)) {
				return startupTemplateEvidence{}, ErrManifestInvalid
			}
			template, err = bindings.project(template, string(identity.Cell))
			if err != nil {
				return startupTemplateEvidence{}, err
			}
		} else if template.Validate() != nil {
			return startupTemplateEvidence{}, ErrManifestInvalid
		}

		if identity.InitialSourceRegistration != nil {
			registration := material.SourceRegistration
			want, _ := json.Marshal(identity.InitialSourceRegistration, json.Deterministic(true))
			actual, _ := json.Marshal(registration, json.Deterministic(true))
			if registration == nil || registration.Validate() != nil || !bytes.Equal(want, actual) || registration.InstallationID != material.InstallationID || registration.PlanSHA256 != material.PlanSHA256 || registration.SeedSlot != template.SeedSlot {
				return startupTemplateEvidence{}, ErrManifestInvalid
			}
		} else if material.SourceRegistration != nil {
			return startupTemplateEvidence{}, ErrManifestInvalid
		}
		if len(template.Profiles) != len(identity.ControllerSlots) || !bytes.Equal(template.ControllerFiles[0].Bytes, identity.InitialRegionIntentWire) || template.ControllerFiles[0].SHA256 != identity.InitialRegionIntentSHA256 {
			return startupTemplateEvidence{}, ErrManifestInvalid
		}
		for _, slot := range identity.ControllerSlots {
			if !slices.ContainsFunc(template.Profiles, func(profile LaunchProfile) bool { return profile.Slot == slot }) {
				return startupTemplateEvidence{}, ErrManifestInvalid
			}
		}
		vault := StartupVaultTarget{CompartmentOCID: region.Plan.ResourceIDs.ControlCompartment, VaultOCID: region.Plan.ResourceIDs.Vault, KMSKeyOCID: region.Plan.ResourceIDs.Key}
		if bindings != nil {
			vault = StartupVaultTarget{CompartmentOCID: bindings.vault.CompartmentOCID(), VaultOCID: bindings.vault.VaultOCID(), KMSKeyOCID: bindings.vault.KMSKeyOCID()}
		}

		if !isOCID(vault.CompartmentOCID, "compartment") || !strings.HasPrefix(vault.VaultOCID, "ocid1.vault.oc1."+identity.OCIRegion+".") || !strings.HasPrefix(vault.KMSKeyOCID, "ocid1.key.oc1."+identity.OCIRegion+".") {
			return startupTemplateEvidence{}, ErrManifestInvalid
		}
		clonedRoots := make(trust.Keyring, len(roots))
		for keyID, key := range roots {
			clonedRoots[keyID] = bytes.Clone(key)
		}
		return startupTemplateEvidence{template: template, identity: cloneBootstrapAnchor(identity), roots: clonedRoots,
			grantWire: bytes.Clone(wire), grantDigest: digestBytes(wire), templateDigest: digestBytes(templateWire),
			planDigest: material.PlanSHA256, installationID: material.InstallationID, generation: grant.Generation,
			issuedAt: envelope.IssuedAt, expiresAt: envelope.ExpiresAt, authorityExpiresAt: envelope.ExpiresAt,
			vault: vault, escrow: escrow, slotIPs: slotIPs}, nil
	}
	return startupTemplateEvidence{}, ErrManifestInvalid
}

func (verified startupTemplateEvidence) ValidateProjection(manifest Manifest) error {
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

func (verified startupTemplateEvidence) ManifestFor(slot string, refs []SecretReference) (Manifest, error) {
	if !slices.Contains(verified.identity.ControllerSlots, slot) {
		return Manifest{}, ErrManifestInvalid
	}
	anchor := verified.identity
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
