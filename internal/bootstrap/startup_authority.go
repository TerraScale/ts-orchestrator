package bootstrap

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/foundationbinding"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
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
	bindings                                                *startupBindings
}

// startupBindings retains independent logical birth proof and finite target observation.
type startupBindings struct {
	logical          *foundationbinding.VerifiedBindings
	vault            foundationbinding.VerifiedStartupVault
	factory          *ociclient.Factory
	targetReferences map[string]bool
}

func (bindings startupBindings) Revalidate(ctx context.Context) error {
	boundedCtx, cancel := context.WithDeadline(ctx, bindings.vault.ExpiresAt())
	defer cancel()
	if bindings.logical != nil {
		if err := bindings.logical.Revalidate(boundedCtx); err != nil {
			return err
		}
	}
	return bindings.vault.Revalidate(boundedCtx)
}

func (bindings startupBindings) project(template StartupTemplate, cell string) (StartupTemplate, error) {
	return projectFoundationStartup(template, cell, func(reference string) (string, error) {
		actualCell, role, err := foundationbinding.Parse(reference)
		if err != nil || actualCell != cell {
			return "", ErrManifestInvalid
		}
		// These consumed target roles required genuine birth in the finite witness.
		if bindings.targetReferences[role] {
			switch role {
			case "control_compartment":
				return bindings.vault.CompartmentOCID(), nil
			case "vault":
				return bindings.vault.VaultOCID(), nil
			case "key":
				return bindings.vault.KMSKeyOCID(), nil
			}
		}
		if bindings.logical == nil {
			return "", ErrManifestInvalid
		}
		return bindings.logical.Resolve(reference)
	})
}

type startupResourceIDs struct {
	ControlCompartment string `json:"control_compartment"`
	Vault              string `json:"vault"`
	Key                string `json:"key"`
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
	return verified.VerifyCurrentContext(context.Background(), now)
}

// VerifyCurrentContext repeats live protected grant and resource observations for bound startup.
func (verified VerifiedStartupTemplate) VerifyCurrentContext(ctx context.Context, now time.Time) error {
	if !verified.IsVerified() || !now.Before(verified.expiresAt) {
		return ErrManifestInvalid
	}
	if verified.bindings != nil {
		if !time.Now().Before(verified.expiresAt) {
			return ErrManifestInvalid
		}
		boundedCtx, cancel := context.WithDeadline(ctx, verified.expiresAt)
		defer cancel()
		ctx = boundedCtx
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
	if verified.bindings != nil {
		if err := verified.bindings.Revalidate(ctx); err != nil {
			return err
		}
	}
	_, err = verifyStartupTemplateForIdentityBindings(verified.grantWire, verified.roots, anchor, verified.startupIdentity(), verified.bindings, now)
	if err != nil {
		return err
	}
	if verified.bindings != nil && !time.Now().Before(verified.expiresAt) {
		return ErrManifestInvalid
	}
	return ctx.Err()
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
	return verifyStartupTemplateForIdentityBindings(wire, roots, anchor, identity, nil, now)
}

func verifyStartupTemplateForIdentityBindings(wire []byte, roots trust.Keyring, anchor VerifiedBootstrapAnchor, identity BootstrapAnchor, bindings *startupBindings, now time.Time) (VerifiedStartupTemplate, error) {
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
	if json.Unmarshal(payload, &grant) != nil || (grant.SchemaVersion != 1 || bindings != nil) && ((grant.SchemaVersion != 2 && grant.SchemaVersion != 3) || bindings == nil) || grant.Generation != home.GrantGeneration || grant.InstallationID != home.InstallationID || grant.TenancyID != home.TenancyID {
		return VerifiedStartupTemplate{}, ErrManifestInvalid
	}
	for _, region := range grant.Regions {
		if region.Plan.Cell != string(identity.Cell) {
			continue
		}
		material := region.BootstrapMaterial
		if material == nil || material.Startup == nil || material.InstallationID != home.InstallationID ||
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
		templateWire, err := json.Marshal(template, json.Deterministic(true))
		if err != nil {
			return VerifiedStartupTemplate{}, err
		}
		if bindings != nil {
			if bindings.logical != nil && (bindings.logical.GrantSHA256() != digestBytes(wire) || bindings.logical.Generation() != grant.Generation || bindings.logical.Cell() != string(identity.Cell)) {
				return VerifiedStartupTemplate{}, ErrManifestInvalid
			}
			template, err = bindings.project(template, string(identity.Cell))
			if err != nil {
				return VerifiedStartupTemplate{}, err
			}
		} else if template.Validate() != nil {
			return VerifiedStartupTemplate{}, ErrManifestInvalid
		}

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
		vault := StartupVaultTarget{CompartmentOCID: region.Plan.ResourceIDs.ControlCompartment, VaultOCID: region.Plan.ResourceIDs.Vault, KMSKeyOCID: region.Plan.ResourceIDs.Key}
		if bindings != nil {
			vault = StartupVaultTarget{CompartmentOCID: bindings.vault.CompartmentOCID(), VaultOCID: bindings.vault.VaultOCID(), KMSKeyOCID: bindings.vault.KMSKeyOCID()}
		}

		if !isOCID(vault.CompartmentOCID, "compartment") || !strings.HasPrefix(vault.VaultOCID, "ocid1.vault.oc1."+identity.OCIRegion+".") || !strings.HasPrefix(vault.KMSKeyOCID, "ocid1.key.oc1."+identity.OCIRegion+".") {
			return VerifiedStartupTemplate{}, ErrManifestInvalid
		}
		expires := envelope.ExpiresAt
		if image.ExpiresAt().Before(expires) {
			expires = image.ExpiresAt()
		}
		if bindings != nil {
			if bindings.vault.ExpiresAt().Before(expires) {
				expires = bindings.vault.ExpiresAt()
			}
			if bindings.logical != nil && bindings.logical.ExpiresAt().Before(expires) {
				expires = bindings.logical.ExpiresAt()
			}
		}
		clonedRoots := make(trust.Keyring, len(roots))
		for keyID, key := range roots {
			clonedRoots[keyID] = bytes.Clone(key)
		}
		if bindings != nil && !time.Now().Before(expires) {
			return VerifiedStartupTemplate{}, ErrManifestInvalid
		}
		return VerifiedStartupTemplate{template: template, anchor: anchor, identity: cloneBootstrapAnchor(identity), roots: clonedRoots, grantWire: bytes.Clone(wire), grantDigest: digestBytes(wire), templateDigest: digestBytes(templateWire),
			planDigest: material.PlanSHA256, installationID: material.InstallationID, generation: grant.Generation, issuedAt: envelope.IssuedAt, expiresAt: expires, image: image, vault: vault, escrow: escrow, slotIPs: slotIPs, bindings: bindings}, nil
	}
	return VerifiedStartupTemplate{}, ErrManifestInvalid
}

// VerifyBoundStartupTemplate independently checks schema-2 startup against the
// exact original grant, create provenance and current OCI resource facts.
func VerifyBoundStartupTemplate(ctx context.Context, factory *ociclient.Factory, wire []byte, roots trust.Keyring, anchor VerifiedBootstrapAnchor, now time.Time) (VerifiedStartupTemplate, error) {
	bindings, err := verifyStartupBindings(ctx, factory, wire, roots, anchor, string(anchor.Anchor().Cell), now)
	if err != nil {
		return VerifiedStartupTemplate{}, err
	}
	verified, err := verifyStartupTemplateForIdentityBindings(wire, roots, anchor, anchor.Anchor(), bindings, now)
	if err != nil {
		return VerifiedStartupTemplate{}, err
	}
	if err := ctx.Err(); err != nil {
		return VerifiedStartupTemplate{}, err
	}
	return verified, nil
}

func verifyStartupBindings(ctx context.Context, factory *ociclient.Factory, wire []byte, roots trust.Keyring, anchor VerifiedBootstrapAnchor, cell string, now time.Time) (*startupBindings, error) {
	identity := anchor.Anchor()
	envelope, err := trust.DecodeEnvelope(anchor.Wire())
	if err != nil {
		return nil, err
	}
	anchor, err = VerifyBootstrapAnchor(envelope, roots, BootstrapAnchorExpectation{DeploymentID: identity.DeploymentID, Environment: identity.Environment, Cell: identity.Cell}, now, BootstrapAnchorTrustPolicy())
	if err != nil {
		return nil, err
	}
	home, err := anchor.FoundationScope()
	if err != nil || digestBytes(wire) != home.GrantSHA256 {
		return nil, ErrManifestInvalid
	}
	scope := trust.Scope{Domain: "terrascale.foundation.scope", DeploymentID: home.DeploymentID, Cell: "GRU", Environment: identity.Environment, Role: "foundation", Slot: home.ClusterID}
	envelope, err = trust.DecodeEnvelope(wire)
	if err != nil {
		return nil, err
	}
	payload, err := trust.VerifyCurrent(envelope, scope, roots, now, BootstrapAnchorTrustPolicy())
	if err != nil || envelope.ExpiresAt.After(anchor.ExpiresAt()) {
		return nil, ErrManifestInvalid
	}
	var grant struct {
		SchemaVersion int `json:"schemaVersion"`
		Regions       []struct {
			Plan struct {
				Cell        string             `json:"cell"`
				ResourceIDs startupResourceIDs `json:"resource_ids"`
			} `json:"plan"`
			BootstrapMaterial *struct {
				Startup *StartupTemplate `json:"startup"`
			} `json:"bootstrapMaterial"`
		} `json:"regions"`
	}
	if json.Unmarshal(payload, &grant) != nil || grant.SchemaVersion != 2 && grant.SchemaVersion != 3 {
		return nil, ErrManifestInvalid
	}
	var keys []string
	selected := false
	for _, region := range grant.Regions {
		if region.Plan.Cell != cell {
			continue
		}
		if selected || region.BootstrapMaterial == nil || region.BootstrapMaterial.Startup == nil {
			return nil, ErrManifestInvalid
		}
		selected = true
		keys, err = region.BootstrapMaterial.Startup.FoundationReferenceKeys(cell)
		if err != nil {
			return nil, err
		}
		for role, value := range map[string]string{"control_compartment": region.Plan.ResourceIDs.ControlCompartment, "vault": region.Plan.ResourceIDs.Vault, "key": region.Plan.ResourceIDs.Key} {
			if value == "" || strings.HasPrefix(value, "foundation:") {
				reference, err := foundationbinding.Reference(cell, role)
				if err != nil || value != "" && value != reference {
					return nil, ErrManifestInvalid
				}
			}
		}
	}
	if !selected {
		return nil, ErrManifestInvalid
	}
	targetReferences := map[string]bool{}
	for _, role := range keys {
		if role == "control_compartment" || role == "vault" || role == "key" {
			targetReferences[role] = true
		}
	}
	authority := foundationbinding.Authority{Scope: scope, Roots: roots, Policy: BootstrapAnchorTrustPolicy(), GrantSHA256: home.GrantSHA256, Generation: home.GrantGeneration,
		InstallationID: home.InstallationID, TenancyID: home.TenancyID, Namespace: home.StorageDomain.Namespace, Bucket: home.StorageDomain.HeadBucket, Prefix: home.StorageDomain.Prefix, Cell: cell, Keys: keys}
	vault, err := foundationbinding.VerifyStartupVault(ctx, factory, authority, wire, anchor.ExpiresAt())
	if err != nil {
		return nil, err
	}
	bound := &startupBindings{factory: factory, vault: vault, targetReferences: targetReferences}
	keys = slices.DeleteFunc(keys, func(role string) bool { return targetReferences[role] })
	authority.Keys = keys
	if len(keys) != 0 {
		boundedCtx, cancel := context.WithDeadline(ctx, vault.ExpiresAt())
		defer cancel()
		logical, err := foundationbinding.Verify(boundedCtx, factory, authority, wire)
		if err != nil {
			return nil, err
		}
		bound.logical = &logical
		if err := vault.Revalidate(boundedCtx); err != nil {
			return nil, err
		}
	}
	return bound, nil
}

// ForCell independently verifies a sibling region in the same original grant.
func (verified VerifiedStartupTemplate) ForCell(ctx context.Context, cell oci.Region, now time.Time) (VerifiedStartupTemplate, error) {
	if err := verified.VerifyCurrentContext(ctx, now); err != nil {
		return VerifiedStartupTemplate{}, err
	}
	if verified.bindings == nil {
		return VerifyRegionalStartupTemplate(verified.grantWire, verified.roots, verified.anchor, cell, now)
	}
	ctx, cancel := context.WithDeadline(ctx, verified.expiresAt)
	defer cancel()
	return VerifyBoundRegionalStartupTemplate(ctx, verified.bindings.factory, verified.grantWire, verified.roots, verified.anchor, cell, now)
}
