package bootstrap

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"fmt"
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
	startupTemplateEvidence
	anchor   VerifiedBootstrapAnchor
	image    release.VerifiedImage
	bindings *startupBindings
}

// startupBindings retains independent logical birth proof and finite target observation.
type startupBindings struct {
	original         context.Context
	logical          *foundationbinding.VerifiedBindings
	vault            foundationbinding.VerifiedStartupVault
	factory          *ociclient.Factory
	targetReferences map[string]bool
}

func (bindings startupBindings) Revalidate(ctx context.Context) error {
	if ctx == nil || bindings.original == nil || bindings.original.Err() != nil {
		return ErrManifestInvalid
	}
	boundedCtx, cancel := context.WithDeadline(ctx, bindings.vault.ExpiresAt())
	defer cancel()
	stopOriginal := context.AfterFunc(bindings.original, cancel)
	defer stopOriginal()
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

func (verified VerifiedStartupTemplate) Template() StartupTemplate { return verified.template.Clone() }
func (verified VerifiedStartupTemplate) GrantWire() []byte         { return bytes.Clone(verified.grantWire) }
func (verified VerifiedStartupTemplate) GrantDigest() string       { return verified.grantDigest }
func (verified VerifiedStartupTemplate) TemplateDigest() string    { return verified.templateDigest }
func (verified VerifiedStartupTemplate) PlanDigest() string        { return verified.planDigest }
func (verified VerifiedStartupTemplate) InstallationID() string    { return verified.installationID }
func (verified VerifiedStartupTemplate) Generation() uint64        { return verified.generation }
func (verified VerifiedStartupTemplate) ExpiresAt() time.Time      { return verified.expiresAt }

// AuthorityExpiresAt retains the signed ceiling independently of local consumption.
func (verified VerifiedStartupTemplate) AuthorityExpiresAt() time.Time {
	return verified.authorityExpiresAt
}
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
	if !verified.IsVerified() {
		return ErrManifestInvalid
	}
	return verified.startupTemplateEvidence.ValidateProjection(manifest)
}

func (verified VerifiedStartupTemplate) VerifyCurrent(now time.Time) error {
	return verified.VerifyCurrentContext(context.Background(), now)
}

func (verified VerifiedStartupTemplate) currentLifetimeError() error {
	if !verified.IsVerified() || !time.Now().Before(verified.expiresAt) {
		return ErrManifestInvalid
	}
	if bindings := verified.bindings; bindings != nil && (bindings.original == nil || bindings.original.Err() != nil) {
		return ErrManifestInvalid
	}
	return nil
}

func (verified VerifiedStartupTemplate) currentReadContext(ctx context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithDeadline(ctx, verified.expiresAt)
	if verified.bindings == nil {
		return ctx, cancel
	}
	original := verified.bindings.original
	if original == nil {
		cancel()
		return ctx, cancel
	}
	stop := context.AfterFunc(original, cancel)
	if original.Err() != nil {
		cancel()
	}
	return ctx, func() { stop(); cancel() }
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
		boundedCtx, cancel := verified.currentReadContext(ctx)
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
	if verified.bindings != nil {
		if err := verified.currentLifetimeError(); err != nil {
			return err
		}
	}
	return ctx.Err()
}

// ManifestFor returns render-only structural inputs. It cannot be passed to a
// materializer or admission gate as a verified signed manifest.
func (verified VerifiedStartupTemplate) ManifestFor(slot string, refs []SecretReference) (Manifest, error) {
	if !verified.IsVerified() {
		return Manifest{}, ErrManifestInvalid
	}
	return verified.startupTemplateEvidence.ManifestFor(slot, refs)
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
	if !anchor.IsVerified() {
		return VerifiedStartupTemplate{}, ErrManifestInvalid
	}
	proof, err := decodeStartupTemplateEvidence(wire, roots, anchor.Anchor(), anchor.ExpiresAt(), identity, bindings, now)
	if err != nil {
		return VerifiedStartupTemplate{}, err
	}
	template := proof.template
	image, err := release.VerifyImageCurrent(template.ReleaseImageReceiptWire, template.ReleaseDelegationWire, roots,
		release.ImageExpectation{Environment: identity.Environment, LogicalRegion: string(identity.Cell), OCIImageOCID: template.ImageOCID, Architecture: strings.TrimPrefix(template.ImageArchitecture, "linux-")}, now)
	if err != nil {
		return VerifiedStartupTemplate{}, fmt.Errorf("verify startup image: %w", err)
	}
	if template.FounderResources != nil && (template.FounderResources.LaunchDeadline.After(proof.expiresAt) || template.FounderResources.LaunchDeadline.After(image.ExpiresAt())) {
		return VerifiedStartupTemplate{}, ErrFounderPlanInvalid
	}
	proof.expiresAt = minTimeLink(proof.expiresAt, image.ExpiresAt())
	proof.authorityExpiresAt = proof.expiresAt
	if bindings != nil {
		proof.expiresAt = minTimeLink(proof.expiresAt, bindings.vault.ExpiresAt())
		if bindings.logical != nil {
			proof.expiresAt = minTimeLink(proof.expiresAt, bindings.logical.ExpiresAt())
		}
	}
	verified := VerifiedStartupTemplate{startupTemplateEvidence: proof, anchor: anchor, image: image, bindings: bindings}
	if bindings != nil {
		if err := verified.currentLifetimeError(); err != nil {
			return VerifiedStartupTemplate{}, err
		}
	}
	return verified, nil
}

// VerifyBoundStartupTemplate independently checks schema-2 startup against the
// exact original grant, create provenance and current OCI resource facts.
func VerifyBoundStartupTemplate(ctx context.Context, factory *ociclient.Factory, wire []byte, roots trust.Keyring, anchor VerifiedBootstrapAnchor, now time.Time) (VerifiedStartupTemplate, error) {
	bindings, err := verifyStartupBindings(ctx, ctx, factory, wire, roots, anchor, string(anchor.Anchor().Cell), now)
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

func verifyStartupBindings(ctx, original context.Context, factory *ociclient.Factory, wire []byte, roots trust.Keyring, anchor VerifiedBootstrapAnchor, cell string, now time.Time) (*startupBindings, error) {
	if ctx == nil || original == nil || ctx.Err() != nil || original.Err() != nil {
		return nil, ErrManifestInvalid
	}
	ctx, cancel := context.WithCancel(ctx)
	stopOriginal := context.AfterFunc(original, cancel)
	defer func() { stopOriginal(); cancel() }()
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
	if json.Unmarshal(payload, &grant) != nil || grant.SchemaVersion != 2 {
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
	vault, err := foundationbinding.VerifyStartupVaultForOperation(ctx, original, factory, authority, wire, anchor.ExpiresAt())
	if err != nil {
		return nil, err
	}
	bound := &startupBindings{original: original, factory: factory, vault: vault, targetReferences: targetReferences}
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
	// The sibling retains the original cap after this operation returns.
	original, cancelOriginal := context.WithDeadline(verified.bindings.original, verified.expiresAt)
	sibling, err := VerifyBoundRegionalStartupTemplateForOperation(ctx, original, verified.bindings.factory, verified.grantWire, verified.roots, verified.anchor, cell, now)
	if err != nil {
		cancelOriginal()
		return VerifiedStartupTemplate{}, err
	}
	context.AfterFunc(original, cancelOriginal)
	return sibling, nil
}
