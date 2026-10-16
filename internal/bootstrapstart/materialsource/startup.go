package materialsource

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json/jsontext"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// StartupProjection is render-only until exact house-rendered config bytes are
// committed to the source CAS. Only recovered, verified source may bind them.
type StartupProjection struct {
	template bootstrap.VerifiedStartupTemplate
	material VerifiedColdStartMaterial
	manifest bootstrap.Manifest
}

func NewStartupProjection(template bootstrap.VerifiedStartupTemplate, material VerifiedColdStartMaterial, slot string) (StartupProjection, error) {
	if !template.IsVerified() || !material.IsVerified() || template.GrantDigest() != digestWire(material.Grant().FoundationGrantWire()) || template.PlanDigest() != material.Grant().PlanDigest() || template.InstallationID() != material.Grant().InstallationID() || material.source.link != nil {
		return StartupProjection{}, ErrMaterialSource
	}
	target := template.VaultTarget()
	publication := material.Publication()
	if publication.Target.CompartmentOCID != target.CompartmentOCID || publication.Target.VaultOCID != target.VaultOCID || publication.Target.KMSKeyOCID != target.KMSKeyOCID {
		return StartupProjection{}, ErrMaterialSource
	}
	refs := make([]bootstrap.SecretReference, len(publication.References))
	for i, ref := range publication.References {
		refs[i] = ref.Reference
	}
	manifest, err := template.ManifestFor(slot, refs)
	if err != nil {
		return StartupProjection{}, err
	}
	return StartupProjection{template: template, material: material, manifest: manifest}, nil
}
func (projection StartupProjection) Manifest() bootstrap.Manifest {
	manifest, _ := projection.template.ManifestFor(projection.manifest.Slot, slices.Clone(projection.manifest.Secrets))
	return manifest
}
func (projection StartupProjection) TrustedSigners() jsontext.Value {
	return projection.template.Template().TrustedSigners
}

// BindConfigs records every slot's public provenance atomically before any
// install. The app's private final wrapper renders and compares all config bytes.
func (projection StartupProjection) BindConfigs(ctx context.Context, configs map[string][]byte) (bootstrap.DerivedStartupAuthority, error) {
	if !projection.material.IsVerified() || projection.template.VerifyCurrent(time.Now()) != nil || len(configs) != len(projection.manifest.ControllerSlots) {
		return bootstrap.DerivedStartupAuthority{}, ErrMaterialSource
	}
	source := projection.material.source
	fresh, err := source.InstallMaterial(ctx)
	if err != nil || fresh.publication.MaterialSHA256 != projection.material.publication.MaterialSHA256 || source.state.Reference.SHA256 == "" {
		return bootstrap.DerivedStartupAuthority{}, ErrMaterialSource
	}
	metadata, err := os.ReadFile(filepath.Join(source.directory, "material.json"))
	if err != nil || digestWire(metadata) != fresh.publication.MaterialSHA256 {
		return bootstrap.DerivedStartupAuthority{}, ErrMaterialSource
	}
	key, err := os.ReadFile(filepath.Join(source.directory, "founder-ledger.key"))
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return bootstrap.DerivedStartupAuthority{}, ErrMaterialSource
	}
	defer clear(key)
	issued := source.record.IssuedAt
	if projection.template.IssuedAt().After(issued) {
		issued = projection.template.IssuedAt()
	}
	expires := projection.template.ExpiresAt()
	if source.record.ExpiresAt.Before(expires) {
		expires = source.record.ExpiresAt
	}
	if issued.Add(bootstrap.MaxManifestLifetime).Before(expires) {
		expires = issued.Add(bootstrap.MaxManifestLifetime)
	}
	next := source.state
	next.Startup = make(map[string][]byte, len(projection.manifest.ControllerSlots))
	for _, slot := range projection.manifest.ControllerSlots {
		config := configs[slot]
		if len(config) == 0 || len(config) > bootstrap.MaxControllerConfigBytes {
			return bootstrap.DerivedStartupAuthority{}, ErrMaterialSource
		}
		manifest, err := projection.template.ManifestFor(slot, projection.manifest.Secrets)
		if err != nil {
			return bootstrap.DerivedStartupAuthority{}, err
		}
		manifest.ControllerConfig, manifest.ControllerConfigSHA256 = bytes.Clone(config), digestWire(config)
		if err := projection.template.ValidateProjection(manifest); err != nil {
			return bootstrap.DerivedStartupAuthority{}, err
		}
		binding := bootstrap.DerivedStartupBinding{SchemaVersion: 1, GrantSHA256: projection.template.GrantDigest(), TemplateSHA256: projection.template.TemplateDigest(), SourceSHA256: source.state.Reference.SHA256, MaterialRecord: metadata, Manifest: manifest}
		payload, err := trust.EncodePayload(binding)
		if err != nil {
			return bootstrap.DerivedStartupAuthority{}, err
		}
		envelope, err := trust.Sign(payload, bootstrap.DerivedStartupScope(manifest), issued, expires, ed25519.PrivateKey(key))
		if err != nil {
			return bootstrap.DerivedStartupAuthority{}, err
		}
		wire, err := trust.EncodeEnvelope(envelope)
		if err != nil {
			return bootstrap.DerivedStartupAuthority{}, err
		}
		if prior := source.state.Startup[slot]; len(prior) > 0 && !bytes.Equal(prior, wire) {
			return bootstrap.DerivedStartupAuthority{}, ErrMaterialSource
		}
		next.Startup[slot] = wire
	}
	if len(source.state.Startup) > 0 && len(source.state.Startup) != len(next.Startup) {
		return bootstrap.DerivedStartupAuthority{}, ErrMaterialSource
	}
	if len(source.state.Startup) == 0 {
		etag, err := source.write(ctx, next, source.etag)
		if err != nil {
			return bootstrap.DerivedStartupAuthority{}, err
		}
		source.state, source.etag = next, etag
	}
	wire := next.Startup[projection.manifest.Slot]
	// Keep the source projection current after adding the immutable public proof.
	if _, err := source.InstallMaterial(ctx); err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	return bootstrap.VerifyDerivedStartupAuthority(ctx, projection.template, source.objects, wire, time.Now())
}
