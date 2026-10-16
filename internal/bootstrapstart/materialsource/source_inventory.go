package materialsource

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func (source *ColdStartMaterial) signInventory(ctx context.Context) ([]byte, error) {
	if source == nil || source.kind != "" || ctx.Err() != nil || source.state.Reference.SecretOCID == "" || source.guard(ctx) != nil {
		return nil, ErrMaterialSource
	}
	if _, err := source.grant.SourceRegistration(); err != nil {
		return bytes.Clone(source.state.Inventory), nil
	}
	binding := bootstrap.RegionalSourceInventory{Actor: bootstrap.SourceInventoryActor{InstanceID: source.state.Actor.InstanceID, GrantDigest: source.state.Actor.GrantDigest, TemplateDigest: source.state.Actor.TemplateDigest}, SchemaVersion: 1, GrantSHA256: digestWire(source.grant.FoundationGrantWire()), PlanSHA256: source.grant.PlanDigest(), SourceSHA256: source.state.Reference.SHA256, MaterialRecord: bytes.Clone(source.archive.Files["material.json"])}
	payload, err := trust.EncodePayload(binding)
	if err != nil {
		return nil, err
	}
	cfg := source.grant.Config()
	scope := trust.Scope{Domain: "terrascale.bootstrap.source-inventory", DeploymentID: cfg.DeploymentID, Cell: strings.ToUpper(cfg.Cell), Environment: cfg.Environment, Role: "source", Slot: source.grant.InstallationID()}
	key := source.archive.Files["founder-ledger.key"]
	if len(key) != ed25519.PrivateKeySize {
		return nil, ErrMaterialSource
	}
	now := time.Now()
	if prior, err := trust.DecodeEnvelope(source.state.Inventory); err == nil && bytes.Equal(prior.Payload, payload) {
		id, _ := trust.KeyID(ed25519.PrivateKey(key).Public().(ed25519.PublicKey))
		if _, err := trust.VerifyCurrent(prior, scope, trust.Keyring{id: ed25519.PrivateKey(key).Public().(ed25519.PublicKey)}, now, bootstrap.ManifestTrustPolicy()); err == nil {
			return bytes.Clone(source.state.Inventory), nil
		}
	}
	// Source creation and grant renewal share the exact recovered original key.
	grantEnvelope, err := trust.DecodeEnvelope(source.grant.FoundationGrantWire())
	if err != nil {
		return nil, err
	}
	issued := source.record.IssuedAt
	if grantEnvelope.IssuedAt.After(issued) {
		issued = grantEnvelope.IssuedAt
	}
	expires := source.grant.ExpiresAt()
	if source.record.ExpiresAt.Before(expires) {
		expires = source.record.ExpiresAt
	}
	if issued.Add(bootstrap.MaxManifestLifetime).Before(expires) {
		expires = issued.Add(bootstrap.MaxManifestLifetime)
	}
	if !expires.After(issued) {
		return nil, ErrMaterialSource
	}
	envelope, err := trust.Sign(payload, scope, issued, expires, ed25519.PrivateKey(key))
	if err != nil {
		return nil, err
	}
	return trust.EncodeEnvelope(envelope)
}
