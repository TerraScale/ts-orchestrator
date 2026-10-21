package materialsource

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func (source *ColdStartMaterial) signInventory(ctx context.Context) ([]byte, error) {
	if source == nil || source.kind != "" || ctx.Err() != nil || source.state.Reference.SecretOCID == "" || source.guard(ctx) != nil {
		return nil, ErrMaterialSource
	}
	if _, err := source.grant.SourceRegistration(); err != nil {
		return bytes.Clone(source.state.Inventory), nil
	}
	if err := source.validateAdmissionRecord(ctx, source.record); err != nil {
		return nil, err
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

func (source *ColdStartMaterial) admissionAuthorization(ctx context.Context) (string, error) {
	if source.kind != "" {
		return "", nil
	}
	proof, err := source.grant.AdmissionAttestor(ctx)
	if err != nil {
		return "", ErrMaterialSource
	}
	if !proof.IsVerified() {
		return "", nil
	}
	a := proof.Authorization()
	domain := source.grant.StorageDomain()
	if a.SourceObject != source.key || a.SourceNamespace != domain.Namespace || a.SourceBucket != domain.HeadBucket {
		return "", ErrMaterialSource
	}
	return a.Digest()
}

func immutableAdmissionSource(prior, next materialSourceState) bool {
	if prior.AdmissionAuthorizationSHA256 != next.AdmissionAuthorizationSHA256 {
		return false
	}
	if prior.AdmissionAuthorizationSHA256 == "" {
		return len(prior.OriginalAdmissionInventory) == 0 && len(next.OriginalAdmissionInventory) == 0
	}
	if prior.Actor != next.Actor || prior.InstallationID != next.InstallationID || prior.Cell != next.Cell || prior.Generation != next.Generation || prior.PlanSHA256 != next.PlanSHA256 || prior.Target != next.Target || prior.SecretName != next.SecretName || prior.RetryToken != next.RetryToken || !prior.StartedAt.Equal(next.StartedAt) || prior.Kind != next.Kind || prior.BindingSHA256 != next.BindingSHA256 ||
		prior.Reference.SecretOCID != "" && prior.Reference != next.Reference {
		return false
	}
	if len(prior.OriginalAdmissionInventory) > 0 {
		return bytes.Equal(prior.OriginalAdmissionInventory, next.OriginalAdmissionInventory)
	}
	// Archive selection and first inventory selection use distinct CAS revisions.
	return len(next.OriginalAdmissionInventory) == 0 || prior.Reference.SecretOCID != "" && len(prior.Inventory) == 0 && bytes.Equal(next.OriginalAdmissionInventory, next.Inventory)
}

func (source *ColdStartMaterial) validateAdmissionRecord(ctx context.Context, record bootstrapmaterial.Record) error {
	authorization, err := source.admissionAuthorization(ctx)
	if err != nil || authorization != source.state.AdmissionAuthorizationSHA256 {
		return ErrMaterialSource
	}
	if authorization == "" {
		if record.Public.AdmissionAttestor != (release.AdmissionAttestorMaterial{}) || len(source.state.OriginalAdmissionInventory) > 0 {
			return ErrMaterialSource
		}
		return nil
	}
	if record.Public.AdmissionAttestor.Validate() != nil || record.Public.AdmissionAttestor.AuthorizationSHA256 != authorization {
		return ErrMaterialSource
	}
	if len(source.state.OriginalAdmissionInventory) == 0 {
		return nil // Only the initial, separately checkpointed selection may fill it.
	}
	envelope, err := trust.DecodeEnvelope(source.state.OriginalAdmissionInventory)
	if err != nil {
		return ErrMaterialSource
	}
	var original bootstrap.RegionalSourceInventory
	if json.Unmarshal(envelope.Payload, &original, json.RejectUnknownMembers(true)) != nil || original.SchemaVersion != 1 || original.Actor != (bootstrap.SourceInventoryActor{InstanceID: source.state.Actor.InstanceID, GrantDigest: source.state.Actor.GrantDigest, TemplateDigest: source.state.Actor.TemplateDigest}) || original.GrantSHA256 != source.state.Actor.GrantDigest || original.PlanSHA256 != source.state.PlanSHA256 || original.SourceSHA256 != source.state.Reference.SHA256 || !bytes.Equal(original.MaterialRecord, source.archive.Files["material.json"]) {
		return ErrMaterialSource
	}
	key := source.archive.Files["founder-ledger.key"]
	if len(key) != ed25519.PrivateKeySize {
		return ErrMaterialSource
	}
	public := ed25519.PrivateKey(key).Public().(ed25519.PublicKey)
	id, _ := trust.KeyID(public)
	cfg := record.Config
	scope := trust.Scope{Domain: "terrascale.bootstrap.source-inventory", DeploymentID: cfg.DeploymentID, Cell: strings.ToUpper(cfg.Cell), Environment: cfg.Environment, Role: "source", Slot: source.grant.InstallationID()}
	if _, err := trust.VerifyHistorical(envelope, scope, trust.Keyring{id: public}, bootstrap.ManifestTrustPolicy()); err != nil {
		return ErrMaterialSource
	}
	return nil
}
