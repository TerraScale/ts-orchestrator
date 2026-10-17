package bootstrap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"io"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

type SourceInventoryActor struct {
	InstanceID     string `json:"instanceId"`
	GrantDigest    string `json:"grantDigest"`
	TemplateDigest string `json:"templateDigest"`
}

// RegionalSourceInventory binds public inventory to the original source escrow.
// It contains no private material and is available before config publication.
type RegionalSourceInventory struct {
	SchemaVersion  int                  `json:"schemaVersion"`
	Actor          SourceInventoryActor `json:"actor"`
	GrantSHA256    string               `json:"grantSha256"`
	PlanSHA256     string               `json:"planSha256"`
	SourceSHA256   string               `json:"sourceSha256"`
	MaterialRecord []byte               `json:"materialRecord"`
}

type VerifiedRegionalSource struct {
	template                      VerifiedStartupTemplate
	client                        ObjectStorageClient
	binding                       RegionalSourceInventory
	wire                          []byte
	ledgerKey                     ed25519.PublicKey
	expiresAt, authorityExpiresAt time.Time
}

func (source VerifiedRegionalSource) OriginalActor() SourceInventoryActor {
	return source.binding.Actor
}
func (source VerifiedRegionalSource) IsVerified() bool {
	return source.client != nil && source.template.IsVerified() && len(source.wire) > 0
}
func (source VerifiedRegionalSource) MaterialRecord() []byte {
	return bytes.Clone(source.binding.MaterialRecord)
}
func (source VerifiedRegionalSource) Inventory() []byte                 { return bytes.Clone(source.wire) }
func (source VerifiedRegionalSource) Template() VerifiedStartupTemplate { return source.template }
func (source VerifiedRegionalSource) ExpiresAt() time.Time              { return source.expiresAt }
func (source VerifiedRegionalSource) AuthorityExpiresAt() time.Time     { return source.authorityExpiresAt }
func (source VerifiedRegionalSource) StorageDomain() StorageDomain {
	home, _ := source.template.anchor.FoundationScope()
	return home.StorageDomain
}
func (source VerifiedRegionalSource) Manifest() Manifest {
	manifest, _ := source.template.ManifestFor(source.template.template.SeedSlot, nil)
	return manifest
}
func (source VerifiedRegionalSource) VerifyCurrent(ctx context.Context, now time.Time) error {
	if ctx == nil || !source.IsVerified() || !now.Before(source.expiresAt) {
		return ErrManifestInvalid
	}
	ctx, cancel := context.WithDeadline(ctx, source.expiresAt)
	defer cancel()
	current, err := LoadRegionalSource(ctx, source.template, source.client, now)
	if err != nil {
		return err
	}
	if !bytes.Equal(current.wire, source.wire) {
		return ErrManifestInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !time.Now().Before(source.expiresAt) {
		return ErrManifestInvalid
	}
	return source.template.currentLifetimeError()
}

// LoadRegionalSource uses only the exact public object named by the signed grant.
// The existing founder registration admits its source key; no Vault read occurs.
func LoadRegionalSource(ctx context.Context, template VerifiedStartupTemplate, client ObjectStorageClient, now time.Time) (VerifiedRegionalSource, error) {
	deny := func() (VerifiedRegionalSource, error) { return VerifiedRegionalSource{}, ErrManifestInvalid }
	if client == nil || ctx == nil || ctx.Err() != nil {
		return deny()
	}
	ctx, cancel := template.currentReadContext(ctx)
	defer cancel()
	if template.VerifyCurrentContext(ctx, now) != nil || template.startupIdentity().InitialSourceRegistration == nil {
		return deny()
	}
	proof, err := loadRegionalSourceEvidence(ctx, template.startupTemplateEvidence, client, now)
	if err != nil {
		return VerifiedRegionalSource{}, err
	}
	expires := minTimeLink(proof.authorityExpiresAt, template.ExpiresAt())
	if ctx.Err() != nil || template.currentLifetimeError() != nil || !time.Now().Before(expires) {
		return deny()
	}
	return VerifiedRegionalSource{template: template, client: client, binding: proof.binding, wire: proof.wire, ledgerKey: proof.ledgerKey, expiresAt: expires, authorityExpiresAt: proof.authorityExpiresAt}, nil
}

func RegionalSourceInventoryScope(template VerifiedStartupTemplate) trust.Scope {
	return regionalSourceInventoryScope(template.startupTemplateEvidence)
}

// regionalSourceEvidence retains signed data without current source authority.
type regionalSourceEvidence struct {
	recipe             startupTemplateEvidence
	binding            RegionalSourceInventory
	wire               []byte
	ledgerKey          ed25519.PublicKey
	authorityExpiresAt time.Time
}

func loadRegionalSourceEvidence(ctx context.Context, template startupTemplateEvidence, client ObjectStorageClient, now time.Time) (regionalSourceEvidence, error) {
	deny := func() (regionalSourceEvidence, error) { return regionalSourceEvidence{}, ErrManifestInvalid }
	if ctx == nil || ctx.Err() != nil || client == nil || template.identity.InitialSourceRegistration == nil {
		return deny()
	}
	domain := template.sourceDomain()
	response, err := client.GetObject(ociclient.RequestContext(ctx), objectstorage.GetObjectRequest{NamespaceName: new(domain.Namespace), BucketName: new(domain.HeadBucket), ObjectName: new(template.sourceKey())})
	if err != nil {
		return regionalSourceEvidence{}, err
	}
	if response.Content == nil {
		return deny()
	}
	defer response.Content.Close()
	wire, err := io.ReadAll(io.LimitReader(response.Content, 2<<20))
	if err != nil || len(wire) >= 2<<20 || response.ETag == nil || *response.ETag == "" {
		return deny()
	}
	var state struct {
		Actor          SourceInventoryActor `json:"actor"`
		SchemaVersion  int                  `json:"schemaVersion"`
		Kind           string               `json:"kind"`
		InstallationID string               `json:"installationId"`
		Cell           string               `json:"cell"`
		Generation     uint64               `json:"generation"`
		PlanSHA256     string               `json:"planSha256"`
		Target         StartupVaultTarget   `json:"target"`
		Reference      struct {
			SecretOCID string `json:"secretOcid"`
			SHA256     string `json:"sha256"`
			MaxBytes   int64  `json:"maxBytes"`
		} `json:"reference"`
		Inventory []byte `json:"inventory"`
	}
	if json.Unmarshal(wire, &state) != nil || state.SchemaVersion != 1 || state.Kind != "" || state.InstallationID != template.installationID || state.Cell != strings.ToLower(string(template.identity.Cell)) || state.Generation == 0 || state.Generation > template.generation || state.PlanSHA256 != template.planDigest || state.Target != template.escrow || !isOCID(state.Reference.SecretOCID, "vaultsecret") || !validDigest(state.Reference.SHA256) || state.Reference.MaxBytes <= 0 || state.Reference.MaxBytes > 25<<10 || len(state.Inventory) == 0 || len(state.Inventory) > 64<<10 {
		return deny()
	}
	envelope, err := trust.DecodeEnvelope(state.Inventory)
	if err != nil {
		return deny()
	}
	var binding RegionalSourceInventory
	if json.Unmarshal(envelope.Payload, &binding, json.RejectUnknownMembers(true)) != nil || binding.SchemaVersion != 1 || binding.Actor != state.Actor || !isOCID(binding.Actor.InstanceID, "instance") || !validDigest(binding.Actor.GrantDigest) || !validDigest(binding.Actor.TemplateDigest) || state.Generation == template.generation && (binding.Actor.GrantDigest != template.grantDigest || binding.Actor.TemplateDigest != template.templateDigest) || binding.GrantSHA256 != template.grantDigest || binding.PlanSHA256 != template.planDigest || binding.SourceSHA256 != state.Reference.SHA256 {
		return deny()
	}
	var record struct {
		Config    jsontext.Value `json:"config"`
		IssuedAt  time.Time      `json:"issuedAt"`
		ExpiresAt time.Time      `json:"expiresAt"`
		Public    struct {
			LedgerSignerPublicKey string `json:"ledgerSignerPublicKey"`
			PeerSignerPublicKey   string `json:"peerSignerPublicKey"`
		} `json:"public"`
	}
	if json.Unmarshal(binding.MaterialRecord, &record) != nil || digestBytes(record.Config) != template.planDigest || record.IssuedAt.IsZero() || !now.Before(record.ExpiresAt) {
		return deny()
	}
	key, err := base64.StdEncoding.Strict().DecodeString(record.Public.LedgerSignerPublicKey)
	peer, peerErr := base64.StdEncoding.Strict().DecodeString(record.Public.PeerSignerPublicKey)
	if err != nil || peerErr != nil || len(key) != ed25519.PublicKeySize || len(peer) != ed25519.PublicKeySize {
		return deny()
	}
	id, _ := trust.KeyID(key)
	if _, err := trust.VerifyCurrent(envelope, regionalSourceInventoryScope(template), trust.Keyring{id: key}, now, ManifestTrustPolicy()); err != nil || envelope.IssuedAt.Before(template.issuedAt) || envelope.IssuedAt.Before(record.IssuedAt) || envelope.ExpiresAt.After(template.authorityExpiresAt) || envelope.ExpiresAt.After(record.ExpiresAt) {
		return deny()
	}
	if err := ctx.Err(); err != nil {
		return regionalSourceEvidence{}, err
	}
	return regionalSourceEvidence{recipe: template, binding: binding, wire: bytes.Clone(state.Inventory), ledgerKey: bytes.Clone(key), authorityExpiresAt: envelope.ExpiresAt}, nil
}

func regionalSourceInventoryScope(template startupTemplateEvidence) trust.Scope {
	identity := template.identity
	return trust.Scope{Domain: "terrascale.bootstrap.source-inventory", DeploymentID: identity.DeploymentID, Cell: string(identity.Cell), Environment: identity.Environment, Role: "source", Slot: template.installationID}
}

func (source VerifiedRegionalSource) evidence() regionalSourceEvidence {
	return regionalSourceEvidence{recipe: source.template.startupTemplateEvidence, binding: source.binding, wire: bytes.Clone(source.wire), ledgerKey: bytes.Clone(source.ledgerKey), authorityExpiresAt: source.authorityExpiresAt}
}
func (source regionalSourceEvidence) OriginalActor() SourceInventoryActor {
	return source.binding.Actor
}
func (source regionalSourceEvidence) MaterialRecord() []byte {
	return bytes.Clone(source.binding.MaterialRecord)
}
func (source regionalSourceEvidence) StorageDomain() StorageDomain {
	return source.recipe.sourceDomain()
}
func (source regionalSourceEvidence) Manifest() Manifest {
	manifest, _ := source.recipe.ManifestFor(source.recipe.template.SeedSlot, nil)
	return manifest
}
