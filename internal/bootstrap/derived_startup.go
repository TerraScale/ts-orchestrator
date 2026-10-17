package bootstrap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

const derivedStartupDomain = "terrascale.bootstrap.derived-startup"

// DerivedStartupBinding is public evidence stored write-once in the original
// source CAS. MaterialRecord contains public inventory, never source key bytes.
type DerivedStartupBinding struct {
	SchemaVersion  int                   `json:"schemaVersion"`
	GrantSHA256    string                `json:"grantSha256"`
	TemplateSHA256 string                `json:"templateSha256"`
	SourceSHA256   string                `json:"sourceSha256"`
	MaterialRecord []byte                `json:"materialRecord"`
	Manifest       Manifest              `json:"manifest"`
	Link           *RegionalLinkEvidence `json:"link,omitempty"`
}

// DerivedStartupAuthority retains distinct provenance: the original signed
// grant, exact source CAS binding and source-key signature, not a root manifest.
type DerivedStartupAuthority struct {
	template                  VerifiedStartupTemplate
	binding                   DerivedStartupBinding
	client                    ObjectStorageClient
	wire                      []byte
	digest                    string
	envelope                  trust.Envelope
	expires, authorityExpires time.Time
	ledgerKey, peerKey        ed25519.PublicKey
}

func (authority DerivedStartupAuthority) IsVerified() bool {
	return authority.digest != "" && authority.client != nil && authority.template.IsVerified()
}
func (authority DerivedStartupAuthority) Manifest() Manifest {
	return cloneManifest(authority.binding.Manifest)
}
func (authority DerivedStartupAuthority) Digest() string { return authority.digest }
func (authority DerivedStartupAuthority) StorageDomain() StorageDomain {
	return authority.binding.Manifest.StorageDomain
}
func (authority DerivedStartupAuthority) IssuedAt() time.Time  { return authority.envelope.IssuedAt }
func (authority DerivedStartupAuthority) ExpiresAt() time.Time { return authority.expires }
func (authority DerivedStartupAuthority) AuthorityExpiresAt() time.Time {
	return authority.authorityExpires
}
func (authority DerivedStartupAuthority) Wire() []byte      { return bytes.Clone(authority.wire) }
func (authority DerivedStartupAuthority) GrantWire() []byte { return authority.template.GrantWire() }
func (authority DerivedStartupAuthority) MaterialRecord() []byte {
	return bytes.Clone(authority.binding.MaterialRecord)
}

// MaterialSHA256 identifies the same checked public inventory on every slot.
func (authority DerivedStartupAuthority) MaterialSHA256() string {
	if !authority.IsVerified() {
		return ""
	}
	return digestBytes(authority.binding.MaterialRecord)
}
func (authority DerivedStartupAuthority) SourceSHA256() string {
	if !authority.IsVerified() {
		return ""
	}
	return authority.binding.SourceSHA256
}
func (authority DerivedStartupAuthority) LinkMaterialRecord() []byte {
	if !authority.IsVerified() || authority.binding.Link == nil {
		return nil
	}
	return bytes.Clone(authority.binding.Link.MaterialRecord)
}

// RendererDerivation returns the exact renderer approved by the signed startup recipe.
func (authority DerivedStartupAuthority) RendererDerivation() string {
	if !authority.IsVerified() {
		return ""
	}
	return authority.template.Template().ControllerConfigDerivation
}

func (authority DerivedStartupAuthority) TrustedSigners() jsontext.Value {
	return bytes.Clone(authority.template.template.TrustedSigners)
}
func (authority DerivedStartupAuthority) Profile(slot string) (LaunchProfile, bool) {
	if !authority.IsVerified() {
		return LaunchProfile{}, false
	}
	for _, profile := range authority.binding.Manifest.Profiles {
		if profile.Slot == slot {
			return cloneProfile(profile), true
		}
	}
	return LaunchProfile{}, false
}
func (authority DerivedStartupAuthority) verifyStartupAuthority() error {
	if !authority.IsVerified() || authority.binding.Manifest.validateStructure(true) != nil {
		return ErrManifestInvalid
	}
	return nil
}
func (authority DerivedStartupAuthority) VerifyCurrent(ctx context.Context, now time.Time) error {
	if ctx == nil || !authority.IsVerified() || !time.Now().Before(authority.expires) {
		return ErrManifestInvalid
	}
	ctx, cancel := context.WithDeadline(ctx, authority.expires)
	defer cancel()
	_, err := VerifyDerivedStartupAuthority(ctx, authority.template, authority.client, authority.wire, now)
	return err
}

func DerivedStartupScope(manifest Manifest) trust.Scope {
	return trust.Scope{Domain: derivedStartupDomain, DeploymentID: manifest.DeploymentID, Cell: string(manifest.Cell), Environment: manifest.Environment, Role: "controller", Slot: manifest.Slot}
}

// RestoreDerivedStartupAuthority rechecks the original signatures and live CAS
// after a process handoff or disk restart. Public peers need no source escrow.
func RestoreDerivedStartupAuthority(ctx context.Context, grantWire []byte, anchor VerifiedBootstrapAnchor, roots trust.Keyring, client ObjectStorageClient, wire []byte, now time.Time) (DerivedStartupAuthority, error) {
	template, err := VerifyStartupTemplate(grantWire, roots, anchor, now)
	if err != nil {
		return DerivedStartupAuthority{}, err
	}
	return VerifyDerivedStartupAuthority(ctx, template, client, wire, now)
}

// LoadDerivedStartupAuthority discovers a joining slot's immutable public
// proof directly; first-boot metadata never needs a dynamic config payload.
func LoadDerivedStartupAuthority(ctx context.Context, template VerifiedStartupTemplate, client ObjectStorageClient, slot string, now time.Time) (DerivedStartupAuthority, error) {
	if ctx == nil || client == nil {
		return DerivedStartupAuthority{}, ErrManifestInvalid
	}
	ctx, cancel := template.currentReadContext(ctx)
	defer cancel()
	if template.VerifyCurrentContext(ctx, now) != nil || !slices.Contains(template.startupIdentity().ControllerSlots, slot) {
		return DerivedStartupAuthority{}, ErrManifestInvalid
	}
	domain := template.startupSourceDomain()
	key := startupSourceKey(template)
	response, err := client.GetObject(ociclient.RequestContext(ctx), objectstorage.GetObjectRequest{NamespaceName: new(domain.Namespace), BucketName: new(domain.HeadBucket), ObjectName: new(key)})
	if err != nil {
		return DerivedStartupAuthority{}, err
	}
	if response.Content == nil {
		return DerivedStartupAuthority{}, ErrManifestInvalid
	}
	defer response.Content.Close()
	wire, err := io.ReadAll(io.LimitReader(response.Content, 2<<20))
	var state struct {
		Startup map[string][]byte `json:"startup"`
	}
	if err != nil || len(wire) >= 2<<20 || json.Unmarshal(wire, &state) != nil {
		return DerivedStartupAuthority{}, ErrManifestInvalid
	}
	return VerifyDerivedStartupAuthority(ctx, template, client, state.Startup[slot], now)
}

func startupSourceKey(template VerifiedStartupTemplate) string {
	anchor := template.startupIdentity()
	scopeHash := digestBytes([]byte(template.InstallationID() + "\x00" + strings.ToLower(string(anchor.Cell))))
	return template.startupSourceDomain().Prefix + "/bootstrap/v2/material-source/" + scopeHash + ".json"
}

func (template VerifiedStartupTemplate) startupSourceDomain() StorageDomain {
	home, _ := template.anchor.FoundationScope()
	return home.StorageDomain
}

// VerifyDerivedStartupAuthority derives the object locator from signed identity;
// no caller-supplied path, Vault target or source digest selects authority.
func VerifyDerivedStartupAuthority(ctx context.Context, template VerifiedStartupTemplate, client ObjectStorageClient, wire []byte, now time.Time) (DerivedStartupAuthority, error) {
	deny := func(reason string) (DerivedStartupAuthority, error) {
		return DerivedStartupAuthority{}, fmt.Errorf("%w: derived startup %s", ErrManifestInvalid, reason)
	}
	if client == nil || ctx == nil || ctx.Err() != nil || len(wire) == 0 || len(wire) > MaxManifestBytes {
		return deny("current grant")
	}
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil {
		return deny("envelope")
	}
	ctx, cancelTemplate := template.currentReadContext(ctx)
	defer cancelTemplate()
	ctx, cancelEnvelope := context.WithDeadline(ctx, minTimeLink(envelope.ExpiresAt, template.ExpiresAt()))
	defer cancelEnvelope()
	if template.VerifyCurrentContext(ctx, now) != nil {
		return deny("current grant")
	}

	proof, err := decodeDerivedStartupEvidence(template.startupTemplateEvidence, wire, now)
	if err != nil {
		return DerivedStartupAuthority{}, err
	}
	expires := minTimeLink(envelope.ExpiresAt, template.ExpiresAt())
	authorityExpires := proof.authorityExpires
	binding, manifest := proof.binding, proof.binding.Manifest
	linkRefs := map[string]SecretReference{}
	if binding.Link != nil {
		link, err := VerifyStartupLink(ctx, template, client, *binding.Link, now)
		if err != nil {
			return deny("Link provenance")
		}
		expires = minTimeLink(expires, link.ExpiresAt())
		authorityExpires = minTimeLink(authorityExpires, link.AuthorityExpiresAt())
		var cancelLink context.CancelFunc
		ctx, cancelLink = context.WithDeadline(ctx, expires)
		defer cancelLink()
		evidence := link.Evidence()
		binding.Link = &evidence
		for _, ref := range link.References() {
			if linkRefs[ref.TargetFile].TargetFile != "" || !slices.Contains(manifest.Secrets, ref) {
				return deny("Link reference")
			}
			linkRefs[ref.TargetFile] = ref
		}
	}
	domain := template.startupSourceDomain()
	key := startupSourceKey(template)
	response, err := client.GetObject(ociclient.RequestContext(ctx), objectstorage.GetObjectRequest{NamespaceName: new(domain.Namespace), BucketName: new(domain.HeadBucket), ObjectName: new(key)})
	if err != nil {
		return deny("source read")
	}
	if response.Content == nil {
		return deny("source body")
	}
	defer response.Content.Close()
	stateWire, err := io.ReadAll(io.LimitReader(response.Content, 2<<20))
	if err != nil || len(stateWire) >= 2<<20 || response.ETag == nil || *response.ETag == "" {
		return deny("source revision")
	}

	proof.binding = binding
	if err := validateDerivedSourceEvidence(template.startupTemplateEvidence, proof, stateWire, linkRefs, now); err != nil {
		return DerivedStartupAuthority{}, err
	}
	if ctx.Err() != nil || template.currentLifetimeError() != nil || !time.Now().Before(expires) {
		return deny("authority lifetime")
	}
	return DerivedStartupAuthority{template: template, binding: binding, client: client, wire: proof.wire, digest: proof.digest, envelope: envelope, expires: expires, authorityExpires: authorityExpires, ledgerKey: proof.ledgerKey, peerKey: proof.peerKey}, nil
}

func derivedReceiptDomain(seed bool) string {
	if seed {
		return "terrascale.bootstrap.derived-seed-receipt"
	}
	return "terrascale.bootstrap.derived-peer-receipt"
}

// SignDerivedReceipt uses the registered source signer. It cannot mint a
// legacy root seed receipt or a fabricated root delegation.
func SignDerivedReceipt(authority DerivedStartupAuthority, facts InstanceFacts, issuedAt, expiresAt time.Time, key ed25519.PrivateKey) (trust.Envelope, error) {
	receipt, err := NewReceipt(authority, facts)
	if err != nil || len(key) != ed25519.PrivateKeySize || issuedAt.Before(authority.IssuedAt()) || expiresAt.After(authority.ExpiresAt()) {
		return trust.Envelope{}, ErrReceiptInvalid
	}
	seed := facts.Slot == authority.binding.Manifest.SeedSlot
	wantKey := authority.peerKey
	if seed {
		wantKey = authority.ledgerKey
	}
	if !bytes.Equal(key.Public().(ed25519.PublicKey), wantKey) {
		return trust.Envelope{}, ErrReceiptInvalid
	}
	envelope, err := signReceipt(receipt, derivedReceiptDomain(seed), issuedAt, expiresAt, key)
	if err != nil {
		return trust.Envelope{}, err
	}
	if authority.template.currentLifetimeError() != nil || !time.Now().Before(authority.ExpiresAt()) {
		return trust.Envelope{}, ErrReceiptInvalid
	}
	return envelope, nil
}

func verifyDerivedReceipt(envelope trust.Envelope, authority DerivedStartupAuthority, facts InstanceFacts, seed bool, now time.Time, policy trust.Policy) (VerifiedReceipt, error) {
	if authority.verifyStartupAuthority() != nil || !now.Before(authority.ExpiresAt()) {
		return VerifiedReceipt{}, ErrReceiptInvalid
	}
	receipt, err := verifyDerivedReceiptEvidence(envelope, authority.evidence(), facts, seed, now, policy)
	if err != nil {
		return VerifiedReceipt{}, err
	}
	return VerifiedReceipt{receipt: receipt, manifestDigest: authority.Digest(), issuedAt: envelope.IssuedAt, expiresAt: minTimeLink(envelope.ExpiresAt, authority.ExpiresAt()), verified: true}, nil
}

func (authority DerivedStartupAuthority) evidence() derivedStartupEvidence {
	return derivedStartupEvidence{binding: authority.binding, wire: bytes.Clone(authority.wire), digest: authority.digest, envelope: authority.envelope, authorityExpires: authority.authorityExpires, ledgerKey: bytes.Clone(authority.ledgerKey), peerKey: bytes.Clone(authority.peerKey)}
}

func verifyDerivedReceiptEvidence(envelope trust.Envelope, proof derivedStartupEvidence, facts InstanceFacts, seed bool, now time.Time, policy trust.Policy) (Receipt, error) {
	if proof.digest == "" || seed != (facts.Slot == proof.binding.Manifest.SeedSlot) || validateFactsAgainstManifest(proof.binding.Manifest, facts) != nil || envelope.IssuedAt.Before(proof.envelope.IssuedAt) || envelope.ExpiresAt.After(proof.authorityExpires) {
		return Receipt{}, ErrReceiptInvalid
	}
	key := proof.peerKey
	if seed {
		key = proof.ledgerKey
	}
	keyID, _ := trust.KeyID(key)
	manifest := proof.binding.Manifest
	expected := trust.Scope{Domain: derivedReceiptDomain(seed), DeploymentID: manifest.DeploymentID, Cell: string(manifest.Cell), Environment: manifest.Environment, Role: manifest.ControllerRole, Slot: facts.Slot}
	payload, err := trust.VerifyCurrent(envelope, expected, trust.Keyring{keyID: key}, now, policy)
	if err != nil {
		return Receipt{}, err
	}
	want, err := receiptForManifest(proof.binding.Manifest, proof.digest, facts)
	if err != nil {
		return Receipt{}, err
	}
	receipt, err := matchReceiptPayload(payload, want)
	if err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

// LedgerConfig retains the original buckets, floors, scope and exact domains.
// New source registration substitutes its sealed capability for a fixed root
// delegation; existing pinned delegations remain required and unchanged.
func (authority DerivedStartupAuthority) LedgerConfig(roots trust.Keyring) (LedgerConfig, error) {
	if authority.verifyStartupAuthority() != nil || len(roots) == 0 {
		return LedgerConfig{}, ErrRecordAuthorization
	}
	anchor := authority.template.startupIdentity()
	domain := anchor.StorageDomain
	config := LedgerConfig{DeploymentID: anchor.DeploymentID, Cell: anchor.Cell, ClusterID: anchor.ClusterID, InitialRegionIntentGeneration: anchor.InitialRegionIntentGeneration, InitialRegionIntentSHA256: anchor.InitialRegionIntentSHA256, Namespace: domain.Namespace, Bucket: domain.LedgerBucket, KMSKeyID: domain.LedgerKMSKeyOCID, Prefix: domain.Prefix, HeadBucket: domain.HeadBucket, HeadKMSKeyID: domain.HeadKMSKeyOCID, Environment: anchor.Environment, ControllerSlots: slices.Clone(anchor.ControllerSlots), AnchorExpiresAt: authority.ExpiresAt(), TrustRoots: roots, TrustPolicy: ManifestTrustPolicy(), DerivedStartup: new(authority)}
	if len(anchor.LedgerDelegationWire) != 0 {
		grant, err := authority.template.anchor.LedgerDelegation()
		if err != nil {
			return LedgerConfig{}, err
		}
		config.Delegations = []trust.VerifiedDelegation{grant}
	}
	return config, nil
}

func (authority DerivedStartupAuthority) AnchorDigest() string {
	return authority.template.anchor.Digest()
}

func (authority DerivedStartupAuthority) OpenLedger(ctx context.Context, roots trust.Keyring) (*Ledger, error) {
	if err := authority.VerifyCurrent(ctx, time.Now()); err != nil {
		return nil, err
	}
	config, err := authority.LedgerConfig(roots)
	if err != nil {
		return nil, err
	}
	return NewInstancePrincipalLedger(config.Cell, config)
}

// OpenLedgerWithClient keeps regional ledger traffic separate from the home
// source-CAS reader. Production passes the founder's guarded regional factory.
func (authority DerivedStartupAuthority) OpenLedgerWithClient(ctx context.Context, roots trust.Keyring, client ObjectStorageClient) (*Ledger, error) {
	if err := authority.VerifyCurrent(ctx, time.Now()); err != nil {
		return nil, err
	}
	config, err := authority.LedgerConfig(roots)
	if err != nil {
		return nil, err
	}
	return NewLedger(client, config)
}

func (authority DerivedStartupAuthority) VerifyLedgerKey(key ed25519.PublicKey) error {
	if authority.verifyStartupAuthority() != nil || !bytes.Equal(key, authority.ledgerKey) {
		return ErrRecordAuthorization
	}
	return nil
}

func (authority DerivedStartupAuthority) VerifyPeerKey(key ed25519.PublicKey) error {
	if authority.verifyStartupAuthority() != nil || !bytes.Equal(key, authority.peerKey) {
		return ErrRecordAuthorization
	}
	return nil
}

func (authority DerivedStartupAuthority) VerifyLedgerEnvelope(envelope trust.Envelope, scope trust.Scope, now time.Time) error {
	manifest := authority.binding.Manifest
	if authority.verifyStartupAuthority() != nil || !now.Before(authority.ExpiresAt()) || !slices.Contains(BootstrapLedgerCapabilityDomains(), scope.Domain) || scope.DeploymentID != manifest.DeploymentID || scope.Cell != string(manifest.Cell) || scope.Environment != manifest.Environment || scope.Role != manifest.ControllerRole || !slices.Contains(manifest.ControllerSlots, scope.Slot) || envelope.IssuedAt.Before(authority.IssuedAt()) || envelope.ExpiresAt.After(authority.AuthorityExpiresAt()) {
		return ErrRecordAuthorization
	}
	keyID, _ := trust.KeyID(authority.ledgerKey)
	_, err := trust.VerifyCurrent(envelope, scope, trust.Keyring{keyID: authority.ledgerKey}, now, ManifestTrustPolicy())
	return err
}
func (authority DerivedStartupAuthority) TemplateDigest() string {
	return authority.template.TemplateDigest()
}

// RestoreBoundDerivedStartupAuthority reconstructs schema-2 provenance after a
// process handoff using fresh protected grant and OCI binding observations.
func RestoreBoundDerivedStartupAuthority(ctx context.Context, factory *ociclient.Factory, grantWire []byte, anchor VerifiedBootstrapAnchor, roots trust.Keyring, client ObjectStorageClient, wire []byte, now time.Time) (DerivedStartupAuthority, error) {
	template, err := VerifyBoundStartupTemplate(ctx, factory, grantWire, roots, anchor, now)
	if err != nil {
		return DerivedStartupAuthority{}, err
	}
	return VerifyDerivedStartupAuthority(ctx, template, client, wire, now)
}

// derivedStartupEvidence is signed provenance without a current capability.
type derivedStartupEvidence struct {
	binding            DerivedStartupBinding
	wire               []byte
	digest             string
	envelope           trust.Envelope
	authorityExpires   time.Time
	ledgerKey, peerKey ed25519.PublicKey
	material           derivedMaterialEvidence
}

type derivedMaterialEvidence struct {
	Config    jsontext.Value `json:"config"`
	IssuedAt  time.Time      `json:"issuedAt"`
	ExpiresAt time.Time      `json:"expiresAt"`
	Public    struct {
		LedgerSignerPublicKey string `json:"ledgerSignerPublicKey"`
		PeerSignerPublicKey   string `json:"peerSignerPublicKey"`
	} `json:"public"`
	Files []struct {
		Name     string        `json:"name"`
		Purpose  SecretPurpose `json:"purpose"`
		Slot     string        `json:"slot"`
		SHA256   string        `json:"sha256"`
		MaxBytes int64         `json:"maxBytes"`
	} `json:"files"`
}

func decodeDerivedStartupEvidence(template startupTemplateEvidence, wire []byte, now time.Time) (derivedStartupEvidence, error) {
	deny := func(reason string) (derivedStartupEvidence, error) {
		return derivedStartupEvidence{}, fmt.Errorf("%w: derived startup %s", ErrManifestInvalid, reason)
	}
	if len(wire) == 0 || len(wire) > MaxManifestBytes {
		return deny("envelope")
	}
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil {
		return deny("envelope")
	}
	var binding DerivedStartupBinding
	if json.Unmarshal(envelope.Payload, &binding, json.RejectUnknownMembers(true)) != nil || binding.SchemaVersion != 1 || binding.GrantSHA256 != template.grantDigest || binding.TemplateSHA256 != template.templateDigest || !validDigest(binding.SourceSHA256) || binding.Manifest.validateStructure(true) != nil {
		return deny("binding")
	}
	manifest := binding.Manifest
	if err := template.ValidateProjection(manifest); err != nil {
		return deny("template projection")
	}
	var record derivedMaterialEvidence
	if json.Unmarshal(binding.MaterialRecord, &record) != nil || digestBytes(record.Config) != template.planDigest || record.IssuedAt.IsZero() || !now.Before(record.ExpiresAt) {
		return deny("public material")
	}
	ledgerKey, keyErr := base64.StdEncoding.Strict().DecodeString(record.Public.LedgerSignerPublicKey)
	peerKey, peerErr := base64.StdEncoding.Strict().DecodeString(record.Public.PeerSignerPublicKey)
	if keyErr != nil || peerErr != nil || len(ledgerKey) != ed25519.PublicKeySize || len(peerKey) != ed25519.PublicKeySize {
		return deny("source keys")
	}
	keyID, _ := trust.KeyID(ledgerKey)
	anchor := template.identity
	if len(anchor.LedgerDelegationWire) != 0 {
		pinEnvelope, err := trust.DecodeEnvelope(anchor.LedgerDelegationWire)
		if err != nil {
			return deny("pinned ledger signer")
		}
		pin, err := decodeBootstrapLedgerDelegation(pinEnvelope)
		if err != nil || pin.SubjectKeyID != keyID {
			return deny("pinned ledger signer")
		}
	} else if anchor.InitialSourceRegistration == nil {
		return deny("source registration")
	}
	if _, err := trust.VerifyCurrent(envelope, DerivedStartupScope(manifest), trust.Keyring{keyID: ledgerKey}, now, ManifestTrustPolicy()); err != nil || envelope.IssuedAt.Before(template.issuedAt) || envelope.IssuedAt.Before(record.IssuedAt) || envelope.ExpiresAt.After(template.authorityExpiresAt) || envelope.ExpiresAt.After(record.ExpiresAt) {
		return deny("source signature")
	}

	return derivedStartupEvidence{binding: binding, wire: bytes.Clone(wire), digest: digestBytes(wire), envelope: envelope, authorityExpires: envelope.ExpiresAt, ledgerKey: bytes.Clone(ledgerKey), peerKey: bytes.Clone(peerKey), material: record}, nil
}

func validateDerivedSourceEvidence(template startupTemplateEvidence, proof derivedStartupEvidence, stateWire []byte, linkRefs map[string]SecretReference, now time.Time) error {
	deny := func(reason string) error { return fmt.Errorf("%w: derived startup %s", ErrManifestInvalid, reason) }
	binding, envelope, record := proof.binding, proof.envelope, proof.material
	manifest, anchor, wire := binding.Manifest, template.identity, proof.wire
	ledgerKey := proof.ledgerKey
	keyID, _ := trust.KeyID(ledgerKey)
	var state struct {
		SchemaVersion  int    `json:"schemaVersion"`
		Kind           string `json:"kind"`
		InstallationID string `json:"installationId"`
		Cell           string `json:"cell"`
		Generation     uint64 `json:"generation"`
		PlanSHA256     string `json:"planSha256"`
		Reference      struct {
			SecretOCID string `json:"secretOcid"`
			SHA256     string `json:"sha256"`
			MaxBytes   int64  `json:"maxBytes"`
		} `json:"reference"`
		Journal []byte             `json:"journal"`
		Target  StartupVaultTarget `json:"target"`
		Startup map[string][]byte  `json:"startup"`
	}
	if json.Unmarshal(stateWire, &state) != nil || state.SchemaVersion != 1 || state.Kind != "" || state.Target != template.escrow || state.InstallationID != template.installationID || state.Cell != strings.ToLower(string(anchor.Cell)) || state.Generation == 0 || state.Generation > template.generation || state.PlanSHA256 != template.planDigest || !isOCID(state.Reference.SecretOCID, "vaultsecret") || state.Reference.SHA256 != binding.SourceSHA256 || state.Reference.MaxBytes <= 0 || state.Reference.MaxBytes > 25<<10 || len(state.Startup) != len(anchor.ControllerSlots) || !bytes.Equal(state.Startup[manifest.Slot], wire) {
		return deny("immutable source binding")
	}
	for _, slot := range anchor.ControllerSlots {
		siblingEnvelope, err := trust.DecodeEnvelope(state.Startup[slot])
		if err != nil {
			return deny("complete slot binding")
		}
		var sibling DerivedStartupBinding
		if json.Unmarshal(siblingEnvelope.Payload, &sibling, json.RejectUnknownMembers(true)) != nil || sibling.SchemaVersion != binding.SchemaVersion || sibling.GrantSHA256 != binding.GrantSHA256 || sibling.TemplateSHA256 != binding.TemplateSHA256 || sibling.SourceSHA256 != binding.SourceSHA256 || !bytes.Equal(sibling.MaterialRecord, binding.MaterialRecord) || sibling.Manifest.Slot != slot || template.ValidateProjection(sibling.Manifest) != nil {
			return deny("sibling provenance")
		}
		refs, _ := json.Marshal(sibling.Manifest.Secrets, json.Deterministic(true))
		ownRefs, _ := json.Marshal(manifest.Secrets, json.Deterministic(true))
		linkWire, _ := json.Marshal(binding.Link, json.Deterministic(true))
		siblingLinkWire, _ := json.Marshal(sibling.Link, json.Deterministic(true))
		if !bytes.Equal(refs, ownRefs) || !bytes.Equal(linkWire, siblingLinkWire) || !siblingEnvelope.IssuedAt.Equal(envelope.IssuedAt) || !siblingEnvelope.ExpiresAt.Equal(envelope.ExpiresAt) {
			return deny("sibling material")
		}
		if _, err := trust.VerifyCurrent(siblingEnvelope, DerivedStartupScope(sibling.Manifest), trust.Keyring{keyID: ledgerKey}, now, ManifestTrustPolicy()); err != nil {
			return deny("sibling signature")
		}
	}
	var journal struct {
		SchemaVersion int `json:"schemaVersion"`
		Target        struct {
			CompartmentOCID string `json:"compartmentOcid"`
			VaultOCID       string `json:"vaultOcid"`
			KMSKeyOCID      string `json:"kmsKeyOcid"`
		} `json:"target"`
		MaterialSHA256 string `json:"materialSha256"`
		Entries        []struct {
			FileName   string `json:"fileName"`
			SecretOCID string `json:"secretOcid"`
			Verified   bool   `json:"verified"`
		} `json:"entries"`
	}
	target := template.vault
	if json.Unmarshal(state.Journal, &journal) != nil || journal.SchemaVersion != 1 || journal.MaterialSHA256 != digestBytes(binding.MaterialRecord) || journal.Target.CompartmentOCID != target.CompartmentOCID || journal.Target.VaultOCID != target.VaultOCID || journal.Target.KMSKeyOCID != target.KMSKeyOCID {
		return deny("publication target")
	}
	count, overrides := 0, 0
	for _, file := range record.Files {
		if file.Purpose == "owner-only" {
			continue
		}
		count++
		index := slices.IndexFunc(manifest.Secrets, func(ref SecretReference) bool { return ref.TargetFile == file.Name })
		if index < 0 {
			return deny("publication reference")
		}
		ref := manifest.Secrets[index]
		if replacement, ok := linkRefs[file.Name]; ok {
			if file.Name != "cell.jwt" || manifest.Cell != "GRU" || ref != replacement {
				return deny("Link override")
			}
			overrides++
			if !slices.ContainsFunc(journal.Entries, func(entry struct {
				FileName   string `json:"fileName"`
				SecretOCID string `json:"secretOcid"`
				Verified   bool   `json:"verified"`
			}) bool {
				return entry.FileName == file.Name && entry.Verified && isOCID(entry.SecretOCID, "vaultsecret")
			}) {
				return deny("regional publication override")
			}
			continue
		}
		entry := slices.IndexFunc(journal.Entries, func(entry struct {
			FileName   string `json:"fileName"`
			SecretOCID string `json:"secretOcid"`
			Verified   bool   `json:"verified"`
		}) bool {
			return entry.FileName == file.Name && entry.Verified && entry.SecretOCID == ref.SecretOCID
		})
		if entry < 0 || ref.Purpose != file.Purpose || ref.Slot != file.Slot || ref.SHA256 != file.SHA256 || ref.MaxBytes != file.MaxBytes || ref.VersionNumber != 1 {
			return deny("publication contents")
		}
	}
	if count+len(linkRefs)-overrides != len(manifest.Secrets) || count != len(journal.Entries) {
		return deny("publication completeness")
	}
	return nil
}
