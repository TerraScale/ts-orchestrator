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
	SchemaVersion  int      `json:"schemaVersion"`
	GrantSHA256    string   `json:"grantSha256"`
	TemplateSHA256 string   `json:"templateSha256"`
	SourceSHA256   string   `json:"sourceSha256"`
	MaterialRecord []byte   `json:"materialRecord"`
	Manifest       Manifest `json:"manifest"`
}

// DerivedStartupAuthority retains distinct provenance: the original signed
// grant, exact source CAS binding and source-key signature, not a root manifest.
type DerivedStartupAuthority struct {
	template           VerifiedStartupTemplate
	binding            DerivedStartupBinding
	client             ObjectStorageClient
	wire               []byte
	digest             string
	envelope           trust.Envelope
	ledgerKey, peerKey ed25519.PublicKey
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
func (authority DerivedStartupAuthority) ExpiresAt() time.Time { return authority.envelope.ExpiresAt }
func (authority DerivedStartupAuthority) Wire() []byte         { return bytes.Clone(authority.wire) }
func (authority DerivedStartupAuthority) GrantWire() []byte    { return authority.template.GrantWire() }
func (authority DerivedStartupAuthority) MaterialRecord() []byte {
	return bytes.Clone(authority.binding.MaterialRecord)
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
	if client == nil || template.VerifyCurrent(now) != nil || !slices.Contains(template.startupIdentity().ControllerSlots, slot) {
		return DerivedStartupAuthority{}, ErrManifestInvalid
	}
	domain := template.startupIdentity().StorageDomain
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
	return anchor.StorageDomain.Prefix + "/bootstrap/v2/material-source/" + scopeHash + ".json"
}

// VerifyDerivedStartupAuthority derives the object locator from signed identity;
// no caller-supplied path, Vault target or source digest selects authority.
func VerifyDerivedStartupAuthority(ctx context.Context, template VerifiedStartupTemplate, client ObjectStorageClient, wire []byte, now time.Time) (DerivedStartupAuthority, error) {
	deny := func(reason string) (DerivedStartupAuthority, error) {
		return DerivedStartupAuthority{}, fmt.Errorf("%w: derived startup %s", ErrManifestInvalid, reason)
	}
	if client == nil || ctx.Err() != nil || template.VerifyCurrent(now) != nil || len(wire) == 0 || len(wire) > MaxManifestBytes {
		return deny("current grant")
	}
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil {
		return deny("envelope")
	}
	var binding DerivedStartupBinding
	if json.Unmarshal(envelope.Payload, &binding, json.RejectUnknownMembers(true)) != nil || binding.SchemaVersion != 1 || binding.GrantSHA256 != template.GrantDigest() || binding.TemplateSHA256 != template.TemplateDigest() || !validDigest(binding.SourceSHA256) || binding.Manifest.validateStructure(true) != nil {
		return deny("binding")
	}
	manifest := binding.Manifest
	if err := template.ValidateProjection(manifest); err != nil {
		return deny("template projection")
	}
	var record struct {
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
	if json.Unmarshal(binding.MaterialRecord, &record) != nil || digestBytes(record.Config) != template.PlanDigest() || record.IssuedAt.IsZero() || !now.Before(record.ExpiresAt) {
		return deny("public material")
	}
	ledgerKey, keyErr := base64.StdEncoding.Strict().DecodeString(record.Public.LedgerSignerPublicKey)
	peerKey, peerErr := base64.StdEncoding.Strict().DecodeString(record.Public.PeerSignerPublicKey)
	if keyErr != nil || peerErr != nil || len(ledgerKey) != ed25519.PublicKeySize || len(peerKey) != ed25519.PublicKeySize {
		return deny("source keys")
	}
	keyID, _ := trust.KeyID(ledgerKey)
	anchor := template.startupIdentity()
	if len(anchor.LedgerDelegationWire) != 0 {
		delegation, grantErr := template.anchor.LedgerDelegation()
		if grantErr != nil || delegation.SubjectKeyID() != keyID {
			return deny("pinned ledger signer")
		}
	} else if anchor.InitialSourceRegistration == nil {
		return deny("source registration")
	}
	if _, err := trust.VerifyCurrent(envelope, DerivedStartupScope(manifest), trust.Keyring{keyID: ledgerKey}, now, ManifestTrustPolicy()); err != nil || envelope.IssuedAt.Before(template.IssuedAt()) || envelope.IssuedAt.Before(record.IssuedAt) || envelope.ExpiresAt.After(template.ExpiresAt()) || envelope.ExpiresAt.After(record.ExpiresAt) {
		return deny("source signature")
	}
	domain := anchor.StorageDomain
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
	if json.Unmarshal(stateWire, &state) != nil || state.SchemaVersion != 1 || state.Kind != "" || state.Target != template.escrow || state.InstallationID != template.InstallationID() || state.Cell != strings.ToLower(string(anchor.Cell)) || state.Generation == 0 || state.Generation > template.Generation() || state.PlanSHA256 != template.PlanDigest() || !isOCID(state.Reference.SecretOCID, "vaultsecret") || state.Reference.SHA256 != binding.SourceSHA256 || state.Reference.MaxBytes <= 0 || state.Reference.MaxBytes > 25<<10 || len(state.Startup) != len(anchor.ControllerSlots) || !bytes.Equal(state.Startup[manifest.Slot], wire) {
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
		if !bytes.Equal(refs, ownRefs) || !siblingEnvelope.IssuedAt.Equal(envelope.IssuedAt) || !siblingEnvelope.ExpiresAt.Equal(envelope.ExpiresAt) {
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
	target := template.VaultTarget()
	if json.Unmarshal(state.Journal, &journal) != nil || journal.SchemaVersion != 1 || journal.MaterialSHA256 != digestBytes(binding.MaterialRecord) || journal.Target.CompartmentOCID != target.CompartmentOCID || journal.Target.VaultOCID != target.VaultOCID || journal.Target.KMSKeyOCID != target.KMSKeyOCID {
		return deny("publication target")
	}
	count := 0
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
	if count != len(manifest.Secrets) || count != len(journal.Entries) {
		return deny("publication completeness")
	}
	return DerivedStartupAuthority{template: template, binding: binding, client: client, wire: bytes.Clone(wire), digest: digestBytes(wire), envelope: envelope, ledgerKey: bytes.Clone(ledgerKey), peerKey: bytes.Clone(peerKey)}, nil
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
	return signReceipt(receipt, derivedReceiptDomain(seed), issuedAt, expiresAt, key)
}

func verifyDerivedReceipt(envelope trust.Envelope, authority DerivedStartupAuthority, facts InstanceFacts, seed bool, now time.Time, policy trust.Policy) (VerifiedReceipt, error) {
	if authority.verifyStartupAuthority() != nil || seed != (facts.Slot == authority.binding.Manifest.SeedSlot) || validateFactsAgainstManifest(authority.binding.Manifest, facts) != nil || envelope.IssuedAt.Before(authority.IssuedAt()) || envelope.ExpiresAt.After(authority.ExpiresAt()) {
		return VerifiedReceipt{}, ErrReceiptInvalid
	}
	key := authority.peerKey
	if seed {
		key = authority.ledgerKey
	}
	keyID, _ := trust.KeyID(key)
	manifest := authority.binding.Manifest
	expected := trust.Scope{Domain: derivedReceiptDomain(seed), DeploymentID: manifest.DeploymentID, Cell: string(manifest.Cell), Environment: manifest.Environment, Role: manifest.ControllerRole, Slot: facts.Slot}
	payload, err := trust.VerifyCurrent(envelope, expected, trust.Keyring{keyID: key}, now, policy)
	if err != nil {
		return VerifiedReceipt{}, err
	}
	want, err := NewReceipt(authority, facts)
	if err != nil {
		return VerifiedReceipt{}, err
	}
	receipt, err := matchReceiptPayload(payload, want)
	if err != nil {
		return VerifiedReceipt{}, err
	}
	return VerifiedReceipt{receipt: receipt, manifestDigest: authority.Digest(), issuedAt: envelope.IssuedAt, expiresAt: envelope.ExpiresAt, verified: true}, nil
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
	return NewLedger(authority.client, config)
}

func (authority DerivedStartupAuthority) VerifyLedgerKey(key ed25519.PublicKey) error {
	if authority.verifyStartupAuthority() != nil || !bytes.Equal(key, authority.ledgerKey) {
		return ErrRecordAuthorization
	}
	return nil
}

func (authority DerivedStartupAuthority) VerifyLedgerEnvelope(envelope trust.Envelope, scope trust.Scope, now time.Time) error {
	manifest := authority.binding.Manifest
	if authority.verifyStartupAuthority() != nil || !slices.Contains(BootstrapLedgerCapabilityDomains(), scope.Domain) || scope.DeploymentID != manifest.DeploymentID || scope.Cell != string(manifest.Cell) || scope.Environment != manifest.Environment || scope.Role != manifest.ControllerRole || !slices.Contains(manifest.ControllerSlots, scope.Slot) || envelope.IssuedAt.Before(authority.IssuedAt()) || envelope.ExpiresAt.After(authority.ExpiresAt()) {
		return ErrRecordAuthorization
	}
	keyID, _ := trust.KeyID(authority.ledgerKey)
	_, err := trust.VerifyCurrent(envelope, scope, trust.Keyring{keyID: authority.ledgerKey}, now, ManifestTrustPolicy())
	return err
}
func (authority DerivedStartupAuthority) TemplateDigest() string {
	return authority.template.TemplateDigest()
}
