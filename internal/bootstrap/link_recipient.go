package bootstrap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// LinkRecipient is a public regional source bound to the same signed foundation
// registration as GRU. It conveys only an exact Link delivery destination.
type LinkRecipient struct {
	regional, home                               VerifiedRegionalSource
	sourceSHA256, homeSHA256, bindingSHA256, key string
}

// VerifyLinkRecipient checks both current public source objects. Neither source
// escrow nor a caller-selected Vault or object path supplies recipient authority.
func VerifyLinkRecipient(ctx context.Context, regional, home VerifiedRegionalSource, now time.Time) (LinkRecipient, error) {
	if ctx.Err() != nil || now.IsZero() || !regional.IsVerified() || !home.IsVerified() {
		return LinkRecipient{}, ErrManifestInvalid
	}
	if err := regional.VerifyCurrent(ctx, now); err != nil {
		return LinkRecipient{}, err
	}
	if err := home.VerifyCurrent(ctx, now); err != nil {
		return LinkRecipient{}, err
	}
	recipient, issuer := regional.Manifest(), home.Manifest()
	rt, ht := regional.template, home.template
	if issuer.Cell != oci.RegionGRU || recipient.Cell == oci.RegionGRU || rt.InstallationID() != ht.InstallationID() || rt.Generation() != ht.Generation() || rt.GrantDigest() != ht.GrantDigest() || recipient.DeploymentID != issuer.DeploymentID || recipient.Environment != issuer.Environment || regional.StorageDomain() != home.StorageDomain() || recipient.ClusterID == issuer.ClusterID || rt.startupIdentity().InitialSourceRegistration == nil || ht.startupIdentity().InitialSourceRegistration == nil {
		return LinkRecipient{}, ErrManifestInvalid
	}
	sourceSHA, homeSHA := digestBytes(regional.MaterialRecord()), digestBytes(home.MaterialRecord())
	bindingWire, err := json.Marshal([]string{"spoke-link-v1", sourceSHA, homeSHA}, json.Deterministic(true))
	if err != nil {
		return LinkRecipient{}, err
	}
	binding := digestBytes(bindingWire)
	scope := sha256.Sum256([]byte(rt.InstallationID() + "\x00" + strings.ToLower(string(recipient.Cell)) + "\x00spoke-link-v1\x00" + binding))
	key := home.StorageDomain().Prefix + "/bootstrap/v2/material-source/spoke-link-" + hex.EncodeToString(scope[:]) + ".json"
	return LinkRecipient{regional: regional, home: home, sourceSHA256: sourceSHA, homeSHA256: homeSHA, bindingSHA256: binding, key: key}, nil
}

func (recipient LinkRecipient) IsVerified() bool {
	return recipient.key != "" && recipient.regional.IsVerified() && recipient.home.IsVerified()
}
func (recipient LinkRecipient) VerifyCurrent(ctx context.Context, now time.Time) error {
	if !recipient.IsVerified() {
		return ErrManifestInvalid
	}
	current, err := VerifyLinkRecipient(ctx, recipient.regional, recipient.home, now)
	if err != nil {
		return err
	}
	if current.sourceSHA256 != recipient.sourceSHA256 || current.homeSHA256 != recipient.homeSHA256 || current.bindingSHA256 != recipient.bindingSHA256 || current.key != recipient.key {
		return ErrManifestInvalid
	}
	return nil
}
func (recipient LinkRecipient) InstallationID() string {
	return recipient.regional.template.InstallationID()
}
func (recipient LinkRecipient) Generation() uint64           { return recipient.regional.template.Generation() }
func (recipient LinkRecipient) GrantDigest() string          { return recipient.regional.template.GrantDigest() }
func (recipient LinkRecipient) GrantWire() []byte            { return recipient.regional.template.GrantWire() }
func (recipient LinkRecipient) Cell() oci.Region             { return recipient.regional.Manifest().Cell }
func (recipient LinkRecipient) SourceSHA256() string         { return recipient.sourceSHA256 }
func (recipient LinkRecipient) HomeSHA256() string           { return recipient.homeSHA256 }
func (recipient LinkRecipient) BindingSHA256() string        { return recipient.bindingSHA256 }
func (recipient LinkRecipient) LinkObjectKey() string        { return recipient.key }
func (recipient LinkRecipient) StorageDomain() StorageDomain { return recipient.home.StorageDomain() }
func (recipient LinkRecipient) VaultTarget() StartupVaultTarget {
	return recipient.regional.template.VaultTarget()
}
func (recipient LinkRecipient) MaterialRecord() []byte { return recipient.regional.MaterialRecord() }
func (recipient LinkRecipient) ExpiresAt() time.Time {
	return minTimeLink(recipient.regional.ExpiresAt(), recipient.home.ExpiresAt())
}

// VerifyHome binds a recovered home inventory to the public home proof without
// exposing the private source or treating a hostname as an admission record.
func (recipient LinkRecipient) VerifyHome(metadata []byte) error {
	if !recipient.IsVerified() || !bytes.Equal(metadata, recipient.home.MaterialRecord()) {
		return ErrManifestInvalid
	}
	return nil
}
func minTimeLink(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// SignLinkDelivery uses the already registered GRU source ledger key. The
// envelope carries public inventories and regional Vault references only.
func SignLinkDelivery(recipient LinkRecipient, payload []byte, key ed25519.PrivateKey, issuedAt, expiresAt time.Time) ([]byte, error) {
	if !recipient.IsVerified() || len(key) != ed25519.PrivateKeySize || !bytes.Equal(key.Public().(ed25519.PublicKey), recipient.home.ledgerKey) || len(payload) == 0 || len(payload) > 48<<10 || issuedAt.IsZero() || !expiresAt.After(issuedAt) || expiresAt.After(recipient.ExpiresAt()) {
		return nil, ErrManifestInvalid
	}
	envelope, err := trust.Sign(payload, recipient.deliveryScope(), issuedAt, expiresAt, key)
	if err != nil {
		return nil, err
	}
	return trust.EncodeEnvelope(envelope)
}

// VerifyLinkDelivery rechecks both source registrations before trusting the
// home's public delivery. A regional founder cannot sign its own global grant.
func VerifyLinkDelivery(ctx context.Context, recipient LinkRecipient, wire []byte, now time.Time) ([]byte, error) {
	if len(wire) == 0 || len(wire) > 64<<10 || recipient.VerifyCurrent(ctx, now) != nil {
		return nil, ErrManifestInvalid
	}
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil {
		return nil, err
	}
	keyID, err := trust.KeyID(recipient.home.ledgerKey)
	if err != nil {
		return nil, err
	}
	payload, err := trust.VerifyCurrent(envelope, recipient.deliveryScope(), trust.Keyring{keyID: recipient.home.ledgerKey}, now, ManifestTrustPolicy())
	if err != nil || envelope.ExpiresAt.After(recipient.ExpiresAt()) {
		return nil, ErrManifestInvalid
	}
	return payload, nil
}
func (recipient LinkRecipient) deliveryScope() trust.Scope {
	manifest := recipient.regional.Manifest()
	return trust.Scope{Domain: "terrascale.bootstrap.link-delivery", DeploymentID: manifest.DeploymentID, Cell: string(manifest.Cell), Environment: manifest.Environment, Role: "link", Slot: recipient.bindingSHA256}
}

// RegionalSourceTemplate retains the root-signed recipe used for this admission.
func (recipient LinkRecipient) RegionalSourceTemplate() VerifiedStartupTemplate {
	return recipient.regional.Template()
}

func (recipient LinkRecipient) OriginalActor() SourceInventoryActor {
	return recipient.regional.OriginalActor()
}
