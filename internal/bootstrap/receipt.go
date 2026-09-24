package bootstrap

import (
	"crypto/ed25519"
	"fmt"
	"slices"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

// Receipt binds a signed bootstrap intent and root-authorized launch profile
// to one exact instance created after the manifest was signed.
type Receipt struct {
	SchemaVersion        int        `json:"schemaVersion"`
	DeploymentID         string     `json:"deploymentId"`
	Environment          string     `json:"environment"`
	ClusterID            string     `json:"clusterId"`
	Cell                 oci.Region `json:"cell"`
	OCIRegion            string     `json:"ociRegion"`
	Role                 string     `json:"role"`
	Slot                 string     `json:"slot"`
	InstanceOCID         string     `json:"instanceOcid"`
	CompartmentOCID      string     `json:"compartmentOcid"`
	ImageOCID            string     `json:"imageOcid"`
	CreateKey            string     `json:"createKey"`
	IntentSHA256         string     `json:"intentSha256"`
	ManifestDigest       string     `json:"manifestDigest"`
	ManifestIntentSHA256 string     `json:"manifestIntentSha256"`
	IntentGeneration     uint64     `json:"intentGeneration"`
	ProfileSHA256        string     `json:"profileSha256"`
}

// InstanceFacts is assembled from authenticated OCI GetInstance/VNIC
// observations and the exact immutable launch-intent record. A caller must not
// fill it from instance tags or an untrusted receipt.
type InstanceFacts struct {
	DeploymentID    string
	Environment     string
	ClusterID       string
	Cell            oci.Region
	OCIRegion       string
	Role            string
	Slot            string
	InstanceOCID    string
	CompartmentOCID string
	ImageOCID       string
	CreateKey       string
	IntentSHA256    string
	Profile         LaunchProfile
}

// VerifiedReceipt is constructed only after current signature verification and
// exact comparison with caller-authenticated instance and intent facts.
type VerifiedReceipt struct {
	receipt        Receipt
	manifestDigest string
	issuedAt       time.Time
	expiresAt      time.Time
	verified       bool
}

// Receipt returns a value copy of the verified receipt.
func (verified VerifiedReceipt) Receipt() Receipt { return verified.receipt }

// InstanceOCID returns the exact verified instance identity.
func (verified VerifiedReceipt) InstanceOCID() string { return verified.receipt.InstanceOCID }

// Slot returns the exact verified controller slot.
func (verified VerifiedReceipt) Slot() string { return verified.receipt.Slot }

// NewReceipt constructs a receipt only when launch, manifest, and observed
// instance facts agree exactly. The observed profile must include the exact
// network attachments observed from OCI, not only launch-request fields.
func NewReceipt(manifest VerifiedManifest, facts InstanceFacts) (Receipt, error) {
	if err := validateVerifiedManifest(manifest); err != nil {
		return Receipt{}, err
	}
	profile, ok := manifest.Profile(facts.Slot)
	if !ok || !sameProfile(profile, facts.Profile) {
		return Receipt{}, fmt.Errorf("%w: observed OCI launch profile differs from the manifest", ErrIdentityMismatch)
	}
	if err := validateFacts(manifest, facts); err != nil {
		return Receipt{}, err
	}
	profileDigest, err := launchProfileDigest(profile)
	if err != nil {
		return Receipt{}, err
	}
	return Receipt{
		SchemaVersion: ReceiptSchemaVersion, DeploymentID: manifest.manifest.DeploymentID,
		Environment: manifest.manifest.Environment, ClusterID: manifest.manifest.ClusterID,
		Cell: manifest.manifest.Cell, OCIRegion: manifest.manifest.OCIRegion,
		Role: manifest.manifest.ControllerRole, Slot: facts.Slot, InstanceOCID: facts.InstanceOCID,
		CompartmentOCID: profile.CompartmentOCID, ImageOCID: manifest.manifest.ImageOCID,
		CreateKey: facts.CreateKey, IntentSHA256: facts.IntentSHA256,
		ManifestDigest: manifest.digest, ManifestIntentSHA256: manifest.manifest.IntentSHA256,
		IntentGeneration: manifest.manifest.IntentGeneration, ProfileSHA256: profileDigest,
	}, nil
}

// SignSeedReceipt creates a root-signed receipt for the exact seed instance.
func SignSeedReceipt(manifest VerifiedManifest, facts InstanceFacts, issuedAt, expiresAt time.Time, rootPrivateKey ed25519.PrivateKey) (trust.Envelope, error) {
	receipt, err := NewReceipt(manifest, facts)
	if err != nil {
		return trust.Envelope{}, err
	}
	if receipt.Slot != manifest.manifest.SeedSlot {
		return trust.Envelope{}, fmt.Errorf("%w: seed receipt is not for the manifest seed slot", ErrReceiptInvalid)
	}
	if !receiptIntervalWithinManifest(manifest, issuedAt, expiresAt) {
		return trust.Envelope{}, fmt.Errorf("%w: receipt validity exceeds its signed manifest", ErrReceiptInvalid)
	}
	return signReceipt(receipt, seedReceiptDomain, issuedAt, expiresAt, rootPrivateKey)
}

// SignPeerReceipt creates a founder-key-signed receipt only for a peer slot
// delegated by the root-signed manifest.
func SignPeerReceipt(manifest VerifiedManifest, facts InstanceFacts, issuedAt, expiresAt time.Time, founderPrivateKey ed25519.PrivateKey) (trust.Envelope, error) {
	receipt, err := NewReceipt(manifest, facts)
	if err != nil {
		return trust.Envelope{}, err
	}
	if !manifest.hasDelegation || receipt.Slot == manifest.manifest.SeedSlot {
		return trust.Envelope{}, fmt.Errorf("%w: peer receipt is not authorized for this manifest slot", ErrReceiptInvalid)
	}
	if !receiptIntervalWithinManifest(manifest, issuedAt, expiresAt) {
		return trust.Envelope{}, fmt.Errorf("%w: receipt validity exceeds its signed manifest", ErrReceiptInvalid)
	}
	if len(founderPrivateKey) != ed25519.PrivateKeySize {
		return trust.Envelope{}, fmt.Errorf("%w: invalid peer signer key", ErrReceiptInvalid)
	}
	keyID, err := trust.KeyID(founderPrivateKey.Public().(ed25519.PublicKey))
	if err != nil {
		return trust.Envelope{}, err
	}
	if keyID != manifest.delegation.SubjectKeyID() {
		return trust.Envelope{}, fmt.Errorf("%w: peer signer key differs from root delegation", ErrReceiptInvalid)
	}
	return signReceipt(receipt, peerReceiptDomain, issuedAt, expiresAt, founderPrivateKey)
}

// VerifySeedReceipt verifies root authorization and exact seed instance facts.
func VerifySeedReceipt(envelope trust.Envelope, manifest VerifiedManifest, roots trust.Keyring, facts InstanceFacts, now time.Time, policy trust.Policy) (VerifiedReceipt, error) {
	return verifyReceipt(envelope, manifest, roots, facts, seedReceiptDomain, now, policy)
}

// VerifyPeerReceipt verifies the root-delegated founder key and exact peer
// instance facts. A peer receipt cannot authorize the seed slot.
func VerifyPeerReceipt(envelope trust.Envelope, manifest VerifiedManifest, facts InstanceFacts, now time.Time, policy trust.Policy) (VerifiedReceipt, error) {
	if !manifest.hasDelegation {
		return VerifiedReceipt{}, fmt.Errorf("%w: manifest has no peer receipt delegation", ErrReceiptInvalid)
	}
	return verifyReceipt(envelope, manifest, nil, facts, peerReceiptDomain, now, policy)
}

// ReceiptPayload strictly decodes a receipt for tools that already verified
// its signature. Runtime code should call VerifySeedReceipt or VerifyPeerReceipt.
func ReceiptPayload(payload []byte) (Receipt, error) {
	if len(payload) == 0 || len(payload) > MaxReceiptBytes {
		return Receipt{}, fmt.Errorf("%w: receipt size", ErrReceiptInvalid)
	}
	var receipt Receipt
	if err := protocol.DecodeStrict(payload, &receipt, MaxReceiptBytes); err != nil {
		return Receipt{}, fmt.Errorf("decode bootstrap receipt: %w", err)
	}
	if err := receipt.validate(); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

func signReceipt(receipt Receipt, domain string, issuedAt, expiresAt time.Time, privateKey ed25519.PrivateKey) (trust.Envelope, error) {
	if err := receipt.validate(); err != nil {
		return trust.Envelope{}, err
	}
	payload, err := trust.EncodePayload(receipt)
	if err != nil {
		return trust.Envelope{}, err
	}
	scope := trust.Scope{
		Domain: domain, DeploymentID: receipt.DeploymentID, Cell: string(receipt.Cell),
		Environment: receipt.Environment, Role: receipt.Role, Slot: receipt.Slot,
	}
	return trust.Sign(payload, scope, issuedAt, expiresAt, privateKey)
}

func verifyReceipt(envelope trust.Envelope, manifest VerifiedManifest, roots trust.Keyring, facts InstanceFacts, domain string, now time.Time, policy trust.Policy) (VerifiedReceipt, error) {
	if err := validateVerifiedManifest(manifest); err != nil {
		return VerifiedReceipt{}, err
	}
	if err := validateFacts(manifest, facts); err != nil {
		return VerifiedReceipt{}, err
	}
	if domain == seedReceiptDomain && facts.Slot != manifest.manifest.SeedSlot {
		return VerifiedReceipt{}, fmt.Errorf("%w: seed receipt targets a peer slot", ErrReceiptInvalid)
	}
	if domain == peerReceiptDomain && facts.Slot == manifest.manifest.SeedSlot {
		return VerifiedReceipt{}, fmt.Errorf("%w: peer receipt targets the seed slot", ErrReceiptInvalid)
	}
	scope := trust.Scope{
		Domain: domain, DeploymentID: manifest.manifest.DeploymentID, Cell: string(manifest.manifest.Cell),
		Environment: manifest.manifest.Environment, Role: manifest.manifest.ControllerRole, Slot: facts.Slot,
	}
	var payload []byte
	var err error
	if domain == seedReceiptDomain {
		payload, err = trust.VerifyCurrent(envelope, scope, roots, now, policy)
	} else {
		payload, err = trust.VerifyDelegatedCurrent(envelope, scope, manifest.delegation, now, policy)
	}
	if err != nil {
		return VerifiedReceipt{}, fmt.Errorf("verify bootstrap instance receipt: %w", err)
	}
	if envelope.IssuedAt.Before(manifest.issuedAt) || envelope.ExpiresAt.After(manifest.expiresAt) {
		return VerifiedReceipt{}, fmt.Errorf("%w: receipt validity exceeds its signed manifest", ErrReceiptInvalid)
	}
	if len(payload) > MaxReceiptBytes {
		return VerifiedReceipt{}, fmt.Errorf("%w: receipt exceeds its size limit", ErrReceiptInvalid)
	}
	receipt, err := ReceiptPayload(payload)
	if err != nil {
		return VerifiedReceipt{}, err
	}
	want, err := NewReceipt(manifest, facts)
	if err != nil {
		return VerifiedReceipt{}, err
	}
	if receipt != want || envelope.Scope != scope {
		return VerifiedReceipt{}, fmt.Errorf("%w: signed receipt does not match exact instance facts", ErrIdentityMismatch)
	}
	return VerifiedReceipt{
		receipt: receipt, manifestDigest: manifest.digest,
		issuedAt: envelope.IssuedAt, expiresAt: envelope.ExpiresAt, verified: true,
	}, nil
}

func (receipt Receipt) validate() error {
	ociRegion, err := receipt.Cell.OCIRegion()
	if err != nil || receipt.SchemaVersion != ReceiptSchemaVersion || !deploymentRE.MatchString(receipt.DeploymentID) ||
		receipt.Environment != "production" && receipt.Environment != "canary" || !clusterRE.MatchString(receipt.ClusterID) ||
		receipt.OCIRegion != ociRegion || receipt.Role != "controller" || !slotNameRE.MatchString(receipt.Slot) ||
		!isOCID(receipt.InstanceOCID, "instance") || !isOCID(receipt.CompartmentOCID, "compartment") ||
		!isOCID(receipt.ImageOCID, "image") || !createKeyRE.MatchString(receipt.CreateKey) ||
		!sha256RE.MatchString(receipt.IntentSHA256) || !sha256RE.MatchString(receipt.ManifestDigest) ||
		!sha256RE.MatchString(receipt.ManifestIntentSHA256) || receipt.IntentGeneration == 0 || !sha256RE.MatchString(receipt.ProfileSHA256) {
		return fmt.Errorf("%w: required receipt identity or binding field", ErrReceiptInvalid)
	}
	return nil
}

func validateFacts(manifest VerifiedManifest, facts InstanceFacts) error {
	profile, ok := manifest.Profile(facts.Slot)
	if !ok || !sameProfile(profile, facts.Profile) {
		return fmt.Errorf("%w: observed launch profile is unauthorized", ErrIdentityMismatch)
	}
	if facts.DeploymentID != manifest.manifest.DeploymentID || facts.Environment != manifest.manifest.Environment ||
		facts.ClusterID != manifest.manifest.ClusterID || facts.Cell != manifest.manifest.Cell ||
		facts.OCIRegion != manifest.manifest.OCIRegion || facts.Role != manifest.manifest.ControllerRole ||
		facts.CompartmentOCID != profile.CompartmentOCID || facts.ImageOCID != manifest.manifest.ImageOCID ||
		!isOCID(facts.InstanceOCID, "instance") || !createKeyRE.MatchString(facts.CreateKey) || !sha256RE.MatchString(facts.IntentSHA256) {
		return fmt.Errorf("%w: authenticated instance facts do not match manifest", ErrIdentityMismatch)
	}
	return nil
}

func validateVerifiedManifest(manifest VerifiedManifest) error {
	if !manifest.verified || manifest.digest == "" || manifest.manifest.Validate() != nil {
		return fmt.Errorf("%w: verified manifest is absent or invalid", ErrManifestInvalid)
	}
	return nil
}

func sameProfile(left, right LaunchProfile) bool {
	return left.Slot == right.Slot && left.CompartmentOCID == right.CompartmentOCID &&
		left.AvailabilityDomain == right.AvailabilityDomain && left.FaultDomain == right.FaultDomain &&
		left.SubnetOCID == right.SubnetOCID && left.Shape == right.Shape &&
		slices.Equal(left.NetworkSecurityGroupOCIDs, right.NetworkSecurityGroupOCIDs)
}

func launchProfileDigest(profile LaunchProfile) (string, error) {
	encoded, err := trust.EncodePayload(profile)
	if err != nil {
		return "", err
	}
	return digestBytes(encoded), nil
}

func receiptIntervalWithinManifest(manifest VerifiedManifest, issuedAt, expiresAt time.Time) bool {
	return manifest.verified && !issuedAt.Before(manifest.issuedAt) && !expiresAt.After(manifest.expiresAt) && expiresAt.After(issuedAt)
}
