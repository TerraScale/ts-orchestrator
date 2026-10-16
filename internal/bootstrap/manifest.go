package bootstrap

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

const (
	// MaterialDirectory is the fixed production controller credential directory.
	MaterialDirectory         = "/var/lib/terrascale-orchestrator-secrets"
	ManifestSchemaVersion     = 1
	ReceiptSchemaVersion      = 1
	MaxManifestBytes          = 64 << 10
	MaxControllerConfigBytes  = 16 << 10
	MaxControllerSidecarBytes = 16 << 10
	MaxReceiptBytes           = 32 << 10
	MaxManifestLifetime       = 365 * 24 * time.Hour
	ManifestClockSkew         = time.Minute
	DefaultManifestValidity   = 30 * 24 * time.Hour
	MinimumManifestWindow     = 24 * time.Hour
	manifestDomain            = "terrascale.bootstrap.manifest"
	seedReceiptDomain         = "terrascale.bootstrap.seed-receipt"
	peerReceiptDomain         = "terrascale.bootstrap.peer-receipt"
)

var (
	ErrManifestInvalid  = errors.New("bootstrap manifest is invalid")
	ErrReceiptInvalid   = errors.New("bootstrap instance receipt is invalid")
	ErrIdentityMismatch = errors.New("bootstrap instance identity does not match receipt")
	clusterRE           = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	ociIDRE             = regexp.MustCompile(`^ocid1\.[a-z0-9-]+\.[a-z0-9-]+\.[a-z0-9-]*\.[a-z0-9-]+(?:\.[a-z0-9-]+)?$`)
	sha256RE            = regexp.MustCompile(`^[0-9a-f]{64}$`)
	fileNameRE          = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	slotNameRE          = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$`)
	controllerSlotRE    = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	shapeRE             = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	faultDomainRE       = regexp.MustCompile(`^FAULT-DOMAIN-[1-3]$`)
	createKeyRE         = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

type SecretPurpose string

const (
	SecretRegionalShared   SecretPurpose = "regional-shared"
	SecretHostIssuer       SecretPurpose = "host-issuer"
	SecretSeedFounder      SecretPurpose = "seed-founder"
	SecretSeedLedgerSigner SecretPurpose = "seed-ledger-signer"
	SecretController       SecretPurpose = "controller"
)

// SecretReference pins a Vault secret OCID, immutable numeric version, exact
// content digest, authorized materialization scope, and simple output name.
type SecretReference struct {
	Purpose       SecretPurpose `json:"purpose"`
	Slot          string        `json:"slot,omitempty"`
	SecretOCID    string        `json:"secretOcid"`
	VersionNumber int64         `json:"versionNumber"`
	SHA256        string        `json:"sha256"`
	MaxBytes      int64         `json:"maxBytes"`
	TargetFile    string        `json:"targetFile"`
}

// LaunchProfile is the exact per-slot OCI launch configuration authorized by
// the root-signed manifest. OCI region is derived from Cell and image is
// pinned once at the manifest level.
type LaunchProfile struct {
	Slot                      string   `json:"slot"`
	CompartmentOCID           string   `json:"compartmentOcid"`
	AvailabilityDomain        string   `json:"availabilityDomain"`
	FaultDomain               string   `json:"faultDomain"`
	SubnetOCID                string   `json:"subnetOcid"`
	NetworkSecurityGroupOCIDs []string `json:"networkSecurityGroupOcids"`
	Shape                     string   `json:"shape"`
}

// ControllerConfigFile is one root-signed public input installed alongside the
// controller role config. Names are fixed so OCI metadata cannot choose paths.
type ControllerConfigFile struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Bytes  []byte `json:"bytes"`
}

var ControllerConfigFileNames = [...]string{"oci-region-intent.json", "oci-region.json", "placement.json"}

// StorageDomain pins the immutable bootstrap ledger and its separate CAS-head
// bucket so a manifest cannot redirect slot history to another object domain.
type StorageDomain struct {
	Namespace        string `json:"namespace"`
	LedgerBucket     string `json:"ledgerBucket"`
	LedgerKMSKeyOCID string `json:"ledgerKmsKeyOcid"`
	HeadBucket       string `json:"headBucket"`
	HeadKMSKeyOCID   string `json:"headKmsKeyOcid"`
	Prefix           string `json:"prefix"`
}

// ManagedMaterialDomain is the root-signed destination for initial TerraBase
// material and the subnet allowed to receive its private member addresses.
type ManagedMaterialDomain struct {
	Namespace                string `json:"namespace"`
	Bucket                   string `json:"bucket"`
	KMSKeyOCID               string `json:"kmsKeyOcid"`
	MemberCompartmentOCID    string `json:"memberCompartmentOcid"`
	MemberSubnetOCID         string `json:"memberSubnetOcid"`
	MemberSubnetCIDR         string `json:"memberSubnetCidr"`
	RecipientSignerPublicKey string `json:"recipientSignerPublicKey"`
	NativeVerifierSHA256     string `json:"nativeVerifierSha256"`
}

func (domain ManagedMaterialDomain) Validate() error {
	prefix, err := netip.ParsePrefix(domain.MemberSubnetCIDR)
	signer, signerErr := base64.StdEncoding.Strict().DecodeString(domain.RecipientSignerPublicKey)
	if !ledgerIDPattern.MatchString(domain.Namespace) || !ledgerNamePattern.MatchString(domain.Bucket) ||
		!isOCID(domain.KMSKeyOCID, "key") || !isOCID(domain.MemberCompartmentOCID, "compartment") ||
		!isOCID(domain.MemberSubnetOCID, "subnet") || err != nil || !prefix.Addr().Is4() ||
		!prefix.Addr().IsPrivate() || prefix.Masked() != prefix || prefix.Bits() < 16 || prefix.Bits() > 29 ||
		signerErr != nil || len(signer) != ed25519.PublicKeySize || !sha256RE.MatchString(domain.NativeVerifierSHA256) {
		return fmt.Errorf("%w: invalid signed managed material domain", ErrManifestInvalid)
	}
	return nil
}

// Validate enforces the bounded Object Storage names, separate bucket roles,
// OCI KMS key identities, and a canonical manifest prefix.
func (domain StorageDomain) Validate() error {
	if !ledgerIDPattern.MatchString(domain.Namespace) ||
		!ledgerNamePattern.MatchString(domain.LedgerBucket) || !ledgerNamePattern.MatchString(domain.HeadBucket) || domain.LedgerBucket == domain.HeadBucket ||
		!isOCID(domain.LedgerKMSKeyOCID, "key") || !isOCID(domain.HeadKMSKeyOCID, "key") ||
		len(domain.Prefix) > 128 || !validLedgerPrefix(domain.Prefix) {
		return fmt.Errorf("%w: invalid signed bootstrap storage domain", ErrManifestInvalid)
	}
	return nil
}

// Manifest is the public, offline-root-signed bootstrap authority delivered to
// one exact controller slot. It carries signed public release proof bytes and
// references to private material stored outside the manifest.
type Manifest struct {
	SchemaVersion        int             `json:"schemaVersion"`
	DeploymentID         string          `json:"deploymentId"`
	Environment          string          `json:"environment"`
	ClusterID            string          `json:"clusterId"`
	Cell                 oci.Region      `json:"cell"`
	OCIRegion            string          `json:"ociRegion"`
	IntentGeneration     uint64          `json:"intentGeneration"`
	IntentSHA256         string          `json:"intentSha256"`
	ControllerRole       string          `json:"controllerRole"`
	Slot                 string          `json:"slot"`
	SeedSlot             string          `json:"seedSlot"`
	ControllerSlots      []string        `json:"controllerSlots"`
	Profiles             []LaunchProfile `json:"profiles"`
	ImageOCID            string          `json:"imageOcid"`
	ImageArchitecture    string          `json:"imageArchitecture"`
	ReleaseReceiptSHA256 string          `json:"releaseReceiptSha256"`
	// These fields carry the exact canonical public trust-envelope bytes.
	ReleaseImageReceiptWire []byte                 `json:"releaseImageReceiptWire"`
	ReleaseDelegationWire   []byte                 `json:"releaseDelegationWire"`
	PeerReceiptDelegation   *trust.Envelope        `json:"peerReceiptDelegation,omitempty"`
	StorageDomain           StorageDomain          `json:"storageDomain"`
	ManagedMaterial         *ManagedMaterialDomain `json:"managedMaterial,omitempty"`
	Secrets                 []SecretReference      `json:"secrets"`
	ControllerConfigSHA256  string                 `json:"controllerConfigSha256"`
	ControllerConfig        []byte                 `json:"controllerConfig"`
	ControllerFiles         []ControllerConfigFile `json:"controllerFiles"`
}

// ManifestExpectation contains deployment and slot facts established outside
// the untrusted manifest transport, such as cloud-init's requested slot.
type ManifestExpectation struct {
	DeploymentID     string
	Environment      string
	ClusterID        string
	Cell             oci.Region
	Slot             string
	ImageOCID        string
	StorageDomain    StorageDomain
	ControllerSlots  []string
	IntentGeneration uint64
	IntentSHA256     string
}

// VerifiedManifest is constructed only after root signature, exact scope,
// content, delegated signer, and current validity checks succeed.
type VerifiedManifest struct {
	manifest      Manifest
	envelope      trust.Envelope
	digest        string
	delegation    trust.VerifiedDelegation
	hasDelegation bool
	issuedAt      time.Time
	expiresAt     time.Time
	verified      bool
}

// Manifest returns a defensive copy. Callers cannot mutate verification state.
func (verified VerifiedManifest) Manifest() Manifest { return cloneManifest(verified.manifest) }

// Digest returns the canonical root-signed envelope digest.
func (verified VerifiedManifest) Digest() string { return verified.digest }

// StorageDomain returns the exact root-authorized bootstrap ledger domain.
func (verified VerifiedManifest) StorageDomain() StorageDomain {
	return verified.manifest.StorageDomain
}

// Profile returns the root-authorized launch profile for one allowed slot.
func (verified VerifiedManifest) Profile(slot string) (LaunchProfile, bool) {
	if !verified.verified {
		return LaunchProfile{}, false
	}
	for _, profile := range verified.manifest.Profiles {
		if profile.Slot == slot {
			return cloneProfile(profile), true
		}
	}
	return LaunchProfile{}, false
}

// ManifestTrustPolicy returns the shared current-verification policy for
// root-signed bootstrap manifests and their root-signed peer delegations.
func ManifestTrustPolicy() trust.Policy {
	return trust.Policy{MaxLifetime: MaxManifestLifetime, ClockSkew: ManifestClockSkew}
}

// SignManifest canonicalizes and signs a manifest under the offline root.
func SignManifest(manifest Manifest, issuedAt, expiresAt time.Time, rootPrivateKey ed25519.PrivateKey) (trust.Envelope, error) {
	if err := manifest.Validate(); err != nil {
		return trust.Envelope{}, err
	}
	payload, err := trust.EncodePayload(manifest)
	if err != nil {
		return trust.Envelope{}, err
	}
	if len(payload) > MaxManifestBytes {
		return trust.Envelope{}, fmt.Errorf("%w: manifest exceeds its size limit", ErrManifestInvalid)
	}
	scope := manifestScope(manifest.DeploymentID, string(manifest.Cell), manifest.Environment, manifest.ControllerRole, manifest.Slot)
	envelope, err := trust.Sign(payload, scope, issuedAt, expiresAt, rootPrivateKey)
	if err != nil {
		return trust.Envelope{}, err
	}
	if envelope.ExpiresAt.Sub(envelope.IssuedAt) > MaxManifestLifetime {
		return trust.Envelope{}, fmt.Errorf("%w: manifest validity exceeds %s", ErrManifestInvalid, MaxManifestLifetime)
	}
	if err := validateManifestEnvelopeSize(envelope); err != nil {
		return trust.Envelope{}, err
	}
	return envelope, nil
}

// VerifyManifest verifies the root signature before decoding or using any
// Vault reference, and checks the exact expected deployment and controller
// slot. The signed scope itself is per-slot.
func VerifyManifest(envelope trust.Envelope, roots trust.Keyring, expected ManifestExpectation, now time.Time, policy trust.Policy) (VerifiedManifest, error) {
	if err := validateManifestEnvelopeSize(envelope); err != nil {
		return VerifiedManifest{}, err
	}
	if err := expected.validate(); err != nil {
		return VerifiedManifest{}, err
	}
	scope := manifestScope(expected.DeploymentID, string(expected.Cell), expected.Environment, "controller", expected.Slot)
	payload, err := trust.VerifyCurrent(envelope, scope, roots, now, policy)
	if err != nil {
		return VerifiedManifest{}, fmt.Errorf("verify bootstrap manifest signature: %w", err)
	}
	if len(payload) > MaxManifestBytes {
		return VerifiedManifest{}, fmt.Errorf("%w: manifest exceeds its size limit", ErrManifestInvalid)
	}
	manifest, digest, err := verifiedManifestPayload(envelope, payload, expected)
	if err != nil {
		return VerifiedManifest{}, err
	}
	verified := VerifiedManifest{
		manifest: cloneManifest(manifest), envelope: cloneEnvelope(envelope), digest: digest,
		issuedAt: envelope.IssuedAt, expiresAt: envelope.ExpiresAt, verified: true,
	}
	if manifest.PeerReceiptDelegation != nil {
		delegation, err := trust.VerifyDelegationCurrent(*manifest.PeerReceiptDelegation, roots, now, policy)
		if err != nil {
			return VerifiedManifest{}, fmt.Errorf("verify peer receipt delegation: %w", err)
		}
		if err := validatePeerDelegation(manifest, delegation); err != nil {
			return VerifiedManifest{}, err
		}
		verified.delegation = delegation
		verified.hasDelegation = true
	}
	return verified, nil
}

func verifiedManifestPayload(envelope trust.Envelope, payload []byte, expected ManifestExpectation) (Manifest, string, error) {
	manifest, err := ManifestPayload(payload)
	if err != nil {
		return Manifest{}, "", err
	}
	if manifest.DeploymentID != expected.DeploymentID || manifest.Environment != expected.Environment || manifest.ClusterID != expected.ClusterID ||
		manifest.Cell != expected.Cell || manifest.Slot != expected.Slot || manifest.ImageOCID != expected.ImageOCID ||
		manifest.StorageDomain != expected.StorageDomain ||
		!slices.Equal(manifest.ControllerSlots, expected.ControllerSlots) ||
		expected.IntentGeneration != 0 && manifest.IntentGeneration != expected.IntentGeneration ||
		expected.IntentSHA256 != "" && manifest.IntentSHA256 != expected.IntentSHA256 ||
		envelope.Scope.Role != manifest.ControllerRole || envelope.Scope.Slot != manifest.Slot {
		return Manifest{}, "", fmt.Errorf("%w: manifest does not match deployment expectation", ErrManifestInvalid)
	}
	digest, err := trust.Fingerprint(envelope)
	if err != nil {
		return Manifest{}, "", err
	}
	return manifest, digest, nil
}

func validateManifestEnvelopeSize(envelope trust.Envelope) error {
	encoded, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		return fmt.Errorf("%w: invalid manifest envelope: %v", ErrManifestInvalid, err)
	}
	if len(encoded) > MaxManifestBytes {
		return fmt.Errorf("%w: signed manifest envelope exceeds its size limit", ErrManifestInvalid)
	}
	return nil
}

// Validate checks the closed manifest schema and all exact role, slot,
// deployment, launch-profile, signer-delegation, and secret-scope constraints.
func (manifest Manifest) Validate() error {
	return manifest.validateStructure(false)
}

func (manifest Manifest) validateStructure(derived bool) error {
	ociRegion, err := manifest.Cell.OCIRegion()
	if err != nil || manifest.SchemaVersion != ManifestSchemaVersion || !entityid.Valid(manifest.DeploymentID) ||
		!entityid.Valid(manifest.ClusterID) || manifest.Environment != "production" && manifest.Environment != "canary" ||
		manifest.OCIRegion != ociRegion || manifest.IntentGeneration == 0 || !sha256RE.MatchString(manifest.IntentSHA256) ||
		manifest.ControllerRole != "controller" || !controllerSlotRE.MatchString(manifest.Slot) || !controllerSlotRE.MatchString(manifest.SeedSlot) ||
		!slices.Contains(manifest.ControllerSlots, manifest.Slot) || !slices.Contains(manifest.ControllerSlots, manifest.SeedSlot) ||
		!isOCID(manifest.ImageOCID, "image") || manifest.ImageArchitecture != "linux-amd64" && manifest.ImageArchitecture != "linux-arm64" ||
		!sha256RE.MatchString(manifest.ReleaseReceiptSHA256) || len(manifest.ControllerSlots) == 0 || len(manifest.ControllerSlots) > 64 ||
		len(manifest.Profiles) != len(manifest.ControllerSlots) || len(manifest.Secrets) > 128 {
		return fmt.Errorf("%w: required manifest identity or binding field", ErrManifestInvalid)
	}
	if err := manifest.StorageDomain.Validate(); err != nil {
		return err
	}
	if len(manifest.ControllerConfig) == 0 || len(manifest.ControllerConfig) > MaxControllerConfigBytes ||
		!sha256RE.MatchString(manifest.ControllerConfigSHA256) ||
		digestBytes(manifest.ControllerConfig) != manifest.ControllerConfigSHA256 {
		return fmt.Errorf("%w: controller configuration bytes or digest", ErrManifestInvalid)
	}
	var config map[string]any
	if err := protocol.DecodeStrict(manifest.ControllerConfig, &config, MaxControllerConfigBytes); err != nil ||
		config["nats"] == nil || config["controller"] == nil {
		return fmt.Errorf("%w: controller configuration JSON", ErrManifestInvalid)
	}
	if len(manifest.ControllerFiles) != len(ControllerConfigFileNames) {
		return fmt.Errorf("%w: controller public sidecars are incomplete", ErrManifestInvalid)
	}
	for index, file := range manifest.ControllerFiles {
		if file.Name != ControllerConfigFileNames[index] || len(file.Bytes) == 0 ||
			len(file.Bytes) > MaxControllerSidecarBytes || !sha256RE.MatchString(file.SHA256) ||
			digestBytes(file.Bytes) != file.SHA256 {
			return fmt.Errorf("%w: controller public sidecar %d", ErrManifestInvalid, index)
		}
		var value map[string]any
		if err := protocol.DecodeStrict(file.Bytes, &value, MaxControllerSidecarBytes); err != nil || value == nil {
			return fmt.Errorf("%w: controller public sidecar JSON", ErrManifestInvalid)
		}
	}
	if manifest.ManagedMaterial != nil {
		if err := manifest.ManagedMaterial.Validate(); err != nil {
			return err
		}
	}
	if err := validateReleaseProofWires(manifest); err != nil {
		return err
	}
	if hasDuplicate(manifest.ControllerSlots) || !slices.IsSorted(manifest.ControllerSlots) {
		return fmt.Errorf("%w: controller slot list is duplicated or not sorted", ErrManifestInvalid)
	}
	profiles := make(map[string]struct{}, len(manifest.Profiles))
	for _, profile := range manifest.Profiles {
		if err := profile.validate(); err != nil {
			return err
		}
		if !slices.Contains(manifest.ControllerSlots, profile.Slot) {
			return fmt.Errorf("%w: launch profile slot is not authorized", ErrManifestInvalid)
		}
		if _, exists := profiles[profile.Slot]; exists {
			return fmt.Errorf("%w: duplicate launch profile slot", ErrManifestInvalid)
		}
		profiles[profile.Slot] = struct{}{}
	}
	for _, slot := range manifest.ControllerSlots {
		if _, exists := profiles[slot]; !exists {
			return fmt.Errorf("%w: controller slot has no launch profile", ErrManifestInvalid)
		}
	}
	secretFiles := make(map[string]struct{}, len(manifest.Secrets))
	for _, secret := range manifest.Secrets {
		if err := secret.validate(manifest); err != nil {
			return err
		}
		if _, exists := secretFiles[secret.TargetFile]; exists {
			return fmt.Errorf("%w: duplicate secret output file", ErrManifestInvalid)
		}
		secretFiles[secret.TargetFile] = struct{}{}
	}
	peerSlots := slices.DeleteFunc(slices.Clone(manifest.ControllerSlots), func(slot string) bool { return slot == manifest.SeedSlot })
	if derived && manifest.PeerReceiptDelegation != nil || !derived && (len(peerSlots) == 0 && manifest.PeerReceiptDelegation != nil || len(peerSlots) > 0 && manifest.PeerReceiptDelegation == nil) {
		return fmt.Errorf("%w: peer signer delegation must exactly match peer slot presence", ErrManifestInvalid)
	}
	payload, err := trust.EncodePayload(manifest)
	if err != nil {
		return fmt.Errorf("%w: encode manifest: %v", ErrManifestInvalid, err)
	}
	if len(payload) > MaxManifestBytes {
		return fmt.Errorf("%w: manifest exceeds its size limit", ErrManifestInvalid)
	}
	return nil
}

func validateReleaseProofWires(manifest Manifest) error {
	if len(manifest.ReleaseImageReceiptWire) == 0 || len(manifest.ReleaseImageReceiptWire) > MaxManifestBytes ||
		len(manifest.ReleaseDelegationWire) == 0 || len(manifest.ReleaseDelegationWire) > MaxManifestBytes {
		return fmt.Errorf("%w: required release proof wire is absent or exceeds the manifest limit", ErrManifestInvalid)
	}
	if _, err := trust.DecodeEnvelope(manifest.ReleaseImageReceiptWire); err != nil {
		return fmt.Errorf("%w: image receipt wire is not canonical: %v", ErrManifestInvalid, err)
	}
	if _, err := trust.DecodeEnvelope(manifest.ReleaseDelegationWire); err != nil {
		return fmt.Errorf("%w: release delegation wire is not canonical: %v", ErrManifestInvalid, err)
	}
	if digestBytes(manifest.ReleaseImageReceiptWire) != manifest.ReleaseReceiptSHA256 {
		return fmt.Errorf("%w: release image receipt wire does not match its exact-wire SHA-256 pin", ErrManifestInvalid)
	}
	return nil
}

func (profile LaunchProfile) validate() error {
	if !controllerSlotRE.MatchString(profile.Slot) || !isOCID(profile.CompartmentOCID, "compartment") ||
		strings.TrimSpace(profile.AvailabilityDomain) == "" || strings.ContainsAny(profile.AvailabilityDomain, " \t\r\n") || len(profile.AvailabilityDomain) > 128 ||
		!faultDomainRE.MatchString(profile.FaultDomain) || !isOCID(profile.SubnetOCID, "subnet") ||
		!shapeRE.MatchString(profile.Shape) || len(profile.NetworkSecurityGroupOCIDs) > 16 {
		return fmt.Errorf("%w: invalid launch profile", ErrManifestInvalid)
	}
	if hasDuplicate(profile.NetworkSecurityGroupOCIDs) {
		return fmt.Errorf("%w: duplicate network security group", ErrManifestInvalid)
	}
	for _, nsg := range profile.NetworkSecurityGroupOCIDs {
		if !isOCID(nsg, "networksecuritygroup") {
			return fmt.Errorf("%w: invalid network security group OCID", ErrManifestInvalid)
		}
	}
	return nil
}

func (secret SecretReference) validate(manifest Manifest) error {
	if err := secret.ValidateIdentity(); err != nil {
		return err
	}
	hostIssuerFiles := []string{"host-nats-issuer.seed", "host-tls-issuer-key.pem", "host-tls-issuer-cert.pem",
		"terrabase-member-ca.pem", "terrabase-member-ca.key"}
	if slices.Contains(hostIssuerFiles, secret.TargetFile) && secret.Purpose != SecretHostIssuer ||
		slices.Contains([]string{"issuer-operator.seed", "issuer-system.seed", "issuer-cell.seed", "issuer-ca.key",
			"operator.creds", "operator-tls-cert.pem", "operator-tls-key.pem"}, secret.TargetFile) {
		return fmt.Errorf("%w: offline or issuer material has the wrong publication role", ErrManifestInvalid)
	}
	switch secret.Purpose {
	case SecretRegionalShared:
		if secret.Slot != "" {
			return fmt.Errorf("%w: regional-shared secret cannot be slot-bound", ErrManifestInvalid)
		}
	case SecretHostIssuer:
		if secret.Slot != "" || !slices.Contains(hostIssuerFiles, secret.TargetFile) {
			return fmt.Errorf("%w: host issuer secret must name one exact regional issuer", ErrManifestInvalid)
		}
	case SecretSeedFounder:
		if secret.Slot != manifest.SeedSlot {
			return fmt.Errorf("%w: founder secret must be seed-slot-bound", ErrManifestInvalid)
		}
	case SecretSeedLedgerSigner:
		if secret.Slot != manifest.SeedSlot {
			return fmt.Errorf("%w: ledger signer secret must be seed-slot-bound", ErrManifestInvalid)
		}
	case SecretController:
		if !slices.Contains(manifest.ControllerSlots, secret.Slot) {
			return fmt.Errorf("%w: controller secret slot is not authorized", ErrManifestInvalid)
		}
	default:
		return fmt.Errorf("%w: unknown secret purpose", ErrManifestInvalid)
	}
	return nil
}

// ValidateIdentity checks an exact immutable Vault reference. Callers must
// separately authorize its material role and the controller slot.
func (secret SecretReference) ValidateIdentity() error {
	if !isOCID(secret.SecretOCID, "vaultsecret") || secret.VersionNumber <= 0 || !sha256RE.MatchString(secret.SHA256) ||
		secret.MaxBytes <= 0 || secret.MaxBytes > MaxSecretBytes || !fileNameRE.MatchString(secret.TargetFile) ||
		strings.Contains(secret.TargetFile, "..") {
		return fmt.Errorf("%w: secret reference identity or bound", ErrManifestInvalid)
	}
	return nil
}

func (expected ManifestExpectation) validate() error {
	if !entityid.Valid(expected.DeploymentID) || expected.Environment != "production" && expected.Environment != "canary" ||
		!entityid.Valid(expected.ClusterID) || !controllerSlotRE.MatchString(expected.Slot) || !isOCID(expected.ImageOCID, "image") {
		return fmt.Errorf("%w: invalid expected manifest identity", ErrManifestInvalid)
	}
	if _, err := expected.Cell.OCIRegion(); err != nil {
		return fmt.Errorf("%w: unsupported expected region", ErrManifestInvalid)
	}
	if err := expected.StorageDomain.Validate(); err != nil {
		return fmt.Errorf("%w: invalid expected storage domain", ErrManifestInvalid)
	}
	if expected.IntentGeneration == 0 && expected.IntentSHA256 != "" ||
		expected.IntentGeneration != 0 && !sha256RE.MatchString(expected.IntentSHA256) {
		return fmt.Errorf("%w: incomplete expected region-intent pin", ErrManifestInvalid)
	}
	if len(expected.ControllerSlots) == 0 || len(expected.ControllerSlots) > MaxBootstrapAnchorSlots ||
		hasDuplicate(expected.ControllerSlots) || !slices.IsSorted(expected.ControllerSlots) {
		return fmt.Errorf("%w: invalid expected controller slot set", ErrManifestInvalid)
	}
	for _, slot := range expected.ControllerSlots {
		if !controllerSlotRE.MatchString(slot) {
			return fmt.Errorf("%w: invalid expected controller slot", ErrManifestInvalid)
		}
	}
	return nil
}

func validatePeerDelegation(manifest Manifest, delegation trust.VerifiedDelegation) error {
	peerSlots := slices.DeleteFunc(slices.Clone(manifest.ControllerSlots), func(slot string) bool { return slot == manifest.SeedSlot })
	capabilities := delegation.Capabilities()
	if len(peerSlots) == 0 || len(capabilities) != 1 {
		return fmt.Errorf("%w: peer signer delegation has an invalid capability set", ErrManifestInvalid)
	}
	capability := capabilities[0]
	if capability.Domain != peerReceiptDomain || capability.DeploymentID != manifest.DeploymentID || capability.Cell != string(manifest.Cell) ||
		capability.Environment != manifest.Environment || capability.Role != manifest.ControllerRole ||
		!sameStrings(capability.Slots, peerSlots) || !sameStrings(capability.Actions, []string{"sign"}) {
		return fmt.Errorf("%w: founder delegation exceeds peer receipt authority", ErrManifestInvalid)
	}
	return nil
}

func hasDuplicate(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			return true
		}
		seen[value] = struct{}{}
	}
	return false
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for _, value := range left {
		if !slices.Contains(right, value) {
			return false
		}
	}
	return true
}

func isOCID(value, kind string) bool {
	return ociIDRE.MatchString(value) && strings.HasPrefix(value, "ocid1."+kind+".") && len(value) <= 255
}

func manifestScope(deployment, cell, environment, role, slot string) trust.Scope {
	return trust.Scope{Domain: manifestDomain, DeploymentID: deployment, Cell: cell, Environment: environment, Role: role, Slot: slot}
}

// DigestManifest returns the digest of an already root-signed canonical envelope.
func DigestManifest(envelope trust.Envelope) (string, error) { return trust.Fingerprint(envelope) }

// ManifestPayload decodes a payload for tooling that already verified its
// signature. Runtime code should use VerifyManifest instead.
func ManifestPayload(payload []byte) (Manifest, error) {
	if len(payload) == 0 || len(payload) > MaxManifestBytes {
		return Manifest{}, fmt.Errorf("%w: manifest size", ErrManifestInvalid)
	}
	var manifest Manifest
	if err := protocol.DecodeStrict(payload, &manifest, MaxManifestBytes); err != nil {
		return Manifest{}, fmt.Errorf("decode bootstrap manifest: %w", err)
	}
	if err := manifest.Validate(); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func digestBytes(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func cloneManifest(manifest Manifest) Manifest {
	if manifest.ManagedMaterial != nil {
		manifest.ManagedMaterial = new(*manifest.ManagedMaterial)
	}
	manifest.ControllerSlots = slices.Clone(manifest.ControllerSlots)
	profiles := manifest.Profiles
	manifest.Profiles = make([]LaunchProfile, len(profiles))
	for index, profile := range profiles {
		manifest.Profiles[index] = cloneProfile(profile)
	}
	manifest.Secrets = slices.Clone(manifest.Secrets)
	manifest.ReleaseImageReceiptWire = bytes.Clone(manifest.ReleaseImageReceiptWire)
	manifest.ReleaseDelegationWire = bytes.Clone(manifest.ReleaseDelegationWire)
	manifest.ControllerConfig = bytes.Clone(manifest.ControllerConfig)
	manifest.ControllerFiles = slices.Clone(manifest.ControllerFiles)
	for index := range manifest.ControllerFiles {
		manifest.ControllerFiles[index].Bytes = bytes.Clone(manifest.ControllerFiles[index].Bytes)
	}
	if manifest.PeerReceiptDelegation != nil {
		delegation := cloneEnvelope(*manifest.PeerReceiptDelegation)
		manifest.PeerReceiptDelegation = &delegation
	}
	return manifest
}

func cloneProfile(profile LaunchProfile) LaunchProfile {
	profile.NetworkSecurityGroupOCIDs = slices.Clone(profile.NetworkSecurityGroupOCIDs)
	return profile
}

func cloneEnvelope(envelope trust.Envelope) trust.Envelope {
	envelope.Payload = envelope.Payload.Clone()
	return envelope
}
