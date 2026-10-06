package bootstrap

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

const (
	InstallContinuitySchemaVersion = 1
	MaxInstallContinuityBytes      = 16 << 10
	MaxInstallContinuityWireBytes  = 32 << 10
	MaxInstallContinuityLifetime   = 365 * 24 * time.Hour
	installContinuityDomain        = "terrascale.bootstrap.install-continuity"
	installContinuityRole          = "controller"
)

var ErrInstallContinuityInvalid = errors.New("bootstrap install continuity proof is invalid")

// InstallContinuity binds a current root signature to one exact historical
// installation and one generation of the read-only continuity selector. The
// selector separately pins the digest of this signed proof, avoiding a
// self-referential selector digest. This document carries no launch, effect,
// or Vault authorization.
type InstallContinuity struct {
	SchemaVersion        int               `json:"schemaVersion"`
	DeploymentID         string            `json:"deploymentId"`
	Environment          string            `json:"environment"`
	ClusterID            string            `json:"clusterId"`
	Cell                 oci.Region        `json:"cell"`
	OCIRegion            string            `json:"ociRegion"`
	Slot                 string            `json:"slot"`
	GenesisAnchorSHA256  string            `json:"genesisAnchorSha256"`
	AcceptedMarkerSHA256 string            `json:"acceptedMarkerSha256"`
	ManifestSHA256       string            `json:"manifestSha256"`
	ResultSHA256         string            `json:"resultSha256"`
	ReceiptSHA256        string            `json:"receiptSha256"`
	ImageReceiptSHA256   string            `json:"imageReceiptSha256"`
	ImageOCID            string            `json:"imageOcid"`
	InstanceOCID         string            `json:"instanceOcid"`
	PrimaryVNICOCID      string            `json:"primaryVnicOcid"`
	PrimaryPrivateIP     string            `json:"primaryPrivateIp"`
	LedgerAttempt        uint64            `json:"ledgerAttempt"`
	LedgerGeneration     uint64            `json:"ledgerGeneration"`
	AcceptedAt           time.Time         `json:"acceptedAt"`
	BinarySHA256         string            `json:"binarySha256"`
	MaterialSHA256       map[string]string `json:"materialSha256"`
	CredentialSHA256     string            `json:"credentialSha256"`
	CredentialValidUntil time.Time         `json:"credentialValidUntil"`
	SelectorGeneration   uint64            `json:"selectorGeneration"`
	// MaterialGenerationSHA256 is the fingerprint of the install's newest
	// adopted material generation (TS-568), if any. With it,
	// CredentialSHA256 is InstallContinuityGenerationDigest of it and
	// CredentialValidUntil is that generation's expiry; without it, they
	// derive from the manifest-pinned credential files.
	MaterialGenerationSHA256 string `json:"materialGenerationSha256,omitempty"`
}

// InstallContinuityCredentialDigest fingerprints the exact installed
// credential inventory represented by materialSHA256. The input is encoded
// with deterministic JSON, so every caller derives the same digest.
func InstallContinuityCredentialDigest(materialSHA256 map[string]string) (string, error) {
	if len(materialSHA256) == 0 || len(materialSHA256) > 64 {
		return "", fmt.Errorf("%w: credential inventory is absent or oversized", ErrInstallContinuityInvalid)
	}
	for name, digest := range materialSHA256 {
		if !fileNameRE.MatchString(name) || !sha256RE.MatchString(digest) {
			return "", fmt.Errorf("%w: invalid credential inventory entry", ErrInstallContinuityInvalid)
		}
	}
	wire, err := protocol.EncodeJSON(materialSHA256)
	if err != nil {
		return "", fmt.Errorf("%w: encode credential inventory: %v", ErrInstallContinuityInvalid, err)
	}
	digest := sha256.Sum256(wire)
	return hex.EncodeToString(digest[:]), nil
}

// InstallContinuityGenerationDigest is CredentialSHA256 for an install that
// adopted a material generation (TS-568). It binds the newest generation's
// fingerprint instead of file digests, so the slot renewing its issued leaf
// and credentials under that generation needs no new proof; the proof's
// CredentialValidUntil is then the generation's expiry.
func InstallContinuityGenerationDigest(fingerprint string) (string, error) {
	if !sha256RE.MatchString(fingerprint) {
		return "", fmt.Errorf("%w: invalid material generation fingerprint", ErrInstallContinuityInvalid)
	}
	digest := sha256.Sum256([]byte("terrascale.install-continuity.material-generation\x00" + fingerprint))
	return hex.EncodeToString(digest[:]), nil
}

// InstallContinuityTrustPolicy is the hard verification ceiling. The signed
// proof expires no later than CredentialValidUntil, which is derived from the
// actual live JWT and TLS credential validity; this lifetime ceiling is not a
// promise that every proof remains valid for this duration.
func InstallContinuityTrustPolicy() trust.Policy {
	return trust.Policy{MaxLifetime: MaxInstallContinuityLifetime, ClockSkew: ManifestClockSkew}
}

// SignInstallContinuity signs a validated exact-install proof with the offline
// root key. expiresAt must not extend beyond the current credential cutoff.
func SignInstallContinuity(proof InstallContinuity, issuedAt, expiresAt time.Time,
	rootPrivateKey ed25519.PrivateKey,
) (trust.Envelope, error) {
	if err := validateInstallContinuity(proof); err != nil {
		return trust.Envelope{}, err
	}
	issuedAt = issuedAt.Round(0).UTC()
	expiresAt = expiresAt.Round(0).UTC()
	if issuedAt.IsZero() || expiresAt.IsZero() || !expiresAt.After(issuedAt) ||
		issuedAt.Before(proof.AcceptedAt) || expiresAt.After(proof.CredentialValidUntil) ||
		expiresAt.Sub(issuedAt) > MaxInstallContinuityLifetime {
		return trust.Envelope{}, fmt.Errorf("%w: signature interval exceeds the accepted-install or credential window", ErrInstallContinuityInvalid)
	}
	payload, err := trust.EncodePayload(proof)
	if err != nil {
		return trust.Envelope{}, fmt.Errorf("%w: encode proof: %v", ErrInstallContinuityInvalid, err)
	}
	if len(payload) == 0 || len(payload) > MaxInstallContinuityBytes {
		return trust.Envelope{}, fmt.Errorf("%w: payload exceeds %d bytes", ErrInstallContinuityInvalid, MaxInstallContinuityBytes)
	}
	envelope, err := trust.Sign(payload, installContinuityScope(proof), issuedAt, expiresAt, rootPrivateKey)
	if err != nil {
		return trust.Envelope{}, fmt.Errorf("%w: sign proof: %v", ErrInstallContinuityInvalid, err)
	}
	if err := validateInstallContinuityEnvelopeSize(envelope); err != nil {
		return trust.Envelope{}, err
	}
	return envelope, nil
}

// InstallContinuityExpectation contains the already independently verified
// exact local marker facts and current signed selector snapshot. The caller
// must verify the selector signature and durable floor before invoking this
// function.
type InstallContinuityExpectation struct {
	Install                InstallContinuity
	SelectorGeneration     uint64
	SelectorSHA256         string
	PinnedContinuitySHA256 string
}

// VerifiedInstallContinuity is a current, read-only restart-continuity proof.
// It has no conversion to launch, effect, or Vault verification capabilities.
type VerifiedInstallContinuity struct {
	install            InstallContinuity
	wire               []byte
	digest             string
	selectorGeneration uint64
	selectorSHA256     string
	issuedAt           time.Time
	expiresAt          time.Time
	clockSkew          time.Duration
	verified           bool
}

// IsVerified reports whether current root-signature, install bindings, and
// selector-pin verification succeeded.
func (verified VerifiedInstallContinuity) IsVerified() bool { return verified.verified }

// Continuity returns a defensive copy of the exact signed continuity facts.
func (verified VerifiedInstallContinuity) Continuity() InstallContinuity {
	return cloneInstallContinuity(verified.install)
}

// Wire returns the exact canonical signed envelope bytes used for the selector
// digest pin.
func (verified VerifiedInstallContinuity) Wire() []byte { return bytes.Clone(verified.wire) }

// Digest returns the SHA-256 of the exact canonical signed envelope.
func (verified VerifiedInstallContinuity) Digest() string { return verified.digest }

// SelectorGeneration returns the generation bound by the proof and selected
// by the independently verified current selector.
func (verified VerifiedInstallContinuity) SelectorGeneration() uint64 {
	return verified.selectorGeneration
}

// SelectorSHA256 returns the digest of the current signed selector snapshot
// supplied during verification.
func (verified VerifiedInstallContinuity) SelectorSHA256() string {
	return verified.selectorSHA256
}

// ExpiresAt returns the current root signature's exclusive expiry.
func (verified VerifiedInstallContinuity) ExpiresAt() time.Time { return verified.expiresAt }

// FinalRecheck confirms this proof and the exact signed selector snapshot are
// still current immediately before read-only restart proceeds. The caller
// must freshly fetch and verify the selector and recheck its durable antirollback
// floor before supplying the observed generation and digest.
func (verified VerifiedInstallContinuity) FinalRecheck(now time.Time,
	selectorGeneration uint64, selectorSHA256 string,
) error {
	if !verified.verified || selectorGeneration != verified.selectorGeneration ||
		selectorGeneration != verified.install.SelectorGeneration || selectorSHA256 != verified.selectorSHA256 ||
		!sha256RE.MatchString(selectorSHA256) {
		return fmt.Errorf("%w: final selector snapshot differs from verified continuity", ErrInstallContinuityInvalid)
	}
	now = now.Round(0).UTC()
	if now.IsZero() || verified.issuedAt.Sub(now) > verified.clockSkew ||
		!now.Before(verified.expiresAt) || !now.Before(verified.install.CredentialValidUntil) {
		return fmt.Errorf("%w: final recheck is outside current signature or credential validity", ErrInstallContinuityInvalid)
	}
	return nil
}

// VerifyCurrentInstallContinuity verifies the proof's current root signature,
// exact historical-install bindings, selected selector generation, and
// selector pin. The selected selector itself must already have been verified
// by the caller, including its antirollback floor.
func VerifyCurrentInstallContinuity(envelope trust.Envelope, roots trust.Keyring,
	expected InstallContinuityExpectation, now time.Time, policy trust.Policy,
) (VerifiedInstallContinuity, error) {
	if err := validateInstallContinuity(expected.Install); err != nil {
		return VerifiedInstallContinuity{}, err
	}
	if policy.MaxLifetime <= 0 || policy.MaxLifetime > MaxInstallContinuityLifetime || policy.ClockSkew < 0 ||
		expected.SelectorGeneration == 0 || expected.SelectorGeneration != expected.Install.SelectorGeneration ||
		!sha256RE.MatchString(expected.SelectorSHA256) || !sha256RE.MatchString(expected.PinnedContinuitySHA256) {
		return VerifiedInstallContinuity{}, fmt.Errorf("%w: invalid verification policy or selector expectation", ErrInstallContinuityInvalid)
	}
	if err := validateInstallContinuityEnvelopeSize(envelope); err != nil {
		return VerifiedInstallContinuity{}, err
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		return VerifiedInstallContinuity{}, fmt.Errorf("%w: encode signed envelope: %v", ErrInstallContinuityInvalid, err)
	}
	digest := digestBytes(wire)
	if digest != expected.PinnedContinuitySHA256 {
		return VerifiedInstallContinuity{}, fmt.Errorf("%w: selected selector does not pin this proof", ErrInstallContinuityInvalid)
	}
	scope := installContinuityScope(expected.Install)
	payload, err := trust.VerifyCurrent(envelope, scope, roots, now, policy)
	if err != nil {
		return VerifiedInstallContinuity{}, fmt.Errorf("%w: verify current root signature: %v", ErrInstallContinuityInvalid, err)
	}
	var proof InstallContinuity
	if err := protocol.DecodeStrict(payload, &proof, MaxInstallContinuityBytes); err != nil {
		return VerifiedInstallContinuity{}, fmt.Errorf("%w: decode proof: %v", ErrInstallContinuityInvalid, err)
	}
	if err := validateInstallContinuity(proof); err != nil {
		return VerifiedInstallContinuity{}, err
	}
	canonicalPayload, err := trust.EncodePayload(proof)
	if err != nil || !bytes.Equal(canonicalPayload, payload) {
		return VerifiedInstallContinuity{}, fmt.Errorf("%w: payload is not the exact canonical proof", ErrInstallContinuityInvalid)
	}
	wantPayload, err := trust.EncodePayload(expected.Install)
	if err != nil || !bytes.Equal(wantPayload, canonicalPayload) {
		return VerifiedInstallContinuity{}, fmt.Errorf("%w: proof does not match exact accepted-install facts", ErrInstallContinuityInvalid)
	}
	if envelope.IssuedAt.Before(proof.AcceptedAt) || envelope.ExpiresAt.After(proof.CredentialValidUntil) ||
		envelope.ExpiresAt.Sub(envelope.IssuedAt) > MaxInstallContinuityLifetime {
		return VerifiedInstallContinuity{}, fmt.Errorf("%w: signature interval exceeds the accepted-install or credential window", ErrInstallContinuityInvalid)
	}
	return VerifiedInstallContinuity{
		install: cloneInstallContinuity(proof), wire: bytes.Clone(wire), digest: digest,
		selectorGeneration: expected.SelectorGeneration, selectorSHA256: expected.SelectorSHA256,
		issuedAt: envelope.IssuedAt, expiresAt: envelope.ExpiresAt, clockSkew: policy.ClockSkew, verified: true,
	}, nil
}

func validateInstallContinuityEnvelopeSize(envelope trust.Envelope) error {
	if len(envelope.Payload) == 0 || len(envelope.Payload) > MaxInstallContinuityBytes {
		return fmt.Errorf("%w: payload is absent or exceeds %d bytes", ErrInstallContinuityInvalid, MaxInstallContinuityBytes)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil || len(wire) > MaxInstallContinuityWireBytes {
		return fmt.Errorf("%w: signed envelope is invalid or exceeds %d bytes", ErrInstallContinuityInvalid, MaxInstallContinuityWireBytes)
	}
	return nil
}

func validateInstallContinuity(proof InstallContinuity) error {
	region, err := proof.Cell.OCIRegion()
	// MaterialSHA256 is the accepted marker's inventory, part of every
	// proof's install identity; a generation replaces only the credential
	// binding derived from it.
	credentialDigest, credentialErr := InstallContinuityCredentialDigest(proof.MaterialSHA256)
	if proof.MaterialGenerationSHA256 != "" && credentialErr == nil {
		credentialDigest, credentialErr = InstallContinuityGenerationDigest(proof.MaterialGenerationSHA256)
	}
	if err != nil || proof.SchemaVersion != InstallContinuitySchemaVersion ||
		!deploymentRE.MatchString(proof.DeploymentID) || !clusterRE.MatchString(proof.ClusterID) ||
		(proof.Environment != "production" && proof.Environment != "canary") || region == "" || proof.OCIRegion != region ||
		!controllerSlotRE.MatchString(proof.Slot) || !sha256RE.MatchString(proof.GenesisAnchorSHA256) ||
		!sha256RE.MatchString(proof.AcceptedMarkerSHA256) || !sha256RE.MatchString(proof.ManifestSHA256) ||
		!sha256RE.MatchString(proof.ResultSHA256) || !sha256RE.MatchString(proof.ReceiptSHA256) ||
		!sha256RE.MatchString(proof.ImageReceiptSHA256) || !isOCID(proof.ImageOCID, "image") ||
		!isOCID(proof.InstanceOCID, "instance") || !isOCID(proof.PrimaryVNICOCID, "vnic") ||
		!validPrivateIPv4(proof.PrimaryPrivateIP) || proof.LedgerAttempt == 0 || proof.LedgerGeneration == 0 ||
		!validContinuityTime(proof.AcceptedAt) || !sha256RE.MatchString(proof.BinarySHA256) ||
		!sha256RE.MatchString(proof.CredentialSHA256) || credentialErr != nil || proof.CredentialSHA256 != credentialDigest ||
		!validContinuityTime(proof.CredentialValidUntil) || !proof.CredentialValidUntil.After(proof.AcceptedAt) ||
		proof.SelectorGeneration == 0 {
		return fmt.Errorf("%w: required identity, digest, inventory, or generation binding", ErrInstallContinuityInvalid)
	}
	payload, err := trust.EncodePayload(proof)
	if err != nil || len(payload) > MaxInstallContinuityBytes {
		return fmt.Errorf("%w: proof payload exceeds its size limit", ErrInstallContinuityInvalid)
	}
	return nil
}

func validContinuityTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value == value.Round(0).UTC()
}

func installContinuityScope(proof InstallContinuity) trust.Scope {
	return trust.Scope{
		Domain: installContinuityDomain, DeploymentID: proof.DeploymentID, Cell: string(proof.Cell),
		Environment: proof.Environment, Role: installContinuityRole, Slot: proof.Slot,
	}
}

func cloneInstallContinuity(proof InstallContinuity) InstallContinuity {
	materials := make(map[string]string, len(proof.MaterialSHA256))
	for name, digest := range proof.MaterialSHA256 {
		materials[name] = digest
	}
	proof.MaterialSHA256 = materials
	return proof
}
