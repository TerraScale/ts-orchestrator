// Package trust defines the shared, domain-separated signed JSON envelope and
// constrained signing-key delegation used by bootstrap and release records.
package trust

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

const (
	SchemaVersion             = 1
	MaxPayloadBytes           = 1 << 20
	MaxEnvelopeBytes          = MaxPayloadBytes + 16<<10
	DelegationDomain          = "terrascale.trust.delegation"
	DelegationDeploymentID    = "0000000000XXZR988BPPNZ2B32"
	delegationCell            = "global"
	delegationEnvironment     = "global"
	delegationRole            = "delegate"
	delegationSlot            = "capabilities"
	signatureDomain           = "TERRA-SCALE-TRUST-ENVELOPE-V1\x00"
	maxDelegationCapabilities = 64
	maxCapabilitySlots        = 256
)

var (
	ErrInvalid          = errors.New("trust document is invalid")
	ErrScopeMismatch    = errors.New("trust document scope does not match")
	ErrKeyMismatch      = errors.New("trust signing key does not match key ID")
	ErrUntrustedKey     = errors.New("trust signing key is not trusted")
	ErrBadSignature     = errors.New("trust signature is invalid")
	ErrNotYetValid      = errors.New("trust document is not yet valid")
	ErrExpired          = errors.New("trust document has expired")
	ErrCapabilityDenied = errors.New("delegated signing capability is insufficient")
	ErrDelegationTime   = errors.New("delegation does not cover the signed document interval")
	domainRE            = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$`)
	identityRE          = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	cellRE              = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	tokenRE             = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	slotRE              = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$`)
)

// Scope names the exact purpose and deployment target authorized by a
// signature. Every field is signed and must match exactly during verification.
type Scope struct {
	Domain       string `json:"domain"`
	DeploymentID string `json:"deploymentId"`
	Cell         string `json:"cell"`
	Environment  string `json:"environment"`
	Role         string `json:"role"`
	Slot         string `json:"slot"`
}

// Envelope contains one bounded JSON object and its detached Ed25519
// signature. Payload member ordering and contents are covered by the digest.
type Envelope struct {
	SchemaVersion int            `json:"schemaVersion"`
	KeyID         string         `json:"keyId"`
	Scope         Scope          `json:"scope"`
	IssuedAt      time.Time      `json:"issuedAt"`
	ExpiresAt     time.Time      `json:"expiresAt"`
	Payload       jsontext.Value `json:"payload"`
	Signature     string         `json:"signature"`
}

// Policy bounds accepted signature lifetimes and tolerated future clock skew.
type Policy struct {
	MaxLifetime time.Duration
	ClockSkew   time.Duration
}

// Keyring maps a complete SHA-256 public-key identifier to its public key.
type Keyring map[string]ed25519.PublicKey

// Capability is a closed signing grant. Slot entries are exact; wildcards are
// intentionally unsupported so a delegate cannot widen its own role.
type Capability struct {
	Domain       string   `json:"domain"`
	DeploymentID string   `json:"deploymentId"`
	Cell         string   `json:"cell"`
	Environment  string   `json:"environment"`
	Role         string   `json:"role"`
	Slots        []string `json:"slots"`
	Actions      []string `json:"actions"`
}

// Delegation is the root-authorized public key and its bounded capabilities.
// It contains no private material.
type Delegation struct {
	SchemaVersion    int          `json:"schemaVersion"`
	SubjectKeyID     string       `json:"subjectKeyId"`
	SubjectPublicKey string       `json:"subjectPublicKey"`
	Capabilities     []Capability `json:"capabilities"`
}

// VerifiedDelegation can only be populated by the verification constructors.
// Its fields are private to prevent callers manufacturing signing authority.
type VerifiedDelegation struct {
	keyID        string
	publicKey    ed25519.PublicKey
	capabilities []Capability
	issuedAt     time.Time
	expiresAt    time.Time
}

// Capabilities returns a defensive copy of the verified signing grants.
func (delegation VerifiedDelegation) Capabilities() []Capability {
	capabilities := make([]Capability, len(delegation.capabilities))
	for index, capability := range delegation.capabilities {
		capabilities[index] = capability
		capabilities[index].Slots = append([]string(nil), capability.Slots...)
		capabilities[index].Actions = append([]string(nil), capability.Actions...)
	}
	return capabilities
}

// SubjectKeyID returns the full SHA-256 key identifier authorized by this grant.
func (delegation VerifiedDelegation) SubjectKeyID() string { return delegation.keyID }

// KeyID derives the stable full-key SHA-256 identifier.
func KeyID(publicKey ed25519.PublicKey) (string, error) {
	return protocol.KeyID(publicKey)
}

// EncodePayload emits deterministic JSON for a signed payload.
func EncodePayload(value any) ([]byte, error) {
	encoded, err := json.Marshal(value, json.Deterministic(true))
	if err != nil {
		return nil, fmt.Errorf("encode trust payload: %w", err)
	}
	if err := validatePayload(encoded); err != nil {
		return nil, err
	}
	return encoded, nil
}

// Sign signs a strict, bounded JSON object for the exact supplied scope.
func Sign(payload []byte, scope Scope, issuedAt, expiresAt time.Time, privateKey ed25519.PrivateKey) (Envelope, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return Envelope{}, fmt.Errorf("%w: invalid Ed25519 private key", ErrInvalid)
	}
	if err := scope.validate(); err != nil {
		return Envelope{}, err
	}
	compact, err := compactPayload(payload)
	if err != nil {
		return Envelope{}, err
	}
	issuedAt = issuedAt.Round(0).UTC()
	expiresAt = expiresAt.Round(0).UTC()
	if !validTime(issuedAt) || !validTime(expiresAt) || !expiresAt.After(issuedAt) {
		return Envelope{}, fmt.Errorf("%w: invalid trust validity interval", ErrInvalid)
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	keyID, err := KeyID(publicKey)
	if err != nil {
		return Envelope{}, err
	}
	envelope := Envelope{
		SchemaVersion: SchemaVersion,
		KeyID:         keyID,
		Scope:         scope,
		IssuedAt:      issuedAt,
		ExpiresAt:     expiresAt,
		Payload:       compact,
	}
	material, err := signingMaterial(envelope)
	if err != nil {
		return Envelope{}, err
	}
	envelope.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, material))
	return envelope, nil
}

// EncodeEnvelope emits the single deterministic JSON wire representation.
func EncodeEnvelope(envelope Envelope) ([]byte, error) {
	if err := envelope.validateShape(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(envelope, json.Deterministic(true))
	if err != nil {
		return nil, fmt.Errorf("encode trust envelope: %w", err)
	}
	if len(encoded) > MaxEnvelopeBytes {
		return nil, fmt.Errorf("%w: encoded envelope exceeds size limit", ErrInvalid)
	}
	return encoded, nil
}

// DecodeEnvelope strictly decodes one canonical wire envelope. Unknown or
// duplicate fields, alternate outer JSON encodings, and oversized payloads fail.
func DecodeEnvelope(encoded []byte) (Envelope, error) {
	if len(encoded) == 0 || len(encoded) > MaxEnvelopeBytes {
		return Envelope{}, fmt.Errorf("%w: envelope is empty or too large", ErrInvalid)
	}
	var envelope Envelope
	if err := protocol.DecodeStrict(encoded, &envelope, MaxEnvelopeBytes); err != nil {
		return Envelope{}, fmt.Errorf("decode trust envelope: %w", err)
	}
	canonical, err := EncodeEnvelope(envelope)
	if err != nil {
		return Envelope{}, err
	}
	if string(canonical) != string(encoded) {
		return Envelope{}, fmt.Errorf("%w: envelope JSON is not canonical", ErrInvalid)
	}
	return envelope, nil
}

// VerifyCurrent verifies the exact scope, signature, lifetime, and current
// validity. Use this API before any current mutation or secret retrieval.
func VerifyCurrent(envelope Envelope, expected Scope, keys Keyring, now time.Time, policy Policy) ([]byte, error) {
	if !validTime(now) || policy.MaxLifetime <= 0 || policy.ClockSkew < 0 {
		return nil, fmt.Errorf("%w: invalid verification policy", ErrInvalid)
	}
	if err := verifySignature(envelope, expected, keys, policy.MaxLifetime); err != nil {
		return nil, err
	}
	if envelope.IssuedAt.Sub(now) > policy.ClockSkew {
		return nil, ErrNotYetValid
	}
	if !now.Before(envelope.ExpiresAt) {
		return nil, ErrExpired
	}
	return bytesClone(envelope.Payload), nil
}

// VerifyHistorical verifies scope, signature, key, and the bounded signed
// interval but deliberately makes no current-authorization claim.
func VerifyHistorical(envelope Envelope, expected Scope, keys Keyring, policy Policy) ([]byte, error) {
	if policy.MaxLifetime <= 0 || policy.ClockSkew < 0 {
		return nil, fmt.Errorf("%w: invalid verification policy", ErrInvalid)
	}
	if err := verifySignature(envelope, expected, keys, policy.MaxLifetime); err != nil {
		return nil, err
	}
	return bytesClone(envelope.Payload), nil
}

// SignDelegation signs root-controlled delegated key capabilities.
func SignDelegation(delegation Delegation, issuedAt, expiresAt time.Time, rootPrivateKey ed25519.PrivateKey) (Envelope, error) {
	if err := delegation.Validate(); err != nil {
		return Envelope{}, err
	}
	payload, err := EncodePayload(delegation)
	if err != nil {
		return Envelope{}, err
	}
	return Sign(payload, delegationScope(), issuedAt, expiresAt, rootPrivateKey)
}

// VerifyDelegationCurrent verifies a root-signed delegation and requires it to
// be currently valid before the key can authorize a current action.
func VerifyDelegationCurrent(envelope Envelope, roots Keyring, now time.Time, policy Policy) (VerifiedDelegation, error) {
	payload, err := VerifyCurrent(envelope, delegationScope(), roots, now, policy)
	if err != nil {
		return VerifiedDelegation{}, err
	}
	return decodeVerifiedDelegation(envelope, payload)
}

// VerifyDelegationHistorical validates the delegation signature and bounded
// interval without granting present-day authority.
func VerifyDelegationHistorical(envelope Envelope, roots Keyring, policy Policy) (VerifiedDelegation, error) {
	payload, err := VerifyHistorical(envelope, delegationScope(), roots, policy)
	if err != nil {
		return VerifiedDelegation{}, err
	}
	return decodeVerifiedDelegation(envelope, payload)
}

// VerifyDelegatedCurrent enforces current signer authority, key delegation
// validity, and exact capability scope.
func VerifyDelegatedCurrent(envelope Envelope, expected Scope, delegation VerifiedDelegation, now time.Time, policy Policy) ([]byte, error) {
	if !now.Before(delegation.expiresAt) || now.Add(policy.ClockSkew).Before(delegation.issuedAt) {
		return nil, ErrExpired
	}
	if err := delegation.authorize(expected); err != nil {
		return nil, err
	}
	if envelope.IssuedAt.Before(delegation.issuedAt) || envelope.ExpiresAt.After(delegation.expiresAt) {
		return nil, ErrDelegationTime
	}
	return VerifyCurrent(envelope, expected, Keyring{delegation.keyID: delegation.publicKey}, now, policy)
}

// VerifyDelegatedHistorical proves the key was delegated for the exact scope
// when the immutable record was signed; it does not authorize a new action.
func VerifyDelegatedHistorical(envelope Envelope, expected Scope, delegation VerifiedDelegation, policy Policy) ([]byte, error) {
	if err := delegation.authorize(expected); err != nil {
		return nil, err
	}
	if envelope.IssuedAt.Before(delegation.issuedAt) || envelope.ExpiresAt.After(delegation.expiresAt) {
		return nil, ErrDelegationTime
	}
	return VerifyHistorical(envelope, expected, Keyring{delegation.keyID: delegation.publicKey}, policy)
}

func (delegation Delegation) Validate() error {
	if delegation.SchemaVersion != SchemaVersion || len(delegation.Capabilities) == 0 || len(delegation.Capabilities) > maxDelegationCapabilities {
		return fmt.Errorf("%w: delegation version or capability count", ErrInvalid)
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(delegation.SubjectPublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: delegated public key", ErrInvalid)
	}
	keyID, err := KeyID(ed25519.PublicKey(publicKey))
	if err != nil || keyID != delegation.SubjectKeyID {
		return ErrKeyMismatch
	}
	seenCapabilities := make(map[string]struct{}, len(delegation.Capabilities))
	for _, capability := range delegation.Capabilities {
		if err := capability.validate(); err != nil {
			return err
		}
		encoded, err := EncodePayload(capability)
		if err != nil {
			return err
		}
		if _, exists := seenCapabilities[string(encoded)]; exists {
			return fmt.Errorf("%w: duplicate delegation capability", ErrInvalid)
		}
		seenCapabilities[string(encoded)] = struct{}{}
	}
	return nil
}

func (capability Capability) validate() error {
	if !domainRE.MatchString(capability.Domain) || capability.Domain == DelegationDomain ||
		!entityid.Valid(capability.DeploymentID) || !cellRE.MatchString(capability.Cell) ||
		!tokenRE.MatchString(capability.Environment) || !tokenRE.MatchString(capability.Role) ||
		len(capability.Slots) == 0 || len(capability.Slots) > maxCapabilitySlots || len(capability.Actions) != 1 || capability.Actions[0] != "sign" {
		return fmt.Errorf("%w: invalid delegation capability", ErrInvalid)
	}
	seenSlots := make(map[string]struct{}, len(capability.Slots))
	for _, slot := range capability.Slots {
		if !slotRE.MatchString(slot) {
			return fmt.Errorf("%w: invalid capability slot", ErrInvalid)
		}
		if _, exists := seenSlots[slot]; exists {
			return fmt.Errorf("%w: duplicate capability slot", ErrInvalid)
		}
		seenSlots[slot] = struct{}{}
	}
	return nil
}

func (delegation VerifiedDelegation) authorize(scope Scope) error {
	if err := scope.validate(); err != nil {
		return err
	}
	for _, capability := range delegation.capabilities {
		if capability.Domain == scope.Domain && capability.DeploymentID == scope.DeploymentID && capability.Cell == scope.Cell &&
			capability.Environment == scope.Environment && capability.Role == scope.Role && slices.Contains(capability.Slots, scope.Slot) && slices.Contains(capability.Actions, "sign") {
			return nil
		}
	}
	return ErrCapabilityDenied
}

func decodeVerifiedDelegation(envelope Envelope, payload []byte) (VerifiedDelegation, error) {
	var delegation Delegation
	if err := protocol.DecodeStrict(payload, &delegation, MaxPayloadBytes); err != nil {
		return VerifiedDelegation{}, fmt.Errorf("decode trust delegation: %w", err)
	}
	if err := delegation.Validate(); err != nil {
		return VerifiedDelegation{}, err
	}
	publicKey, _ := base64.RawURLEncoding.DecodeString(delegation.SubjectPublicKey)
	return VerifiedDelegation{
		keyID: delegation.SubjectKeyID, publicKey: ed25519.PublicKey(publicKey),
		capabilities: delegation.Capabilities, issuedAt: envelope.IssuedAt, expiresAt: envelope.ExpiresAt,
	}, nil
}

func verifySignature(envelope Envelope, expected Scope, keys Keyring, maximumLifetime time.Duration) error {
	if err := envelope.validateShape(); err != nil {
		return err
	}
	if err := expected.validate(); err != nil {
		return err
	}
	if envelope.Scope != expected {
		return ErrScopeMismatch
	}
	if !envelope.ExpiresAt.After(envelope.IssuedAt) || envelope.ExpiresAt.Sub(envelope.IssuedAt) > maximumLifetime {
		return fmt.Errorf("%w: invalid or excessive trust validity interval", ErrInvalid)
	}
	publicKey, exists := keys[envelope.KeyID]
	if !exists {
		return ErrUntrustedKey
	}
	keyID, err := KeyID(publicKey)
	if err != nil {
		return err
	}
	if keyID != envelope.KeyID {
		return ErrKeyMismatch
	}
	material, err := signingMaterial(envelope)
	if err != nil {
		return err
	}
	signature, err := decodeCanonicalSignature(envelope.Signature)
	if err != nil || !ed25519.Verify(publicKey, material, signature) {
		return ErrBadSignature
	}
	return nil
}

func (envelope Envelope) validateShape() error {
	if envelope.SchemaVersion != SchemaVersion || !domainRE.MatchString(envelope.Scope.Domain) || envelope.KeyID == "" || envelope.Signature == "" ||
		!canonicalTime(envelope.IssuedAt) || !canonicalTime(envelope.ExpiresAt) {
		return fmt.Errorf("%w: envelope header", ErrInvalid)
	}
	if _, err := decodeCanonicalSignature(envelope.Signature); err != nil {
		return err
	}
	if err := envelope.Scope.validate(); err != nil {
		return err
	}
	_, err := compactPayload(envelope.Payload)
	return err
}

func (scope Scope) validate() error {
	if !domainRE.MatchString(scope.Domain) {
		return fmt.Errorf("%w: scope domain", ErrInvalid)
	}
	if scope.Domain == DelegationDomain && scope == delegationScope() {
		return nil
	}
	if !entityid.Valid(scope.DeploymentID) || !cellRE.MatchString(scope.Cell) ||
		!tokenRE.MatchString(scope.Environment) || !tokenRE.MatchString(scope.Role) || !slotRE.MatchString(scope.Slot) {
		return fmt.Errorf("%w: incomplete or invalid scope", ErrInvalid)
	}
	return nil
}

func delegationScope() Scope {
	return Scope{
		Domain: DelegationDomain, DeploymentID: DelegationDeploymentID, Cell: delegationCell,
		Environment: delegationEnvironment, Role: delegationRole, Slot: delegationSlot,
	}
}

func compactPayload(payload []byte) (jsontext.Value, error) {
	if len(payload) == 0 || len(payload) > MaxPayloadBytes || !utf8.Valid(payload) {
		return nil, fmt.Errorf("%w: payload is empty, invalid UTF-8, or too large", ErrInvalid)
	}
	value := jsontext.Value(payload).Clone()
	if err := value.Compact(jsontext.AllowDuplicateNames(false), jsontext.AllowInvalidUTF8(false)); err != nil {
		return nil, fmt.Errorf("%w: invalid payload JSON: %v", ErrInvalid, err)
	}
	if len(value) == 0 || value.Kind() != jsontext.Kind('{') {
		return nil, fmt.Errorf("%w: payload must be a JSON object", ErrInvalid)
	}
	return value, nil
}

func validatePayload(payload []byte) error {
	_, err := compactPayload(payload)
	return err
}

func signingMaterial(envelope Envelope) ([]byte, error) {
	payload, err := compactPayload(envelope.Payload)
	if err != nil {
		return nil, err
	}
	material := make([]byte, 0, len(signatureDomain)+256+sha256.Size)
	material = append(material, signatureDomain...)
	material = binary.BigEndian.AppendUint16(material, uint16(envelope.SchemaVersion))
	for _, field := range []string{
		envelope.KeyID, envelope.Scope.Domain, envelope.Scope.DeploymentID, envelope.Scope.Cell,
		envelope.Scope.Environment, envelope.Scope.Role, envelope.Scope.Slot,
		envelope.IssuedAt.Format(time.RFC3339Nano), envelope.ExpiresAt.Format(time.RFC3339Nano),
	} {
		if len(field) > 1<<16-1 {
			return nil, fmt.Errorf("%w: signed field exceeds limit", ErrInvalid)
		}
		material = binary.BigEndian.AppendUint16(material, uint16(len(field)))
		material = append(material, field...)
	}
	payloadDigest := sha256.Sum256(payload)
	material = append(material, payloadDigest[:]...)
	return material, nil
}

func validTime(value time.Time) bool {
	return !value.IsZero() && value.Year() >= 1 && value.Year() <= 9999
}

func canonicalTime(value time.Time) bool {
	return validTime(value) && value.Location() == time.UTC &&
		value.Format(time.RFC3339Nano) == value.UTC().Format(time.RFC3339Nano)
}

func decodeCanonicalSignature(encoded string) ([]byte, error) {
	signature, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(signature) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(signature) != encoded {
		return nil, ErrBadSignature
	}
	return signature, nil
}

func bytesClone(value []byte) []byte { return append([]byte(nil), value...) }

// DelegatedKeyID creates the key ID stored alongside a delegated public key.
func DelegatedKeyID(publicKey ed25519.PublicKey) (string, error) {
	return KeyID(publicKey)
}

// EncodeDelegatedPublicKey uses the canonical unpadded URL-safe Base64 form.
func EncodeDelegatedPublicKey(publicKey ed25519.PublicKey) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("%w: invalid Ed25519 public key", ErrInvalid)
	}
	return base64.RawURLEncoding.EncodeToString(publicKey), nil
}

// ParseKeyring validates baked-in root public keys and derives their full IDs.
func ParseKeyring(publicKeys ...ed25519.PublicKey) (Keyring, error) {
	keyring := make(Keyring, len(publicKeys))
	for _, publicKey := range publicKeys {
		keyID, err := KeyID(publicKey)
		if err != nil {
			return nil, err
		}
		if _, exists := keyring[keyID]; exists {
			return nil, fmt.Errorf("%w: duplicate trusted root", ErrInvalid)
		}
		keyring[keyID] = append(ed25519.PublicKey(nil), publicKey...)
	}
	if len(keyring) == 0 {
		return nil, fmt.Errorf("%w: empty trusted root set", ErrInvalid)
	}
	return keyring, nil
}

// String returns a non-secret representation useful in diagnostics.
func (scope Scope) String() string {
	return strings.Join([]string{scope.Domain, scope.DeploymentID, scope.Cell, scope.Environment, scope.Role, scope.Slot}, "/")
}

// Fingerprint returns the SHA-256 digest of canonical encoded envelope bytes.
func Fingerprint(envelope Envelope) (string, error) {
	encoded, err := EncodeEnvelope(envelope)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}
