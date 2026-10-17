package protocol

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

const (
	EnvelopeSchemaVersion = 1
	MaxPayloadBytes       = DefaultMaxJSONBytes - 4096
	envelopeDomain        = "TERRA-SCALE-ORCHESTRATOR-ENVELOPE-V1\x00"
)

var (
	ErrInvalidEnvelope = errors.New("protocol envelope is invalid")
	ErrInvalidScope    = errors.New("protocol envelope scope is invalid")
	ErrInvalidPayload  = errors.New("protocol envelope payload is invalid")
	ErrScopeMismatch   = errors.New("protocol envelope scope does not match")
	ErrKeyMismatch     = errors.New("protocol envelope key ID does not match")
	ErrBadSignature    = errors.New("protocol envelope signature is invalid")
	ErrNotYetValid     = errors.New("protocol envelope is not yet valid")
	ErrExpired         = errors.New("protocol envelope has expired")
	ErrInvalidPolicy   = errors.New("protocol envelope verification policy is invalid")
)

// EnvelopeScope contains the semantic authority and fencing fields shared by
// all signed messages. Feature slices define and validate their own payloads.
type EnvelopeScope struct {
	Region      string
	Kind        string
	Actor       string
	OperationID string
	Generation  uint64
	Epoch       uint64
}

// Envelope is the common versioned signed message. Payload contains one JSON
// object encoded as a raw JSON value, not base64-encoded bytes.
type Envelope struct {
	SchemaVersion int            `json:"schemaVersion"`
	Region        string         `json:"region"`
	Kind          string         `json:"kind"`
	Actor         string         `json:"actor"`
	Generation    uint64         `json:"generation"`
	Epoch         uint64         `json:"epoch"`
	OperationID   string         `json:"operationId"`
	IssuedAt      time.Time      `json:"issuedAt"`
	ExpiresAt     time.Time      `json:"expiresAt"`
	KeyID         string         `json:"keyId"`
	Payload       jsontext.Value `json:"payload"`
	Signature     string         `json:"signature"`
}

// VerifyPolicy bounds the validity window and future clock skew accepted by a
// verifier. MaxLifetime must be positive; ClockSkew may be zero.
type VerifyPolicy struct {
	MaxLifetime time.Duration
	ClockSkew   time.Duration
}

// KeyID derives the stable key lookup identifier used by signed envelopes.
func KeyID(publicKey ed25519.PublicKey) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("%w: expected an Ed25519 public key", ErrInvalidEnvelope)
	}
	digest := sha256.Sum256(publicKey)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

// SignEnvelope signs compacted raw JSON payload bytes and their complete scope.
// Payload object member order remains significant; insignificant JSON whitespace
// is removed before signing and stored in the returned envelope.
func SignEnvelope(
	payload []byte,
	scope EnvelopeScope,
	issuedAt time.Time,
	expiresAt time.Time,
	privateKey ed25519.PrivateKey,
) (Envelope, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return Envelope{}, fmt.Errorf("%w: expected an Ed25519 private key", ErrInvalidEnvelope)
	}
	normalized, err := normalizeScope(scope)
	if err != nil {
		return Envelope{}, err
	}
	issuedAt = issuedAt.Round(0).UTC()
	expiresAt = expiresAt.Round(0).UTC()
	if !validProtocolTime(issuedAt) || !validProtocolTime(expiresAt) || !expiresAt.After(issuedAt) {
		return Envelope{}, fmt.Errorf("%w: issuedAt and expiresAt must form a valid UTC interval", ErrInvalidEnvelope)
	}
	compactPayload, err := compactPayload(payload)
	if err != nil {
		return Envelope{}, err
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	keyID, err := KeyID(publicKey)
	if err != nil {
		return Envelope{}, err
	}
	envelope := Envelope{
		SchemaVersion: EnvelopeSchemaVersion,
		Region:        normalized.Region,
		Kind:          normalized.Kind,
		Actor:         normalized.Actor,
		Generation:    normalized.Generation,
		Epoch:         normalized.Epoch,
		OperationID:   normalized.OperationID,
		IssuedAt:      issuedAt,
		ExpiresAt:     expiresAt,
		KeyID:         keyID,
		Payload:       compactPayload,
	}
	material, err := signedMaterial(envelope)
	if err != nil {
		return Envelope{}, err
	}
	envelope.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, material))
	return envelope, nil
}

// VerifyEnvelope verifies signature, exact semantic scope, expiry, and fencing
// metadata. Replay prevention for OperationID belongs to the durable consumer.
func VerifyEnvelope(
	envelope Envelope,
	expected EnvelopeScope,
	publicKey ed25519.PublicKey,
	now time.Time,
	policy VerifyPolicy,
) error {
	if len(publicKey) != ed25519.PublicKeySize || policy.MaxLifetime <= 0 || policy.ClockSkew < 0 || !validProtocolTime(now) {
		return ErrInvalidPolicy
	}
	if envelope.SchemaVersion != EnvelopeSchemaVersion {
		return fmt.Errorf("%w: unsupported schema version", ErrInvalidEnvelope)
	}
	actualScope, err := normalizeScope(EnvelopeScope{
		Region: envelope.Region, Kind: envelope.Kind, Actor: envelope.Actor,
		OperationID: envelope.OperationID, Generation: envelope.Generation, Epoch: envelope.Epoch,
	})
	if err != nil {
		return err
	}
	expectedScope, err := normalizeScope(expected)
	if err != nil {
		return err
	}
	if actualScope != expectedScope {
		return ErrScopeMismatch
	}
	if !validProtocolTime(envelope.IssuedAt) || !validProtocolTime(envelope.ExpiresAt) ||
		!envelope.ExpiresAt.After(envelope.IssuedAt) ||
		envelope.ExpiresAt.Sub(envelope.IssuedAt) > policy.MaxLifetime {
		return fmt.Errorf("%w: invalid timestamp interval", ErrInvalidEnvelope)
	}
	issuedAt := envelope.IssuedAt.Round(0).UTC()
	expiresAt := envelope.ExpiresAt.Round(0).UTC()
	if issuedAt.Sub(now) > policy.ClockSkew {
		return ErrNotYetValid
	}
	if !now.Before(expiresAt) {
		return ErrExpired
	}
	expectedKeyID, err := KeyID(publicKey)
	if err != nil {
		return err
	}
	if envelope.KeyID != expectedKeyID {
		return ErrKeyMismatch
	}
	compact, err := compactPayload(envelope.Payload)
	if err != nil {
		return err
	}
	envelope.Region = actualScope.Region
	envelope.Kind = actualScope.Kind
	envelope.Actor = actualScope.Actor
	envelope.OperationID = actualScope.OperationID
	envelope.IssuedAt = issuedAt
	envelope.ExpiresAt = expiresAt
	envelope.Payload = compact
	material, err := signedMaterial(envelope)
	if err != nil {
		return err
	}
	signature, err := base64.RawURLEncoding.DecodeString(envelope.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, material, signature) {
		return ErrBadSignature
	}
	return nil
}

func normalizeScope(scope EnvelopeScope) (EnvelopeScope, error) {
	region, err := CanonicalRegion(scope.Region)
	if err != nil || !validKind(scope.Kind) || !validIdentity(scope.Actor, 256) || !entityid.Valid(scope.OperationID) {
		return EnvelopeScope{}, ErrInvalidScope
	}
	scope.Region = region
	return scope, nil
}

func validKind(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for part := range strings.SplitSeq(value, ".") {
		if part == "" || !validToken(part) || part != strings.ToLower(part) {
			return false
		}
	}
	return true
}

func validIdentity(value string, maximum int) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func validProtocolTime(value time.Time) bool {
	return !value.IsZero() && value.Year() >= 1 && value.Year() <= 9999
}

func compactPayload(payload []byte) (jsontext.Value, error) {
	if len(payload) == 0 || len(payload) > MaxPayloadBytes {
		return nil, fmt.Errorf("%w: payload is empty or too large", ErrInvalidPayload)
	}
	value := jsontext.Value(payload).Clone()
	if err := value.Compact(
		jsontext.AllowDuplicateNames(false),
		jsontext.AllowInvalidUTF8(false),
	); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPayload, err)
	}
	if len(value) == 0 || value.Kind() != jsontext.Kind('{') {
		return nil, fmt.Errorf("%w: payload must be a JSON object", ErrInvalidPayload)
	}
	return value, nil
}

func signedMaterial(envelope Envelope) ([]byte, error) {
	payload, err := compactPayload(envelope.Payload)
	if err != nil {
		return nil, err
	}
	material := make([]byte, 0, len(envelopeDomain)+256+sha256.Size)
	material = append(material, envelopeDomain...)
	material = binary.BigEndian.AppendUint16(material, uint16(envelope.SchemaVersion))
	for _, value := range []string{
		envelope.Region,
		envelope.Kind,
		envelope.Actor,
		envelope.OperationID,
		envelope.KeyID,
		envelope.IssuedAt.UTC().Format(time.RFC3339Nano),
		envelope.ExpiresAt.UTC().Format(time.RFC3339Nano),
	} {
		material = appendString(material, value)
	}
	material = binary.BigEndian.AppendUint64(material, envelope.Generation)
	material = binary.BigEndian.AppendUint64(material, envelope.Epoch)
	payloadDigest := sha256.Sum256(payload)
	material = append(material, payloadDigest[:]...)
	return material, nil
}

func appendString(target []byte, value string) []byte {
	target = binary.BigEndian.AppendUint32(target, uint32(len(value)))
	return append(target, value...)
}
