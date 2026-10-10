package trust

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

// A root chain makes the image's baked root set only the genesis anchor.
// Each rotation statement replaces the whole root set: a majority of the
// replaced roots and every new root sign the same payload, which names its
// sequence and the digest of the statement (or genesis set) it replaces.
// A minority of compromised roots therefore cannot rotate, a rotation
// cannot name a key nobody holds, and once a controller adopts a rotation
// the replaced roots can neither extend the chain nor sign anything it
// verifies as current. Controllers only adopt a chain that extends the one
// they hold, so a rival or shorter chain is refused.
const (
	RotationDomain = "terrascale.trust.root-rotation"
	RotationSchema = "terrascale.trust.root-rotation.v1"
	// MaxRotations bounds the chain; MaxRootSet bounds one root set, like
	// the baked inventory.
	MaxRotations        = 32
	MaxRootSet          = 16
	MaxRootChainBytes   = 512 << 10
	MaxRotationLifetime = 7 * 24 * time.Hour
	rotationRole        = "root"
)

var ErrRotationSigners = errors.New("root rotation lacks a majority of the replaced roots or a signature from every new root")

// RotationPolicy bounds rotation signatures.
func RotationPolicy() Policy { return Policy{MaxLifetime: MaxRotationLifetime, ClockSkew: time.Minute} }

// ChainIdentity binds a root chain to one deployment, cell and environment.
type ChainIdentity struct {
	DeploymentID string
	Cell         string
	Environment  string
}

// Rotation is the signed payload of one statement. Roots are the new set's
// canonical Base64 public keys, sorted by key ID.
type Rotation struct {
	Schema   string   `json:"schema"`
	Sequence uint64   `json:"sequence"`
	Previous string   `json:"previous"`
	Roots    []string `json:"roots"`
}

// SignedRotation is one rotation payload with each signer's envelope.
type SignedRotation struct {
	Signatures []Envelope `json:"signatures"`
}

// RootChain is every rotation after genesis, in order.
type RootChain struct {
	Version   int              `json:"version"`
	Rotations []SignedRotation `json:"rotations"`
}

// VerifiedRoots is the outcome of a chain verified from genesis. Only
// Current authorizes current actions; Historical (genesis and every rotated
// set) verifies records signed before a rotation.
type VerifiedRoots struct {
	Current    Keyring
	Historical Keyring
	Sequence   uint64
	// Head is the digest the next rotation's Previous must name.
	Head string
}

// RotationScope is the exact signature scope of statement sequence.
func RotationScope(id ChainIdentity, sequence uint64) Scope {
	return Scope{Domain: RotationDomain, DeploymentID: id.DeploymentID, Cell: id.Cell,
		Environment: id.Environment, Role: rotationRole, Slot: strconv.FormatUint(sequence, 10)}
}

// RootSetDigest is the SHA-256 of the set's sorted key IDs.
func RootSetDigest(roots Keyring) string {
	sum := sha256.Sum256([]byte(strings.Join(slices.Sorted(maps.Keys(roots)), "\n")))
	return hex.EncodeToString(sum[:])
}

// NextRotation builds the statement that replaces verified's current set
// with roots.
func NextRotation(verified VerifiedRoots, roots ...ed25519.PublicKey) (Rotation, error) {
	keyring, err := ParseKeyring(roots...)
	if err != nil {
		return Rotation{}, err
	}
	if len(keyring) > MaxRootSet {
		return Rotation{}, fmt.Errorf("%w: more than %d roots", ErrInvalid, MaxRootSet)
	}
	rotation := Rotation{Schema: RotationSchema, Sequence: verified.Sequence + 1, Previous: verified.Head}
	for _, keyID := range slices.Sorted(maps.Keys(keyring)) {
		rotation.Roots = append(rotation.Roots, base64.RawURLEncoding.EncodeToString(keyring[keyID]))
	}
	return rotation, nil
}

// SignRotation signs rotation with one old or new root.
func SignRotation(rotation Rotation, id ChainIdentity, issuedAt, expiresAt time.Time, key ed25519.PrivateKey) (Envelope, error) {
	if _, err := rotation.keyring(); err != nil {
		return Envelope{}, err
	}
	payload, err := EncodePayload(rotation)
	if err != nil {
		return Envelope{}, err
	}
	return Sign(payload, RotationScope(id, rotation.Sequence), issuedAt, expiresAt, key)
}

// Payload returns the statement every signature covers.
func (signed SignedRotation) Payload() (Rotation, error) {
	payload, err := signed.payload()
	if err != nil {
		return Rotation{}, err
	}
	return decodeRotation(payload)
}

// VerifyRootChain verifies every statement from genesis. It checks
// signatures and links, not whether the newest statement is still current;
// see RotationCurrent.
func VerifyRootChain(genesis Keyring, id ChainIdentity, chain RootChain) (VerifiedRoots, error) {
	if chain.Version != 1 || len(genesis) == 0 || len(genesis) > MaxRootSet || len(chain.Rotations) > MaxRotations {
		return VerifiedRoots{}, fmt.Errorf("%w: root chain genesis or length", ErrInvalid)
	}
	if err := RotationScope(id, 1).validate(); err != nil {
		return VerifiedRoots{}, err
	}
	verified := VerifiedRoots{Current: maps.Clone(genesis), Historical: maps.Clone(genesis), Head: RootSetDigest(genesis)}
	for index, signed := range chain.Rotations {
		next, payload, err := verifyRotation(signed, id, verified)
		if err != nil {
			return VerifiedRoots{}, fmt.Errorf("root rotation %d: %w", index+1, err)
		}
		sum := sha256.Sum256(payload)
		verified.Current, verified.Sequence, verified.Head = next, verified.Sequence+1, hex.EncodeToString(sum[:])
		maps.Copy(verified.Historical, next)
	}
	return verified, nil
}

func verifyRotation(signed SignedRotation, id ChainIdentity, previous VerifiedRoots) (Keyring, []byte, error) {
	if len(signed.Signatures) == 0 || len(signed.Signatures) > 2*MaxRootSet {
		return nil, nil, fmt.Errorf("%w: signature count", ErrInvalid)
	}
	payload, err := signed.payload()
	if err != nil {
		return nil, nil, err
	}
	rotation, err := decodeRotation(payload)
	if err != nil {
		return nil, nil, err
	}
	if rotation.Sequence != previous.Sequence+1 || rotation.Previous != previous.Head {
		return nil, nil, fmt.Errorf("%w: statement does not extend the verified chain", ErrInvalid)
	}
	next, err := rotation.keyring()
	if err != nil {
		return nil, nil, err
	}
	scope := RotationScope(id, rotation.Sequence)
	signers := map[string]bool{}
	for _, envelope := range signed.Signatures {
		key, ok := previous.Current[envelope.KeyID]
		if !ok {
			key, ok = next[envelope.KeyID]
		}
		if !ok {
			return nil, nil, ErrUntrustedKey
		}
		if signers[envelope.KeyID] {
			return nil, nil, fmt.Errorf("%w: duplicate rotation signer", ErrInvalid)
		}
		// Every signature must cover the same statement.
		if own, err := compactPayload(envelope.Payload); err != nil || !bytes.Equal(own, payload) {
			return nil, nil, fmt.Errorf("%w: signatures cover different statements", ErrInvalid)
		}
		if _, err := VerifyHistorical(envelope, scope, Keyring{envelope.KeyID: key}, RotationPolicy()); err != nil {
			return nil, nil, err
		}
		signers[envelope.KeyID] = true
	}
	old := 0
	for keyID := range previous.Current {
		if signers[keyID] {
			old++
		}
	}
	if old < len(previous.Current)/2+1 {
		return nil, nil, ErrRotationSigners
	}
	for keyID := range next {
		if !signers[keyID] {
			return nil, nil, ErrRotationSigners
		}
	}
	return next, payload, nil
}

// RotationCurrent requires every signature of a statement to be within its
// validity window at now, so a withheld statement cannot be applied late.
// It does not verify signatures; verify the chain first.
func RotationCurrent(signed SignedRotation, now time.Time) error {
	policy := RotationPolicy()
	for _, envelope := range signed.Signatures {
		if envelope.IssuedAt.Sub(now) > policy.ClockSkew {
			return ErrNotYetValid
		}
		if !now.Before(envelope.ExpiresAt) {
			return ErrExpired
		}
	}
	return nil
}

// Extends reports whether chain keeps every statement of prefix in order:
// adopting it neither forks nor rolls back the adopted chain.
func (chain RootChain) Extends(prefix RootChain) bool {
	if chain.Version != 1 || prefix.Version != 1 || len(chain.Rotations) < len(prefix.Rotations) {
		return false
	}
	for index, signed := range prefix.Rotations {
		left, leftErr := signed.payload()
		right, rightErr := chain.Rotations[index].payload()
		if leftErr != nil || rightErr != nil || !bytes.Equal(left, right) {
			return false
		}
	}
	return true
}

// EncodeRootChain emits the deterministic, bounded wire form.
func EncodeRootChain(chain RootChain) ([]byte, error) {
	if chain.Version != 1 {
		return nil, fmt.Errorf("%w: root chain requires version 1", ErrInvalid)
	}
	if chain.Rotations == nil {
		chain.Rotations = []SignedRotation{}
	}
	encoded, err := json.Marshal(chain, json.Deterministic(true))
	if err != nil {
		return nil, fmt.Errorf("encode root chain: %w", err)
	}
	if len(encoded) > MaxRootChainBytes {
		return nil, fmt.Errorf("%w: root chain exceeds %d bytes", ErrInvalid, MaxRootChainBytes)
	}
	return encoded, nil
}

// DecodeRootChain strictly decodes the canonical wire form.
func DecodeRootChain(wire []byte) (RootChain, error) {
	var chain RootChain
	if err := protocol.DecodeStrict(wire, &chain, MaxRootChainBytes); err != nil {
		return RootChain{}, fmt.Errorf("decode root chain: %w", err)
	}
	canonical, err := EncodeRootChain(chain)
	if err != nil {
		return RootChain{}, err
	}
	if !bytes.Equal(canonical, wire) {
		return RootChain{}, fmt.Errorf("%w: root chain is not canonical", ErrInvalid)
	}
	return chain, nil
}

func (signed SignedRotation) payload() ([]byte, error) {
	if len(signed.Signatures) == 0 {
		return nil, fmt.Errorf("%w: unsigned rotation", ErrInvalid)
	}
	return compactPayload(signed.Signatures[0].Payload)
}

func decodeRotation(payload []byte) (Rotation, error) {
	var rotation Rotation
	if err := protocol.DecodeStrict(payload, &rotation, MaxPayloadBytes); err != nil {
		return Rotation{}, fmt.Errorf("decode root rotation: %w", err)
	}
	canonical, err := EncodePayload(rotation)
	if err != nil || !bytes.Equal(canonical, payload) {
		return Rotation{}, fmt.Errorf("%w: root rotation is not canonical", ErrInvalid)
	}
	return rotation, nil
}

// keyring checks the statement's shape and returns its root set.
func (rotation Rotation) keyring() (Keyring, error) {
	if rotation.Schema != RotationSchema || rotation.Sequence == 0 || len(rotation.Previous) != 64 ||
		len(rotation.Roots) == 0 || len(rotation.Roots) > MaxRootSet {
		return nil, fmt.Errorf("%w: root rotation shape", ErrInvalid)
	}
	if _, err := hex.DecodeString(rotation.Previous); err != nil || strings.ToLower(rotation.Previous) != rotation.Previous {
		return nil, fmt.Errorf("%w: root rotation previous digest", ErrInvalid)
	}
	keys := make([]ed25519.PublicKey, 0, len(rotation.Roots))
	previousID := ""
	for _, encoded := range rotation.Roots {
		key, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
		if err != nil || len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: root rotation public key", ErrInvalid)
		}
		keyID, err := KeyID(key)
		if err != nil || keyID <= previousID {
			return nil, fmt.Errorf("%w: root rotation keys must be sorted by key ID without repeats", ErrInvalid)
		}
		previousID = keyID
		keys = append(keys, key)
	}
	return ParseKeyring(keys...)
}
