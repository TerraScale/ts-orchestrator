package delivery

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// TrustSet is the orchestrator's active release-signing trust (D-70: the
// release signing key is a crown jewel that lives in the orchestrator). The
// set normally holds two keys during rotation overlap; verification accepts
// any key in the set and fails closed when the set is empty or the signature
// matches none. Key rotation swaps the whole set atomically.
type TrustSet struct {
	keys map[string]ed25519.PublicKey
}

// NewTrustSet validates a trust set: at least one key, unique non-empty key
// IDs, well-formed public keys.
func NewTrustSet(keys map[string]ed25519.PublicKey) (*TrustSet, error) {
	if len(keys) == 0 {
		return nil, errors.New("delivery: release trust set requires at least one signing key")
	}
	copied := make(map[string]ed25519.PublicKey, len(keys))
	for id, key := range keys {
		trimmed := strings.TrimSpace(id)
		if trimmed == "" || len(trimmed) > 64 || trimmed != id {
			return nil, fmt.Errorf("delivery: signing key id %q is invalid", id)
		}
		if len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("delivery: signing key %s is not an ed25519 public key", id)
		}
		copied[id] = append(ed25519.PublicKey(nil), key...)
	}
	return &TrustSet{keys: copied}, nil
}

// IDs lists the active key IDs in stable order.
func (t *TrustSet) IDs() []string {
	if t == nil {
		return nil
	}
	ids := make([]string, 0, len(t.keys))
	for id := range t.keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// VerifySignature checks the raw 64-byte detached Ed25519 signature
// published by ts-deploy against every active key. An empty set or malformed signature is a
// rejection, never an error: signature verification fails closed.
func (t *TrustSet) VerifySignature(message, signature []byte) bool {
	return t.verifyingKey(message, signature) != ""
}

// verifyingKey returns the key ID that verified the signature, or "".
func (t *TrustSet) verifyingKey(message, signature []byte) string {
	if t == nil || len(t.keys) == 0 || len(message) == 0 {
		return ""
	}
	if len(signature) != ed25519.SignatureSize {
		return ""
	}
	for _, id := range t.IDs() {
		if ed25519.Verify(t.keys[id], message, signature) {
			return id
		}
	}
	return ""
}
