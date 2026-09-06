// Package placementtransition issues durable GRU epoch grants. Pending placement,
// health, and authority leases are never evidence of old-member fencing.
package placementtransition

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"slices"
	"strings"
)

var (
	ErrInvalid  = errors.New("placement transition: invalid request or evidence")
	ErrConflict = errors.New("placement transition: immutable identity or prior epoch conflict")
	ErrMissing  = errors.New("placement transition: grant missing")
)

// Signed carries exact JSON bytes; verifiers authenticate these bytes before
// decoding them, avoiding cross-language JSON canonicalization assumptions.
type Signed struct {
	KeyID     string `json:"key_id"`
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}
type Member struct {
	Identity        string `json:"identity"`
	Region          string `json:"region"`
	PlacementDigest string `json:"placement_digest"`
}
type Request struct {
	OperationID string   `json:"operation_id"`
	ScopeID     string   `json:"scope_id"`
	PriorEpoch  uint64   `json:"prior_epoch"`
	Epoch       uint64   `json:"epoch"`
	Generation  uint64   `json:"generation"`
	Members     []Member `json:"members"`
}
type GenesisGrant struct {
	Kind          string `json:"kind"`
	GrantID       string `json:"grant_id"`
	RequestDigest string `json:"request_digest"`
}
type DrainReceipt struct {
	Kind            string `json:"kind"`
	MemberIdentity  string `json:"member_identity"`
	ScopeID         string `json:"scope_id"`
	PriorEpoch      uint64 `json:"prior_epoch"`
	PriorGeneration uint64 `json:"prior_generation"`
	RequestDigest   string `json:"request_digest"`
	FrontierDigest  string `json:"frontier_digest"`
}
type Proof struct {
	SchemaVersion       int      `json:"schema_version"`
	Kind                string   `json:"kind"`
	Request             Request  `json:"request"`
	RequestDigest       string   `json:"request_digest"`
	AuthorityEpoch      uint64   `json:"authority_epoch"`
	JournalRevision     uint64   `json:"journal_revision"`
	GenesisGrantID      string   `json:"genesis_grant_id"`
	ReceiptDigests      []string `json:"receipt_digests"`
	DrainReceipts       []Signed `json:"drain_receipts"`
	PriorGeneration     uint64   `json:"prior_generation"`
	PreviousProofDigest string   `json:"previous_proof_digest"`
	LeaseID             string   `json:"lease_id"`
	GenesisGrant        *Signed  `json:"genesis_grant"`
}

func token(s string) bool {
	if len(s) == 0 || len(s) > 256 {
		return false
	}
	for _, b := range []byte(s) {
		if b < 33 || b > 126 {
			return false
		}
	}
	return true
}
func digest(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == sha256.Size && strings.ToLower(s) == s
}
func hash(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func signatureInput(data []byte) []byte {
	return append([]byte("terrabase-placement-transition-v1\x00"), data...)
}

// RequestDigest accepts only already ordered, complete member bindings.
func RequestDigest(r Request) (string, error) {
	if !token(r.OperationID) || !token(r.ScopeID) || r.Epoch == 0 || r.Epoch <= r.PriorEpoch || r.Generation == 0 || len(r.Members) < 2 || len(r.Members) > 40 {
		return "", ErrInvalid
	}
	regions := map[string]int{}
	for n, m := range r.Members {
		if !token(m.Identity) || !token(m.Region) || !digest(m.PlacementDigest) || (n > 0 && r.Members[n-1].Identity >= m.Identity) {
			return "", ErrInvalid
		}
		regions[m.Region]++
	}
	for _, count := range regions {
		if count != 2 {
			return "", ErrInvalid
		}
	}
	b, e := json.Marshal(r)
	if e != nil {
		return "", ErrInvalid
	}
	return hash(b), nil
}

// SignEvidence is shared by authorized genesis and member drain producers.
// Callers must produce the actual durable fence/drain before signing a receipt.
func SignEvidence(keyID string, key ed25519.PrivateKey, value any) (Signed, error) {
	if !token(keyID) || len(key) != ed25519.PrivateKeySize {
		return Signed{}, ErrInvalid
	}
	b, e := json.Marshal(value)
	if e != nil || len(b) > 64<<10 {
		return Signed{}, ErrInvalid
	}
	return Signed{keyID, b, ed25519.Sign(key, signatureInput(b))}, nil
}
func verify(s Signed, key ed25519.PublicKey, target any) error {
	if len(key) != ed25519.PublicKeySize || len(s.Payload) == 0 || len(s.Payload) > 64<<10 || !ed25519.Verify(key, signatureInput(s.Payload), s.Signature) {
		return ErrInvalid
	}
	if json.Unmarshal(s.Payload, target, json.RejectUnknownMembers(true)) != nil {
		return ErrInvalid
	}
	return nil
}
func cloneSigned(s Signed) Signed {
	s.Payload = slices.Clone(s.Payload)
	s.Signature = slices.Clone(s.Signature)
	return s
}
