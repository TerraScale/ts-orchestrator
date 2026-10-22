package region

import (
	"crypto/sha256"
	"encoding/json/v2"
	"sync"
	"time"
)

// foundationVerificationMemoLimit bounds one authority's remembered documents.
const foundationVerificationMemoLimit = 32

// foundationVerificationMemo remembers grant documents that already passed
// full signature and schema verification under one exact trust binding. Keys
// are the binding digest plus the exact document digest, so different roots,
// anchors, scope or bytes never share an entry. Only successes are stored, and
// every hit rechecks the signed validity window against the current time.
// Callers still read current remote bytes; the memo only skips re-verifying
// bytes that are identical to ones already verified.
type foundationVerificationMemo struct {
	mu      sync.Mutex
	limit   int
	entries map[[sha256.Size]byte]verifiedFoundationDocument
}

type verifiedFoundationDocument struct {
	payload   []byte
	issuedAt  time.Time
	expiresAt time.Time
}

func newFoundationVerificationMemo() *foundationVerificationMemo {
	return newFoundationVerificationMemoWithLimit(foundationVerificationMemoLimit)
}

func newFoundationVerificationMemoWithLimit(limit int) *foundationVerificationMemo {
	return &foundationVerificationMemo{limit: limit, entries: map[[sha256.Size]byte]verifiedFoundationDocument{}}
}

func foundationVerificationKey(binding, document [sha256.Size]byte) [sha256.Size]byte {
	return sha256.Sum256(append(binding[:], document[:]...))
}

func (m *foundationVerificationMemo) lookup(key [sha256.Size]byte) (verifiedFoundationDocument, bool) {
	if m == nil {
		return verifiedFoundationDocument{}, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.entries[key]
	return entry, ok
}

func (m *foundationVerificationMemo) store(key [sha256.Size]byte, entry verifiedFoundationDocument) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.entries[key]; !ok && len(m.entries) >= m.limit {
		clear(m.entries)
	}
	m.entries[key] = entry
}

// signedFootprintBinding digests every input of verifyOriginalDocument other
// than the document bytes and the clock.
func signedFootprintBinding(s *SignedFootprint) ([sha256.Size]byte, error) {
	wire, err := json.Marshal(struct {
		Scope   any
		Roots   any
		Home    any
		Local   any
		Storage any
		Tenancy string
		Expires time.Time
	}{s.scope, s.roots, s.home, s.local, s.storage, s.tenancy, s.expires}, json.Deterministic(true))
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(wire), nil
}

// validatePreparedOriginalDocument runs ValidatePreparedFoundation on a grant
// that verifyOriginalDocument just returned for wire. The check is a pure
// function of those verified bytes, so a success is remembered under the same
// binding; the caller re-verifies signature, digest and validity every call.
func (s *SignedFootprint) validatePreparedOriginalDocument(wire []byte, grant FoundationGrant) error {
	if s.memo == nil {
		return ValidatePreparedFoundation(grant)
	}
	binding, err := signedFootprintBinding(s)
	if err != nil {
		return err
	}
	key := foundationVerificationKey(binding, sha256.Sum256(append([]byte("prepared\x00"), wire...)))
	if _, ok := s.memo.lookup(key); ok {
		return nil
	}
	if err := ValidatePreparedFoundation(grant); err != nil {
		return err
	}
	s.memo.store(key, verifiedFoundationDocument{})
	return nil
}

// originalRecordChecks remembers successful pure journal checks. Each check
// depends only on the record, so the key is the check name plus the digest of
// the record's deterministic encoding, which is exactly what the journal
// persists. Any changed byte is a different key and is checked in full; a
// failure is never remembered.
var originalRecordChecks = newFoundationVerificationMemoWithLimit(256)

func rememberOriginalRecordCheck(name string, record FoundationRecord, check func(FoundationRecord) error) error {
	wire, err := json.Marshal(record, json.Deterministic(true))
	if err != nil {
		return check(record)
	}
	key := sha256.Sum256(append(append([]byte(name), 0), wire...))
	if _, ok := originalRecordChecks.lookup(key); ok {
		return nil
	}
	if err := check(record); err != nil {
		return err
	}
	originalRecordChecks.store(key, verifiedFoundationDocument{})
	return nil
}
