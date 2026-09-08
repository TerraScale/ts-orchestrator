package delivery

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// Operation states.
const (
	OperationRunning = "running"
	OperationDone    = "done"
)

// OperationKeyPrefix is the key namespace used by a DurableStore. A
// JetStream KeyValue adapter can map this directly to its bucket keys.
const OperationKeyPrefix = "delivery.operation."

// ErrStoreNotFound means that a key does not exist. A store must not use this
// error for an unavailable or indeterminate read: the journal fails closed
// for those errors.
var ErrStoreNotFound = errors.New("delivery: durable store entry not found")

// ErrStoreConflict means that a create-only or compare-and-set operation lost
// a race. It is not a persistence outage and may be safely re-read.
var ErrStoreConflict = errors.New("delivery: durable store compare-and-set conflict")

// ErrOperationConflict means that an operation ID is already bound to a
// different request. It is deliberately distinct from a store outage: the
// former is a client conflict while the latter must be surfaced as a retryable
// journal failure.
var ErrOperationConflict = errors.New("delivery: operation ID is bound to a different request")

// ErrOperationLeaseActive means another durable owner still holds the
// operation lease. Recovery and takeover must fail closed in this case.
var ErrOperationLeaseActive = errors.New("delivery: operation lease is active")

// OperationFence is the authoritative capability passed to every delivery
// side-effect. The digest binds it to the exact admitted request while owner
// and generation fence stale processes after takeover.
type OperationFence struct {
	OperationID   string
	RequestDigest string
	OwnerID       string
	Generation    uint64
}

// FenceChecker verifies a fence immediately before a provider mutation.
type FenceChecker func(OperationFence) error

const minimumOperationLeaseTTL = time.Second

// StoreEntry is one versioned value in a DurableStore. Revisions are opaque
// to Journal, but must increase for every successful write to a key and must
// be accepted by Update only when they still match.
type StoreEntry struct {
	Key      string
	Value    []byte
	Revision uint64
}

// DurableStore is the persistence boundary for accepted delivery operations.
// It intentionally has the shape of JetStream KeyValue: Create is atomic and
// Update is compare-and-set by the observed revision. Implementations must
// make each method concurrency-safe and return ErrStoreNotFound, rather than
// a successful empty value, for a missing key.
//
// List is used for status output and recovery. It must return all values whose
// keys have the supplied prefix, and must not return a partial result on error.
type DurableStore interface {
	Get(key string) (StoreEntry, error)
	Create(key string, value []byte) (StoreEntry, error)
	Update(key string, expectedRevision uint64, value []byte) (StoreEntry, error)
	List(prefix string) ([]StoreEntry, error)
}

// InMemoryStore is a deterministic, concurrency-safe DurableStore adapter for
// tests. It is deliberately not selected by any durable constructor; a
// production process must be given a store backed by JetStream (or another
// durable implementation).
type InMemoryStore struct {
	mu      sync.RWMutex
	entries map[string]StoreEntry
	nextRev uint64
}

// NewInMemoryStore creates the test-only in-memory adapter.
func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{entries: make(map[string]StoreEntry)}
}

func (s *InMemoryStore) Get(key string) (StoreEntry, error) {
	if s == nil {
		return StoreEntry{}, errors.New("delivery: durable store is not configured")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.entries[key]
	if !ok {
		return StoreEntry{}, ErrStoreNotFound
	}
	return cloneStoreEntry(entry), nil
}

func (s *InMemoryStore) Create(key string, value []byte) (StoreEntry, error) {
	if s == nil {
		return StoreEntry{}, errors.New("delivery: durable store is not configured")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.entries[key]; ok {
		return StoreEntry{}, ErrStoreConflict
	}
	entry := s.writeEntry(key, value)
	s.entries[key] = entry
	return cloneStoreEntry(entry), nil
}

func (s *InMemoryStore) Update(key string, expectedRevision uint64, value []byte) (StoreEntry, error) {
	if s == nil {
		return StoreEntry{}, errors.New("delivery: durable store is not configured")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prior, ok := s.entries[key]
	if !ok {
		return StoreEntry{}, ErrStoreNotFound
	}
	if prior.Revision != expectedRevision {
		return StoreEntry{}, ErrStoreConflict
	}
	entry := s.writeEntry(key, value)
	s.entries[key] = entry
	return cloneStoreEntry(entry), nil
}

func (s *InMemoryStore) List(prefix string) ([]StoreEntry, error) {
	if s == nil {
		return nil, errors.New("delivery: durable store is not configured")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	entries := make([]StoreEntry, 0, len(s.entries))
	for key, entry := range s.entries {
		if len(prefix) == 0 || (len(key) >= len(prefix) && key[:len(prefix)] == prefix) {
			entries = append(entries, cloneStoreEntry(entry))
		}
	}
	sort.Slice(entries, func(i, k int) bool { return entries[i].Key < entries[k].Key })
	return entries, nil
}

func (s *InMemoryStore) writeEntry(key string, value []byte) StoreEntry {
	s.nextRev++
	return StoreEntry{Key: key, Value: append([]byte(nil), value...), Revision: s.nextRev}
}

func cloneStoreEntry(entry StoreEntry) StoreEntry {
	entry.Value = append([]byte(nil), entry.Value...)
	return entry
}

// Operation is one durable delivery operation: the request, its canonical
// digest (idempotency), and the terminal receipt once it exists.
type Operation struct {
	OperationID              string
	Request                  *Request
	RequestDigest            string
	State                    string
	Receipt                  *Receipt
	StartedAt                time.Time
	FinishedAt               time.Time
	UpdatedAt                time.Time
	OwnerID                  string
	Generation               uint64
	LeaseUntil               time.Time
	Rollout                  *RolloutProgress
	ReleaseSignature         []byte
	ReleaseManifest          []byte
	ReleaseManifestSignature []byte
	ReleaseSignatureKey      string
}

// RolloutProgress is the durable host mutation ledger.
type RolloutProgress struct {
	Hosts []RolloutHostProgress
	Edges []EdgeRolloutProgress
}

type RolloutHostProgress struct {
	Host                string
	PriorDigest         string
	PriorManifestDigest string
	CandidateDigest     string
	Mutated             bool
	Completed           bool
}

// EdgeRolloutProgress records an edge mutation before calling the provider.
// Applied remains conservative when a provider returns an indeterminate error.
type EdgeRolloutProgress struct {
	Kind            string
	Service         string
	PriorDigest     string
	PriorState      string
	CandidateDigest string
	Stage           int
	Applied         bool
	Completed       bool
}

// OperationLease identifies the process that is allowed to execute and
// finish an operation. Generation fencing prevents stale owners from renewing
// or finishing after a durable takeover.
type OperationLease struct {
	OwnerID    string
	TTL        time.Duration
	Generation uint64
}

const defaultOperationLeaseTTL = 30 * time.Second

func leaseTTL(value time.Duration) time.Duration {
	if value <= 0 {
		return defaultOperationLeaseTTL
	}
	return value
}

func validateLease(lease OperationLease) error {
	if strings.TrimSpace(lease.OwnerID) == "" || lease.OwnerID != strings.TrimSpace(lease.OwnerID) || len(lease.OwnerID) > 128 {
		return errors.New("delivery: operation lease owner is required")
	}
	if lease.TTL > 0 && lease.TTL < minimumOperationLeaseTTL {
		return fmt.Errorf("delivery: operation lease TTL must be at least %s", minimumOperationLeaseTTL)
	}
	return nil
}

// Journal is the delivery operation journal backing idempotency and receipt
// polling. All accepted and terminal state is read from and written to the
// supplied DurableStore; no process-local operation map is authoritative.
type Journal struct {
	store DurableStore
	clock func() time.Time
}

// NewJournal returns a Journal using the deterministic in-memory adapter.
// This compatibility constructor exists for unit tests and local fixtures.
// Production code must use NewDurableJournal with its JetStream-backed store.
// The optional argument is provided to make migration from the old no-arg API
// painless; at most one store should be supplied.
func NewJournal(stores ...DurableStore) *Journal {
	store := DurableStore(NewInMemoryStore())
	if len(stores) != 0 && stores[0] != nil {
		store = stores[0]
	}
	return &Journal{store: store}
}

// NewDurableJournal constructs a journal over an authoritative durable store.
func NewDurableJournal(store DurableStore) (*Journal, error) {
	if store == nil {
		return nil, errors.New("delivery: journal requires a durable store")
	}
	return &Journal{store: store}, nil
}

// Begin admits one operation. Create is atomic, so concurrent callers cannot
// both become the owner. An existing record with the same request digest is
// returned with exists=true (idempotent replay); the same operation ID with a
// different request is a conflict, never a restart. Store failures are
// returned and never treated as an empty journal.
func (j *Journal) Begin(request *Request, leases ...OperationLease) (operation *Operation, exists bool, err error) {
	if j == nil || j.store == nil {
		return nil, false, errors.New("delivery: journal is not configured")
	}
	if request == nil {
		return nil, false, errors.New("delivery: journal requires a request")
	}
	if len(leases) > 0 {
		if err := validateLease(leases[0]); err != nil {
			return nil, false, err
		}
	}
	if !operationIDPattern.MatchString(request.OperationID) {
		return nil, false, errors.New("delivery: journal operation ID is invalid")
	}
	digest, err := requestDigest(request)
	if err != nil {
		return nil, false, err
	}
	now := j.now()
	operation = &Operation{
		OperationID:   request.OperationID,
		Request:       cloneRequest(request),
		RequestDigest: digest,
		State:         OperationRunning,
		StartedAt:     now,
		UpdatedAt:     now,
	}
	if len(leases) > 0 && leases[0].OwnerID != "" {
		operation.OwnerID = leases[0].OwnerID
		operation.Generation = 1
		operation.LeaseUntil = now.Add(leaseTTL(leases[0].TTL))
	}
	key := operationKey(request.OperationID)
	value, err := encodeOperation(operation)
	if err != nil {
		return nil, false, fmt.Errorf("delivery: journal admission encoding failed: %w", err)
	}
	entry, err := j.store.Create(key, value)
	if err == nil {
		operation, err = decodeOperation(entry, request.OperationID)
		if err != nil {
			return nil, false, err
		}
		return operation, false, nil
	}
	if !errors.Is(err, ErrStoreConflict) {
		return nil, false, fmt.Errorf("delivery: journal admission persistence failed: %w", err)
	}
	return j.existingForBegin(key, request.OperationID, digest)
}

// Takeover acquires an expired running operation using a compare-and-set
// generation fence. It never executes provider work itself.
func (j *Journal) Takeover(operationID, requestDigest string, lease OperationLease) (*Operation, error) {
	if j == nil || j.store == nil || lease.OwnerID == "" {
		return nil, errors.New("delivery: operation takeover requires a configured journal and owner")
	}
	if err := validateLease(lease); err != nil {
		return nil, err
	}
	key := operationKey(operationID)
	entry, err := j.store.Get(key)
	if err != nil {
		return nil, fmt.Errorf("delivery: operation takeover read failed: %w", err)
	}
	operation, err := decodeOperation(entry, operationID)
	if err != nil {
		return nil, err
	}
	if operation.RequestDigest != requestDigest {
		return nil, ErrOperationConflict
	}
	if operation.State == OperationDone {
		return operation, nil
	}
	if operation.State != OperationRunning {
		return nil, fmt.Errorf("delivery: operation %s has invalid state %q", operationID, operation.State)
	}
	now := j.now()
	// Legacy running records without a lease have no provable owner boundary;
	// they remain fail-closed and require explicit operator recovery.
	if operation.LeaseUntil.IsZero() {
		return nil, ErrOperationLeaseActive
	}
	if !operation.LeaseUntil.IsZero() && now.Before(operation.LeaseUntil) {
		return nil, ErrOperationLeaseActive
	}
	next := cloneOperation(operation)
	next.OwnerID = lease.OwnerID
	next.Generation++
	if next.Generation == 0 {
		return nil, errors.New("delivery: operation takeover generation overflow")
	}
	next.LeaseUntil = now.Add(leaseTTL(lease.TTL))
	next.UpdatedAt = now
	value, err := encodeOperation(next)
	if err != nil {
		return nil, err
	}
	updated, err := j.store.Update(key, entry.Revision, value)
	if err != nil {
		if errors.Is(err, ErrStoreConflict) {
			return nil, ErrOperationLeaseActive
		}
		return nil, fmt.Errorf("delivery: operation takeover persistence failed: %w", err)
	}
	return decodeOperation(updated, operationID)
}

// Renew extends an owner's lease only when both owner and generation still
// match. A stale process can therefore never regain execution authority.
func (j *Journal) Renew(operationID, requestDigest string, lease OperationLease, generation uint64) error {
	if j == nil || j.store == nil || lease.OwnerID == "" || generation == 0 {
		return errors.New("delivery: operation renewal requires a configured journal and owner")
	}
	if err := validateLease(lease); err != nil {
		return err
	}
	key := operationKey(operationID)
	entry, err := j.store.Get(key)
	if err != nil {
		return fmt.Errorf("delivery: operation renewal read failed: %w", err)
	}
	operation, err := decodeOperation(entry, operationID)
	if err != nil {
		return err
	}
	if operation.RequestDigest != requestDigest {
		return ErrOperationConflict
	}
	if operation.State != OperationRunning || operation.OwnerID != lease.OwnerID || operation.Generation != generation {
		return ErrOperationLeaseActive
	}
	now := j.now()
	if !operation.LeaseUntil.IsZero() && !now.Before(operation.LeaseUntil) {
		return ErrOperationLeaseActive
	}
	next := cloneOperation(operation)
	next.LeaseUntil = now.Add(leaseTTL(lease.TTL))
	next.UpdatedAt = now
	value, err := encodeOperation(next)
	if err != nil {
		return err
	}
	if _, err := j.store.Update(key, entry.Revision, value); err != nil {
		if errors.Is(err, ErrStoreConflict) {
			return ErrOperationLeaseActive
		}
		return fmt.Errorf("delivery: operation renewal persistence failed: %w", err)
	}
	return nil
}

// RecordRollout persists progress while the owner lease is held. It is
// intentionally compare-and-set based so a takeover cannot be overwritten.
func (j *Journal) RecordRollout(operationID, requestDigest string, lease OperationLease, host, priorDigest, priorManifest, candidate string, mutated, completed bool) error {
	if j == nil || j.store == nil {
		return errors.New("delivery: rollout journal is not configured")
	}
	for attempt := 0; attempt < 3; attempt++ {
		entry, err := j.store.Get(operationKey(operationID))
		if err != nil {
			return err
		}
		op, err := decodeOperation(entry, operationID)
		if err != nil {
			return err
		}
		if op.State != OperationRunning || op.RequestDigest != requestDigest || op.OwnerID != lease.OwnerID || op.Generation != lease.Generation {
			return ErrOperationLeaseActive
		}
		if op.Rollout == nil {
			op.Rollout = &RolloutProgress{}
		}
		found := false
		for i := range op.Rollout.Hosts {
			if op.Rollout.Hosts[i].Host == host {
				op.Rollout.Hosts[i].Mutated = op.Rollout.Hosts[i].Mutated || mutated
				op.Rollout.Hosts[i].Completed = op.Rollout.Hosts[i].Completed || completed
				found = true
				break
			}
		}
		if !found {
			op.Rollout.Hosts = append(op.Rollout.Hosts, RolloutHostProgress{Host: host, PriorDigest: priorDigest, PriorManifestDigest: priorManifest, CandidateDigest: candidate, Mutated: mutated, Completed: completed})
		}
		op.UpdatedAt = j.now()
		value, err := encodeOperation(op)
		if err != nil {
			return err
		}
		if _, err = j.store.Update(entry.Key, entry.Revision, value); err == nil {
			return nil
		}
		if !errors.Is(err, ErrStoreConflict) {
			return err
		}
	}
	return ErrOperationLeaseActive
}

// RecordEdgeRollout persists edge intent and readback progress under the owner lease.
func (j *Journal) RecordEdgeRollout(operationID, requestDigest string, lease OperationLease, kind, service, priorDigest, priorState, candidate string, stage int, applied, completed bool) error {
	if j == nil || j.store == nil {
		return errors.New("delivery: rollout journal is not configured")
	}
	for attempt := 0; attempt < 3; attempt++ {
		entry, err := j.store.Get(operationKey(operationID))
		if err != nil {
			return err
		}
		op, err := decodeOperation(entry, operationID)
		if err != nil {
			return err
		}
		if op.State != OperationRunning || op.RequestDigest != requestDigest || op.OwnerID != lease.OwnerID || op.Generation != lease.Generation {
			return ErrOperationLeaseActive
		}
		if op.Rollout == nil {
			op.Rollout = &RolloutProgress{}
		}
		found := false
		for i := range op.Rollout.Edges {
			if op.Rollout.Edges[i].Kind == kind && op.Rollout.Edges[i].Service == service {
				e := &op.Rollout.Edges[i]
				e.PriorDigest, e.PriorState, e.CandidateDigest = priorDigest, priorState, candidate
				e.Stage = max(e.Stage, stage)
				e.Applied = e.Applied || applied
				e.Completed = e.Completed || completed
				found = true
				break
			}
		}
		if !found {
			op.Rollout.Edges = append(op.Rollout.Edges, EdgeRolloutProgress{Kind: kind, Service: service, PriorDigest: priorDigest, PriorState: priorState, CandidateDigest: candidate, Stage: stage, Applied: applied, Completed: completed})
		}
		op.UpdatedAt = j.now()
		value, err := encodeOperation(op)
		if err != nil {
			return err
		}
		if _, err = j.store.Update(entry.Key, entry.Revision, value); err == nil {
			return nil
		}
		if !errors.Is(err, ErrStoreConflict) {
			return err
		}
	}
	return ErrOperationLeaseActive
}

func (j *Journal) RecordReleaseSignature(operationID, requestDigest string, lease OperationLease, signature []byte) error {
	return j.recordReleaseEvidence(operationID, requestDigest, lease, signature, nil, nil, "", false)
}

func (j *Journal) RecordReleaseEvidence(operationID, requestDigest string, lease OperationLease, signature, manifest, manifestSignature []byte, signatureKey string) error {
	return j.recordReleaseEvidence(operationID, requestDigest, lease, signature, manifest, manifestSignature, signatureKey, true)
}

func (j *Journal) recordReleaseEvidence(operationID, requestDigest string, lease OperationLease, signature, manifest, manifestSignature []byte, signatureKey string, requireManifest bool) error {
	if len(signature) != ed25519.SignatureSize {
		return errors.New("delivery: release signature has invalid size")
	}
	if requireManifest && (len(manifest) == 0 || len(manifestSignature) != ed25519.SignatureSize || signatureKey == "") {
		return errors.New("delivery: complete release evidence is required")
	}
	for attempt := 0; attempt < 3; attempt++ {
		entry, err := j.store.Get(operationKey(operationID))
		if err != nil {
			return err
		}
		op, err := decodeOperation(entry, operationID)
		if err != nil {
			return err
		}
		if op.State != OperationRunning || op.RequestDigest != requestDigest || op.OwnerID != lease.OwnerID || op.Generation != lease.Generation {
			return ErrOperationLeaseActive
		}
		if len(op.ReleaseSignature) != 0 && !bytes.Equal(op.ReleaseSignature, signature) {
			return errors.New("delivery: release signature changed")
		}
		if len(op.ReleaseManifest) != 0 && !bytes.Equal(op.ReleaseManifest, manifest) {
			return errors.New("delivery: release manifest changed")
		}
		if len(op.ReleaseManifestSignature) != 0 && !bytes.Equal(op.ReleaseManifestSignature, manifestSignature) {
			return errors.New("delivery: release manifest signature changed")
		}
		if op.ReleaseSignatureKey != "" && op.ReleaseSignatureKey != signatureKey {
			return errors.New("delivery: release signature key changed")
		}
		op.ReleaseSignature = bytes.Clone(signature)
		op.ReleaseManifest = bytes.Clone(manifest)
		op.ReleaseManifestSignature = bytes.Clone(manifestSignature)
		op.ReleaseSignatureKey = signatureKey
		op.UpdatedAt = j.now()
		value, err := encodeOperation(op)
		if err != nil {
			return err
		}
		if _, err = j.store.Update(entry.Key, entry.Revision, value); err == nil {
			return nil
		}
		if !errors.Is(err, ErrStoreConflict) {
			return err
		}
	}
	return ErrOperationLeaseActive
}

func (j *Journal) existingForBegin(key, operationID, digest string) (*Operation, bool, error) {
	entry, err := j.store.Get(key)
	if err != nil {
		return nil, false, fmt.Errorf("delivery: journal admission read failed: %w", err)
	}
	operation, err := decodeOperation(entry, operationID)
	if err != nil {
		return nil, false, err
	}
	if operation.RequestDigest != digest {
		return nil, false, fmt.Errorf("%w: %s exists with a different request", ErrOperationConflict, operationID)
	}
	return operation, true, nil
}

// Finish records the terminal receipt of one operation using compare and set.
// A terminal operation is immutable: replaying the exact same receipt is fine,
// replacing it (even with the same status and different fields) is not.
func (j *Journal) Finish(operationID, requestDigest string, receipt *Receipt, leases ...OperationLease) error {
	if j == nil || j.store == nil || receipt == nil {
		return errors.New("delivery: journal finish requires a configured journal and receipt")
	}
	if operationID == "" || requestDigest == "" {
		return errors.New("delivery: journal finish requires an operation and request digest")
	}
	key := operationKey(operationID)
	entry, err := j.store.Get(key)
	if err != nil {
		return fmt.Errorf("delivery: journal finish read failed: %w", err)
	}
	operation, err := decodeOperation(entry, operationID)
	if err != nil {
		return err
	}
	if operation.RequestDigest != requestDigest {
		return fmt.Errorf("delivery: operation %s digest changed", operationID)
	}
	if operation.OwnerID != "" && len(leases) == 0 {
		return ErrOperationLeaseActive
	}
	if len(leases) > 0 && (operation.OwnerID != leases[0].OwnerID || operation.Generation != leases[0].Generation) {
		return ErrOperationLeaseActive
	}
	if len(leases) > 0 && !operation.LeaseUntil.IsZero() && !j.now().Before(operation.LeaseUntil) {
		return ErrOperationLeaseActive
	}
	if operation.State == OperationDone {
		if sameReceipt(operation.Receipt, receipt) {
			return nil
		}
		return fmt.Errorf("delivery: operation %s is already terminal", operationID)
	}
	if operation.State != OperationRunning {
		return fmt.Errorf("delivery: operation %s has invalid state %q", operationID, operation.State)
	}
	if err := validateJournalReceipt(receipt, operationID); err != nil {
		return err
	}
	if ValidateRequest(operation.Request) == nil {
		if err := ValidateReceipt(receipt, operation.Request); err != nil {
			return fmt.Errorf("delivery: journal finish receipt is invalid: %w", err)
		}
	}
	now := j.now()
	if now.Before(operation.UpdatedAt) {
		now = operation.UpdatedAt
	}
	next := cloneOperation(operation)
	next.State = OperationDone
	next.Receipt = cloneReceipt(receipt)
	next.FinishedAt = now
	next.UpdatedAt = now
	value, err := encodeOperation(next)
	if err != nil {
		return fmt.Errorf("delivery: journal finish encoding failed: %w", err)
	}
	if _, err := j.store.Update(key, entry.Revision, value); err == nil {
		return nil
	} else if !errors.Is(err, ErrStoreConflict) {
		return fmt.Errorf("delivery: journal finish persistence failed: %w", err)
	}
	// Another writer may have completed the operation. Re-read before
	// reporting an error so an idempotent replay remains successful.
	latest, readErr := j.store.Get(key)
	if readErr != nil {
		return fmt.Errorf("delivery: journal finish conflict recovery failed: %w", readErr)
	}
	current, decodeErr := decodeOperation(latest, operationID)
	if decodeErr != nil {
		return decodeErr
	}
	if current.RequestDigest == requestDigest && current.State == OperationDone && sameReceipt(current.Receipt, receipt) {
		return nil
	}
	return fmt.Errorf("delivery: operation %s changed concurrently", operationID)
}

// VerifyFence checks the durable owner, generation, request digest, and lease
// expiry. It is intentionally a fresh store read so callers invoke it at the
// provider boundary rather than relying on a context value captured earlier.
func (j *Journal) VerifyFence(fence OperationFence) error {
	if j == nil || j.store == nil || fence.OperationID == "" || fence.RequestDigest == "" || fence.OwnerID == "" || fence.Generation == 0 {
		return ErrOperationLeaseActive
	}
	entry, err := j.store.Get(operationKey(fence.OperationID))
	if err != nil {
		return fmt.Errorf("delivery: operation fence read failed: %w", err)
	}
	operation, err := decodeOperation(entry, fence.OperationID)
	if err != nil {
		return err
	}
	if operation.State != OperationRunning || operation.RequestDigest != fence.RequestDigest || operation.OwnerID != fence.OwnerID || operation.Generation != fence.Generation || operation.LeaseUntil.IsZero() || !j.now().Before(operation.LeaseUntil) {
		return ErrOperationLeaseActive
	}
	return nil
}

// RecoverUnknown closes an accepted running operation without executing any
// provider work. It is an explicit crash-recovery fence: an operator may use
// it only after establishing that the former owner is stopped. The receipt
// records an indeterminate outcome so callers must choose a fresh operation ID
// after investigating provider state.
func (j *Journal) RecoverUnknown(operationID string) (*Receipt, error) {
	if j == nil || j.store == nil {
		return nil, errors.New("delivery: journal recovery requires a configured journal")
	}
	if operationID == "" || !operationIDPattern.MatchString(operationID) {
		return nil, errors.New("delivery: journal recovery operation ID is invalid")
	}
	key := operationKey(operationID)
	entry, err := j.store.Get(key)
	if err != nil {
		return nil, fmt.Errorf("delivery: journal recovery read failed: %w", err)
	}
	operation, err := decodeOperation(entry, operationID)
	if err != nil {
		return nil, err
	}
	if operation.State == OperationDone {
		return operation.Receipt, nil
	}
	if operation.State != OperationRunning {
		return nil, fmt.Errorf("delivery: operation %s has invalid state %q", operationID, operation.State)
	}
	// A record without a durable lease has no enforceable owner boundary. It
	// may be an old record written before fencing was introduced, but treating
	// it as recoverable would let recovery race an owner that is still alive.
	if operation.OwnerID == "" || operation.Generation == 0 || operation.LeaseUntil.IsZero() {
		return nil, ErrOperationLeaseActive
	}
	if j.now().Before(operation.LeaseUntil) {
		return nil, ErrOperationLeaseActive
	}
	// Recovery itself takes a generation fence before publishing an unknown
	// outcome. The compare-and-set below is the hand-off point: either this
	// recovery wins, or a concurrent owner/takeover wins and this call must not
	// claim a terminal result. The owner identity is deliberately unique to
	// this recovery attempt so a stale process can never renew or finish it.
	nextGeneration := operation.Generation + 1
	if nextGeneration == 0 {
		return nil, errors.New("delivery: operation recovery generation overflow")
	}
	recoveryOwner := fmt.Sprintf("recovery-%s-%d", operationID, nextGeneration)
	receipt, err := buildReceipt(operation.Request, RolloutResult{
		Status:    StatusFailed,
		Checks:    []*HealthCheck{{Name: "recovery", Status: "failed"}},
		Converged: false,
		Rollback:  &Rollback{Attempted: true, Status: RollbackFailed},
		Error: &Error{
			Code:        ptr("operation_unknown"),
			Message:     ptr("The prior delivery owner stopped before its outcome was recorded."),
			Remediation: ptr("Inspect provider state and retry with a fresh operation ID."),
		},
	}, false)
	if err != nil {
		return nil, err
	}
	if ValidateRequest(operation.Request) == nil {
		if err := ValidateReceipt(receipt, operation.Request); err != nil {
			return nil, fmt.Errorf("delivery: journal recovery receipt is invalid: %w", err)
		}
	}
	now := j.now()
	if now.Before(operation.UpdatedAt) {
		now = operation.UpdatedAt
	}
	next := cloneOperation(operation)
	next.OwnerID = recoveryOwner
	next.Generation = nextGeneration
	next.LeaseUntil = time.Time{}
	next.State = OperationDone
	next.Receipt = cloneReceipt(receipt)
	next.FinishedAt = now
	next.UpdatedAt = now
	value, err := encodeOperation(next)
	if err != nil {
		return nil, fmt.Errorf("delivery: journal recovery encoding failed: %w", err)
	}
	if _, err := j.store.Update(key, entry.Revision, value); err == nil {
		return receipt, nil
	} else if !errors.Is(err, ErrStoreConflict) {
		return nil, fmt.Errorf("delivery: journal recovery persistence failed: %w", err)
	}
	latest, readErr := j.store.Get(key)
	if readErr != nil {
		return nil, fmt.Errorf("delivery: journal recovery conflict recovery failed: %w", readErr)
	}
	current, decodeErr := decodeOperation(latest, operationID)
	if decodeErr != nil {
		return nil, decodeErr
	}
	if current.State == OperationDone && current.Receipt != nil {
		return current.Receipt, nil
	}
	return nil, fmt.Errorf("delivery: operation %s changed concurrently", operationID)
}

// Get returns a copy of one operation by ID. Persistence errors are reported
// as not-found for compatibility with the original API; callers that must
// distinguish outage from absence should use GetWithError.
func (j *Journal) Get(operationID string) (*Operation, bool) {
	operation, found, err := j.GetWithError(operationID)
	if err != nil {
		return nil, false
	}
	return operation, found
}

// GetWithError returns a copy and preserves durable-store errors. A missing
// key is the only successful false result.
func (j *Journal) GetWithError(operationID string) (*Operation, bool, error) {
	if j == nil || j.store == nil {
		return nil, false, errors.New("delivery: journal is not configured")
	}
	entry, err := j.store.Get(operationKey(operationID))
	if errors.Is(err, ErrStoreNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("delivery: journal read failed: %w", err)
	}
	operation, err := decodeOperation(entry, operationID)
	if err != nil {
		return nil, false, err
	}
	return operation, true, nil
}

// Snapshot lists every operation, oldest first, for rollout status output.
// On persistence failure it returns nil for compatibility; SnapshotWithError
// should be used by fail-closed callers.
func (j *Journal) Snapshot() []Operation {
	operations, err := j.SnapshotWithError()
	if err != nil {
		return nil
	}
	return operations
}

// SnapshotWithError lists every operation and never returns a partial result.
func (j *Journal) SnapshotWithError() ([]Operation, error) {
	if j == nil || j.store == nil {
		return nil, errors.New("delivery: journal is not configured")
	}
	entries, err := j.store.List(OperationKeyPrefix)
	if err != nil {
		return nil, fmt.Errorf("delivery: journal snapshot failed: %w", err)
	}
	operations := make([]Operation, 0, len(entries))
	for _, entry := range entries {
		operationID := entry.Key
		if len(operationID) >= len(OperationKeyPrefix) && operationID[:len(OperationKeyPrefix)] == OperationKeyPrefix {
			operationID = operationID[len(OperationKeyPrefix):]
		}
		operation, err := decodeOperation(entry, operationID)
		if err != nil {
			return nil, err
		}
		operations = append(operations, *operation)
	}
	sort.SliceStable(operations, func(i, k int) bool {
		if operations[i].StartedAt.Equal(operations[k].StartedAt) {
			return operations[i].OperationID < operations[k].OperationID
		}
		return operations[i].StartedAt.Before(operations[k].StartedAt)
	})
	return operations, nil
}

func operationKey(operationID string) string { return OperationKeyPrefix + operationID }

func (j *Journal) now() time.Time {
	if j.clock != nil {
		return j.clock()
	}
	return time.Now().UTC()
}

func encodeOperation(operation *Operation) ([]byte, error) {
	return json.Marshal(operation)
}

func decodeOperation(entry StoreEntry, operationID string) (*Operation, error) {
	if entry.Key != "" && entry.Key != operationKey(operationID) {
		return nil, fmt.Errorf("delivery: durable operation %s has a mismatched key", operationID)
	}
	var operation Operation
	decoder := json.NewDecoder(bytes.NewReader(entry.Value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&operation); err != nil {
		return nil, fmt.Errorf("delivery: durable operation %s is corrupt: %w", operationID, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("delivery: durable operation %s has trailing data", operationID)
		}
		return nil, fmt.Errorf("delivery: durable operation %s has trailing data: %w", operationID, err)
	}
	if operation.OperationID != operationID || operation.Request == nil || operation.RequestDigest == "" || operation.State == "" {
		return nil, fmt.Errorf("delivery: durable operation %s is invalid", operationID)
	}
	digest, err := requestDigest(operation.Request)
	if err != nil || digest != operation.RequestDigest {
		return nil, fmt.Errorf("delivery: durable operation %s request digest is invalid", operationID)
	}
	if !operationIDPattern.MatchString(operation.OperationID) {
		return nil, fmt.Errorf("delivery: durable operation %s has an invalid operation ID", operationID)
	}
	if operation.State == OperationRunning && operation.Receipt != nil {
		return nil, fmt.Errorf("delivery: durable operation %s has a receipt while running", operationID)
	}
	if operation.State == OperationDone && operation.Receipt == nil {
		return nil, fmt.Errorf("delivery: durable operation %s is done without a receipt", operationID)
	}
	if operation.Receipt != nil {
		if err := validateJournalReceipt(operation.Receipt, operationID); err != nil {
			return nil, err
		}
		// The journal is also a receipt boundary. Legacy/unit-only records may
		// contain deliberately skeletal requests, but any production-shaped
		// request must have a receipt that satisfies the complete contract before
		// it can be replayed after restart.
		if ValidateRequest(operation.Request) == nil {
			if err := ValidateReceipt(operation.Receipt, operation.Request); err != nil {
				return nil, fmt.Errorf("delivery: durable operation %s receipt is invalid: %w", operationID, err)
			}
		}
	}
	if operation.State != OperationRunning && operation.State != OperationDone {
		return nil, fmt.Errorf("delivery: durable operation %s has invalid state %q", operationID, operation.State)
	}
	if operation.StartedAt.IsZero() || operation.UpdatedAt.IsZero() {
		return nil, fmt.Errorf("delivery: durable operation %s has invalid timestamps", operationID)
	}
	if !operation.FinishedAt.IsZero() && operation.FinishedAt.Before(operation.StartedAt) {
		return nil, fmt.Errorf("delivery: durable operation %s has an invalid finish timestamp", operationID)
	}
	if operation.OwnerID == "" && (!operation.LeaseUntil.IsZero() || operation.Generation != 0) {
		return nil, fmt.Errorf("delivery: durable operation %s has an invalid lease", operationID)
	}
	if operation.OwnerID != "" && operation.Generation == 0 {
		return nil, fmt.Errorf("delivery: durable operation %s has an invalid lease generation", operationID)
	}
	return cloneOperation(&operation), nil
}

func validateJournalReceipt(receipt *Receipt, operationID string) error {
	if receipt == nil || receipt.OperationID != operationID {
		return fmt.Errorf("delivery: durable operation %s has an invalid receipt identity", operationID)
	}
	switch receipt.Status {
	case StatusSucceeded, StatusFailed, StatusRolledBack:
		return nil
	default:
		return fmt.Errorf("delivery: durable operation %s has an invalid receipt status %q", operationID, receipt.Status)
	}
}

func sameReceipt(left, right *Receipt) bool {
	if left == nil || right == nil {
		return left == right
	}
	leftBytes, leftErr := json.Marshal(left)
	rightBytes, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && string(leftBytes) == string(rightBytes)
}

func cloneOperation(operation *Operation) *Operation {
	if operation == nil {
		return nil
	}
	copied := *operation
	copied.Request = cloneRequest(operation.Request)
	copied.Receipt = cloneReceipt(operation.Receipt)
	if operation.Rollout != nil {
		copied.Rollout = &RolloutProgress{Hosts: slices.Clone(operation.Rollout.Hosts), Edges: slices.Clone(operation.Rollout.Edges)}
	}
	copied.ReleaseSignature = bytes.Clone(operation.ReleaseSignature)
	copied.ReleaseManifest = bytes.Clone(operation.ReleaseManifest)
	copied.ReleaseManifestSignature = bytes.Clone(operation.ReleaseManifestSignature)
	return &copied
}

func cloneRequest(request *Request) *Request {
	if request == nil {
		return nil
	}
	var copied Request
	encoded, err := json.Marshal(request)
	if err != nil || json.Unmarshal(encoded, &copied) != nil {
		return nil
	}
	return &copied
}

func cloneReceipt(receipt *Receipt) *Receipt {
	if receipt == nil {
		return nil
	}
	var copied Receipt
	encoded, err := json.Marshal(receipt)
	if err != nil || json.Unmarshal(encoded, &copied) != nil {
		return nil
	}
	return &copied
}

// requestDigest is the canonical idempotency identity of a request: the
// sha256 of its compact JSON form (struct field order is deterministic).
func requestDigest(request *Request) (string, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:]), nil
}
