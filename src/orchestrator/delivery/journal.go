package delivery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
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

// OperationStore is retained as a descriptive alias for integrations that
// prefer the operation-specific name.
type OperationStore = DurableStore

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

// NewInMemoryDurableStore is an explicit name for NewInMemoryStore.
func NewInMemoryDurableStore() *InMemoryStore { return NewInMemoryStore() }

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
	OperationID   string
	Request       *Request
	RequestDigest string
	State         string
	Receipt       *Receipt
	StartedAt     time.Time
	FinishedAt    time.Time
	UpdatedAt     time.Time
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

// NewJournalWithStore is the explicit constructor name for integrations.
func NewJournalWithStore(store DurableStore) (*Journal, error) {
	return NewDurableJournal(store)
}

// Begin admits one operation. Create is atomic, so concurrent callers cannot
// both become the owner. An existing record with the same request digest is
// returned with exists=true (idempotent replay); the same operation ID with a
// different request is a conflict, never a restart. Store failures are
// returned and never treated as an empty journal.
func (j *Journal) Begin(request *Request) (operation *Operation, exists bool, err error) {
	if j == nil || j.store == nil {
		return nil, false, errors.New("delivery: journal is not configured")
	}
	if request == nil {
		return nil, false, errors.New("delivery: journal requires a request")
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
		return nil, false, fmt.Errorf("delivery: operation %s exists with a different request", operationID)
	}
	return operation, true, nil
}

// Finish records the terminal receipt of one operation using compare and set.
// A terminal operation is immutable: replaying the exact same receipt is fine,
// replacing it (even with the same status and different fields) is not.
func (j *Journal) Finish(operationID, requestDigest string, receipt *Receipt) error {
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
	if err := json.Unmarshal(entry.Value, &operation); err != nil {
		return nil, fmt.Errorf("delivery: durable operation %s is corrupt: %w", operationID, err)
	}
	if operation.OperationID != operationID || operation.Request == nil || operation.RequestDigest == "" || operation.State == "" {
		return nil, fmt.Errorf("delivery: durable operation %s is invalid", operationID)
	}
	digest, err := requestDigest(operation.Request)
	if err != nil || digest != operation.RequestDigest {
		return nil, fmt.Errorf("delivery: durable operation %s request digest is invalid", operationID)
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
	}
	if operation.State != OperationRunning && operation.State != OperationDone {
		return nil, fmt.Errorf("delivery: durable operation %s has invalid state %q", operationID, operation.State)
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
