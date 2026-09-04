package reconcile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Progress is durable bookkeeping for one provider mutation. Pending and
// unknown records survive a restart and prevent an unsafe destructive replay.
type Progress struct {
	Key       string     `json:"key"`
	Action    ActionKind `json:"action"`
	Ref       string     `json:"ref"`
	Attempt   int        `json:"attempt"`
	Outcome   string     `json:"outcome"` // pending | applied | failed | unknown
	UpdatedAt time.Time  `json:"updatedAt"`
	Detail    string     `json:"detail,omitempty"`
}

// ProgressStore persists mutation progress. Implementations must be safe for
// concurrent use and make Save atomic from the caller's point of view.
type ProgressStore interface {
	Load(ctx context.Context, key string) (Progress, bool, error)
	Save(ctx context.Context, progress Progress) error
}

// ErrProgressConflict means that another reconciler changed a record after it
// was observed. Callers must re-load the record and fail closed when the
// outcome is pending or unknown; they must never blindly replay the action.
var ErrProgressConflict = errors.New("reconcile: progress compare-and-set conflict")

// ProgressCAS is the optional compare-and-swap extension implemented by
// durable stores. The nil expected value means that the key must be absent.
// It lets independent processes make an admission decision while holding the
// same cross-process lock used by Save.
type ProgressCAS interface {
	CompareAndSwap(ctx context.Context, key string, expected *Progress, next Progress) error
}

// MemoryProgressStore is useful for tests and explicitly ephemeral operation.
// Production should use FileProgressStore or a JetStream-backed adapter.
type MemoryProgressStore struct {
	mu    sync.Mutex
	items map[string]Progress
}

func NewMemoryProgressStore() *MemoryProgressStore {
	return &MemoryProgressStore{items: make(map[string]Progress)}
}
func (s *MemoryProgressStore) Load(_ context.Context, key string) (Progress, bool, error) {
	if key == "" {
		return Progress{}, false, errors.New("reconcile: progress key is empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.items[key]
	if ok {
		if err := validateProgress(p); err != nil {
			return Progress{}, false, err
		}
	}
	return p, ok, nil
}
func (s *MemoryProgressStore) Save(_ context.Context, progress Progress) error {
	if err := validateProgress(progress); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.items == nil {
		s.items = make(map[string]Progress)
	}
	if current, found := s.items[progress.Key]; found && !progressTransitionAllowed(current, progress) {
		return ErrProgressConflict
	}
	s.items[progress.Key] = progress
	return nil
}

// CompareAndSwap implements ProgressCAS for deterministic tests and keeps the
// in-memory adapter's behavior aligned with the file-backed store.
func (s *MemoryProgressStore) CompareAndSwap(_ context.Context, key string, expected *Progress, next Progress) error {
	if key == "" || next.Key != key {
		return errors.New("reconcile: progress key is empty or mismatched")
	}
	if err := validateProgress(next); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, found := s.items[key]
	if expected == nil {
		if found {
			return ErrProgressConflict
		}
	} else if !found || !sameProgress(current, *expected) {
		return ErrProgressConflict
	}
	s.items[key] = next
	return nil
}

// FileProgressStore stores one JSON journal under path. The write uses a
// sibling temporary file and rename, preventing a crash from leaving a
// partially written record. The file is intentionally scoped by the caller;
// no broad workspace path is inferred.
type FileProgressStore struct {
	mu   sync.Mutex
	path string
}

func NewFileProgressStore(path string) (*FileProgressStore, error) {
	if path == "" {
		return nil, errors.New("reconcile: progress path is empty")
	}
	return &FileProgressStore{path: path}, nil
}
func (s *FileProgressStore) Load(ctx context.Context, key string) (Progress, bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return Progress{}, false, err
	}
	if key == "" {
		return Progress{}, false, errors.New("reconcile: progress key is empty")
	}
	var result Progress
	var found bool
	err := s.withLock(ctx, false, func() error {
		b, err := os.ReadFile(s.path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("reconcile: load progress: %w", err)
		}
		records, err := decodeProgressRecords(b)
		if err != nil {
			return err
		}
		result, found = records[key]
		if found {
			if err := validateProgress(result); err != nil {
				return err
			}
		}
		return nil
	})
	return result, found, err
}
func (s *FileProgressStore) Save(ctx context.Context, progress Progress) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateProgress(progress); err != nil {
		return err
	}
	return s.withLock(ctx, true, func() error {
		records, err := s.readRecords()
		if err != nil {
			return err
		}
		if current, found := records[progress.Key]; found && !progressTransitionAllowed(current, progress) {
			return ErrProgressConflict
		}
		records[progress.Key] = progress
		return s.writeRecords(records)
	})
}

// CompareAndSwap atomically replaces one observed record. It is the durable
// admission primitive for callers that need a strict read/modify/write
// boundary across independent processes.
func (s *FileProgressStore) CompareAndSwap(ctx context.Context, key string, expected *Progress, next Progress) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if key == "" || next.Key != key {
		return errors.New("reconcile: progress key is empty or mismatched")
	}
	if expected != nil {
		if expected.Key != key {
			return errors.New("reconcile: expected progress key is mismatched")
		}
		if err := validateProgress(*expected); err != nil {
			return err
		}
	}
	if err := validateProgress(next); err != nil {
		return err
	}
	return s.withLock(ctx, true, func() error {
		records, err := s.readRecords()
		if err != nil {
			return err
		}
		current, found := records[key]
		if expected == nil {
			if found {
				return ErrProgressConflict
			}
		} else if !found || !sameProgress(current, *expected) {
			return ErrProgressConflict
		}
		records[key] = next
		return s.writeRecords(records)
	})
}

func (s *FileProgressStore) withLock(ctx context.Context, exclusive bool, operation func() error) error {
	if s == nil || s.path == "" {
		return errors.New("reconcile: progress store is not configured")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	directory := filepath.Dir(s.path)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return fmt.Errorf("reconcile: create progress directory: %w", err)
	}
	lock, err := os.OpenFile(s.path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("reconcile: open progress lock: %w", err)
	}
	defer lock.Close()
	mode := syscall.LOCK_SH
	if exclusive {
		mode = syscall.LOCK_EX
	}
	if err := flockContext(ctx, int(lock.Fd()), mode); err != nil {
		return fmt.Errorf("reconcile: lock progress: %w", err)
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	return operation()
}

func (s *FileProgressStore) readRecords() (map[string]Progress, error) {
	b, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return make(map[string]Progress), nil
	}
	if err != nil {
		return nil, fmt.Errorf("reconcile: read progress: %w", err)
	}
	return decodeProgressRecords(b)
}

// writeRecords commits a complete snapshot using a synced sibling temporary
// and a synced parent directory. Either the old snapshot or the complete new
// snapshot is visible after a crash; a partial JSON file is never durable.
func (s *FileProgressStore) writeRecords(records map[string]Progress) error {
	b, err := json.Marshal(records)
	if err != nil {
		return fmt.Errorf("reconcile: encode progress: %w", err)
	}
	directory := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(directory, ".reconcile-progress-")
	if err != nil {
		return fmt.Errorf("reconcile: create progress temporary: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("reconcile: chmod progress temporary: %w", err)
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("reconcile: write progress: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("reconcile: sync progress temporary: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("reconcile: close progress temporary: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("reconcile: commit progress: %w", err)
	}
	return syncProgressDirectory(directory)
}

func syncProgressDirectory(directory string) error {
	dir, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("reconcile: open progress directory: %w", err)
	}
	syncErr := dir.Sync()
	closeErr := dir.Close()
	if syncErr != nil {
		return fmt.Errorf("reconcile: sync progress directory: %w", syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("reconcile: close progress directory: %w", closeErr)
	}
	return nil
}

func sameProgress(left, right Progress) bool {
	leftBytes, leftErr := json.Marshal(left)
	rightBytes, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}

func progressTransitionAllowed(current, next Progress) bool {
	// A pending record is the cross-process admission token. Even an
	// byte-for-byte duplicate must lose, because accepting it would allow two
	// reconcilers that observed an absent key to both start provider work.
	if current.Outcome == "pending" && next.Outcome == "pending" {
		return false
	}
	if sameProgress(current, next) {
		return true
	}
	// Identity is immutable for an idempotency key. A different action or
	// provider reference must never replace the observed record.
	if current.Key != next.Key || current.Action != next.Action || current.Ref != next.Ref {
		return false
	}
	// Unknown is a permanent safety stop until an operator resolves it. A
	// terminal result can only be replaced by a fresh pending admission; this
	// prevents stale workers from overwriting a newer terminal outcome.
	if current.Outcome == "unknown" {
		return false
	}
	if (current.Outcome == "applied" || current.Outcome == "failed") &&
		(next.Outcome == "applied" || next.Outcome == "failed") {
		// Retry attempts advance monotonically. Equal-attempt terminal writes
		// are a stale-worker race, while a later attempt is a legitimate
		// continuation of the same provider operation.
		return next.Attempt > current.Attempt
	}
	return true
}

func flockContext(ctx context.Context, fd int, mode int) error {
	for {
		err := syscall.Flock(fd, mode|syscall.LOCK_NB)
		if err == nil {
			return nil
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
			return err
		}
		timer := time.NewTimer(5 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func decodeProgressRecords(data []byte) (map[string]Progress, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var raw map[string]json.RawMessage
	if err := decoder.Decode(&raw); err != nil {
		return nil, fmt.Errorf("reconcile: decode progress: %w", err)
	}
	if raw == nil {
		return nil, errors.New("reconcile: progress journal must be a JSON object")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, errors.New("reconcile: decode progress: trailing data")
		}
		return nil, fmt.Errorf("reconcile: decode progress: trailing data: %w", err)
	}
	records := make(map[string]Progress, len(raw))
	for key, value := range raw {
		valueDecoder := json.NewDecoder(bytes.NewReader(value))
		valueDecoder.DisallowUnknownFields()
		var progress Progress
		if err := valueDecoder.Decode(&progress); err != nil {
			return nil, fmt.Errorf("reconcile: decode progress %q: %w", key, err)
		}
		if err := validateProgress(progress); err != nil {
			return nil, fmt.Errorf("reconcile: invalid progress %q: %w", key, err)
		}
		if key != progress.Key {
			return nil, fmt.Errorf("reconcile: progress key %q does not match record key", key)
		}
		records[key] = progress
	}
	return records, nil
}

func validateProgress(progress Progress) error {
	if progress.Key == "" || progress.Ref == "" || progress.Key != strings.TrimSpace(progress.Key) || progress.Ref != strings.TrimSpace(progress.Ref) {
		return errors.New("reconcile: progress key and ref are required")
	}
	if len(progress.Key) > 256 || len(progress.Ref) > 256 {
		return errors.New("reconcile: progress key and ref are too long")
	}
	switch progress.Action {
	case ActionCreate, ActionUpdate, ActionDelete:
	default:
		return fmt.Errorf("reconcile: progress action %q is invalid", progress.Action)
	}
	switch progress.Outcome {
	case "pending", "applied", "failed", "unknown":
	default:
		return fmt.Errorf("reconcile: progress outcome %q is invalid", progress.Outcome)
	}
	if progress.Attempt < 1 {
		return errors.New("reconcile: progress attempt must be positive")
	}
	if progress.UpdatedAt.IsZero() {
		return errors.New("reconcile: progress updatedAt is required")
	}
	if len(progress.Detail) > 1024 {
		return errors.New("reconcile: progress detail is too long")
	}
	return nil
}

// OperationKey is a deterministic provider idempotency key for an action.
func OperationKey(action Action) string {
	payload, _ := json.Marshal(struct {
		Kind       ActionKind
		Ref        interface{}
		Attributes []Attribute
		Changes    []Change
		Repair     bool
	}{action.Kind, action.Ref, normalizeAttributes(action.Attributes), action.Changes, action.Repair})
	digest := sha256.Sum256(payload)
	return "reconcile-" + hex.EncodeToString(digest[:16])
}
