// Package vmdisk contains the hermetic, test-only storage provider used by the
// Firecracker qualification stack. It deliberately models drives as regular
// files. No operation in this package opens a block device or requires root.
package vmdisk

import (
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

	"golang.org/x/sys/unix"
)

const (
	metadataVersion = 1
	maxDriveSize    = int64(1) << 40
	copyBufferSize  = 1 << 20
)

var (
	ErrNotFound     = errors.New("vmdisk: drive not found")
	ErrExists       = errors.New("vmdisk: drive already exists")
	ErrInvalidID    = errors.New("vmdisk: invalid drive id")
	ErrInvalidRoot  = errors.New("vmdisk: invalid root")
	ErrInvalidSize  = errors.New("vmdisk: invalid drive size")
	ErrDetached     = errors.New("vmdisk: drive is detached")
	ErrReadOnly     = errors.New("vmdisk: drive is read-only")
	ErrIOFailure    = errors.New("vmdisk: injected I/O failure")
	ErrInvalidFault = errors.New("vmdisk: invalid fault plan")
	ErrOutsideRoot  = errors.New("vmdisk: path is outside root")
)

// FaultKind identifies a host-side fault action. The default runner handles
// Fill and Corrupt with file APIs; lifecycle actions are represented in the
// drive metadata and are safe no-ops at the host layer.
type FaultKind string

const (
	FaultFill       FaultKind = "fill"
	FaultIOFailure  FaultKind = "io-failure"
	FaultReadOnly   FaultKind = "read-only"
	FaultDetach     FaultKind = "detach"
	FaultReattach   FaultKind = "reattach"
	FaultCorruption FaultKind = "corruption"
)

// FaultAction is passed to an injected runner. Path is always a regular file
// below the store root when produced by Store.ApplyFaultPlan.
type FaultAction struct {
	Kind    FaultKind
	Path    string
	Offset  int64
	Length  int64
	Pattern byte
}

// FaultRunner is the narrow seam for a Firecracker host integration. A real
// host adapter can translate actions to its labelled, privileged controls;
// tests should use FaultRunnerFunc or the default file runner.
type FaultRunner interface {
	Apply(context.Context, FaultAction) error
}

// FaultRunnerFunc adapts a function to FaultRunner.
type FaultRunnerFunc func(context.Context, FaultAction) error

func (f FaultRunnerFunc) Apply(ctx context.Context, action FaultAction) error {
	return f(ctx, action)
}

// Corruption describes bytes to overwrite with a deterministic pattern.
type Corruption struct {
	Offset  int64
	Length  int64
	Pattern byte
}

// FaultPlan is an atomic set of host faults. A zero plan makes no change.
// FillBytes requests a bounded fill; FillAll requests the complete drive.
// Corruption entries are applied in order. Reattach wins over Detach when both
// are requested.
type FaultPlan struct {
	FillBytes int64
	FillAll   bool
	IOFailure bool
	// IOError is accepted as a spelling alias for IOFailure in declarative
	// plans; both produce the same persisted fault.
	IOError     bool
	ReadOnly    bool
	Detach      bool
	Reattach    bool
	Corruptions []Corruption
}

// FaultState is the persisted state visible to qualification tests.
type FaultState struct {
	IOFailure   bool
	ReadOnly    bool
	FilledBytes int64
}

// Drive is a point-in-time view of a file-backed drive. Path is absolute and
// remains confined to the Store root.
type Drive struct {
	ID          string
	Path        string
	Size        int64
	Attached    bool
	Attachment  AttachmentState
	ReadOnly    bool
	IOFailure   bool
	FilledBytes int64
	Generation  uint64
	UpdatedAt   time.Time
}

// AttachmentState is explicit so callers do not have to infer availability
// from a host path or a boolean that might be stale.
type AttachmentState string

const (
	AttachmentAttached AttachmentState = "attached"
	AttachmentDetached AttachmentState = "detached"
)

// Snapshot identifies an immutable drive image made by Snapshot.
type Snapshot struct {
	DriveID    string
	Path       string
	Size       int64
	Checksum   string
	Generation uint64
	CreatedAt  time.Time
}

// DriveSpec is the declarative form accepted by CreateSpec.
type DriveSpec struct {
	ID   string
	Size int64
}

// Config configures a test drive store. Root must be a dedicated temporary
// directory (or a directory explicitly owned by the caller).
type Config struct {
	Root   string
	Runner FaultRunner
}

// Store owns only drives and snapshots below Config.Root. Its cleanup method
// never removes the root itself or unrelated root children.
type Store struct {
	root      string
	drives    string
	snapshots string
	runner    FaultRunner
	mu        sync.Mutex
}

// New creates a root-confined file-backed drive store.
func New(config Config) (*Store, error) {
	if config.Root == "" {
		return nil, fmt.Errorf("%w: root is empty", ErrInvalidRoot)
	}
	root, err := filepath.Abs(config.Root)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidRoot, err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("%w: create root: %v", ErrInvalidRoot, err)
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: root must be a non-symlink directory", ErrInvalidRoot)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("%w: resolve root: %v", ErrInvalidRoot, err)
	}
	d := &Store{root: root, drives: filepath.Join(root, "drives"), snapshots: filepath.Join(root, "snapshots"), runner: config.Runner}
	if d.runner == nil {
		d.runner = fileFaultRunner{}
	}
	for _, dir := range []string{d.drives, d.snapshots} {
		if err := mkdirOwned(dir); err != nil {
			return nil, err
		}
	}
	return d, nil
}

// NewStore is an explicit alias for New with the default safe file runner.
func NewStore(root string, runners ...FaultRunner) (*Store, error) {
	var runner FaultRunner
	if len(runners) > 1 {
		return nil, fmt.Errorf("%w: more than one runner", ErrInvalidRoot)
	}
	if len(runners) == 1 {
		runner = runners[0]
	}
	return New(Config{Root: root, Runner: runner})
}

// Root returns the canonical store root.
func (s *Store) Root() string { return s.root }

// Create creates and preallocates an attached drive.
func (s *Store) Create(ctx context.Context, id string, size int64) (*Drive, error) {
	return s.create(ctx, id, size)
}

// Preallocate is equivalent to Create and makes the intent explicit at call
// sites that model a Firecracker drive image preparation step.
func (s *Store) Preallocate(ctx context.Context, id string, size int64) (*Drive, error) {
	return s.create(ctx, id, size)
}

// CreateSpec creates a drive from a declarative specification.
func (s *Store) CreateSpec(ctx context.Context, spec DriveSpec) (*Drive, error) {
	return s.create(ctx, spec.ID, spec.Size)
}

func (s *Store) create(ctx context.Context, id string, size int64) (*Drive, error) {
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	if err := validateID(id); err != nil {
		return nil, err
	}
	if err := validateSize(size); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dir, image, metadata := s.drivePaths(id)
	if _, err := os.Lstat(dir); err == nil {
		return nil, ErrExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create drive directory: %w", err)
	}
	created := true
	defer func() {
		if created {
			_ = os.RemoveAll(dir)
		}
	}()
	if err := allocate(ctx, image, size); err != nil {
		return nil, err
	}
	state := diskMetadata{Version: metadataVersion, ID: id, Size: size, Attached: true, Generation: 1, UpdatedAt: time.Now().UTC()}
	if err := writeMetadata(ctx, metadata, state); err != nil {
		return nil, err
	}
	created = false
	return state.drive(image), nil
}

// Get returns the current explicit attachment and fault state.
func (s *Store) Get(ctx context.Context, id string) (*Drive, error) {
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	if err := validateID(id); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadDrive(id)
}

// State is an alias for Get.
func (s *Store) State(ctx context.Context, id string) (*Drive, error) { return s.Get(ctx, id) }

// Attach marks a drive available to the guest. It is idempotent.
func (s *Store) Attach(ctx context.Context, id string) error { return s.setAttached(ctx, id, true) }

// Reattach marks a drive available to the guest. It is idempotent.
func (s *Store) Reattach(ctx context.Context, id string) error { return s.setAttached(ctx, id, true) }

// Detach marks a drive unavailable to the guest. It is idempotent.
func (s *Store) Detach(ctx context.Context, id string) error { return s.setAttached(ctx, id, false) }

func (s *Store) setAttached(ctx context.Context, id string, attached bool) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	if err := validateID(id); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state, err := s.loadMetadata(id)
	if err != nil {
		return err
	}
	if state.Attached == attached {
		return nil
	}
	kind := FaultDetach
	if attached {
		kind = FaultReattach
	}
	if err := s.runner.Apply(ctx, FaultAction{Kind: kind, Path: s.imagePath(id)}); err != nil {
		return err
	}
	state.Attached = attached
	state.Generation++
	state.UpdatedAt = time.Now().UTC()
	return writeMetadata(ctx, s.metadataPath(id), state)
}

// Expand increases a drive's capacity without changing existing bytes.
func (s *Store) Expand(ctx context.Context, id string, size int64) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	if err := validateSize(size); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state, err := s.loadMetadata(id)
	if err != nil {
		return err
	}
	if err := state.availableForWrite(); err != nil {
		return err
	}
	if size < state.Size {
		return fmt.Errorf("%w: expansion cannot shrink %d to %d", ErrInvalidSize, state.Size, size)
	}
	if size == state.Size {
		return nil
	}
	file, err := openRegular(s.imagePath(id), os.O_RDWR)
	if err != nil {
		return err
	}
	if err := contextErr(ctx); err != nil {
		_ = file.Close()
		return err
	}
	if err := unix.Fallocate(int(file.Fd()), 0, state.Size, size-state.Size); err != nil && !isFallocateUnsupported(err) {
		_ = file.Close()
		return err
	}
	if err := file.Truncate(size); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	old := state.Size
	state.Size = size
	state.Generation++
	state.UpdatedAt = time.Now().UTC()
	if err := writeMetadata(ctx, s.metadataPath(id), state); err != nil {
		_ = os.Truncate(s.imagePath(id), old)
		return err
	}
	return nil
}

// Resize is an alias for Expand.
func (s *Store) Resize(ctx context.Context, id string, size int64) error {
	return s.Expand(ctx, id, size)
}

// Snapshot copies an attached drive into a root-confined immutable image.
func (s *Store) Snapshot(ctx context.Context, id string) (Snapshot, error) {
	if err := contextErr(ctx); err != nil {
		return Snapshot{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state, err := s.loadMetadata(id)
	if err != nil {
		return Snapshot{}, err
	}
	if !state.Attached {
		return Snapshot{}, ErrDetached
	}
	image := s.imagePath(id)
	checksum, err := checksumFile(ctx, image, state.Size)
	if err != nil {
		return Snapshot{}, err
	}
	path := filepath.Join(s.snapshots, fmt.Sprintf("%s-%d-%d.img", id, state.Generation, time.Now().UnixNano()))
	temporary := path + fmt.Sprintf(".tmp-%d", time.Now().UnixNano())
	if err := copyImage(ctx, image, temporary, state.Size); err != nil {
		_ = os.Remove(temporary)
		return Snapshot{}, err
	}
	if err := contextErr(ctx); err != nil {
		_ = os.Remove(temporary)
		return Snapshot{}, err
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return Snapshot{}, err
	}
	if err := os.Chmod(path, 0o440); err != nil {
		_ = os.Remove(path)
		return Snapshot{}, err
	}
	if err := syncDirectory(s.snapshots); err != nil {
		return Snapshot{}, err
	}
	return Snapshot{DriveID: id, Path: path, Size: state.Size, Checksum: checksum, Generation: state.Generation, CreatedAt: time.Now().UTC()}, nil
}

// Restore atomically replaces a drive image from a trusted snapshot.
func (s *Store) Restore(ctx context.Context, id string, source any) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	if err := validateID(id); err != nil {
		return err
	}
	snapshot, err := snapshotValue(source, id)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state, err := s.loadMetadata(id)
	if err != nil {
		return err
	}
	if err := state.availableForWrite(); err != nil {
		return err
	}
	if snapshot.Size == 0 {
		info, statErr := os.Stat(snapshot.Path)
		if statErr != nil {
			return statErr
		}
		snapshot.Size = info.Size()
	}
	if snapshot.DriveID != id || snapshot.Size <= 0 || snapshot.Size > state.Size {
		return fmt.Errorf("%w: snapshot does not match drive", ErrInvalidSize)
	}
	if err := s.validateSnapshotPath(snapshot); err != nil {
		return err
	}
	if got, err := checksumFile(ctx, snapshot.Path, snapshot.Size); err != nil {
		return err
	} else if snapshot.Checksum != "" && got != snapshot.Checksum {
		return fmt.Errorf("%w: snapshot checksum mismatch", ErrIOFailure)
	}
	temporary := s.imagePath(id) + fmt.Sprintf(".restore-%d", time.Now().UnixNano())
	if err := copyImage(ctx, snapshot.Path, temporary, snapshot.Size); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	backup := s.imagePath(id) + ".restore-backup"
	_ = os.Remove(backup)
	if err := contextErr(ctx); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if err := os.Rename(s.imagePath(id), backup); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if err := os.Rename(temporary, s.imagePath(id)); err != nil {
		_ = os.Rename(backup, s.imagePath(id))
		_ = os.Remove(temporary)
		return err
	}
	state.Generation++
	state.Size = snapshot.Size
	state.UpdatedAt = time.Now().UTC()
	if err := writeMetadata(ctx, s.metadataPath(id), state); err != nil {
		_ = os.Remove(s.imagePath(id))
		_ = os.Rename(backup, s.imagePath(id))
		return err
	}
	_ = os.Remove(backup)
	return syncDirectory(filepath.Dir(s.imagePath(id)))
}

// RestorePath restores from a path returned by Snapshot.
func (s *Store) RestorePath(ctx context.Context, id, path string) error {
	return s.Restore(ctx, id, Snapshot{DriveID: id, Path: path})
}

func snapshotValue(source any, id string) (Snapshot, error) {
	switch snapshot := source.(type) {
	case Snapshot:
		return snapshot, nil
	case *Snapshot:
		if snapshot == nil {
			return Snapshot{}, fmt.Errorf("%w: nil snapshot", ErrInvalidFault)
		}
		return *snapshot, nil
	case string:
		info, err := os.Stat(snapshot)
		if err != nil {
			return Snapshot{}, err
		}
		if !info.Mode().IsRegular() {
			return Snapshot{}, ErrOutsideRoot
		}
		return Snapshot{DriveID: id, Path: snapshot, Size: info.Size()}, nil
	default:
		return Snapshot{}, fmt.Errorf("%w: expected Snapshot or path", ErrInvalidFault)
	}
}

// Checksum returns the SHA-256 digest of the logical drive bytes.
func (s *Store) Checksum(ctx context.Context, id string) (string, error) {
	if err := contextErr(ctx); err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state, err := s.loadMetadata(id)
	if err != nil {
		return "", err
	}
	if !state.Attached {
		return "", ErrDetached
	}
	if state.IOFailure {
		return "", ErrIOFailure
	}
	return checksumFile(ctx, s.imagePath(id), state.Size)
}

// Faults returns the persisted logical fault state.
func (s *Store) Faults(ctx context.Context, id string) (FaultState, error) {
	drive, err := s.Get(ctx, id)
	if err != nil {
		return FaultState{}, err
	}
	return FaultState{IOFailure: drive.IOFailure, ReadOnly: drive.ReadOnly, FilledBytes: drive.FilledBytes}, nil
}

// ReadAt reads logical drive bytes and observes current injected faults.
func (s *Store) ReadAt(ctx context.Context, id string, p []byte, offset int64) (int, error) {
	return s.ioAt(ctx, id, p, offset, false)
}

// WriteAt writes logical drive bytes and observes current injected faults.
func (s *Store) WriteAt(ctx context.Context, id string, p []byte, offset int64) (int, error) {
	return s.ioAt(ctx, id, p, offset, true)
}

func (s *Store) ioAt(ctx context.Context, id string, p []byte, offset int64, write bool) (int, error) {
	if err := contextErr(ctx); err != nil {
		return 0, err
	}
	if offset < 0 {
		return 0, fmt.Errorf("%w: negative offset", ErrInvalidSize)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state, err := s.loadMetadata(id)
	if err != nil {
		return 0, err
	}
	if !state.Attached {
		return 0, ErrDetached
	}
	if state.IOFailure {
		return 0, ErrIOFailure
	}
	if write && state.ReadOnly {
		return 0, ErrReadOnly
	}
	if int64(len(p)) > state.Size-offset {
		return 0, io.ErrShortBuffer
	}
	file, err := openRegular(s.imagePath(id), func() int {
		if write {
			return os.O_RDWR
		}
		return os.O_RDONLY
	}())
	if err != nil {
		return 0, err
	}
	defer file.Close()
	if write {
		err = writeContextAt(ctx, file, p, offset)
	} else {
		_, err = readContextAt(ctx, file, p, offset)
	}
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// ApplyFaultPlan applies all actions and commits metadata as one update. A
// failed runner or canceled context leaves metadata unchanged.
func (s *Store) ApplyFaultPlan(ctx context.Context, id string, plan FaultPlan) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	if err := validateID(id); err != nil {
		return err
	}
	if plan.FillBytes < 0 {
		return fmt.Errorf("%w: negative fill length", ErrInvalidFault)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state, err := s.loadMetadata(id)
	if err != nil {
		return err
	}
	fill := plan.FillBytes
	if fill == 0 && !plan.FillAll && len(plan.Corruptions) == 0 && !plan.IOFailure && !plan.IOError && !plan.ReadOnly && !plan.Detach && !plan.Reattach {
		return nil
	}
	if plan.FillAll {
		fill = state.Size
	}
	if fill > state.Size {
		return fmt.Errorf("%w: fill exceeds drive", ErrInvalidFault)
	}
	for _, corruption := range plan.Corruptions {
		if corruption.Offset < 0 || corruption.Length <= 0 || corruption.Offset > state.Size-corruption.Length {
			return fmt.Errorf("%w: corruption range", ErrInvalidFault)
		}
	}
	if fill > 0 {
		if err := state.availableForWrite(); err != nil {
			return err
		}
		if err := s.runner.Apply(ctx, FaultAction{Kind: FaultFill, Path: s.imagePath(id), Offset: 0, Length: fill, Pattern: 0xa5}); err != nil {
			return err
		}
		state.FilledBytes += fill
	}
	for _, corruption := range plan.Corruptions {
		if err := state.availableForWrite(); err != nil {
			return err
		}
		if err := s.runner.Apply(ctx, FaultAction{Kind: FaultCorruption, Path: s.imagePath(id), Offset: corruption.Offset, Length: corruption.Length, Pattern: corruption.Pattern}); err != nil {
			return err
		}
	}
	if plan.IOFailure || plan.IOError {
		if !state.IOFailure {
			if err := s.runner.Apply(ctx, FaultAction{Kind: FaultIOFailure, Path: s.imagePath(id)}); err != nil {
				return err
			}
			state.IOFailure = true
		}
	}
	if plan.ReadOnly {
		if !state.ReadOnly {
			if err := s.runner.Apply(ctx, FaultAction{Kind: FaultReadOnly, Path: s.imagePath(id)}); err != nil {
				return err
			}
			state.ReadOnly = true
		}
	}
	if plan.Detach {
		if state.Attached {
			if err := s.runner.Apply(ctx, FaultAction{Kind: FaultDetach, Path: s.imagePath(id)}); err != nil {
				return err
			}
			state.Attached = false
		}
	}
	if plan.Reattach {
		if !state.Attached {
			if err := s.runner.Apply(ctx, FaultAction{Kind: FaultReattach, Path: s.imagePath(id)}); err != nil {
				return err
			}
			state.Attached = true
		}
	}
	if err := contextErr(ctx); err != nil {
		return err
	}
	state.Generation++
	state.UpdatedAt = time.Now().UTC()
	if err := writeMetadata(ctx, s.metadataPath(id), state); err != nil {
		return err
	}
	if state.ReadOnly {
		if err := os.Chmod(s.imagePath(id), 0o440); err != nil {
			return err
		}
	}
	return nil
}

// Fill writes a deterministic nonzero pattern to a bounded part of a drive.
func (s *Store) Fill(ctx context.Context, id string, bytes int64) error {
	if bytes <= 0 {
		return fmt.Errorf("%w: fill must be positive", ErrInvalidFault)
	}
	return s.ApplyFaultPlan(ctx, id, FaultPlan{FillBytes: bytes})
}

// SetReadOnly applies the read-only fault and is idempotent.
func (s *Store) SetReadOnly(ctx context.Context, id string) error {
	return s.ApplyFaultPlan(ctx, id, FaultPlan{ReadOnly: true})
}

// SetIOFailure applies the I/O failure fault and is idempotent.
func (s *Store) SetIOFailure(ctx context.Context, id string) error {
	return s.ApplyFaultPlan(ctx, id, FaultPlan{IOFailure: true})
}

// ClearFaults clears logical faults. It does not undo bytes already filled or
// corrupted; restore a snapshot for that purpose.
func (s *Store) ClearFaults(ctx context.Context, id string) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state, err := s.loadMetadata(id)
	if err != nil {
		return err
	}
	state.IOFailure, state.ReadOnly = false, false
	state.Generation++
	state.UpdatedAt = time.Now().UTC()
	if err := writeMetadata(ctx, s.metadataPath(id), state); err != nil {
		return err
	}
	if err := contextErr(ctx); err != nil {
		return err
	}
	return os.Chmod(s.imagePath(id), 0o600)
}

// Remove deletes one drive and its snapshots. It is idempotent.
func (s *Store) Remove(ctx context.Context, id string) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	if err := validateID(id); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dir := filepath.Join(s.drives, id)
	if err := ensureContained(s.root, dir); err != nil {
		return err
	}
	if err := removeTree(ctx, dir); err != nil {
		return err
	}
	entries, err := os.ReadDir(s.snapshots)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if snapshotBelongsTo(entry.Name(), id) {
			if err := removeTree(ctx, filepath.Join(s.snapshots, entry.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

func snapshotBelongsTo(name, id string) bool {
	if !strings.HasSuffix(name, ".img") {
		return false
	}
	base := strings.TrimSuffix(name, ".img")
	last := strings.LastIndexByte(base, '-')
	if last < 0 {
		return false
	}
	second := strings.LastIndexByte(base[:last], '-')
	if second < 0 || base[:second] != id {
		return false
	}
	for _, number := range []string{base[second+1 : last], base[last+1:]} {
		if number == "" {
			return false
		}
		for _, r := range number {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

// Delete is an alias for Remove.
func (s *Store) Delete(ctx context.Context, id string) error { return s.Remove(ctx, id) }

// Cleanup removes only this store's drives and snapshots. It may be retried
// after cancellation and is safe to call repeatedly.
func (s *Store) Cleanup(ctx context.Context) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, dir := range []string{s.drives, s.snapshots} {
		if err := removeTree(ctx, dir); err != nil {
			return err
		}
		if err := mkdirOwned(dir); err != nil {
			return err
		}
	}
	return nil
}

type diskMetadata struct {
	Version     int       `json:"version"`
	ID          string    `json:"id"`
	Size        int64     `json:"size"`
	Attached    bool      `json:"attached"`
	ReadOnly    bool      `json:"read_only"`
	IOFailure   bool      `json:"io_failure"`
	FilledBytes int64     `json:"filled_bytes"`
	Generation  uint64    `json:"generation"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (m diskMetadata) drive(path string) *Drive {
	attachment := AttachmentDetached
	if m.Attached {
		attachment = AttachmentAttached
	}
	return &Drive{ID: m.ID, Path: path, Size: m.Size, Attached: m.Attached, Attachment: attachment, ReadOnly: m.ReadOnly, IOFailure: m.IOFailure, FilledBytes: m.FilledBytes, Generation: m.Generation, UpdatedAt: m.UpdatedAt}
}
func (m diskMetadata) availableForWrite() error {
	if !m.Attached {
		return ErrDetached
	}
	if m.IOFailure {
		return ErrIOFailure
	}
	if m.ReadOnly {
		return ErrReadOnly
	}
	return nil
}

func (s *Store) drivePaths(id string) (string, string, string) {
	dir := filepath.Join(s.drives, id)
	return dir, filepath.Join(dir, "drive.img"), filepath.Join(dir, "metadata.json")
}
func (s *Store) imagePath(id string) string    { _, image, _ := s.drivePaths(id); return image }
func (s *Store) metadataPath(id string) string { _, _, metadata := s.drivePaths(id); return metadata }

func (s *Store) loadDrive(id string) (*Drive, error) {
	m, err := s.loadMetadata(id)
	if err != nil {
		return nil, err
	}
	return m.drive(s.imagePath(id)), nil
}
func (s *Store) loadMetadata(id string) (diskMetadata, error) {
	if err := validateID(id); err != nil {
		return diskMetadata{}, err
	}
	path := s.metadataPath(id)
	if err := ensureNoSymlinkComponents(s.drives, path); err != nil {
		return diskMetadata{}, err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return diskMetadata{}, ErrNotFound
	}
	if err != nil {
		return diskMetadata{}, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return diskMetadata{}, ErrOutsideRoot
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return diskMetadata{}, err
	}
	var m diskMetadata
	if err := json.Unmarshal(data, &m); err != nil || m.Version != metadataVersion || m.ID != id || m.Size <= 0 || m.Size > maxDriveSize {
		return diskMetadata{}, fmt.Errorf("vmdisk: invalid metadata for %s", id)
	}
	if err := ensureRegular(s.imagePath(id)); err != nil {
		return diskMetadata{}, err
	}
	return m, nil
}

func (s *Store) validateSnapshotPath(snapshot Snapshot) error {
	path, err := filepath.Abs(snapshot.Path)
	if err != nil {
		return err
	}
	if err := ensureContained(s.snapshots, path); err != nil {
		return err
	}
	if err := ensureNoSymlinkComponents(s.snapshots, path); err != nil {
		return err
	}
	if filepath.Ext(path) != ".img" || !snapshotBelongsTo(filepath.Base(path), snapshot.DriveID) {
		return ErrOutsideRoot
	}
	return ensureRegular(path)
}

func validateID(id string) error {
	if id == "" || id == "." || id == ".." || len(id) > 128 || filepath.IsAbs(id) || strings.ContainsAny(id, `/\\`) {
		return ErrInvalidID
	}
	return nil
}
func validateSize(size int64) error {
	if size <= 0 || size > maxDriveSize {
		return ErrInvalidSize
	}
	return nil
}
func contextErr(ctx context.Context) error {
	if ctx == nil {
		return errors.New("vmdisk: nil context")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func mkdirOwned(path string) error {
	if info, err := os.Lstat(path); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: %s", ErrOutsideRoot, path)
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Mkdir(path, 0o700)
}
func ensureContained(root, path string) error {
	r, err := filepath.Abs(root)
	if err != nil {
		return ErrOutsideRoot
	}
	p, err := filepath.Abs(path)
	if err != nil {
		return ErrOutsideRoot
	}
	rel, err := filepath.Rel(r, p)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || filepath.IsAbs(rel) {
		return ErrOutsideRoot
	}
	return nil
}

// ensureNoSymlinkComponents prevents a path that was safe at construction
// time from being redirected outside the root after a test starts.
func ensureNoSymlinkComponents(root, path string) error {
	if err := ensureContained(root, path); err != nil {
		return err
	}
	r, err := filepath.Abs(root)
	if err != nil {
		return ErrOutsideRoot
	}
	p, err := filepath.Abs(path)
	if err != nil {
		return ErrOutsideRoot
	}
	rel, err := filepath.Rel(r, p)
	if err != nil {
		return ErrOutsideRoot
	}
	current := r
	for _, part := range strings.Split(rel, string(os.PathSeparator)) {
		if part == "." || part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, statErr := os.Lstat(current)
		if statErr != nil {
			if errors.Is(statErr, os.ErrNotExist) {
				continue
			}
			return statErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return ErrOutsideRoot
		}
	}
	return nil
}
func ensureRegular(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return ErrOutsideRoot
	}
	return nil
}
func openRegular(path string, flags int) (*os.File, error) {
	if err := ensureRegular(path); err != nil {
		return nil, err
	}
	return os.OpenFile(path, flags, 0)
}

func allocate(ctx context.Context, path string, size int64) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
			_ = os.Remove(path)
		}
	}()
	if err := contextErr(ctx); err != nil {
		return err
	}
	if err := unix.Fallocate(int(f.Fd()), 0, 0, size); err != nil && !isFallocateUnsupported(err) {
		return err
	}
	if err := f.Truncate(size); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}

func isFallocateUnsupported(err error) bool {
	return errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.ENOSYS) || errors.Is(err, syscall.EINVAL)
}

func writeMetadata(ctx context.Context, path string, m diskMetadata) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	if err := ensureNoSymlinkComponents(filepath.Dir(filepath.Dir(path)), path); err != nil {
		return err
	}
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	temporary := path + fmt.Sprintf(".tmp-%d", time.Now().UnixNano())
	f, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
			_ = os.Remove(temporary)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := contextErr(ctx); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	ok = true
	return syncDirectory(filepath.Dir(path))
}

func checksumFile(ctx context.Context, path string, size int64) (string, error) {
	f, err := openRegular(path, os.O_RDONLY)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	buf := make([]byte, copyBufferSize)
	var total int64
	for total < size {
		if err := contextErr(ctx); err != nil {
			return "", err
		}
		want := int64(len(buf))
		if size-total < want {
			want = size - total
		}
		n, err := f.Read(buf[:want])
		if n > 0 {
			_, _ = h.Write(buf[:n])
			total += int64(n)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return "", io.ErrUnexpectedEOF
			}
			return "", err
		}
	}
	var one [1]byte
	if n, _ := f.Read(one[:]); n != 0 {
		return "", fmt.Errorf("vmdisk: image larger than metadata")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func copyImage(ctx context.Context, src, dst string, size int64) error {
	in, err := openRegular(src, os.O_RDONLY)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			_ = out.Close()
			_ = os.Remove(dst)
		}
	}()
	buf := make([]byte, copyBufferSize)
	var total int64
	for total < size {
		if err := contextErr(ctx); err != nil {
			return err
		}
		want := int64(len(buf))
		if size-total < want {
			want = size - total
		}
		n, readErr := in.Read(buf[:want])
		if n > 0 {
			if _, err := out.Write(buf[:n]); err != nil {
				return err
			}
			total += int64(n)
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return io.ErrUnexpectedEOF
			}
			return readErr
		}
	}
	if err := out.Sync(); err != nil {
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}

func writeContextAt(ctx context.Context, f *os.File, p []byte, offset int64) error {
	for len(p) > 0 {
		if err := contextErr(ctx); err != nil {
			return err
		}
		n, err := f.WriteAt(p, offset)
		offset += int64(n)
		p = p[n:]
		if err != nil {
			return err
		}
	}
	return f.Sync()
}
func readContextAt(ctx context.Context, f *os.File, p []byte, offset int64) (int, error) {
	for total := 0; total < len(p); {
		if err := contextErr(ctx); err != nil {
			return total, err
		}
		n, err := f.ReadAt(p[total:], offset+int64(total))
		total += n
		if err != nil {
			if errors.Is(err, io.EOF) && total == len(p) {
				return total, nil
			}
			return total, err
		}
	}
	return len(p), nil
}

func syncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func removeTree(ctx context.Context, path string) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return os.Remove(path)
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := removeTree(ctx, filepath.Join(path, entry.Name())); err != nil {
			return err
		}
	}
	if err := contextErr(ctx); err != nil {
		return err
	}
	return os.Remove(path)
}

type fileFaultRunner struct{}

// SafeFileRunner returns the hermetic runner used by default. It only writes
// regular files and never invokes host commands or block-device ioctls.
func SafeFileRunner() FaultRunner { return fileFaultRunner{} }

func (fileFaultRunner) Apply(ctx context.Context, action FaultAction) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	switch action.Kind {
	case FaultFill, FaultCorruption:
		return overwriteFile(ctx, action.Path, action.Offset, action.Length, action.Pattern)
	}
	return nil
}
func overwriteFile(ctx context.Context, path string, offset, length int64, pattern byte) error {
	if length <= 0 {
		return ErrInvalidFault
	}
	f, err := openRegular(path, os.O_RDWR)
	if err != nil {
		return err
	}
	defer f.Close()
	buf := make([]byte, copyBufferSize)
	for i := range buf {
		buf[i] = pattern
	}
	for length > 0 {
		if err := contextErr(ctx); err != nil {
			return err
		}
		n := int64(len(buf))
		if length < n {
			n = length
		}
		if _, err := f.WriteAt(buf[:n], offset); err != nil {
			return err
		}
		offset += n
		length -= n
	}
	return f.Sync()
}
