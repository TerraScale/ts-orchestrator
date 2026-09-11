// Package vmdisk owns the hermetic, test-only data-drive artifacts used by
// Firecracker qualification. Host files are prepared without requiring root;
// guest-visible attachment and fault changes are explicit next-boot intents.
package vmdisk

import (
	"context"
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
	metadataVersion       = 2
	storeMarkerVersion    = 1
	snapshotVersion       = 1
	copyBufferSize        = 1 << 20
	maxMetadataBytes      = 64 << 10
	maxCorruptionsPerPlan = 64
	maxDriveSize          = int64(1) << 40

	DefaultMaxBytes     = int64(8) << 30
	DefaultMaxDrives    = 64
	DefaultMaxSnapshots = 256
)

var (
	ErrNotFound            = errors.New("vmdisk: drive not found")
	ErrExists              = errors.New("vmdisk: drive already exists")
	ErrInvalidID           = errors.New("vmdisk: invalid drive id")
	ErrInvalidRoot         = errors.New("vmdisk: invalid root")
	ErrInvalidSize         = errors.New("vmdisk: invalid drive size")
	ErrDetached            = errors.New("vmdisk: drive is detached")
	ErrReadOnly            = errors.New("vmdisk: drive is read-only")
	ErrIOFailure           = errors.New("vmdisk: injected I/O failure")
	ErrInvalidFault        = errors.New("vmdisk: invalid fault plan")
	ErrOutsideRoot         = errors.New("vmdisk: path is outside root")
	ErrQuotaExceeded       = errors.New("vmdisk: store quota exceeded")
	ErrOwnership           = errors.New("vmdisk: artifact is not owned by this run")
	ErrCorruptState        = errors.New("vmdisk: corrupt state")
	ErrCorruptSnapshot     = errors.New("vmdisk: corrupt snapshot")
	ErrDriveBusy           = errors.New("vmdisk: drive changed while preparing an offline artifact")
	ErrDurabilityUncertain = errors.New("vmdisk: filesystem state is visible but directory durability could not be confirmed")
	ErrClosed              = errors.New("vmdisk: store is closed")
	ErrCleanupPending      = errors.New("vmdisk: deterministic terminal cleanup is pending")
)

// FaultKind identifies either a byte mutation performed on an unpublished
// copy-on-write artifact or a next-boot guest fault intent.
type FaultKind string

const (
	FaultFill       FaultKind = "fill"
	FaultIOFailure  FaultKind = "io-failure"
	FaultReadOnly   FaultKind = "read-only"
	FaultDetach     FaultKind = "detach"
	FaultReattach   FaultKind = "reattach"
	FaultCorruption FaultKind = "corruption"
)

// FaultAction is passed only for a byte mutation of an unpublished candidate
// image. Lifecycle, read-only, I/O-failure, and filesystem-fill intents are
// consumed from BootPlan by the runtime and are never reported as completed
// host actions by this package.
type FaultAction struct {
	Kind    FaultKind
	Path    string
	Offset  int64
	Length  int64
	Pattern byte
}

type FaultRunner interface {
	Apply(context.Context, FaultAction) error
}

type FaultRunnerFunc func(context.Context, FaultAction) error

func (f FaultRunnerFunc) Apply(ctx context.Context, action FaultAction) error {
	return f(ctx, action)
}

type Corruption struct {
	Offset  int64 `json:"offset"`
	Length  int64 `json:"length"`
	Pattern byte  `json:"pattern"`
}

// FaultPlan combines next-boot intents. Fill is a guest-filesystem operation:
// it never overwrites raw filesystem bytes. Corruptions are materialized into
// a new image and therefore cannot alter an inode already opened by a VMM.
type FaultPlan struct {
	FillBytes   int64
	FillAll     bool
	IOFailure   bool
	IOError     bool
	ReadOnly    bool
	Detach      bool
	Reattach    bool
	Corruptions []Corruption
}

type FaultState struct {
	IOFailure    bool
	ReadOnly     bool
	FilledBytes  int64
	FillToENOSPC bool
}

type AttachmentState string

const (
	AttachmentAttached AttachmentState = "attached"
	AttachmentDetached AttachmentState = "detached"
)

// FilesystemSpec is provisioning intent, not an observation that the raw
// image is already formatted. The guest image/cloud-init path must verify it.
type FilesystemSpec struct {
	Type  string `json:"type"`
	Label string `json:"label"`
}

const FilesystemExt4 = "ext4"

func DefaultFilesystem() FilesystemSpec {
	return FilesystemSpec{Type: FilesystemExt4, Label: "terrascale-data"}
}

type ActivationScope string

const ActivationNextBoot ActivationScope = "next-boot"

type TransitionKind string

const (
	TransitionCreate          TransitionKind = "create"
	TransitionAttach          TransitionKind = "attach"
	TransitionDetach          TransitionKind = "detach"
	TransitionFault           TransitionKind = "fault"
	TransitionClearFault      TransitionKind = "clear-faults"
	TransitionExpand          TransitionKind = "expand"
	TransitionCorrupt         TransitionKind = "corrupt"
	TransitionWrite           TransitionKind = "write"
	TransitionRestore         TransitionKind = "restore"
	TransitionAcknowledgeGrow TransitionKind = "acknowledge-filesystem-grow"
)

type Transition struct {
	Kind         TransitionKind `json:"kind"`
	PreviousSize int64          `json:"previous_size,omitempty"`
	SnapshotID   string         `json:"snapshot_id,omitempty"`
	Corruptions  []Corruption   `json:"corruptions,omitempty"`
}

// BootPlan is the complete contract a stopped-VM runtime must consume before
// the next InstanceStart. Detached means omit Path. IOFailure requires a real
// faulting adapter, ReadOnly belongs in Firecracker's drive configuration,
// and fill fields require a guest filesystem operation that proves ENOSPC.
type BootPlan struct {
	RunID                       string
	DriveID                     string
	Generation                  uint64
	Activation                  ActivationScope
	RequiresStoppedGuest        bool
	Attachment                  AttachmentState
	Path                        string
	Size                        int64
	SHA256                      string
	ReadOnly                    bool
	IOFailure                   bool
	RequiresRuntimeFaultAdapter bool
	FillBytes                   int64
	FillToENOSPC                bool
	RequiresGuestFilesystemFill bool
	RequiresGuestFilesystemGrow bool
	Filesystem                  FilesystemSpec
	Transition                  Transition
}

type TransitionOutcome struct {
	PreviousGeneration uint64
	Plan               BootPlan
}

// Drive is a point-in-time view of persisted next-boot state. These fields do
// not claim that an already-running guest changed configuration.
type Drive struct {
	RunID                       string
	ID                          string
	Path                        string
	Size                        int64
	Attached                    bool
	Attachment                  AttachmentState
	ReadOnly                    bool
	IOFailure                   bool
	FilledBytes                 int64
	FillToENOSPC                bool
	RequiresGuestFilesystemGrow bool
	Filesystem                  FilesystemSpec
	Activation                  ActivationScope
	Transition                  Transition
	Generation                  uint64
	UpdatedAt                   time.Time
}

// Snapshot identifies a content-addressed, integrity-checked snapshot owned
// by this store. Callers must quiesce the guest for application consistency.
type Snapshot struct {
	RunID                string
	ID                   string
	DriveID              string
	Path                 string
	ManifestPath         string
	Size                 int64
	Checksum             string
	Filesystem           FilesystemSpec
	Generation           uint64
	CreatedAt            time.Time
	RequiresStoppedGuest bool
}

type DriveSpec struct {
	ID         string
	Size       int64
	Filesystem FilesystemSpec
}

type Ownership struct {
	UID int
	GID int
}

// StoreIdentity is the exact store identity that a trusted outer cleanup
// journal must persist before New creates any artifacts. Tombstone is derived
// from Root and RunID and is rejected if a caller changes it.
type StoreIdentity struct {
	Root      string    `json:"root"`
	RunID     string    `json:"run_id"`
	Ownership Ownership `json:"ownership"`
	Tombstone string    `json:"tombstone"`
}

type Config struct {
	Root         string
	RunID        string
	Runner       FaultRunner
	Ownership    *Ownership
	MaxBytes     int64
	MaxDrives    int
	MaxSnapshots int
}

type Usage struct {
	Bytes     int64
	Drives    int
	Snapshots int
}

// Paths predicts the stable, committed paths for one drive generation. It
// performs no filesystem mutation and is suitable for cleanup journaling
// before a Store is opened or a drive is created.
type Paths struct {
	Root      string
	DriveDir  string
	Artifact  string
	Metadata  string
	Ownership string
}

type Store struct {
	root         string
	drives       string
	snapshots    string
	runID        string
	owner        Ownership
	maxBytes     int64
	maxDrives    int
	maxSnapshots int
	runner       FaultRunner
	lockFile     *os.File
	closed       bool
	mu           sync.Mutex
	hooks        testHooks
}

// testHooks provide deterministic failure points to same-package adversarial
// tests without changing the production API or using global mutable state.
type testHooks struct {
	beforeCopy           func(string) error
	beforeMetadataCommit func(string) error
	beforeManagedCleanup func(string) error
	afterRootRename      func(StoreIdentity) error
}

func New(config Config) (*Store, error) { return newStore(config) }

func NewStore(root string, runners ...FaultRunner) (*Store, error) {
	if len(runners) > 1 {
		return nil, fmt.Errorf("%w: more than one runner", ErrInvalidRoot)
	}
	var runner FaultRunner
	if len(runners) == 1 {
		runner = runners[0]
	}
	return New(Config{Root: root, Runner: runner})
}

func PlanPaths(root, id string, generation uint64) (Paths, error) {
	if err := validateID(id); err != nil {
		return Paths{}, err
	}
	if generation == 0 {
		return Paths{}, ErrInvalidSize
	}
	plannedRoot, err := validatePlannedRoot(root)
	if err != nil {
		return Paths{}, err
	}
	driveDir := filepath.Join(plannedRoot, "drives", id)
	return Paths{
		Root:      plannedRoot,
		DriveDir:  driveDir,
		Artifact:  filepath.Join(driveDir, artifactName(generation)),
		Metadata:  filepath.Join(driveDir, metadataName),
		Ownership: filepath.Join(driveDir, ownerFileName),
	}, nil
}

// PlanStoreIdentity returns a canonical, replay-safe identity without
// creating or changing the store.
func PlanStoreIdentity(root, runID string, ownership Ownership) (StoreIdentity, error) {
	plannedRoot, err := validatePlannedRoot(root)
	if err != nil {
		return StoreIdentity{}, err
	}
	if err := validateID(runID); err != nil {
		return StoreIdentity{}, fmt.Errorf("%w: invalid run id", ErrInvalidRoot)
	}
	if err := validateOwnership(ownership); err != nil {
		return StoreIdentity{}, err
	}
	name := "." + filepath.Base(plannedRoot) + ".vmdisk-remove-" + runID
	if len(name) > 255 {
		return StoreIdentity{}, fmt.Errorf("%w: terminal cleanup name is too long", ErrInvalidRoot)
	}
	return StoreIdentity{
		Root:      plannedRoot,
		RunID:     runID,
		Ownership: ownership,
		Tombstone: filepath.Join(filepath.Dir(plannedRoot), name),
	}, nil
}

func (s *Store) Identity() StoreIdentity {
	identity, _ := PlanStoreIdentity(s.root, s.runID, s.owner)
	return identity
}

// RemoveStore replays terminal cleanup from a trusted outer journal. It
// resumes a deterministic detached-root cleanup before touching Root.
func RemoveStore(ctx context.Context, identity StoreIdentity) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	identity, err := validateStoreIdentity(identity)
	if err != nil {
		return err
	}
	if err := removeDetachedStore(identity); err != nil {
		return err
	}
	if _, err := os.Lstat(identity.Root); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	store, err := openExistingStore(ctx, identity)
	if err != nil {
		return err
	}
	defer store.closeReplayHandle()
	return store.CloseAndRemove(ctx)
}

// RemoveDriveOwned replays one drive cleanup from a trusted outer journal.
// It resolves the current artifact generation and removes any owned snapshots
// without following journaled artifact paths.
func RemoveDriveOwned(ctx context.Context, identity StoreIdentity, id string) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	identity, err := validateStoreIdentity(identity)
	if err != nil {
		return err
	}
	if err := removeDetachedStore(identity); err != nil {
		return err
	}
	if _, err := os.Lstat(identity.Root); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	store, err := openExistingStore(ctx, identity)
	if err != nil {
		return err
	}
	defer store.closeReplayHandle()
	return store.Remove(ctx, id)
}

func (s *Store) closeReplayHandle() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lockFile != nil {
		_ = s.lockFile.Close()
		s.lockFile = nil
	}
	s.closed = true
}

func (s *Store) Root() string  { return s.root }
func (s *Store) RunID() string { return s.runID }

func (s *Store) Create(ctx context.Context, id string, size int64) (*Drive, error) {
	return s.CreateSpec(ctx, DriveSpec{ID: id, Size: size})
}

func (s *Store) Preallocate(ctx context.Context, id string, size int64) (*Drive, error) {
	return s.Create(ctx, id, size)
}

func (s *Store) CreateSpec(ctx context.Context, spec DriveSpec) (*Drive, error) {
	if err := validateID(spec.ID); err != nil {
		return nil, err
	}
	if err := validateSize(spec.Size); err != nil {
		return nil, err
	}
	filesystem, err := normalizeFilesystem(spec.Filesystem)
	if err != nil {
		return nil, err
	}
	done, err := s.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	if _, err := os.Lstat(s.driveDir(spec.ID)); err == nil {
		return nil, ErrExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	usage, err := s.usageLocked()
	if err != nil {
		return nil, err
	}
	if usage.Drives >= s.maxDrives || exceedsQuota(usage.Bytes, spec.Size, s.maxBytes) {
		return nil, ErrQuotaExceeded
	}
	stageID, err := randomID()
	if err != nil {
		return nil, err
	}
	dir := s.driveDir(spec.ID)
	stageDir := filepath.Join(s.drives, stageDrivePrefix+s.runID+"-"+stageID)
	if err := createOwnedDirectory(stageDir, s.owner); err != nil {
		return nil, err
	}
	created := true
	defer func() {
		if created {
			if err := removeOwnedTree(stageDir, s.runID, spec.ID, s.owner); err != nil {
				_ = removeUncommittedStage(stageDir, s.runID, s.owner)
			}
			_ = syncDirectory(s.drives)
		}
	}()
	if err := writeDriveOwner(stageDir, s.runID, spec.ID, s.owner); err != nil {
		return nil, err
	}
	artifact := artifactName(1)
	path := filepath.Join(stageDir, artifact)
	if err := allocateImage(ctx, path, spec.Size, s.owner); err != nil {
		return nil, err
	}
	if err := syncDirectory(stageDir); err != nil {
		return nil, err
	}
	state := diskMetadata{
		Version: metadataVersion, RunID: s.runID, ID: spec.ID,
		Artifact: artifact, Size: spec.Size, Attached: true,
		Filesystem: filesystem, Transition: Transition{Kind: TransitionCreate},
		Generation: 1, UpdatedAt: time.Now().UTC(),
	}
	if _, err := s.writeDiskMetadata(ctx, filepath.Join(stageDir, metadataName), state); err != nil {
		return nil, err
	}
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	if err := unix.Renameat2(unix.AT_FDCWD, stageDir, unix.AT_FDCWD, dir, unix.RENAME_NOREPLACE); err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, ErrExists
		}
		return nil, err
	}
	created = false
	if err := syncDirectory(s.drives); err != nil {
		return state.drive(filepath.Join(dir, artifact)), fmt.Errorf("%w: %v", ErrDurabilityUncertain, err)
	}
	return state.drive(filepath.Join(dir, artifact)), nil
}

func (s *Store) Get(ctx context.Context, id string) (*Drive, error) {
	if err := validateID(id); err != nil {
		return nil, err
	}
	done, err := s.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	state, path, err := s.loadMetadata(id)
	if err != nil {
		return nil, err
	}
	return state.drive(path), nil
}

func (s *Store) State(ctx context.Context, id string) (*Drive, error) { return s.Get(ctx, id) }

func (s *Store) NextBoot(ctx context.Context, id string) (BootPlan, error) {
	if err := validateID(id); err != nil {
		return BootPlan{}, err
	}
	done, err := s.begin(ctx)
	if err != nil {
		return BootPlan{}, err
	}
	defer done()
	state, path, err := s.loadMetadata(id)
	if err != nil {
		return BootPlan{}, err
	}
	return s.bootPlanLocked(ctx, state, path)
}

func (s *Store) Attach(ctx context.Context, id string) error {
	_, err := s.PrepareAttachment(ctx, id, true)
	return err
}

func (s *Store) Reattach(ctx context.Context, id string) error { return s.Attach(ctx, id) }

func (s *Store) Detach(ctx context.Context, id string) error {
	_, err := s.PrepareAttachment(ctx, id, false)
	return err
}

func (s *Store) PrepareAttachment(ctx context.Context, id string, attached bool) (TransitionOutcome, error) {
	if err := validateID(id); err != nil {
		return TransitionOutcome{}, err
	}
	done, err := s.begin(ctx)
	if err != nil {
		return TransitionOutcome{}, err
	}
	defer done()
	state, path, err := s.loadMetadata(id)
	if err != nil {
		return TransitionOutcome{}, err
	}
	previous := state.Generation
	if state.Attached != attached {
		state.Attached = attached
		state.Generation++
		state.UpdatedAt = time.Now().UTC()
		if attached {
			state.Transition = Transition{Kind: TransitionAttach}
		} else {
			state.Transition = Transition{Kind: TransitionDetach}
		}
		if _, err := s.writeDiskMetadata(ctx, s.metadataPath(id), state); err != nil {
			return TransitionOutcome{}, err
		}
	}
	plan, err := s.bootPlanLocked(ctx, state, path)
	return TransitionOutcome{PreviousGeneration: previous, Plan: plan}, err
}

func (s *Store) Expand(ctx context.Context, id string, size int64) error {
	_, err := s.PrepareExpansion(ctx, id, size)
	return err
}

func (s *Store) Resize(ctx context.Context, id string, size int64) error {
	return s.Expand(ctx, id, size)
}

func (s *Store) PrepareExpansion(ctx context.Context, id string, size int64) (TransitionOutcome, error) {
	if err := validateID(id); err != nil {
		return TransitionOutcome{}, err
	}
	if err := validateSize(size); err != nil {
		return TransitionOutcome{}, err
	}
	done, err := s.begin(ctx)
	if err != nil {
		return TransitionOutcome{}, err
	}
	defer done()
	state, oldPath, err := s.loadMetadata(id)
	if err != nil {
		return TransitionOutcome{}, err
	}
	previous := state.Generation
	if size < state.Size {
		return TransitionOutcome{}, fmt.Errorf("%w: expansion cannot shrink %d to %d", ErrInvalidSize, state.Size, size)
	}
	if size == state.Size {
		plan, planErr := s.bootPlanLocked(ctx, state, oldPath)
		return TransitionOutcome{PreviousGeneration: previous, Plan: plan}, planErr
	}
	usage, err := s.usageLocked()
	if err != nil {
		return TransitionOutcome{}, err
	}
	if exceedsQuota(usage.Bytes, size-state.Size, s.maxBytes) {
		return TransitionOutcome{}, ErrQuotaExceeded
	}
	next := state
	next.Generation++
	next.Size = size
	next.FilledBytes = min64(next.FilledBytes, size)
	next.FillToENOSPC = false
	next.GrowFilesystem = true
	next.Transition = Transition{Kind: TransitionExpand, PreviousSize: state.Size}
	next.UpdatedAt = time.Now().UTC()
	newPath, err := s.stageClone(ctx, state, oldPath, next.Generation, size, nil)
	if err != nil {
		return TransitionOutcome{}, err
	}
	if err := s.commitArtifactState(ctx, state, oldPath, next, newPath); err != nil {
		return TransitionOutcome{}, err
	}
	plan, err := s.bootPlanLocked(ctx, next, newPath)
	return TransitionOutcome{PreviousGeneration: previous, Plan: plan}, err
}

func (s *Store) Snapshot(ctx context.Context, id string) (Snapshot, error) {
	if err := validateID(id); err != nil {
		return Snapshot{}, err
	}
	done, err := s.begin(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	defer done()
	state, path, err := s.loadMetadata(id)
	if err != nil {
		return Snapshot{}, err
	}
	return s.snapshotLocked(ctx, state, path)
}

func (s *Store) Restore(ctx context.Context, id string, source any) error {
	_, err := s.PrepareRestore(ctx, id, source)
	return err
}

func (s *Store) RestorePath(ctx context.Context, id, path string) error {
	return s.Restore(ctx, id, path)
}

func (s *Store) PrepareRestore(ctx context.Context, id string, source any) (TransitionOutcome, error) {
	if err := validateID(id); err != nil {
		return TransitionOutcome{}, err
	}
	done, err := s.begin(ctx)
	if err != nil {
		return TransitionOutcome{}, err
	}
	defer done()
	state, oldPath, err := s.loadMetadata(id)
	if err != nil {
		return TransitionOutcome{}, err
	}
	snapshot, err := s.resolveSnapshot(source, id)
	if err != nil {
		return TransitionOutcome{}, err
	}
	if snapshot.Size > state.Size {
		usage, usageErr := s.usageLocked()
		if usageErr != nil {
			return TransitionOutcome{}, usageErr
		}
		if exceedsQuota(usage.Bytes, snapshot.Size-state.Size, s.maxBytes) {
			return TransitionOutcome{}, ErrQuotaExceeded
		}
	}
	if got, err := checksumExact(ctx, snapshot.Path, snapshot.Size, s.owner, 0o400); err != nil {
		return TransitionOutcome{}, err
	} else if got != snapshot.Checksum {
		return TransitionOutcome{}, fmt.Errorf("%w: checksum mismatch", ErrCorruptSnapshot)
	}
	previous := state.Generation
	next := state
	next.Generation++
	next.Size = snapshot.Size
	next.Filesystem = snapshot.Filesystem
	next.FilledBytes = 0
	next.FillToENOSPC = false
	next.GrowFilesystem = false
	next.Transition = Transition{Kind: TransitionRestore, PreviousSize: state.Size, SnapshotID: snapshot.ID}
	next.UpdatedAt = time.Now().UTC()
	newPath, err := s.stageSnapshotRestore(ctx, snapshot, next.Generation, s.driveDir(id))
	if err != nil {
		return TransitionOutcome{}, err
	}
	if err := s.commitArtifactState(ctx, state, oldPath, next, newPath); err != nil {
		return TransitionOutcome{}, err
	}
	plan, err := s.bootPlanLocked(ctx, next, newPath)
	return TransitionOutcome{PreviousGeneration: previous, Plan: plan}, err
}

func (s *Store) Checksum(ctx context.Context, id string) (string, error) {
	if err := validateID(id); err != nil {
		return "", err
	}
	done, err := s.begin(ctx)
	if err != nil {
		return "", err
	}
	defer done()
	state, path, err := s.loadMetadata(id)
	if err != nil {
		return "", err
	}
	return checksumExact(ctx, path, state.Size, s.owner, 0o600)
}

func (s *Store) Faults(ctx context.Context, id string) (FaultState, error) {
	drive, err := s.Get(ctx, id)
	if err != nil {
		return FaultState{}, err
	}
	return FaultState{IOFailure: drive.IOFailure, ReadOnly: drive.ReadOnly, FilledBytes: drive.FilledBytes, FillToENOSPC: drive.FillToENOSPC}, nil
}

func (s *Store) ReadAt(ctx context.Context, id string, p []byte, offset int64) (int, error) {
	return s.ioAt(ctx, id, p, offset, false)
}

func (s *Store) WriteAt(ctx context.Context, id string, p []byte, offset int64) (int, error) {
	return s.ioAt(ctx, id, p, offset, true)
}

func (s *Store) ioAt(ctx context.Context, id string, p []byte, offset int64, write bool) (int, error) {
	if err := validateID(id); err != nil {
		return 0, err
	}
	if offset < 0 {
		return 0, fmt.Errorf("%w: negative offset", ErrInvalidSize)
	}
	done, err := s.begin(ctx)
	if err != nil {
		return 0, err
	}
	defer done()
	state, path, err := s.loadMetadata(id)
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
	if offset > state.Size || int64(len(p)) > state.Size-offset {
		return 0, io.ErrShortBuffer
	}
	if !write {
		file, err := openOwnedArtifact(path, os.O_RDONLY, s.owner)
		if err != nil {
			return 0, err
		}
		defer file.Close()
		return readContextAt(ctx, file, p, offset)
	}
	if len(p) == 0 {
		return 0, nil
	}
	next := state
	next.Generation++
	next.Transition = Transition{Kind: TransitionWrite}
	next.UpdatedAt = time.Now().UTC()
	mutate := func(candidate string) error {
		file, err := openOwnedRegular(candidate, os.O_RDWR, s.owner, 0o600)
		if err != nil {
			return err
		}
		if err := writeContextAt(ctx, file, p, offset); err != nil {
			_ = file.Close()
			return err
		}
		return file.Close()
	}
	newPath, err := s.stageClone(ctx, state, path, next.Generation, state.Size, mutate)
	if err != nil {
		return 0, err
	}
	if err := s.commitArtifactState(ctx, state, path, next, newPath); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (s *Store) ApplyFaultPlan(ctx context.Context, id string, plan FaultPlan) error {
	_, err := s.PrepareFaultPlan(ctx, id, plan)
	return err
}

func (s *Store) PrepareFaultPlan(ctx context.Context, id string, plan FaultPlan) (TransitionOutcome, error) {
	if err := validateID(id); err != nil {
		return TransitionOutcome{}, err
	}
	if plan.FillBytes < 0 || (plan.FillAll && plan.FillBytes != 0) || (plan.Detach && plan.Reattach) || len(plan.Corruptions) > maxCorruptionsPerPlan {
		return TransitionOutcome{}, ErrInvalidFault
	}
	done, err := s.begin(ctx)
	if err != nil {
		return TransitionOutcome{}, err
	}
	defer done()
	state, oldPath, err := s.loadMetadata(id)
	if err != nil {
		return TransitionOutcome{}, err
	}
	if faultPlanEmpty(plan) {
		boot, bootErr := s.bootPlanLocked(ctx, state, oldPath)
		return TransitionOutcome{PreviousGeneration: state.Generation, Plan: boot}, bootErr
	}
	for _, corruption := range plan.Corruptions {
		if corruption.Offset < 0 || corruption.Length <= 0 || corruption.Offset > state.Size-corruption.Length {
			return TransitionOutcome{}, fmt.Errorf("%w: corruption range", ErrInvalidFault)
		}
	}
	prospectiveAttached := state.Attached
	if plan.Detach {
		prospectiveAttached = false
	}
	if plan.Reattach {
		prospectiveAttached = true
	}
	prospectiveReadOnly := state.ReadOnly || plan.ReadOnly
	prospectiveIOFailure := state.IOFailure || plan.IOFailure || plan.IOError
	if (plan.FillAll || plan.FillBytes > 0) && (!prospectiveAttached || prospectiveReadOnly || prospectiveIOFailure) {
		return TransitionOutcome{}, fmt.Errorf("%w: guest filesystem fill requires an attached writable drive without an I/O fault", ErrInvalidFault)
	}
	previous := state.Generation
	next := state
	next.Generation++
	next.UpdatedAt = time.Now().UTC()
	next.Transition = Transition{Kind: TransitionFault}
	if plan.FillAll {
		next.FillToENOSPC = true
		next.FilledBytes = state.Size
	} else if plan.FillBytes > 0 {
		if plan.FillBytes > state.Size-next.FilledBytes {
			return TransitionOutcome{}, fmt.Errorf("%w: cumulative fill exceeds drive", ErrInvalidFault)
		}
		next.FilledBytes += plan.FillBytes
	}
	if plan.IOFailure || plan.IOError {
		next.IOFailure = true
	}
	if plan.ReadOnly {
		next.ReadOnly = true
	}
	if plan.Detach {
		next.Attached = false
	}
	if plan.Reattach {
		next.Attached = true
	}
	newPath := oldPath
	if len(plan.Corruptions) > 0 {
		next.Transition.Kind = TransitionCorrupt
		next.Transition.Corruptions = append([]Corruption(nil), plan.Corruptions...)
		mutate := func(candidate string) error {
			for _, corruption := range plan.Corruptions {
				if err := s.runner.Apply(ctx, FaultAction{Kind: FaultCorruption, Path: candidate, Offset: corruption.Offset, Length: corruption.Length, Pattern: corruption.Pattern}); err != nil {
					return err
				}
				if err := verifyPattern(ctx, candidate, corruption); err != nil {
					return err
				}
			}
			return nil
		}
		newPath, err = s.stageClone(ctx, state, oldPath, next.Generation, state.Size, mutate)
		if err != nil {
			return TransitionOutcome{}, err
		}
	}
	if newPath == oldPath {
		if _, err := s.writeDiskMetadata(ctx, s.metadataPath(id), next); err != nil {
			return TransitionOutcome{}, err
		}
	} else if err := s.commitArtifactState(ctx, state, oldPath, next, newPath); err != nil {
		return TransitionOutcome{}, err
	}
	boot, err := s.bootPlanLocked(ctx, next, newPath)
	return TransitionOutcome{PreviousGeneration: previous, Plan: boot}, err
}

// AcknowledgeFilesystemGrow clears a one-shot guest resize intent only for
// the generation that the runtime successfully applied. Replaying an
// acknowledgment immediately after its committed transition is idempotent.
func (s *Store) AcknowledgeFilesystemGrow(ctx context.Context, id string, generation uint64) (BootPlan, error) {
	if err := validateID(id); err != nil {
		return BootPlan{}, err
	}
	if generation == 0 {
		return BootPlan{}, ErrCorruptState
	}
	done, err := s.begin(ctx)
	if err != nil {
		return BootPlan{}, err
	}
	defer done()
	state, path, err := s.loadMetadata(id)
	if err != nil {
		return BootPlan{}, err
	}
	if state.Generation != generation {
		if generation != ^uint64(0) && state.Generation == generation+1 && !state.GrowFilesystem && state.Transition.Kind == TransitionAcknowledgeGrow {
			return s.bootPlanLocked(ctx, state, path)
		}
		return BootPlan{}, ErrDriveBusy
	}
	if !state.GrowFilesystem {
		return s.bootPlanLocked(ctx, state, path)
	}
	state.Generation++
	state.GrowFilesystem = false
	state.Transition = Transition{Kind: TransitionAcknowledgeGrow}
	state.UpdatedAt = time.Now().UTC()
	if _, err := s.writeDiskMetadata(ctx, s.metadataPath(id), state); err != nil {
		return BootPlan{}, err
	}
	return s.bootPlanLocked(ctx, state, path)
}

func (s *Store) Fill(ctx context.Context, id string, bytes int64) error {
	if bytes <= 0 {
		return fmt.Errorf("%w: fill must be positive", ErrInvalidFault)
	}
	return s.ApplyFaultPlan(ctx, id, FaultPlan{FillBytes: bytes})
}

func (s *Store) SetReadOnly(ctx context.Context, id string) error {
	return s.ApplyFaultPlan(ctx, id, FaultPlan{ReadOnly: true})
}

func (s *Store) SetIOFailure(ctx context.Context, id string) error {
	return s.ApplyFaultPlan(ctx, id, FaultPlan{IOFailure: true})
}

func (s *Store) ClearFaults(ctx context.Context, id string) error {
	_, err := s.PrepareClearFaults(ctx, id)
	return err
}

func (s *Store) PrepareClearFaults(ctx context.Context, id string) (TransitionOutcome, error) {
	if err := validateID(id); err != nil {
		return TransitionOutcome{}, err
	}
	done, err := s.begin(ctx)
	if err != nil {
		return TransitionOutcome{}, err
	}
	defer done()
	state, path, err := s.loadMetadata(id)
	if err != nil {
		return TransitionOutcome{}, err
	}
	previous := state.Generation
	if state.IOFailure || state.ReadOnly || state.FilledBytes != 0 || state.FillToENOSPC {
		state.IOFailure = false
		state.ReadOnly = false
		state.FilledBytes = 0
		state.FillToENOSPC = false
		state.Generation++
		state.Transition = Transition{Kind: TransitionClearFault}
		state.UpdatedAt = time.Now().UTC()
		if _, err := s.writeDiskMetadata(ctx, s.metadataPath(id), state); err != nil {
			return TransitionOutcome{}, err
		}
	}
	boot, err := s.bootPlanLocked(ctx, state, path)
	return TransitionOutcome{PreviousGeneration: previous, Plan: boot}, err
}

func (s *Store) Usage(ctx context.Context) (Usage, error) {
	done, err := s.begin(ctx)
	if err != nil {
		return Usage{}, err
	}
	defer done()
	return s.usageLocked()
}

func (s *Store) Remove(ctx context.Context, id string) error {
	if err := validateID(id); err != nil {
		return err
	}
	done, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer done()
	driveExists := true
	if _, _, err := s.loadMetadata(id); errors.Is(err, ErrNotFound) {
		driveExists = false
	} else if err != nil {
		return err
	}
	dirs, err := openStoreDirectories(s)
	if err != nil {
		return err
	}
	defer dirs.close()
	entries, err := readDirectoryEntries(dirs.snapshots)
	if err != nil {
		return err
	}
	var ownedSnapshots []string
	for _, entry := range entries {
		if !entry.IsDir() {
			return fmt.Errorf("%w: unexpected snapshot entry %q", ErrOwnership, entry.Name())
		}
		directory, openErr := openOwnedDirectoryAt(dirs.snapshots, entry.Name(), s.owner, 0o700)
		if openErr != nil {
			return openErr
		}
		snapshot, loadErr := s.loadSnapshotDirectoryAt(directory, filepath.Join(s.snapshots, entry.Name()))
		_ = directory.file.Close()
		if loadErr != nil {
			return loadErr
		}
		if snapshot.DriveID == id {
			ownedSnapshots = append(ownedSnapshots, snapshot.ID)
		}
	}
	for _, snapshotID := range ownedSnapshots {
		if err := contextErr(ctx); err != nil {
			return err
		}
		if err := removeManagedDirectoryAt(dirs.snapshots, snapshotID, s.runID, snapshotID, s.owner, true); err != nil {
			return err
		}
	}
	if !driveExists {
		return nil
	}
	return removeManagedDirectoryAt(dirs.drives, id, s.runID, id, s.owner, true)
}

func (s *Store) Delete(ctx context.Context, id string) error { return s.Remove(ctx, id) }

// Cleanup removes only drive/snapshot directories carrying this store's
// integrity-checked ownership record. It leaves the root, run marker, lock,
// and unrelated root children intact.
func (s *Store) Cleanup(ctx context.Context) error {
	done, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer done()
	return s.cleanupLocked(ctx)
}

// Close releases this process's store handle without removing any artifacts.
// A trusted outer cleanup journal can then replay RemoveDriveOwned or
// RemoveStore to model recovery after the original process exited.
func (s *Store) Close(ctx context.Context) error {
	done, err := s.begin(ctx)
	if errors.Is(err, ErrClosed) {
		return nil
	}
	if err != nil {
		return err
	}
	release := true
	defer func() {
		if release {
			done()
		}
	}()
	lockFile := s.lockFile
	s.closed = true
	s.lockFile = nil
	_ = unix.Flock(int(lockFile.Fd()), unix.LOCK_UN)
	closeErr := lockFile.Close()
	s.mu.Unlock()
	release = false
	return closeErr
}

func (s *Store) cleanupLocked(ctx context.Context) error {
	type cleanupTarget struct {
		parent *trustedDirectory
		name   string
		id     string
		path   string
	}
	dirs, err := openStoreDirectories(s)
	if err != nil {
		return err
	}
	defer dirs.close()
	var targets []cleanupTarget
	for _, group := range []struct {
		parent *trustedDirectory
		path   string
	}{{dirs.drives, s.drives}, {dirs.snapshots, s.snapshots}} {
		entries, err := readDirectoryEntries(group.parent)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if err := contextErr(ctx); err != nil {
				return err
			}
			if !entry.IsDir() {
				return fmt.Errorf("%w: unexpected entry %q", ErrOwnership, entry.Name())
			}
			child, err := openOwnedDirectoryAt(group.parent, entry.Name(), s.owner, 0o700)
			if err != nil {
				return err
			}
			owner, err := readArtifactOwnerAt(child, s.owner)
			_ = child.file.Close()
			if err != nil {
				return err
			}
			if owner.RunID != s.runID {
				return ErrOwnership
			}
			if err := validateManagedDirectoryAt(group.parent, entry.Name(), s.runID, owner.ID, s.owner, true); err != nil {
				return err
			}
			targets = append(targets, cleanupTarget{parent: group.parent, name: entry.Name(), id: owner.ID, path: filepath.Join(group.path, entry.Name())})
		}
	}
	for _, target := range targets {
		if err := contextErr(ctx); err != nil {
			return err
		}
		if s.hooks.beforeManagedCleanup != nil {
			if err := s.hooks.beforeManagedCleanup(target.path); err != nil {
				return err
			}
		}
		if err := removeManagedDirectoryAt(target.parent, target.name, s.runID, target.id, s.owner, true); err != nil {
			return err
		}
	}
	return nil
}

// CloseAndRemove performs terminal cleanup for a dedicated qualification
// store. It removes only integrity-checked artifacts owned by this run,
// atomically detaches the exact root while locked, then deletes it.
func (s *Store) CloseAndRemove(ctx context.Context) error {
	identity := s.Identity()
	done, err := s.begin(ctx)
	if err != nil {
		if errors.Is(err, ErrClosed) {
			return removeDetachedStore(identity)
		}
		return err
	}
	release := true
	defer func() {
		if release {
			done()
		}
	}()
	if err := s.validateStoreRootForRemoval(); err != nil {
		return err
	}
	if err := s.cleanupLocked(ctx); err != nil {
		return err
	}
	if err := contextErr(ctx); err != nil {
		return err
	}
	renameSyncErr := renameStoreToTombstone(identity, s.lockFile)
	if renameSyncErr != nil && !errors.Is(renameSyncErr, ErrDurabilityUncertain) {
		return renameSyncErr
	}
	lockFile := s.lockFile
	s.closed = true
	s.lockFile = nil
	_ = unix.Flock(int(lockFile.Fd()), unix.LOCK_UN)
	closeErr := lockFile.Close()
	s.mu.Unlock()
	release = false
	if s.hooks.afterRootRename != nil {
		if err := s.hooks.afterRootRename(identity); err != nil {
			return err
		}
	}
	if err := removeDetachedStore(identity); err != nil {
		if renameSyncErr != nil {
			return fmt.Errorf("%w: detach store root: %v; cleanup: %v", ErrDurabilityUncertain, renameSyncErr, err)
		}
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return nil
}

func (s *Store) validateStoreRootForRemoval() error {
	dirs, err := openStoreDirectories(s)
	if err != nil {
		return err
	}
	defer dirs.close()
	entries, err := readDirectoryEntries(dirs.root)
	if err != nil || len(entries) != 4 {
		return ErrOwnership
	}
	expected := map[string]bool{
		storeMarkerName: false,
		lockFileName:    false,
		"drives":        false,
		"snapshots":     false,
	}
	for _, entry := range entries {
		if _, ok := expected[entry.Name()]; !ok {
			return ErrOwnership
		}
		expected[entry.Name()] = true
	}
	for _, found := range expected {
		if !found {
			return ErrOwnership
		}
	}
	return nil
}

func (s *Store) bootPlanLocked(ctx context.Context, state diskMetadata, path string) (BootPlan, error) {
	digest := ""
	attachment := AttachmentDetached
	if state.Attached {
		attachment = AttachmentAttached
		var err error
		digest, err = checksumExact(ctx, path, state.Size, s.owner, 0o600)
		if err != nil {
			return BootPlan{}, err
		}
	} else {
		path = ""
	}
	return BootPlan{
		RunID: s.runID, DriveID: state.ID, Generation: state.Generation,
		Activation: ActivationNextBoot, RequiresStoppedGuest: true,
		Attachment: attachment, Path: path, Size: state.Size, SHA256: digest,
		ReadOnly: state.ReadOnly, IOFailure: state.IOFailure,
		RequiresRuntimeFaultAdapter: state.Attached && state.IOFailure,
		FillBytes:                   state.FilledBytes, FillToENOSPC: state.FillToENOSPC,
		RequiresGuestFilesystemFill: state.Attached && (state.FilledBytes > 0 || state.FillToENOSPC),
		RequiresGuestFilesystemGrow: state.Attached && state.GrowFilesystem,
		Filesystem:                  state.Filesystem, Transition: cloneTransition(state.Transition),
	}, nil
}

func faultPlanEmpty(plan FaultPlan) bool {
	return plan.FillBytes == 0 && !plan.FillAll && !plan.IOFailure && !plan.IOError && !plan.ReadOnly && !plan.Detach && !plan.Reattach && len(plan.Corruptions) == 0
}

func validateID(id string) error {
	if id == "" || id == "." || id == ".." || len(id) > 128 || filepath.IsAbs(id) || strings.ContainsAny(id, "/\\\x00") {
		return ErrInvalidID
	}
	for _, r := range id {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '.' && r != '_' && r != '-' {
			return ErrInvalidID
		}
	}
	return nil
}

func validateSize(size int64) error {
	if size <= 0 || size > maxDriveSize {
		return ErrInvalidSize
	}
	return nil
}

func normalizeFilesystem(spec FilesystemSpec) (FilesystemSpec, error) {
	if spec.Type == "" && spec.Label == "" {
		return DefaultFilesystem(), nil
	}
	if spec.Type != FilesystemExt4 || spec.Label == "" || len(spec.Label) > 16 {
		return FilesystemSpec{}, fmt.Errorf("%w: filesystem must be ext4 with a 1-16 byte label", ErrInvalidFault)
	}
	for _, r := range spec.Label {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '.' && r != '_' && r != '-' {
			return FilesystemSpec{}, fmt.Errorf("%w: unsafe filesystem label", ErrInvalidFault)
		}
	}
	return spec, nil
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

func isFallocateUnsupported(err error) bool {
	return errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.ENOSYS) || errors.Is(err, syscall.EINVAL)
}

func exceedsQuota(current, add, maximum int64) bool {
	return add < 0 || current > maximum || add > maximum-current
}

func min64(left, right int64) int64 {
	if left < right {
		return left
	}
	return right
}

func cloneTransition(value Transition) Transition {
	value.Corruptions = append([]Corruption(nil), value.Corruptions...)
	return value
}
