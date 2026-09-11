package vmdisk

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	storeMarkerName     = ".vmdisk-owner.json"
	lockFileName        = ".vmdisk.lock"
	ownerFileName       = ".owner.json"
	metadataName        = "metadata.json"
	snapshotImage       = "snapshot.img"
	stageDrivePrefix    = ".stage-drive-"
	stageSnapshotPrefix = ".stage-snapshot-"
	jsonTemporaryPrefix = ".tmp-json-"
	markerMagic         = "terrascale-vmdisk-run-v1"
	ownerMagic          = "terrascale-vmdisk-artifact-v1"
)

type storeMarker struct {
	Version   int       `json:"version"`
	Marker    string    `json:"marker"`
	RunID     string    `json:"run_id"`
	UID       int       `json:"uid"`
	GID       int       `json:"gid"`
	CreatedAt time.Time `json:"created_at"`
	Integrity string    `json:"integrity"`
}

type artifactOwner struct {
	Version   int       `json:"version"`
	Marker    string    `json:"marker"`
	RunID     string    `json:"run_id"`
	ID        string    `json:"id"`
	UID       int       `json:"uid"`
	GID       int       `json:"gid"`
	CreatedAt time.Time `json:"created_at"`
	Integrity string    `json:"integrity"`
}

type diskMetadata struct {
	Version        int            `json:"version"`
	RunID          string         `json:"run_id"`
	ID             string         `json:"id"`
	Artifact       string         `json:"artifact"`
	Size           int64          `json:"size"`
	Attached       bool           `json:"attached"`
	ReadOnly       bool           `json:"read_only"`
	IOFailure      bool           `json:"io_failure"`
	FilledBytes    int64          `json:"filled_bytes"`
	FillToENOSPC   bool           `json:"fill_to_enospc"`
	GrowFilesystem bool           `json:"grow_filesystem"`
	Filesystem     FilesystemSpec `json:"filesystem"`
	Transition     Transition     `json:"transition"`
	Generation     uint64         `json:"generation"`
	UpdatedAt      time.Time      `json:"updated_at"`
	Integrity      string         `json:"integrity"`
}

type snapshotMetadata struct {
	Version    int            `json:"version"`
	RunID      string         `json:"run_id"`
	ID         string         `json:"id"`
	DriveID    string         `json:"drive_id"`
	Size       int64          `json:"size"`
	Checksum   string         `json:"sha256"`
	Filesystem FilesystemSpec `json:"filesystem"`
	Generation uint64         `json:"generation"`
	CreatedAt  time.Time      `json:"created_at"`
	Integrity  string         `json:"integrity"`
}

func (m diskMetadata) drive(path string) *Drive {
	attachment := AttachmentDetached
	if m.Attached {
		attachment = AttachmentAttached
	}
	return &Drive{
		RunID: m.RunID, ID: m.ID, Path: path, Size: m.Size,
		Attached: m.Attached, Attachment: attachment, ReadOnly: m.ReadOnly,
		IOFailure: m.IOFailure, FilledBytes: m.FilledBytes,
		FillToENOSPC: m.FillToENOSPC, Filesystem: m.Filesystem,
		RequiresGuestFilesystemGrow: m.GrowFilesystem,
		Activation:                  ActivationNextBoot, Transition: cloneTransition(m.Transition),
		Generation: m.Generation, UpdatedAt: m.UpdatedAt,
	}
}

func newStore(config Config) (*Store, error) {
	root, err := validatePlannedRoot(config.Root)
	if err != nil {
		return nil, err
	}
	owner := Ownership{UID: os.Geteuid(), GID: os.Getegid()}
	if config.Ownership != nil {
		owner = *config.Ownership
	}
	if err := validateOwnership(owner); err != nil {
		return nil, err
	}
	if config.RunID == "" {
		if err := pendingDetachedStore(root); err != nil {
			return nil, err
		}
	} else {
		identity, err := PlanStoreIdentity(root, config.RunID, owner)
		if err != nil {
			return nil, err
		}
		if err := removeDetachedStore(identity); err != nil {
			return nil, err
		}
	}
	maxBytes, maxDrives, maxSnapshots := config.MaxBytes, config.MaxDrives, config.MaxSnapshots
	if maxBytes == 0 {
		maxBytes = DefaultMaxBytes
	}
	if maxDrives == 0 {
		maxDrives = DefaultMaxDrives
	}
	if maxSnapshots == 0 {
		maxSnapshots = DefaultMaxSnapshots
	}
	if maxBytes <= 0 || maxBytes > maxDriveSize || maxDrives <= 0 || maxDrives > 4096 || maxSnapshots <= 0 || maxSnapshots > 16384 {
		return nil, fmt.Errorf("%w: invalid quota", ErrInvalidRoot)
	}
	created, err := ensureStoreRoot(root, owner)
	if err != nil {
		return nil, err
	}
	if created {
		if err := syncDirectory(filepath.Dir(root)); err != nil {
			return nil, err
		}
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil || resolved != root {
		return nil, fmt.Errorf("%w: root contains a symlink", ErrInvalidRoot)
	}
	lockFile, err := openOrCreateOwned(filepath.Join(root, lockFileName), owner, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(lockFile.Fd()), unix.LOCK_EX); err != nil {
		_ = lockFile.Close()
		return nil, err
	}
	if err := validateOpenedOwnedRegular(lockFile, filepath.Join(root, lockFileName), owner, 0o600); err != nil {
		_ = lockFile.Close()
		return nil, err
	}
	unlock := func() {
		_ = unix.Flock(int(lockFile.Fd()), unix.LOCK_UN)
	}
	defer unlock()
	markerPath := filepath.Join(root, storeMarkerName)
	marker, err := loadStoreMarker(markerPath, owner)
	if errors.Is(err, os.ErrNotExist) {
		entries, readErr := os.ReadDir(root)
		if readErr != nil {
			_ = lockFile.Close()
			return nil, readErr
		}
		for _, entry := range entries {
			if entry.Name() != lockFileName {
				_ = lockFile.Close()
				return nil, fmt.Errorf("%w: refusing to adopt non-empty root", ErrOwnership)
			}
		}
		runID := config.RunID
		if runID == "" {
			runID, err = randomID()
		} else {
			err = validateID(runID)
		}
		if err != nil {
			_ = lockFile.Close()
			return nil, fmt.Errorf("%w: invalid run id", ErrInvalidRoot)
		}
		marker = storeMarker{Version: storeMarkerVersion, Marker: markerMagic, RunID: runID, UID: owner.UID, GID: owner.GID, CreatedAt: time.Now().UTC()}
		sealStoreMarker(&marker)
		committedMarker, writeErr := atomicWriteJSON(context.Background(), markerPath, marker, owner, 0o600)
		if writeErr != nil {
			_ = lockFile.Close()
			if committedMarker != "" {
				return nil, fmt.Errorf("%w: store marker: %v", ErrDurabilityUncertain, writeErr)
			}
			return nil, writeErr
		}
	} else if err != nil {
		_ = lockFile.Close()
		return nil, err
	}
	if config.RunID != "" && config.RunID != marker.RunID {
		_ = lockFile.Close()
		return nil, ErrOwnership
	}
	s := &Store{
		root: root, drives: filepath.Join(root, "drives"), snapshots: filepath.Join(root, "snapshots"),
		runID: marker.RunID, owner: owner, maxBytes: maxBytes, maxDrives: maxDrives,
		maxSnapshots: maxSnapshots, runner: config.Runner, lockFile: lockFile,
	}
	if s.runner == nil {
		s.runner = fileFaultRunner{}
	}
	for _, dir := range []string{s.drives, s.snapshots} {
		if err := ensureOwnedDirectory(dir, owner); err != nil {
			_ = lockFile.Close()
			return nil, err
		}
	}
	if err := validateStoreMountLayout(root, owner); err != nil {
		_ = lockFile.Close()
		return nil, err
	}
	if err := syncDirectory(root); err != nil {
		_ = lockFile.Close()
		return nil, err
	}
	if err := s.recoverLocked(); err != nil {
		_ = lockFile.Close()
		return nil, err
	}
	if usage, err := s.usageLocked(); err != nil {
		_ = lockFile.Close()
		return nil, err
	} else if usage.Drives > s.maxDrives || usage.Snapshots > s.maxSnapshots || usage.Bytes > s.maxBytes {
		_ = lockFile.Close()
		return nil, ErrQuotaExceeded
	}
	return s, nil
}

func openExistingStore(ctx context.Context, identity StoreIdentity) (*Store, error) {
	identity, err := validateStoreIdentity(identity)
	if err != nil {
		return nil, err
	}
	parent, err := openDirectoryPath(filepath.Dir(identity.Root))
	if err != nil {
		return nil, err
	}
	defer parent.file.Close()
	root, err := openOwnedDirectoryAt(parent, filepath.Base(identity.Root), identity.Ownership, 0o700)
	if err != nil {
		return nil, err
	}
	defer root.file.Close()
	marker, err := loadStoreMarkerAt(root, identity.Ownership)
	if err != nil || marker.RunID != identity.RunID {
		return nil, ErrOwnership
	}
	for _, name := range []string{"drives", "snapshots"} {
		dir, err := openOwnedDirectoryAt(root, name, identity.Ownership, 0o700)
		if err != nil {
			return nil, err
		}
		_ = dir.file.Close()
	}
	lockFile, _, err := openOwnedRegularAt(root, lockFileName, unix.O_RDWR, identity.Ownership, 0o600)
	if err != nil {
		return nil, err
	}
	s := &Store{
		root: identity.Root, drives: filepath.Join(identity.Root, "drives"), snapshots: filepath.Join(identity.Root, "snapshots"),
		runID: identity.RunID, owner: identity.Ownership, maxBytes: maxDriveSize, maxDrives: 4096,
		maxSnapshots: 16384, runner: fileFaultRunner{}, lockFile: lockFile,
	}
	done, err := s.begin(ctx)
	if err != nil {
		_ = lockFile.Close()
		return nil, err
	}
	if err := s.recoverLocked(); err != nil {
		done()
		_ = lockFile.Close()
		return nil, err
	}
	done()
	return s, nil
}

func validatePlannedRoot(value string) (string, error) {
	if strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("%w: root is empty", ErrInvalidRoot)
	}
	root, err := filepath.Abs(value)
	if err != nil {
		return "", fmt.Errorf("%w: resolve root: %v", ErrInvalidRoot, err)
	}
	root = filepath.Clean(root)
	if root == string(os.PathSeparator) {
		return "", fmt.Errorf("%w: unsafe root", ErrInvalidRoot)
	}
	ancestor := root
	for {
		info, statErr := os.Lstat(ancestor)
		if statErr == nil {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return "", fmt.Errorf("%w: root ancestor is not a directory", ErrInvalidRoot)
			}
			resolved, resolveErr := filepath.EvalSymlinks(ancestor)
			if resolveErr != nil || resolved != ancestor {
				return "", fmt.Errorf("%w: root contains a symlink", ErrInvalidRoot)
			}
			break
		}
		if !errors.Is(statErr, os.ErrNotExist) {
			return "", fmt.Errorf("%w: inspect root: %v", ErrInvalidRoot, statErr)
		}
		parent := filepath.Dir(ancestor)
		if parent == ancestor {
			return "", fmt.Errorf("%w: no existing root ancestor", ErrInvalidRoot)
		}
		ancestor = parent
	}
	return root, nil
}

func (s *Store) begin(ctx context.Context) (func(), error) {
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	for !s.mu.TryLock() {
		if err := waitForLock(ctx); err != nil {
			return nil, err
		}
	}
	if s.closed || s.lockFile == nil {
		s.mu.Unlock()
		return nil, ErrClosed
	}
	lockFile := s.lockFile
	for {
		err := unix.Flock(int(lockFile.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			s.mu.Unlock()
			return nil, err
		}
		if err := waitForLock(ctx); err != nil {
			s.mu.Unlock()
			return nil, err
		}
	}
	if err := validateOpenedOwnedRegular(lockFile, filepath.Join(s.root, lockFileName), s.owner, 0o600); err != nil {
		_ = unix.Flock(int(lockFile.Fd()), unix.LOCK_UN)
		s.mu.Unlock()
		return nil, err
	}
	if err := contextErr(ctx); err != nil {
		_ = unix.Flock(int(lockFile.Fd()), unix.LOCK_UN)
		s.mu.Unlock()
		return nil, err
	}
	return func() {
		_ = unix.Flock(int(lockFile.Fd()), unix.LOCK_UN)
		s.mu.Unlock()
	}, nil
}

func waitForLock(ctx context.Context) error {
	timer := time.NewTimer(10 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (s *Store) driveDir(id string) string { return filepath.Join(s.drives, id) }

func (s *Store) metadataPath(id string) string { return filepath.Join(s.driveDir(id), metadataName) }

func artifactName(generation uint64) string {
	return fmt.Sprintf("artifact-%020d.img", generation)
}

func randomID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}

func ensureStoreRoot(path string, owner Ownership) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return false, fmt.Errorf("%w: create root: %v", ErrInvalidRoot, err)
		}
		if err := applyOwnershipAndMode(path, owner, 0o700); err != nil {
			return false, err
		}
		return true, nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("%w: root must be a directory", ErrInvalidRoot)
	}
	actual, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(actual.Uid) != owner.UID || int(actual.Gid) != owner.GID {
		return false, fmt.Errorf("%w: %v", ErrInvalidRoot, ErrOwnership)
	}
	if info.Mode().Perm() != 0o700 {
		entries, readErr := os.ReadDir(path)
		if readErr != nil || len(entries) != 0 {
			return false, fmt.Errorf("%w: root mode must be 0700", ErrInvalidRoot)
		}
		if err := os.Chmod(path, 0o700); err != nil {
			return false, fmt.Errorf("%w: secure empty root: %v", ErrInvalidRoot, err)
		}
		if err := syncDirectory(filepath.Dir(path)); err != nil {
			return false, err
		}
	}
	return false, nil
}

func ensureOwnedDirectory(path string, owner Ownership) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := createOwnedDirectory(path, owner); err != nil {
			return err
		}
		return syncDirectory(filepath.Dir(path))
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrOwnership
	}
	return validateOwnerMode(info, owner, 0o700)
}

func createOwnedDirectory(path string, owner Ownership) error {
	if err := os.Mkdir(path, 0o700); err != nil {
		return err
	}
	if err := applyOwnershipAndMode(path, owner, 0o700); err != nil {
		_ = removeEmptyOwnedDirectoryPath(path, owner)
		return err
	}
	return syncDirectory(path)
}

func applyOwnershipAndMode(path string, owner Ownership, mode os.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	actual, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ErrOwnership
	}
	if int(actual.Uid) != owner.UID || int(actual.Gid) != owner.GID {
		if err := os.Chown(path, owner.UID, owner.GID); err != nil {
			return fmt.Errorf("%w: chown %s: %v", ErrOwnership, path, err)
		}
	}
	if info.Mode().Perm() != mode {
		if err := os.Chmod(path, mode); err != nil {
			return err
		}
	}
	return nil
}

func validateOwnerMode(info os.FileInfo, owner Ownership, mode os.FileMode) error {
	actual, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(actual.Uid) != owner.UID || int(actual.Gid) != owner.GID || info.Mode().Perm() != mode {
		return ErrOwnership
	}
	return nil
}

func openOrCreateOwned(path string, owner Ownership, mode os.FileMode) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR|unix.O_NOFOLLOW, mode)
	created := err == nil
	if errors.Is(err, os.ErrExist) {
		file, err = os.OpenFile(path, os.O_RDWR|unix.O_NOFOLLOW, 0)
	}
	if err != nil {
		return nil, err
	}
	closeWithError := func(result error) (*os.File, error) {
		if created {
			fileInfo, fileErr := file.Stat()
			pathInfo, pathErr := os.Lstat(path)
			if fileErr == nil && pathErr == nil && pathInfo.Mode()&os.ModeSymlink == 0 && os.SameFile(fileInfo, pathInfo) {
				_ = unlinkOwnedRegularPath(path, owner, mode)
			}
		}
		_ = file.Close()
		return nil, result
	}
	info, err := file.Stat()
	if err != nil {
		return closeWithError(err)
	}
	if !info.Mode().IsRegular() {
		return closeWithError(ErrOwnership)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return closeWithError(ErrOwnership)
	}
	if created {
		if err := applyFileOwnershipAndMode(file, info, owner, mode); err != nil {
			return closeWithError(err)
		}
	} else if err := validateOwnerMode(info, owner, mode); err != nil {
		return closeWithError(err)
	}
	if err := validateOpenedOwnedRegular(file, path, owner, mode); err != nil {
		return closeWithError(err)
	}
	return file, nil
}

func validateOpenedOwnedRegular(file *os.File, path string, owner Ownership, mode os.FileMode) error {
	parent, err := openOwnedDirectoryPath(filepath.Dir(path), owner, 0o700)
	if err != nil {
		return err
	}
	defer parent.file.Close()
	opened, openedStat, err := openOwnedRegularAt(parent, filepath.Base(path), unix.O_RDONLY, owner, mode)
	if err != nil {
		return err
	}
	_ = opened.Close()
	fileStat, err := statxFile(file)
	if err != nil || !sameStatxIdentity(openedStat, fileStat) {
		return ErrOwnership
	}
	return validateStatxOwnerMode(fileStat, owner, mode, unix.S_IFREG, true)
}

func applyFileOwnershipAndMode(file *os.File, info os.FileInfo, owner Ownership, mode os.FileMode) error {
	actual, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ErrOwnership
	}
	if int(actual.Uid) != owner.UID || int(actual.Gid) != owner.GID {
		if err := file.Chown(owner.UID, owner.GID); err != nil {
			return fmt.Errorf("%w: chown: %v", ErrOwnership, err)
		}
	}
	if info.Mode().Perm() != mode {
		if err := file.Chmod(mode); err != nil {
			return err
		}
	}
	return nil
}

func openOwnedRegular(path string, flags int, owner Ownership, mode os.FileMode) (*os.File, error) {
	parent, err := openOwnedDirectoryPath(filepath.Dir(path), owner, 0o700)
	if err != nil {
		return nil, err
	}
	defer parent.file.Close()
	file, _, err := openOwnedRegularAt(parent, filepath.Base(path), flags, owner, mode)
	return file, err
}

// openOwnedArtifact reads a drive artifact that may carry the VMM jailer's
// hard link while its guest runs; see openOwnedArtifactAt.
func openOwnedArtifact(path string, flags int, owner Ownership) (*os.File, error) {
	parent, err := openOwnedDirectoryPath(filepath.Dir(path), owner, 0o700)
	if err != nil {
		return nil, err
	}
	defer parent.file.Close()
	file, _, err := openOwnedArtifactAt(parent, filepath.Base(path), flags, owner)
	return file, err
}

func syncDirectory(path string) error {
	dir, err := openDirectoryPath(path)
	if err != nil {
		return err
	}
	defer dir.file.Close()
	return dir.file.Sync()
}

func sealStoreMarker(marker *storeMarker) {
	marker.Integrity = ""
	marker.Integrity = structureDigest(*marker)
}

func sealArtifactOwner(owner *artifactOwner) {
	owner.Integrity = ""
	owner.Integrity = structureDigest(*owner)
}

func sealDiskMetadata(metadata *diskMetadata) {
	metadata.Integrity = ""
	metadata.Integrity = structureDigest(*metadata)
}

func sealSnapshotMetadata(metadata *snapshotMetadata) {
	metadata.Integrity = ""
	metadata.Integrity = structureDigest(*metadata)
}

func structureDigest(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func validStoreMarker(marker storeMarker, owner Ownership) bool {
	want := marker.Integrity
	marker.Integrity = ""
	return marker.Version == storeMarkerVersion && marker.Marker == markerMagic && validateID(marker.RunID) == nil && marker.UID == owner.UID && marker.GID == owner.GID && !marker.CreatedAt.IsZero() && want == structureDigest(marker)
}

func loadStoreMarker(path string, owner Ownership) (storeMarker, error) {
	var marker storeMarker
	if err := readStrictJSON(path, owner, 0o600, &marker); err != nil {
		return storeMarker{}, err
	}
	if !validStoreMarker(marker, owner) {
		return storeMarker{}, ErrOwnership
	}
	return marker, nil
}

func writeDriveOwner(dir, runID, id string, owner Ownership) error {
	record := artifactOwner{Version: 1, Marker: ownerMagic, RunID: runID, ID: id, UID: owner.UID, GID: owner.GID, CreatedAt: time.Now().UTC()}
	sealArtifactOwner(&record)
	_, err := atomicWriteJSON(context.Background(), filepath.Join(dir, ownerFileName), record, owner, 0o600)
	return err
}

func readArtifactOwner(dir string, owner Ownership) (artifactOwner, error) {
	var record artifactOwner
	if err := readStrictJSON(filepath.Join(dir, ownerFileName), owner, 0o600, &record); err != nil {
		return artifactOwner{}, fmt.Errorf("%w: %v", ErrOwnership, err)
	}
	want := record.Integrity
	record.Integrity = ""
	if record.Version != 1 || record.Marker != ownerMagic || validateID(record.RunID) != nil || validateID(record.ID) != nil || record.UID != owner.UID || record.GID != owner.GID || record.CreatedAt.IsZero() || want != structureDigest(record) {
		return artifactOwner{}, ErrOwnership
	}
	record.Integrity = want
	return record, nil
}

func readStrictJSON(path string, owner Ownership, mode os.FileMode, target any) error {
	file, err := openOwnedRegular(path, os.O_RDONLY, owner, mode)
	if err != nil {
		return err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxMetadataBytes+1))
	if err != nil {
		return err
	}
	return decodeStrictJSON(data, target)
}

func readStrictJSONAt(dir *trustedDirectory, name string, owner Ownership, mode os.FileMode, target any) error {
	file, _, err := openOwnedRegularAt(dir, name, unix.O_RDONLY, owner, mode)
	if err != nil {
		return err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxMetadataBytes+1))
	if err != nil {
		return err
	}
	return decodeStrictJSON(data, target)
}

func decodeStrictJSON(data []byte, target any) error {
	if len(data) == 0 || len(data) > maxMetadataBytes {
		return ErrCorruptState
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return ErrCorruptState
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(data, canonical) && !bytes.Equal(data, append(canonical, '\n')) {
		return ErrCorruptState
	}
	return nil
}

func validateOwnership(owner Ownership) error {
	const maxUint32 = uint64(1<<32 - 1)
	if owner.UID < 0 || owner.GID < 0 || uint64(owner.UID) > maxUint32 || uint64(owner.GID) > maxUint32 {
		return fmt.Errorf("%w: ownership must contain uint32 UID/GID values", ErrInvalidRoot)
	}
	return nil
}

func atomicWriteJSON(ctx context.Context, path string, value any, owner Ownership, mode os.FileMode) (string, error) {
	if err := contextErr(ctx); err != nil {
		return "", err
	}
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	data = append(data, '\n')
	if len(data) > maxMetadataBytes {
		return "", ErrCorruptState
	}
	if info, statErr := os.Lstat(path); statErr == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return "", ErrOwnership
		}
		if err := validateOwnerMode(info, owner, mode); err != nil {
			return "", err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Nlink != 1 {
			return "", ErrOwnership
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return "", statErr
	}
	token, err := randomID()
	if err != nil {
		return "", err
	}
	temporary := filepath.Join(filepath.Dir(path), jsonTemporaryPrefix+token)
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return "", err
	}
	committed := false
	defer func() {
		if !committed {
			_ = file.Close()
			_ = unlinkOwnedRegularPath(temporary, owner, mode)
		}
	}()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if err := applyFileOwnershipAndMode(file, info, owner, mode); err != nil {
		return "", err
	}
	if err := writeAll(file, data); err != nil {
		return "", err
	}
	if err := file.Sync(); err != nil {
		return "", err
	}
	if err := contextErr(ctx); err != nil {
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(temporary, path); err != nil {
		return "", err
	}
	committed = true
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return path, err
	}
	return path, nil
}

func writeAll(file *os.File, data []byte) error {
	for len(data) != 0 {
		n, err := file.Write(data)
		if n > 0 {
			data = data[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func (s *Store) writeDiskMetadata(ctx context.Context, path string, metadata diskMetadata) (diskMetadata, error) {
	metadata.Integrity = ""
	dir := filepath.Dir(path)
	owner, err := readArtifactOwner(dir, s.owner)
	if err != nil {
		return diskMetadata{}, err
	}
	if owner.RunID != s.runID || owner.ID != metadata.ID || metadata.RunID != s.runID {
		return diskMetadata{}, ErrOwnership
	}
	if err := validateDiskMetadataValue(metadata, filepath.Join(dir, metadata.Artifact), s.owner); err != nil {
		return diskMetadata{}, err
	}
	sealDiskMetadata(&metadata)
	if s.hooks.beforeMetadataCommit != nil {
		if err := s.hooks.beforeMetadataCommit(path); err != nil {
			return diskMetadata{}, err
		}
	}
	committedPath, err := atomicWriteJSON(ctx, path, metadata, s.owner, 0o600)
	if err != nil {
		if committedPath != "" {
			return metadata, fmt.Errorf("%w: %v", ErrDurabilityUncertain, err)
		}
		return diskMetadata{}, err
	}
	return metadata, nil
}

func (s *Store) loadMetadata(id string) (diskMetadata, string, error) {
	if err := validateID(id); err != nil {
		return diskMetadata{}, "", err
	}
	dirs, err := openStoreDirectories(s)
	if err != nil {
		return diskMetadata{}, "", err
	}
	defer dirs.close()
	directory, err := openOwnedDirectoryAt(dirs.drives, id, s.owner, 0o700)
	if errors.Is(err, os.ErrNotExist) {
		return diskMetadata{}, "", ErrNotFound
	}
	if err != nil {
		return diskMetadata{}, "", err
	}
	defer directory.file.Close()
	return s.loadDriveDirectoryAt(directory, s.driveDir(id), id, true)
}

func (s *Store) loadDriveDirectoryAt(directory *trustedDirectory, dir, id string, strictEntries bool) (diskMetadata, string, error) {
	owner, err := readArtifactOwnerAt(directory, s.owner)
	if err != nil {
		return diskMetadata{}, "", err
	}
	if owner.RunID != s.runID || owner.ID != id {
		return diskMetadata{}, "", ErrOwnership
	}
	var metadata diskMetadata
	if err := readStrictJSONAt(directory, metadataName, s.owner, 0o600, &metadata); err != nil {
		return diskMetadata{}, "", fmt.Errorf("%w: disk metadata: %v", ErrCorruptState, err)
	}
	want := metadata.Integrity
	metadata.Integrity = ""
	path := filepath.Join(dir, metadata.Artifact)
	if want == "" || want != structureDigest(metadata) {
		return diskMetadata{}, "", ErrCorruptState
	}
	metadata.Integrity = want
	if metadata.RunID != s.runID || metadata.ID != id {
		return diskMetadata{}, "", ErrOwnership
	}
	if err := validateDiskMetadataValueAt(metadata, directory, s.owner); err != nil {
		return diskMetadata{}, "", err
	}
	if strictEntries {
		if err := validateExactEntriesAt(directory, map[string]os.FileMode{
			ownerFileName:     0o600,
			metadataName:      0o600,
			metadata.Artifact: 0o600,
		}, s.owner, metadata.Artifact); err != nil {
			return diskMetadata{}, "", err
		}
	}
	return metadata, path, nil
}

func validateDiskMetadataValueAt(metadata diskMetadata, directory *trustedDirectory, owner Ownership) error {
	if err := validateDiskMetadataStructure(metadata); err != nil {
		return err
	}
	file, _, err := openOwnedArtifactAt(directory, metadata.Artifact, unix.O_RDONLY, owner)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrCorruptState
		}
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Size() != metadata.Size {
		return ErrCorruptState
	}
	return nil
}

func validateDiskMetadataValue(metadata diskMetadata, path string, owner Ownership) error {
	if err := validateDiskMetadataStructure(metadata); err != nil {
		return err
	}
	file, err := openOwnedRegular(path, os.O_RDONLY, owner, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrCorruptState
		}
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Size() != metadata.Size {
		return ErrCorruptState
	}
	return nil
}

func validateDiskMetadataStructure(metadata diskMetadata) error {
	artifactGeneration, artifactErr := parseArtifactGeneration(metadata.Artifact)
	if metadata.Version != metadataVersion || metadata.Generation == 0 || artifactErr != nil || artifactGeneration > metadata.Generation || metadata.UpdatedAt.IsZero() {
		return ErrCorruptState
	}
	if err := validateID(metadata.RunID); err != nil {
		return ErrCorruptState
	}
	if err := validateID(metadata.ID); err != nil {
		return ErrCorruptState
	}
	if err := validateSize(metadata.Size); err != nil {
		return ErrCorruptState
	}
	filesystem, err := normalizeFilesystem(metadata.Filesystem)
	if err != nil || filesystem != metadata.Filesystem {
		return ErrCorruptState
	}
	if metadata.FilledBytes < 0 || metadata.FilledBytes > metadata.Size || (metadata.FillToENOSPC && metadata.FilledBytes != metadata.Size) {
		return ErrCorruptState
	}
	if !validTransition(metadata.Transition, metadata.Size) {
		return ErrCorruptState
	}
	return nil
}

func validTransition(transition Transition, size int64) bool {
	switch transition.Kind {
	case TransitionExpand:
		if transition.PreviousSize <= 0 || transition.PreviousSize >= size || transition.SnapshotID != "" || len(transition.Corruptions) != 0 {
			return false
		}
	case TransitionRestore:
		if transition.PreviousSize <= 0 || transition.PreviousSize > maxDriveSize || validateID(transition.SnapshotID) != nil || len(transition.Corruptions) != 0 {
			return false
		}
	case TransitionCorrupt:
		if transition.PreviousSize != 0 || transition.SnapshotID != "" || len(transition.Corruptions) == 0 {
			return false
		}
	case TransitionCreate, TransitionAttach, TransitionDetach, TransitionFault, TransitionClearFault, TransitionWrite, TransitionAcknowledgeGrow:
		if transition.PreviousSize != 0 || transition.SnapshotID != "" || len(transition.Corruptions) != 0 {
			return false
		}
	default:
		return false
	}
	if len(transition.Corruptions) > maxCorruptionsPerPlan {
		return false
	}
	for _, corruption := range transition.Corruptions {
		if corruption.Offset < 0 || corruption.Length <= 0 || corruption.Offset > size-corruption.Length {
			return false
		}
	}
	return true
}

func validArtifactName(name string) bool {
	_, err := parseArtifactGeneration(name)
	return err == nil
}

func parseArtifactGeneration(name string) (uint64, error) {
	if !strings.HasPrefix(name, "artifact-") || !strings.HasSuffix(name, ".img") {
		return 0, ErrCorruptState
	}
	digits := strings.TrimSuffix(strings.TrimPrefix(name, "artifact-"), ".img")
	if len(digits) != 20 {
		return 0, ErrCorruptState
	}
	generation, err := strconv.ParseUint(digits, 10, 64)
	if err != nil || generation == 0 {
		return 0, ErrCorruptState
	}
	return generation, nil
}

// VerifyPaths validates a journaled committed drive without creating,
// recovering, locking, or otherwise changing any filesystem object.
func VerifyPaths(paths Paths, runID, id string) error {
	actual, err := VerifyDrive(paths.Root, runID, id)
	if err != nil {
		return err
	}
	if paths != actual {
		return ErrOutsideRoot
	}
	return nil
}

// VerifyPathsOwned is VerifyPaths for a store owned by a configured identity
// rather than the current process identity.
func VerifyPathsOwned(paths Paths, identity StoreIdentity, id string) error {
	actual, err := VerifyDriveOwned(identity, id)
	if err != nil {
		return err
	}
	if paths != actual {
		return ErrOutsideRoot
	}
	return nil
}

// VerifyDrive validates a committed drive read-only and returns the exact
// current generation paths derived from integrity-checked metadata.
func VerifyDrive(root, runID, id string) (Paths, error) {
	identity, err := PlanStoreIdentity(root, runID, Ownership{UID: os.Geteuid(), GID: os.Getegid()})
	if err != nil {
		return Paths{}, err
	}
	return VerifyDriveOwned(identity, id)
}

// VerifyDriveOwned validates a committed drive against a trusted store
// identity persisted before store creation. It never infers ownership from
// mutable filesystem objects.
func VerifyDriveOwned(identity StoreIdentity, id string) (Paths, error) {
	identity, err := validateStoreIdentity(identity)
	if err != nil {
		return Paths{}, err
	}
	if validateID(id) != nil {
		return Paths{}, ErrOwnership
	}
	parent, err := openDirectoryPath(filepath.Dir(identity.Root))
	if err != nil {
		return Paths{}, err
	}
	defer parent.file.Close()
	root, err := openOwnedDirectoryAt(parent, filepath.Base(identity.Root), identity.Ownership, 0o700)
	if err != nil {
		return Paths{}, err
	}
	defer root.file.Close()
	marker, err := loadStoreMarkerAt(root, identity.Ownership)
	if err != nil {
		return Paths{}, err
	}
	if marker.RunID != identity.RunID {
		return Paths{}, ErrOwnership
	}
	lockFile, _, err := openOwnedRegularAt(root, lockFileName, unix.O_RDONLY, identity.Ownership, 0o600)
	if err != nil {
		return Paths{}, err
	}
	_ = lockFile.Close()
	drives := filepath.Join(identity.Root, "drives")
	driveRoot, err := openOwnedDirectoryAt(root, "drives", identity.Ownership, 0o700)
	if err != nil {
		return Paths{}, err
	}
	defer driveRoot.file.Close()
	snapshots, err := openOwnedDirectoryAt(root, "snapshots", identity.Ownership, 0o700)
	if err != nil {
		return Paths{}, err
	}
	_ = snapshots.file.Close()
	store := &Store{root: identity.Root, drives: drives, runID: identity.RunID, owner: identity.Ownership}
	driveDir := filepath.Join(drives, id)
	directory, err := openOwnedDirectoryAt(driveRoot, id, identity.Ownership, 0o700)
	if errors.Is(err, os.ErrNotExist) {
		return Paths{}, ErrNotFound
	}
	if err != nil {
		return Paths{}, err
	}
	defer directory.file.Close()
	state, artifact, err := store.loadDriveDirectoryAt(directory, driveDir, id, true)
	if err != nil {
		return Paths{}, err
	}
	artifactGeneration, err := parseArtifactGeneration(state.Artifact)
	if err != nil {
		return Paths{}, err
	}
	paths, err := PlanPaths(identity.Root, id, artifactGeneration)
	if err != nil {
		return Paths{}, err
	}
	if artifact != paths.Artifact {
		return Paths{}, ErrCorruptState
	}
	return paths, nil
}

func validateExactEntriesAt(directory *trustedDirectory, expected map[string]os.FileMode, owner Ownership, linkedArtifact string) error {
	entries, err := readDirectoryEntries(directory)
	if err != nil {
		return err
	}
	if len(entries) != len(expected) {
		return ErrCorruptState
	}
	for _, entry := range entries {
		mode, ok := expected[entry.Name()]
		if !ok {
			return ErrCorruptState
		}
		var file *os.File
		if entry.Name() == linkedArtifact {
			file, _, err = openOwnedArtifactAt(directory, entry.Name(), unix.O_RDONLY, owner)
		} else {
			file, _, err = openOwnedRegularAt(directory, entry.Name(), unix.O_RDONLY, owner, mode)
		}
		if err != nil {
			return err
		}
		_ = file.Close()
	}
	return nil
}

func allocateImage(ctx context.Context, path string, size int64, owner Ownership) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	complete := false
	defer func() {
		if !complete {
			_ = file.Close()
			_ = unlinkOwnedRegularPath(path, owner, 0o600)
		}
	}()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if err := applyFileOwnershipAndMode(file, info, owner, 0o600); err != nil {
		return err
	}
	if err := unix.Fallocate(int(file.Fd()), 0, 0, size); err != nil && !isFallocateUnsupported(err) {
		return err
	}
	if err := file.Truncate(size); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := contextErr(ctx); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	complete = true
	return nil
}

func (s *Store) stageClone(ctx context.Context, state diskMetadata, source string, generation uint64, targetSize int64, mutate func(string) error) (string, error) {
	if generation <= state.Generation || targetSize < state.Size {
		return "", ErrCorruptState
	}
	usage, err := s.usageLocked()
	if err != nil {
		return "", err
	}
	if exceedsQuota(usage.Bytes, targetSize, s.maxBytes) {
		return "", ErrQuotaExceeded
	}
	if s.hooks.beforeCopy != nil {
		if err := s.hooks.beforeCopy(source); err != nil {
			return "", err
		}
	}
	before, err := checksumExact(ctx, source, state.Size, s.owner, 0o600)
	if err != nil {
		return "", err
	}
	destination := filepath.Join(s.driveDir(state.ID), artifactName(generation))
	if err := allocateImage(ctx, destination, targetSize, s.owner); err != nil {
		return "", err
	}
	complete := false
	defer func() {
		if !complete {
			_ = unlinkOwnedRegularPath(destination, s.owner, 0o600)
			_ = syncDirectory(filepath.Dir(destination))
		}
	}()
	if err := copyOwnedPrefix(ctx, source, 0o600, destination, 0o600, state.Size, s.owner); err != nil {
		return "", err
	}
	copied, err := checksumPrefix(ctx, destination, state.Size, s.owner, 0o600)
	if err != nil {
		return "", err
	}
	after, err := checksumExact(ctx, source, state.Size, s.owner, 0o600)
	if err != nil {
		return "", err
	}
	if before != copied || before != after {
		return "", ErrDriveBusy
	}
	if mutate != nil {
		if err := mutate(destination); err != nil {
			return "", err
		}
	}
	if err := validateExactFile(destination, targetSize, s.owner, 0o600); err != nil {
		return "", err
	}
	if err := syncDirectory(filepath.Dir(destination)); err != nil {
		return "", err
	}
	complete = true
	return destination, nil
}

func (s *Store) commitArtifactState(ctx context.Context, current diskMetadata, oldPath string, next diskMetadata, newPath string) error {
	if filepath.Dir(newPath) != s.driveDir(current.ID) || filepath.Base(newPath) != artifactName(next.Generation) {
		_ = unlinkOwnedRegularPath(newPath, s.owner, 0o600)
		return ErrOutsideRoot
	}
	next.Artifact = filepath.Base(newPath)
	committed := false
	defer func() {
		if !committed {
			_ = unlinkOwnedRegularPath(newPath, s.owner, 0o600)
			_ = syncDirectory(filepath.Dir(newPath))
		}
	}()
	written, err := s.writeDiskMetadata(ctx, s.metadataPath(current.ID), next)
	if err != nil {
		if written.Integrity != "" {
			committed = true
		}
		return err
	}
	committed = true
	if oldPath != newPath {
		if err := unlinkOwnedRegularPath(oldPath, s.owner, 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := syncDirectory(filepath.Dir(oldPath)); err != nil {
			return fmt.Errorf("%w: remove superseded artifact: %v", ErrDurabilityUncertain, err)
		}
	}
	return nil
}

func copyOwnedPrefix(ctx context.Context, source string, sourceMode os.FileMode, destination string, destinationMode os.FileMode, size int64, owner Ownership) error {
	in, err := openOwnedRegular(source, os.O_RDONLY, owner, sourceMode)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := openOwnedRegular(destination, os.O_RDWR, owner, destinationMode)
	if err != nil {
		return err
	}
	defer out.Close()
	buffer := make([]byte, copyBufferSize)
	var offset int64
	for offset < size {
		if err := contextErr(ctx); err != nil {
			return err
		}
		length := int64(len(buffer))
		if remaining := size - offset; remaining < length {
			length = remaining
		}
		n, readErr := in.ReadAt(buffer[:int(length)], offset)
		if n > 0 {
			if err := writeAtAll(out, buffer[:n], offset); err != nil {
				return err
			}
			offset += int64(n)
		}
		if readErr != nil && !(errors.Is(readErr, io.EOF) && offset == size) {
			return readErr
		}
		if n == 0 && readErr == nil {
			return io.ErrNoProgress
		}
	}
	return out.Sync()
}

func writeAtAll(file *os.File, data []byte, offset int64) error {
	for len(data) != 0 {
		n, err := file.WriteAt(data, offset)
		if n > 0 {
			offset += int64(n)
			data = data[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func validateExactFile(path string, size int64, owner Ownership, mode os.FileMode) error {
	file, err := openOwnedRegular(path, os.O_RDONLY, owner, mode)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Size() != size {
		return ErrCorruptState
	}
	return file.Sync()
}

func checksumExact(ctx context.Context, path string, size int64, owner Ownership, mode os.FileMode) (string, error) {
	parent, err := openOwnedDirectoryPath(filepath.Dir(path), owner, 0o700)
	if err != nil {
		return "", err
	}
	defer parent.file.Close()
	file, _, err := openOwnedRegularAt(parent, filepath.Base(path), unix.O_RDONLY, owner, mode)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if info.Size() != size {
		return "", ErrCorruptState
	}
	return checksumReaderAt(ctx, file, size)
}

func checksumPrefix(ctx context.Context, path string, size int64, owner Ownership, mode os.FileMode) (string, error) {
	parent, err := openOwnedDirectoryPath(filepath.Dir(path), owner, 0o700)
	if err != nil {
		return "", err
	}
	defer parent.file.Close()
	file, _, err := openOwnedRegularAt(parent, filepath.Base(path), unix.O_RDONLY, owner, mode)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if info.Size() < size {
		return "", ErrCorruptState
	}
	return checksumReaderAt(ctx, file, size)
}

func checksumReaderAt(ctx context.Context, file *os.File, size int64) (string, error) {
	hash := sha256.New()
	buffer := make([]byte, copyBufferSize)
	var offset int64
	for offset < size {
		if err := contextErr(ctx); err != nil {
			return "", err
		}
		length := int64(len(buffer))
		if remaining := size - offset; remaining < length {
			length = remaining
		}
		n, readErr := file.ReadAt(buffer[:int(length)], offset)
		if n > 0 {
			_, _ = hash.Write(buffer[:n])
			offset += int64(n)
		}
		if readErr != nil && !(errors.Is(readErr, io.EOF) && offset == size) {
			return "", readErr
		}
		if n == 0 && readErr == nil {
			return "", io.ErrNoProgress
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func writeContextAt(ctx context.Context, file *os.File, data []byte, offset int64) error {
	for len(data) != 0 {
		if err := contextErr(ctx); err != nil {
			return err
		}
		n, err := file.WriteAt(data, offset)
		if n > 0 {
			offset += int64(n)
			data = data[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return file.Sync()
}

func readContextAt(ctx context.Context, file *os.File, data []byte, offset int64) (int, error) {
	total := 0
	for total < len(data) {
		if err := contextErr(ctx); err != nil {
			return total, err
		}
		n, err := file.ReadAt(data[total:], offset+int64(total))
		total += n
		if err != nil {
			if errors.Is(err, io.EOF) && total == len(data) {
				return total, nil
			}
			return total, err
		}
		if n == 0 {
			return total, io.ErrNoProgress
		}
	}
	return total, nil
}

type fileFaultRunner struct{}

func SafeFileRunner() FaultRunner { return fileFaultRunner{} }

func (fileFaultRunner) Apply(ctx context.Context, action FaultAction) error {
	if action.Kind != FaultCorruption && action.Kind != FaultFill {
		return ErrInvalidFault
	}
	return overwriteFile(ctx, action.Path, action.Offset, action.Length, action.Pattern)
}

func overwriteFile(ctx context.Context, path string, offset, length int64, pattern byte) error {
	if offset < 0 || length <= 0 {
		return ErrInvalidFault
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || offset > info.Size()-length {
		return ErrInvalidFault
	}
	file, err := os.OpenFile(path, os.O_RDWR|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	buffer := make([]byte, copyBufferSize)
	for index := range buffer {
		buffer[index] = pattern
	}
	for length > 0 {
		if err := contextErr(ctx); err != nil {
			return err
		}
		count := min64(length, int64(len(buffer)))
		if err := writeAtAll(file, buffer[:int(count)], offset); err != nil {
			return err
		}
		offset += count
		length -= count
	}
	return file.Sync()
}

func verifyPattern(ctx context.Context, path string, corruption Corruption) error {
	file, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	buffer := make([]byte, min64(corruption.Length, copyBufferSize))
	remaining := corruption.Length
	offset := corruption.Offset
	for remaining > 0 {
		if err := contextErr(ctx); err != nil {
			return err
		}
		count := min64(remaining, int64(len(buffer)))
		if _, err := file.ReadAt(buffer[:int(count)], offset); err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		for _, value := range buffer[:int(count)] {
			if value != corruption.Pattern {
				return ErrIOFailure
			}
		}
		offset += count
		remaining -= count
	}
	return nil
}

func (s *Store) usageLocked() (Usage, error) {
	var usage Usage
	dirs, err := openStoreDirectories(s)
	if err != nil {
		return Usage{}, err
	}
	defer dirs.close()
	drives, err := readDirectoryEntries(dirs.drives)
	if err != nil {
		return Usage{}, err
	}
	for _, entry := range drives {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), stageDrivePrefix) {
			return Usage{}, fmt.Errorf("%w: unexpected drive entry %q", ErrOwnership, entry.Name())
		}
		directory, err := openOwnedDirectoryAt(dirs.drives, entry.Name(), s.owner, 0o700)
		if err != nil {
			return Usage{}, err
		}
		state, _, err := s.loadDriveDirectoryAt(directory, filepath.Join(s.drives, entry.Name()), entry.Name(), true)
		_ = directory.file.Close()
		if err != nil {
			return Usage{}, err
		}
		usage.Drives++
		if state.Size > 0 && (usage.Bytes > maxDriveSize-state.Size || usage.Bytes > s.maxBytes-state.Size) {
			return Usage{}, ErrQuotaExceeded
		}
		usage.Bytes += state.Size
	}
	snapshots, err := readDirectoryEntries(dirs.snapshots)
	if err != nil {
		return Usage{}, err
	}
	for _, entry := range snapshots {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), stageSnapshotPrefix) {
			return Usage{}, fmt.Errorf("%w: unexpected snapshot entry %q", ErrOwnership, entry.Name())
		}
		directory, err := openOwnedDirectoryAt(dirs.snapshots, entry.Name(), s.owner, 0o700)
		if err != nil {
			return Usage{}, err
		}
		snapshot, err := s.loadSnapshotDirectoryAt(directory, filepath.Join(s.snapshots, entry.Name()))
		_ = directory.file.Close()
		if err != nil {
			return Usage{}, err
		}
		if snapshot.Size > 0 && (usage.Bytes > maxDriveSize-snapshot.Size || usage.Bytes > s.maxBytes-snapshot.Size) {
			return Usage{}, ErrQuotaExceeded
		}
		usage.Bytes += snapshot.Size
		usage.Snapshots++
	}
	return usage, nil
}

func (s *Store) snapshotLocked(ctx context.Context, state diskMetadata, path string) (Snapshot, error) {
	checksum, err := checksumExact(ctx, path, state.Size, s.owner, 0o600)
	if err != nil {
		return Snapshot{}, err
	}
	id := snapshotID(s.runID, state.ID, checksum)
	dir := filepath.Join(s.snapshots, id)
	if _, err := os.Lstat(dir); err == nil {
		loaded, loadErr := s.loadSnapshotDir(dir)
		if loadErr != nil {
			return Snapshot{}, loadErr
		}
		if loaded.DriveID != state.ID || loaded.Checksum != checksum || loaded.Size != state.Size {
			return Snapshot{}, ErrCorruptSnapshot
		}
		return loaded, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return Snapshot{}, err
	}
	usage, err := s.usageLocked()
	if err != nil {
		return Snapshot{}, err
	}
	if usage.Snapshots >= s.maxSnapshots || exceedsQuota(usage.Bytes, state.Size, s.maxBytes) {
		return Snapshot{}, ErrQuotaExceeded
	}
	stageToken, err := randomID()
	if err != nil {
		return Snapshot{}, err
	}
	stageDir := filepath.Join(s.snapshots, stageSnapshotPrefix+s.runID+"-"+stageToken)
	if err := createOwnedDirectory(stageDir, s.owner); err != nil {
		return Snapshot{}, err
	}
	committed := false
	defer func() {
		if !committed {
			if err := removeOwnedTree(stageDir, s.runID, id, s.owner); err != nil {
				_ = removeUncommittedStage(stageDir, s.runID, s.owner)
			}
			_ = syncDirectory(s.snapshots)
		}
	}()
	if err := writeDriveOwner(stageDir, s.runID, id, s.owner); err != nil {
		return Snapshot{}, err
	}
	if s.hooks.beforeCopy != nil {
		if err := s.hooks.beforeCopy(path); err != nil {
			return Snapshot{}, err
		}
	}
	image := filepath.Join(stageDir, snapshotImage)
	if err := allocateImage(ctx, image, state.Size, s.owner); err != nil {
		return Snapshot{}, err
	}
	if err := copyOwnedPrefix(ctx, path, 0o600, image, 0o600, state.Size, s.owner); err != nil {
		return Snapshot{}, err
	}
	copyChecksum, err := checksumExact(ctx, image, state.Size, s.owner, 0o600)
	if err != nil {
		return Snapshot{}, err
	}
	afterChecksum, err := checksumExact(ctx, path, state.Size, s.owner, 0o600)
	if err != nil {
		return Snapshot{}, err
	}
	if copyChecksum != checksum || afterChecksum != checksum {
		return Snapshot{}, ErrDriveBusy
	}
	imageFile, err := openOwnedRegular(image, os.O_RDWR, s.owner, 0o600)
	if err != nil {
		return Snapshot{}, err
	}
	if err := imageFile.Chmod(0o400); err != nil {
		_ = imageFile.Close()
		return Snapshot{}, err
	}
	if err := imageFile.Sync(); err != nil {
		_ = imageFile.Close()
		return Snapshot{}, err
	}
	if err := imageFile.Close(); err != nil {
		return Snapshot{}, err
	}
	metadata := snapshotMetadata{Version: snapshotVersion, RunID: s.runID, ID: id, DriveID: state.ID, Size: state.Size, Checksum: checksum, Filesystem: state.Filesystem, Generation: state.Generation, CreatedAt: time.Now().UTC()}
	sealSnapshotMetadata(&metadata)
	if _, err := atomicWriteJSON(ctx, filepath.Join(stageDir, metadataName), metadata, s.owner, 0o600); err != nil {
		return Snapshot{}, err
	}
	if err := syncDirectory(stageDir); err != nil {
		return Snapshot{}, err
	}
	if err := contextErr(ctx); err != nil {
		return Snapshot{}, err
	}
	if err := unix.Renameat2(unix.AT_FDCWD, stageDir, unix.AT_FDCWD, dir, unix.RENAME_NOREPLACE); err != nil {
		return Snapshot{}, err
	}
	committed = true
	result := Snapshot{RunID: s.runID, ID: id, DriveID: state.ID, Path: filepath.Join(dir, snapshotImage), ManifestPath: filepath.Join(dir, metadataName), Size: state.Size, Checksum: checksum, Filesystem: state.Filesystem, Generation: state.Generation, CreatedAt: metadata.CreatedAt, RequiresStoppedGuest: true}
	if err := syncDirectory(s.snapshots); err != nil {
		return result, fmt.Errorf("%w: %v", ErrDurabilityUncertain, err)
	}
	return result, nil
}

func (s *Store) loadSnapshotDir(dir string) (Snapshot, error) {
	dir = filepath.Clean(dir)
	if filepath.Dir(dir) != s.snapshots || !validPathComponent(filepath.Base(dir)) {
		return Snapshot{}, ErrOutsideRoot
	}
	dirs, err := openStoreDirectories(s)
	if err != nil {
		return Snapshot{}, err
	}
	defer dirs.close()
	directory, err := openOwnedDirectoryAt(dirs.snapshots, filepath.Base(dir), s.owner, 0o700)
	if err != nil {
		return Snapshot{}, err
	}
	defer directory.file.Close()
	return s.loadSnapshotDirectoryAt(directory, dir)
}

func (s *Store) loadSnapshotDirectoryAt(directory *trustedDirectory, dir string) (Snapshot, error) {
	owner, err := readArtifactOwnerAt(directory, s.owner)
	if err != nil {
		return Snapshot{}, err
	}
	if owner.RunID != s.runID || owner.ID != filepath.Base(dir) {
		return Snapshot{}, ErrOwnership
	}
	var metadata snapshotMetadata
	if err := readStrictJSONAt(directory, metadataName, s.owner, 0o600, &metadata); err != nil {
		return Snapshot{}, fmt.Errorf("%w: snapshot metadata: %v", ErrCorruptSnapshot, err)
	}
	want := metadata.Integrity
	metadata.Integrity = ""
	filesystem, filesystemErr := normalizeFilesystem(metadata.Filesystem)
	if metadata.Version != snapshotVersion || metadata.RunID != s.runID || metadata.ID != owner.ID || validateID(metadata.DriveID) != nil || metadata.ID != snapshotID(metadata.RunID, metadata.DriveID, metadata.Checksum) || metadata.Size <= 0 || metadata.Size > maxDriveSize || metadata.Generation == 0 || metadata.CreatedAt.IsZero() || filesystemErr != nil || filesystem != metadata.Filesystem || !validDigest(metadata.Checksum) || want == "" || want != structureDigest(metadata) {
		return Snapshot{}, ErrCorruptSnapshot
	}
	metadata.Integrity = want
	image := filepath.Join(dir, snapshotImage)
	imageFile, _, err := openOwnedRegularAt(directory, snapshotImage, unix.O_RDONLY, s.owner, 0o400)
	if err != nil {
		return Snapshot{}, fmt.Errorf("%w: image: %v", ErrCorruptSnapshot, err)
	}
	defer imageFile.Close()
	imageInfo, err := imageFile.Stat()
	if err != nil || imageInfo.Size() != metadata.Size {
		return Snapshot{}, fmt.Errorf("%w: image size", ErrCorruptSnapshot)
	}
	if err := validateExactEntriesAt(directory, map[string]os.FileMode{
		ownerFileName: 0o600,
		metadataName:  0o600,
		snapshotImage: 0o400,
	}, s.owner, ""); err != nil {
		return Snapshot{}, fmt.Errorf("%w: entries: %v", ErrCorruptSnapshot, err)
	}
	checksum, err := checksumReaderAt(context.Background(), imageFile, metadata.Size)
	if err != nil || checksum != metadata.Checksum {
		return Snapshot{}, fmt.Errorf("%w: image checksum", ErrCorruptSnapshot)
	}
	return Snapshot{RunID: metadata.RunID, ID: metadata.ID, DriveID: metadata.DriveID, Path: image, ManifestPath: filepath.Join(dir, metadataName), Size: metadata.Size, Checksum: metadata.Checksum, Filesystem: metadata.Filesystem, Generation: metadata.Generation, CreatedAt: metadata.CreatedAt, RequiresStoppedGuest: true}, nil
}

func (s *Store) resolveSnapshot(source any, driveID string) (Snapshot, error) {
	var claimed Snapshot
	var dir string
	switch value := source.(type) {
	case Snapshot:
		claimed = value
	case *Snapshot:
		if value == nil {
			return Snapshot{}, ErrCorruptSnapshot
		}
		claimed = *value
	case string:
		if value == "" {
			return Snapshot{}, ErrCorruptSnapshot
		}
		path, err := filepath.Abs(value)
		if err != nil {
			return Snapshot{}, err
		}
		switch filepath.Base(path) {
		case snapshotImage, metadataName:
			dir = filepath.Dir(path)
		default:
			if info, statErr := os.Lstat(path); statErr == nil && info.IsDir() {
				dir = path
			} else {
				return Snapshot{}, ErrOutsideRoot
			}
		}
	default:
		return Snapshot{}, ErrCorruptSnapshot
	}
	if dir == "" {
		switch {
		case claimed.ID != "":
			if validateID(claimed.ID) != nil {
				return Snapshot{}, ErrCorruptSnapshot
			}
			dir = filepath.Join(s.snapshots, claimed.ID)
		case claimed.Path != "":
			path, err := filepath.Abs(claimed.Path)
			if err != nil || filepath.Base(path) != snapshotImage {
				return Snapshot{}, ErrOutsideRoot
			}
			dir = filepath.Dir(path)
		case claimed.ManifestPath != "":
			path, err := filepath.Abs(claimed.ManifestPath)
			if err != nil || filepath.Base(path) != metadataName {
				return Snapshot{}, ErrOutsideRoot
			}
			dir = filepath.Dir(path)
		default:
			return Snapshot{}, ErrCorruptSnapshot
		}
	}
	loaded, err := s.loadSnapshotDir(dir)
	if err != nil {
		return Snapshot{}, err
	}
	if loaded.DriveID != driveID || loaded.RunID != s.runID {
		return Snapshot{}, ErrOwnership
	}
	if claimed.ID != "" && claimed.ID != loaded.ID || claimed.RunID != "" && claimed.RunID != loaded.RunID || claimed.DriveID != "" && claimed.DriveID != loaded.DriveID || claimed.Path != "" && filepath.Clean(claimed.Path) != loaded.Path || claimed.ManifestPath != "" && filepath.Clean(claimed.ManifestPath) != loaded.ManifestPath || claimed.Size != 0 && claimed.Size != loaded.Size || claimed.Checksum != "" && !strings.EqualFold(claimed.Checksum, loaded.Checksum) || claimed.Generation != 0 && claimed.Generation != loaded.Generation {
		return Snapshot{}, ErrCorruptSnapshot
	}
	return loaded, nil
}

func (s *Store) stageSnapshotRestore(ctx context.Context, snapshot Snapshot, generation uint64, driveDir string) (string, error) {
	usage, err := s.usageLocked()
	if err != nil {
		return "", err
	}
	if exceedsQuota(usage.Bytes, snapshot.Size, s.maxBytes) {
		return "", ErrQuotaExceeded
	}
	path := filepath.Join(driveDir, artifactName(generation))
	if s.hooks.beforeCopy != nil {
		if err := s.hooks.beforeCopy(snapshot.Path); err != nil {
			return "", err
		}
	}
	if err := allocateImage(ctx, path, snapshot.Size, s.owner); err != nil {
		return "", err
	}
	complete := false
	defer func() {
		if !complete {
			_ = unlinkOwnedRegularPath(path, s.owner, 0o600)
			_ = syncDirectory(driveDir)
		}
	}()
	if err := copyOwnedPrefix(ctx, snapshot.Path, 0o400, path, 0o600, snapshot.Size, s.owner); err != nil {
		return "", err
	}
	if sourceChecksum, err := checksumExact(ctx, snapshot.Path, snapshot.Size, s.owner, 0o400); err != nil {
		return "", err
	} else if !strings.EqualFold(sourceChecksum, snapshot.Checksum) {
		return "", ErrCorruptSnapshot
	}
	if destinationChecksum, err := checksumExact(ctx, path, snapshot.Size, s.owner, 0o600); err != nil {
		return "", err
	} else if !strings.EqualFold(destinationChecksum, snapshot.Checksum) {
		return "", ErrCorruptSnapshot
	}
	if err := syncDirectory(driveDir); err != nil {
		return "", err
	}
	complete = true
	return path, nil
}

func removeOwnedTree(path, runID, id string, owner Ownership) error {
	return removeManagedDirectoryPath(path, runID, id, owner, true)
}

func removeUncommittedStage(path, runID string, owner Ownership) error {
	name := filepath.Base(path)
	if !strings.HasPrefix(name, stageDrivePrefix+runID+"-") && !strings.HasPrefix(name, stageSnapshotPrefix+runID+"-") {
		return ErrOwnership
	}
	_, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return removeManagedDirectoryPath(path, "", "", owner, false)
}

func validManagedFileName(name string) bool {
	return name == ownerFileName || name == metadataName || name == snapshotImage || strings.HasPrefix(name, jsonTemporaryPrefix) || validArtifactName(name)
}

func (s *Store) recoverLocked() error {
	dirs, err := openStoreDirectories(s)
	if err != nil {
		return err
	}
	defer dirs.close()
	if err := s.recoverRootEntries(dirs.root); err != nil {
		return err
	}
	if err := s.recoverDriveEntries(dirs.drives); err != nil {
		return err
	}
	return s.recoverSnapshotEntries(dirs.snapshots)
}

func (s *Store) recoverRootEntries(root *trustedDirectory) error {
	entries, err := readDirectoryEntries(root)
	if err != nil {
		return err
	}
	removed := false
	for _, entry := range entries {
		switch entry.Name() {
		case lockFileName, storeMarkerName, "drives", "snapshots":
			continue
		default:
			if !strings.HasPrefix(entry.Name(), jsonTemporaryPrefix) || entry.IsDir() {
				return fmt.Errorf("%w: unexpected store entry %q", ErrOwnership, entry.Name())
			}
			if err := unlinkOwnedRegularAt(root, entry.Name(), s.owner, 0o600); err != nil {
				return err
			}
			removed = true
		}
	}
	if removed {
		return root.file.Sync()
	}
	return nil
}

func (s *Store) recoverDriveEntries(drives *trustedDirectory) error {
	entries, err := readDirectoryEntries(drives)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			return fmt.Errorf("%w: unexpected drive entry %q", ErrOwnership, entry.Name())
		}
		if strings.HasPrefix(entry.Name(), stageDrivePrefix) {
			if !strings.HasPrefix(entry.Name(), stageDrivePrefix+s.runID+"-") {
				return ErrOwnership
			}
			if err := removeManagedDirectoryAt(drives, entry.Name(), "", "", s.owner, false); err != nil {
				return err
			}
			continue
		}
		if validateID(entry.Name()) != nil {
			return ErrOwnership
		}
		dir, err := openOwnedDirectoryAt(drives, entry.Name(), s.owner, 0o700)
		if err != nil {
			return err
		}
		path := filepath.Join(s.drives, entry.Name())
		state, _, err := s.loadDriveDirectoryAt(dir, path, entry.Name(), false)
		if err != nil {
			_ = dir.file.Close()
			return err
		}
		dirEntries, err := readDirectoryEntries(dir)
		if err != nil {
			_ = dir.file.Close()
			return err
		}
		removed := false
		for _, child := range dirEntries {
			if child.Name() == ownerFileName || child.Name() == metadataName || child.Name() == state.Artifact {
				continue
			}
			if !strings.HasPrefix(child.Name(), jsonTemporaryPrefix) && !validArtifactName(child.Name()) {
				_ = dir.file.Close()
				return ErrCorruptState
			}
			if err := unlinkOwnedRegularAt(dir, child.Name(), s.owner, 0o600); err != nil {
				_ = dir.file.Close()
				return err
			}
			removed = true
		}
		if removed {
			if err := dir.file.Sync(); err != nil {
				_ = dir.file.Close()
				return err
			}
		}
		if _, _, err := s.loadDriveDirectoryAt(dir, path, entry.Name(), true); err != nil {
			_ = dir.file.Close()
			return err
		}
		if err := dir.file.Close(); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) recoverSnapshotEntries(snapshots *trustedDirectory) error {
	entries, err := readDirectoryEntries(snapshots)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			return fmt.Errorf("%w: unexpected snapshot entry %q", ErrOwnership, entry.Name())
		}
		if strings.HasPrefix(entry.Name(), stageSnapshotPrefix) {
			if !strings.HasPrefix(entry.Name(), stageSnapshotPrefix+s.runID+"-") {
				return ErrOwnership
			}
			if err := removeManagedDirectoryAt(snapshots, entry.Name(), "", "", s.owner, false); err != nil {
				return err
			}
			continue
		}
		dir, err := openOwnedDirectoryAt(snapshots, entry.Name(), s.owner, 0o700)
		if err != nil {
			return err
		}
		path := filepath.Join(s.snapshots, entry.Name())
		if _, err := s.loadSnapshotDirectoryAt(dir, path); err != nil {
			_ = dir.file.Close()
			return err
		}
		if err := dir.file.Close(); err != nil {
			return err
		}
	}
	return nil
}

func validDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

func snapshotID(runID, driveID, checksum string) string {
	identity := sha256.Sum256([]byte(runID + "\x00" + driveID + "\x00" + checksum))
	return "snapshot-" + hex.EncodeToString(identity[:])
}
