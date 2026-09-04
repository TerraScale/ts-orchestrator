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
	if owner.UID < 0 || owner.GID < 0 {
		return nil, fmt.Errorf("%w: negative owner", ErrInvalidRoot)
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
		if _, err := atomicWriteJSON(context.Background(), markerPath, marker, owner, 0o600); err != nil {
			_ = lockFile.Close()
			return nil, err
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
	s.mu.Lock()
	if err := unix.Flock(int(s.lockFile.Fd()), unix.LOCK_EX); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	if err := contextErr(ctx); err != nil {
		_ = unix.Flock(int(s.lockFile.Fd()), unix.LOCK_UN)
		s.mu.Unlock()
		return nil, err
	}
	return func() {
		_ = unix.Flock(int(s.lockFile.Fd()), unix.LOCK_UN)
		s.mu.Unlock()
	}, nil
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
	if err := applyOwnershipAndMode(path, owner, 0o700); err != nil {
		return false, fmt.Errorf("%w: %v", ErrInvalidRoot, err)
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
		_ = os.Remove(path)
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
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, mode)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, pathInfo) {
		_ = file.Close()
		return nil, ErrOwnership
	}
	if err := applyFileOwnershipAndMode(file, info, owner, mode); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
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
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return nil, ErrOutsideRoot
	}
	if err := validateOwnerMode(before, owner, mode); err != nil {
		return nil, err
	}
	beforeStat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || beforeStat.Nlink != 1 {
		return nil, ErrOwnership
	}
	file, err := os.OpenFile(path, flags, 0)
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() {
		_ = file.Close()
		return nil, ErrOutsideRoot
	}
	afterStat, ok := after.Sys().(*syscall.Stat_t)
	if !ok || afterStat.Nlink != 1 {
		_ = file.Close()
		return nil, ErrOwnership
	}
	return file, nil
}

func syncDirectory(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
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
			_ = os.Remove(temporary)
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
	return s.loadDriveDirectory(s.driveDir(id), id, true)
}

func (s *Store) loadDriveDirectory(dir, id string, strictEntries bool) (diskMetadata, string, error) {
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return diskMetadata{}, "", ErrNotFound
	}
	if err != nil {
		return diskMetadata{}, "", err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return diskMetadata{}, "", ErrOwnership
	}
	if err := validateOwnerMode(info, s.owner, 0o700); err != nil {
		return diskMetadata{}, "", err
	}
	owner, err := readArtifactOwner(dir, s.owner)
	if err != nil {
		return diskMetadata{}, "", err
	}
	if owner.RunID != s.runID || owner.ID != id {
		return diskMetadata{}, "", ErrOwnership
	}
	var metadata diskMetadata
	if err := readStrictJSON(filepath.Join(dir, metadataName), s.owner, 0o600, &metadata); err != nil {
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
	if err := validateDiskMetadataValue(metadata, path, s.owner); err != nil {
		return diskMetadata{}, "", err
	}
	if strictEntries {
		if err := validateExactEntries(dir, map[string]os.FileMode{
			ownerFileName:     0o600,
			metadataName:      0o600,
			metadata.Artifact: 0o600,
		}, s.owner); err != nil {
			return diskMetadata{}, "", err
		}
	}
	return metadata, path, nil
}

func validateDiskMetadataValue(metadata diskMetadata, path string, owner Ownership) error {
	if metadata.Version != metadataVersion || metadata.Generation == 0 || !validArtifactName(metadata.Artifact) || metadata.UpdatedAt.IsZero() {
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

func validTransition(transition Transition, size int64) bool {
	switch transition.Kind {
	case TransitionCreate, TransitionAttach, TransitionDetach, TransitionFault, TransitionClearFault, TransitionExpand, TransitionCorrupt, TransitionWrite, TransitionRestore:
	default:
		return false
	}
	if transition.PreviousSize < 0 || transition.PreviousSize > maxDriveSize || (transition.Kind == TransitionExpand && (transition.PreviousSize <= 0 || transition.PreviousSize >= size)) {
		return false
	}
	if transition.SnapshotID != "" && validateID(transition.SnapshotID) != nil {
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
	return strings.HasPrefix(name, "artifact-") && strings.HasSuffix(name, ".img") && validateID(name) == nil
}

func validateExactEntries(dir string, expected map[string]os.FileMode, owner Ownership) error {
	entries, err := os.ReadDir(dir)
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
		info, err := os.Lstat(filepath.Join(dir, entry.Name()))
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return ErrCorruptState
		}
		if err := validateOwnerMode(info, owner, mode); err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Nlink != 1 {
			return ErrOwnership
		}
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
			_ = os.Remove(path)
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
	if s.hooks.beforeCopy != nil {
		if err := s.hooks.beforeCopy(source); err != nil {
			return "", err
		}
	}
	before, err := checksumExact(ctx, source, state.Size)
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
			_ = os.Remove(destination)
			_ = syncDirectory(filepath.Dir(destination))
		}
	}()
	if err := copyOwnedPrefix(ctx, source, 0o600, destination, 0o600, state.Size, s.owner); err != nil {
		return "", err
	}
	copied, err := checksumPrefix(ctx, destination, state.Size)
	if err != nil {
		return "", err
	}
	after, err := checksumExact(ctx, source, state.Size)
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
		_ = os.Remove(newPath)
		return ErrOutsideRoot
	}
	next.Artifact = filepath.Base(newPath)
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(newPath)
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
		if err := os.Remove(oldPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := syncDirectory(filepath.Dir(oldPath)); err != nil {
			return err
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

func checksumExact(ctx context.Context, path string, size int64) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() != size {
		return "", ErrCorruptState
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return "", ErrOwnership
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(info, after) {
		return "", ErrOutsideRoot
	}
	return checksumReaderAt(ctx, file, size)
}

func checksumPrefix(ctx context.Context, path string, size int64) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < size {
		return "", ErrCorruptState
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
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
	file, err := os.OpenFile(path, os.O_RDWR, 0)
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
	file, err := os.Open(path)
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
	drives, err := os.ReadDir(s.drives)
	if err != nil {
		return Usage{}, err
	}
	for _, entry := range drives {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), stageDrivePrefix) {
			return Usage{}, fmt.Errorf("%w: unexpected drive entry %q", ErrOwnership, entry.Name())
		}
		state, _, err := s.loadMetadata(entry.Name())
		if err != nil {
			return Usage{}, err
		}
		usage.Drives++
		if state.Size > 0 && (usage.Bytes > maxDriveSize-state.Size || usage.Bytes > s.maxBytes-state.Size) {
			return Usage{}, ErrQuotaExceeded
		}
		usage.Bytes += state.Size
	}
	snapshots, err := os.ReadDir(s.snapshots)
	if err != nil {
		return Usage{}, err
	}
	for _, entry := range snapshots {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), stageSnapshotPrefix) {
			return Usage{}, fmt.Errorf("%w: unexpected snapshot entry %q", ErrOwnership, entry.Name())
		}
		snapshot, err := s.loadSnapshotDir(filepath.Join(s.snapshots, entry.Name()))
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
	checksum, err := checksumExact(ctx, path, state.Size)
	if err != nil {
		return Snapshot{}, err
	}
	identity := sha256.Sum256([]byte(s.runID + "\x00" + state.ID + "\x00" + checksum))
	id := "snapshot-" + hex.EncodeToString(identity[:])
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
	copyChecksum, err := checksumExact(ctx, image, state.Size)
	if err != nil {
		return Snapshot{}, err
	}
	afterChecksum, err := checksumExact(ctx, path, state.Size)
	if err != nil {
		return Snapshot{}, err
	}
	if copyChecksum != checksum || afterChecksum != checksum {
		return Snapshot{}, ErrDriveBusy
	}
	if err := os.Chmod(image, 0o400); err != nil {
		return Snapshot{}, err
	}
	imageFile, err := openOwnedRegular(image, os.O_RDONLY, s.owner, 0o400)
	if err != nil {
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
	if err := os.Rename(stageDir, dir); err != nil {
		return Snapshot{}, err
	}
	committed = true
	result := Snapshot{RunID: s.runID, ID: id, DriveID: state.ID, Path: filepath.Join(dir, snapshotImage), ManifestPath: filepath.Join(dir, metadataName), Size: state.Size, Checksum: checksum, Filesystem: state.Filesystem, Generation: state.Generation, CreatedAt: metadata.CreatedAt, RequiresStoppedGuest: true}
	if err := syncDirectory(s.snapshots); err != nil {
		return result, fmt.Errorf("%w: %v", ErrDurabilityUncertain, err)
	}
	return result, nil
}

// removeUncommittedStage is used only for a stage directory whose ownership
// record was written before the final rename. It refuses every path that is
// not a direct, labelled child of the snapshots directory.
func removeUncommittedStageV2(path string, owner Ownership) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !strings.HasPrefix(filepath.Base(path), stageSnapshotPrefix) {
		return ErrOwnership
	}
	if _, err := readArtifactOwner(path, owner); err != nil {
		return err
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		child := filepath.Join(path, entry.Name())
		childInfo, err := os.Lstat(child)
		if err != nil {
			return err
		}
		if !childInfo.Mode().IsRegular() || childInfo.Mode()&os.ModeSymlink != 0 {
			return ErrOwnership
		}
		if err := os.Remove(child); err != nil {
			return err
		}
	}
	return os.Remove(path)
}

func (s *Store) loadSnapshotDir(dir string) (Snapshot, error) {
	if err := ensureNoSymlinkPath(s.snapshots, dir); err != nil {
		return Snapshot{}, err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return Snapshot{}, ErrOwnership
	}
	if err := validateOwnerMode(info, s.owner, 0o700); err != nil {
		return Snapshot{}, err
	}
	owner, err := readArtifactOwner(dir, s.owner)
	if err != nil {
		return Snapshot{}, err
	}
	if owner.RunID != s.runID || owner.ID != filepath.Base(dir) {
		return Snapshot{}, ErrOwnership
	}
	var metadata snapshotMetadata
	if err := readStrictJSON(filepath.Join(dir, metadataName), s.owner, 0o600, &metadata); err != nil {
		return Snapshot{}, fmt.Errorf("%w: snapshot metadata: %v", ErrCorruptSnapshot, err)
	}
	want := metadata.Integrity
	metadata.Integrity = ""
	filesystem, filesystemErr := normalizeFilesystem(metadata.Filesystem)
	if metadata.Version != snapshotVersion || metadata.RunID != s.runID || metadata.ID != owner.ID || validateID(metadata.ID) != nil || validateID(metadata.DriveID) != nil || metadata.Size <= 0 || metadata.Size > maxDriveSize || metadata.Generation == 0 || metadata.CreatedAt.IsZero() || filesystemErr != nil || filesystem != metadata.Filesystem || !validDigest(metadata.Checksum) || want == "" || want != structureDigest(metadata) {
		return Snapshot{}, ErrCorruptSnapshot
	}
	metadata.Integrity = want
	image := filepath.Join(dir, snapshotImage)
	if err := validateExactFile(image, metadata.Size, s.owner, 0o400); err != nil {
		return Snapshot{}, fmt.Errorf("%w: image: %v", ErrCorruptSnapshot, err)
	}
	if err := validateExactEntries(dir, map[string]os.FileMode{
		ownerFileName: 0o600,
		metadataName:  0o600,
		snapshotImage: 0o400,
	}, s.owner); err != nil {
		return Snapshot{}, fmt.Errorf("%w: entries: %v", ErrCorruptSnapshot, err)
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
			_ = os.Remove(path)
			_ = syncDirectory(driveDir)
		}
	}()
	if err := copyOwnedPrefix(ctx, snapshot.Path, 0o400, path, 0o600, snapshot.Size, s.owner); err != nil {
		return "", err
	}
	if sourceChecksum, err := checksumExact(ctx, snapshot.Path, snapshot.Size); err != nil {
		return "", err
	} else if !strings.EqualFold(sourceChecksum, snapshot.Checksum) {
		return "", ErrCorruptSnapshot
	}
	if destinationChecksum, err := checksumExact(ctx, path, snapshot.Size); err != nil {
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

func verifyPatternV2(ctx context.Context, path string, corruption Corruption) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	buffer := make([]byte, min64(corruption.Length, copyBufferSize))
	for remaining, offset := corruption.Length, corruption.Offset; remaining > 0; {
		if err := contextErr(ctx); err != nil {
			return err
		}
		want := int64(len(buffer))
		if remaining < want {
			want = remaining
		}
		n, err := file.ReadAt(buffer[:want], offset)
		if err != nil && !(errors.Is(err, io.EOF) && int64(n) == want) {
			return err
		}
		for _, value := range buffer[:n] {
			if value != corruption.Pattern {
				return ErrCorruptState
			}
		}
		offset += int64(n)
		remaining -= int64(n)
	}
	return nil
}

func removeOwnedTree(path, runID, id string, owner Ownership) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrOwnership
	}
	if err := validateOwnerMode(info, owner, 0o700); err != nil {
		return err
	}
	record, err := readArtifactOwner(path, owner)
	if err != nil {
		return err
	}
	if record.RunID != runID || record.ID != id {
		return ErrOwnership
	}
	return removeVerifiedDirectory(path, owner)
}

func removeUncommittedStage(path, runID string, owner Ownership) error {
	name := filepath.Base(path)
	if !strings.HasPrefix(name, stageDrivePrefix+runID+"-") && !strings.HasPrefix(name, stageSnapshotPrefix+runID+"-") {
		return ErrOwnership
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrOwnership
	}
	if err := validateOwnerMode(info, owner, 0o700); err != nil {
		return err
	}
	return removeVerifiedDirectory(path, owner)
}

func removeVerifiedDirectory(path string, owner Ownership) error {
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	files := make([]string, 0, len(entries))
	ownerPath := ""
	for _, entry := range entries {
		if entry.IsDir() || !validManagedFileName(entry.Name()) {
			return ErrOwnership
		}
		child := filepath.Join(path, entry.Name())
		info, err := os.Lstat(child)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return ErrOwnership
		}
		mode := os.FileMode(0o600)
		if entry.Name() == snapshotImage {
			mode = info.Mode().Perm()
			if mode != 0o400 && mode != 0o600 {
				return ErrOwnership
			}
		}
		if err := validateOwnerMode(info, owner, mode); err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Nlink != 1 {
			return ErrOwnership
		}
		if entry.Name() == ownerFileName {
			ownerPath = child
		} else {
			files = append(files, child)
		}
	}
	for _, file := range files {
		if err := os.Remove(file); err != nil {
			return err
		}
	}
	if ownerPath != "" {
		if err := os.Remove(ownerPath); err != nil {
			return err
		}
	}
	if err := syncDirectory(path); err != nil {
		return err
	}
	return os.Remove(path)
}

func validManagedFileName(name string) bool {
	return name == ownerFileName || name == metadataName || name == snapshotImage || strings.HasPrefix(name, jsonTemporaryPrefix) || validArtifactName(name)
}

func ensureNoSymlinkPath(root, path string) error {
	root, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return ErrOutsideRoot
	}
	path, err = filepath.Abs(filepath.Clean(path))
	if err != nil {
		return ErrOutsideRoot
	}
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) || filepath.IsAbs(relative) {
		return ErrOutsideRoot
	}
	current := root
	for _, part := range strings.Split(relative, string(os.PathSeparator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, statErr := os.Lstat(current)
		if errors.Is(statErr, os.ErrNotExist) {
			continue
		}
		if statErr != nil {
			return statErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return ErrOutsideRoot
		}
	}
	return nil
}

func validArtifactNameV2(name string) bool {
	if !strings.HasPrefix(name, "artifact-") || !strings.HasSuffix(name, ".img") {
		return false
	}
	digits := strings.TrimSuffix(strings.TrimPrefix(name, "artifact-"), ".img")
	if len(digits) != 20 {
		return false
	}
	generation, err := strconv.ParseUint(digits, 10, 64)
	return err == nil && generation != 0
}

func (s *Store) recoverLocked() error {
	if err := s.recoverRootEntries(); err != nil {
		return err
	}
	if err := s.recoverDriveEntries(); err != nil {
		return err
	}
	return s.recoverSnapshotEntries()
}

func (s *Store) recoverRootEntries() error {
	entries, err := os.ReadDir(s.root)
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
			if err := validateRemovableFile(filepath.Join(s.root, entry.Name()), s.owner, 0o600); err != nil {
				return err
			}
			if err := os.Remove(filepath.Join(s.root, entry.Name())); err != nil {
				return err
			}
			removed = true
		}
	}
	if removed {
		return syncDirectory(s.root)
	}
	return nil
}

func (s *Store) recoverDriveEntries() error {
	entries, err := os.ReadDir(s.drives)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		path := filepath.Join(s.drives, entry.Name())
		if !entry.IsDir() {
			return fmt.Errorf("%w: unexpected drive entry %q", ErrOwnership, entry.Name())
		}
		if strings.HasPrefix(entry.Name(), stageDrivePrefix) {
			if err := removeUncommittedStage(path, s.runID, s.owner); err != nil {
				return err
			}
			if err := syncDirectory(s.drives); err != nil {
				return err
			}
			continue
		}
		if validateID(entry.Name()) != nil {
			return ErrOwnership
		}
		state, _, err := s.loadDriveDirectory(path, entry.Name(), false)
		if err != nil {
			return err
		}
		dirEntries, err := os.ReadDir(path)
		if err != nil {
			return err
		}
		removed := false
		for _, child := range dirEntries {
			if child.Name() == ownerFileName || child.Name() == metadataName || child.Name() == state.Artifact {
				continue
			}
			if !strings.HasPrefix(child.Name(), jsonTemporaryPrefix) && !validArtifactName(child.Name()) {
				return ErrCorruptState
			}
			if err := validateRemovableFile(filepath.Join(path, child.Name()), s.owner, 0o600); err != nil {
				return err
			}
			if err := os.Remove(filepath.Join(path, child.Name())); err != nil {
				return err
			}
			removed = true
		}
		if removed {
			if err := syncDirectory(path); err != nil {
				return err
			}
		}
		if _, _, err := s.loadDriveDirectory(path, entry.Name(), true); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) recoverSnapshotEntries() error {
	entries, err := os.ReadDir(s.snapshots)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		path := filepath.Join(s.snapshots, entry.Name())
		if !entry.IsDir() {
			return fmt.Errorf("%w: unexpected snapshot entry %q", ErrOwnership, entry.Name())
		}
		if strings.HasPrefix(entry.Name(), stageSnapshotPrefix) {
			if err := removeUncommittedStage(path, s.runID, s.owner); err != nil {
				return err
			}
			if err := syncDirectory(s.snapshots); err != nil {
				return err
			}
			continue
		}
		if _, err := s.loadSnapshotDir(path); err != nil {
			return err
		}
	}
	return nil
}

func validateRemovableFile(path string, owner Ownership, mode os.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return ErrOwnership
	}
	if err := validateOwnerMode(info, owner, mode); err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return ErrOwnership
	}
	return nil
}

func validDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

func readContextAtV2(ctx context.Context, file *os.File, buffer []byte, offset int64) (int, error) {
	total := 0
	for total < len(buffer) {
		if err := contextErr(ctx); err != nil {
			return total, err
		}
		n, err := file.ReadAt(buffer[total:], offset+int64(total))
		total += n
		if err != nil {
			if errors.Is(err, io.EOF) && total == len(buffer) {
				return total, nil
			}
			return total, err
		}
	}
	return total, nil
}

func writeContextAtV2(ctx context.Context, file *os.File, buffer []byte, offset int64) error {
	for len(buffer) > 0 {
		if err := contextErr(ctx); err != nil {
			return err
		}
		n, err := file.WriteAt(buffer, offset)
		if n > 0 {
			offset += int64(n)
			buffer = buffer[n:]
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

type fileFaultRunnerV2 struct{}

func (fileFaultRunnerV2) Apply(ctx context.Context, action FaultAction) error {
	if action.Kind != FaultCorruption {
		return nil
	}
	if action.Offset < 0 || action.Length <= 0 {
		return ErrInvalidFault
	}
	file, err := os.OpenFile(action.Path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	pattern := make([]byte, min64(action.Length, copyBufferSize))
	for index := range pattern {
		pattern[index] = action.Pattern
	}
	for remaining, offset := action.Length, action.Offset; remaining > 0; {
		if err := contextErr(ctx); err != nil {
			return err
		}
		count := int64(len(pattern))
		if remaining < count {
			count = remaining
		}
		if _, err := file.WriteAt(pattern[:count], offset); err != nil {
			return err
		}
		offset += count
		remaining -= count
	}
	return file.Sync()
}
