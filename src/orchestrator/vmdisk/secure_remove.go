package vmdisk

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const statxIdentityMask = unix.STATX_BASIC_STATS | unix.STATX_MNT_ID

type trustedDirectory struct {
	file *os.File
	stat unix.Statx_t
}

type managedEntry struct {
	name string
	mode os.FileMode
}

type storeDirectories struct {
	parent    *trustedDirectory
	root      *trustedDirectory
	drives    *trustedDirectory
	snapshots *trustedDirectory
}

func readDirectoryEntries(dir *trustedDirectory) ([]os.DirEntry, error) {
	if _, err := dir.file.Seek(0, 0); err != nil {
		return nil, err
	}
	return dir.file.ReadDir(-1)
}

func openStoreDirectories(store *Store) (*storeDirectories, error) {
	parent, err := openDirectoryPath(filepath.Dir(store.root))
	if err != nil {
		return nil, err
	}
	closeAll := func(root, drives, snapshots *trustedDirectory) {
		if snapshots != nil {
			_ = snapshots.file.Close()
		}
		if drives != nil {
			_ = drives.file.Close()
		}
		if root != nil {
			_ = root.file.Close()
		}
		_ = parent.file.Close()
	}
	root, err := openOwnedDirectoryAt(parent, filepath.Base(store.root), store.owner, 0o700)
	if err != nil {
		closeAll(nil, nil, nil)
		return nil, err
	}
	marker, err := loadStoreMarkerAt(root, store.owner)
	if err != nil || marker.RunID != store.runID {
		closeAll(root, nil, nil)
		return nil, ErrOwnership
	}
	lock, lockStat, err := openOwnedRegularAt(root, lockFileName, unix.O_RDONLY, store.owner, 0o600)
	if err != nil {
		closeAll(root, nil, nil)
		return nil, err
	}
	_ = lock.Close()
	openedLockStat, err := statxFile(store.lockFile)
	if err != nil || !sameStatxIdentity(lockStat, openedLockStat) {
		closeAll(root, nil, nil)
		return nil, ErrOwnership
	}
	drives, err := openOwnedDirectoryAt(root, "drives", store.owner, 0o700)
	if err != nil {
		closeAll(root, nil, nil)
		return nil, err
	}
	snapshots, err := openOwnedDirectoryAt(root, "snapshots", store.owner, 0o700)
	if err != nil {
		closeAll(root, drives, nil)
		return nil, err
	}
	return &storeDirectories{parent: parent, root: root, drives: drives, snapshots: snapshots}, nil
}

func (dirs *storeDirectories) close() {
	_ = dirs.snapshots.file.Close()
	_ = dirs.drives.file.Close()
	_ = dirs.root.file.Close()
	_ = dirs.parent.file.Close()
}

func openDirectoryPath(path string) (*trustedDirectory, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, absolute, &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW),
		Resolve: unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), absolute)
	stat, err := statxFile(file)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		_ = file.Close()
		return nil, ErrOwnership
	}
	return &trustedDirectory{file: file, stat: stat}, nil
}

func openOwnedDirectoryPath(path string, owner Ownership, mode os.FileMode) (*trustedDirectory, error) {
	dir, err := openDirectoryPath(path)
	if err != nil {
		return nil, err
	}
	if err := validateStatxOwnerMode(dir.stat, owner, mode, unix.S_IFDIR, false); err != nil {
		_ = dir.file.Close()
		return nil, err
	}
	return dir, nil
}

func openOwnedDirectoryAt(parent *trustedDirectory, name string, owner Ownership, mode os.FileMode) (*trustedDirectory, error) {
	if !validPathComponent(name) {
		return nil, ErrOutsideRoot
	}
	fd, err := unix.Openat2(int(parent.file.Fd()), name, &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW),
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV,
	})
	if err != nil {
		if errors.Is(err, unix.EXDEV) {
			return nil, ErrOwnership
		}
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	stat, err := statxFile(file)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := validateStatxOwnerMode(stat, owner, mode, unix.S_IFDIR, false); err != nil {
		_ = file.Close()
		return nil, err
	}
	if stat.Mnt_id != parent.stat.Mnt_id || stat.Dev_major != parent.stat.Dev_major || stat.Dev_minor != parent.stat.Dev_minor {
		_ = file.Close()
		return nil, ErrOwnership
	}
	entry, err := statxAt(int(parent.file.Fd()), name)
	if err != nil || !sameStatxIdentity(stat, entry) {
		_ = file.Close()
		return nil, ErrOwnership
	}
	return &trustedDirectory{file: file, stat: stat}, nil
}

func openOwnedRegularAt(parent *trustedDirectory, name string, flags int, owner Ownership, mode os.FileMode) (*os.File, unix.Statx_t, error) {
	if !validPathComponent(name) {
		return nil, unix.Statx_t{}, ErrOutsideRoot
	}
	fd, err := unix.Openat2(int(parent.file.Fd()), name, &unix.OpenHow{
		Flags:   uint64(flags | unix.O_CLOEXEC | unix.O_NOFOLLOW),
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV,
	})
	if err != nil {
		if errors.Is(err, unix.EXDEV) {
			return nil, unix.Statx_t{}, ErrOwnership
		}
		return nil, unix.Statx_t{}, err
	}
	file := os.NewFile(uintptr(fd), name)
	stat, err := statxFile(file)
	if err != nil {
		_ = file.Close()
		return nil, unix.Statx_t{}, err
	}
	if err := validateStatxOwnerMode(stat, owner, mode, unix.S_IFREG, true); err != nil {
		_ = file.Close()
		return nil, unix.Statx_t{}, err
	}
	if stat.Mnt_id != parent.stat.Mnt_id || stat.Dev_major != parent.stat.Dev_major || stat.Dev_minor != parent.stat.Dev_minor {
		_ = file.Close()
		return nil, unix.Statx_t{}, ErrOwnership
	}
	entry, err := statxAt(int(parent.file.Fd()), name)
	if err != nil || !sameStatxIdentity(stat, entry) {
		_ = file.Close()
		return nil, unix.Statx_t{}, ErrOwnership
	}
	return file, stat, nil
}

func statxFile(file *os.File) (unix.Statx_t, error) {
	var stat unix.Statx_t
	if err := unix.Statx(int(file.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_NO_AUTOMOUNT, statxIdentityMask, &stat); err != nil {
		return unix.Statx_t{}, err
	}
	if stat.Mask&statxIdentityMask != statxIdentityMask {
		return unix.Statx_t{}, ErrOwnership
	}
	return stat, nil
}

func statxAt(dirFD int, name string) (unix.Statx_t, error) {
	var stat unix.Statx_t
	if err := unix.Statx(dirFD, name, unix.AT_SYMLINK_NOFOLLOW|unix.AT_NO_AUTOMOUNT, statxIdentityMask, &stat); err != nil {
		return unix.Statx_t{}, err
	}
	if stat.Mask&statxIdentityMask != statxIdentityMask {
		return unix.Statx_t{}, ErrOwnership
	}
	return stat, nil
}

func validateStatxOwnerMode(stat unix.Statx_t, owner Ownership, mode os.FileMode, fileType uint16, singleLink bool) error {
	if stat.Mode&unix.S_IFMT != fileType || stat.Mode&0o7777 != uint16(mode.Perm()) || stat.Uid != uint32(owner.UID) || stat.Gid != uint32(owner.GID) {
		return ErrOwnership
	}
	if singleLink && stat.Nlink != 1 {
		return ErrOwnership
	}
	return nil
}

func sameStatxIdentity(left, right unix.Statx_t) bool {
	return left.Ino == right.Ino && left.Mnt_id == right.Mnt_id && left.Dev_major == right.Dev_major && left.Dev_minor == right.Dev_minor && left.Mode&unix.S_IFMT == right.Mode&unix.S_IFMT
}

func validPathComponent(name string) bool {
	return name != "" && name != "." && name != ".." && filepath.Base(name) == name && !filepath.IsAbs(name)
}

func validateStoreMountLayout(root string, owner Ownership) error {
	parent, err := openDirectoryPath(filepath.Dir(root))
	if err != nil {
		return err
	}
	defer parent.file.Close()
	store, err := openOwnedDirectoryAt(parent, filepath.Base(root), owner, 0o700)
	if err != nil {
		if errors.Is(err, unix.EXDEV) {
			return ErrOwnership
		}
		return err
	}
	defer store.file.Close()
	for _, name := range []string{"drives", "snapshots"} {
		dir, err := openOwnedDirectoryAt(store, name, owner, 0o700)
		if err != nil {
			if errors.Is(err, unix.EXDEV) {
				return ErrOwnership
			}
			return err
		}
		_ = dir.file.Close()
	}
	return nil
}

func validateManagedDirectoryAt(parent *trustedDirectory, name, runID, id string, owner Ownership, requireOwner bool) error {
	dir, err := openOwnedDirectoryAt(parent, name, owner, 0o700)
	if err != nil {
		return err
	}
	defer dir.file.Close()
	_, err = inspectManagedDirectory(dir, runID, id, owner, requireOwner)
	return err
}

func removeManagedDirectoryPath(path, runID, id string, owner Ownership, requireOwner bool) error {
	parent, err := openOwnedDirectoryPath(filepath.Dir(path), owner, 0o700)
	if err != nil {
		return err
	}
	defer parent.file.Close()
	return removeManagedDirectoryAt(parent, filepath.Base(path), runID, id, owner, requireOwner)
}

func removeManagedDirectoryAt(parent *trustedDirectory, name, runID, id string, owner Ownership, requireOwner bool) error {
	dir, err := openOwnedDirectoryAt(parent, name, owner, 0o700)
	if err != nil {
		return err
	}
	defer dir.file.Close()
	names, err := inspectManagedDirectory(dir, runID, id, owner, requireOwner)
	if err != nil {
		return err
	}
	for _, child := range names {
		if child.name == ownerFileName {
			continue
		}
		if err := unlinkOwnedRegularAt(dir, child.name, owner, child.mode); err != nil {
			return err
		}
	}
	if containsManagedEntry(names, ownerFileName) {
		if err := unlinkOwnedRegularAt(dir, ownerFileName, owner, 0o600); err != nil {
			return err
		}
	}
	if err := dir.file.Sync(); err != nil {
		return err
	}
	current, err := statxAt(int(parent.file.Fd()), name)
	if err != nil || !sameStatxIdentity(dir.stat, current) {
		return ErrOwnership
	}
	if err := unix.Unlinkat(int(parent.file.Fd()), name, unix.AT_REMOVEDIR); err != nil {
		return err
	}
	return parent.file.Sync()
}

func inspectManagedDirectory(dir *trustedDirectory, runID, id string, owner Ownership, requireOwner bool) ([]managedEntry, error) {
	entries, err := readDirectoryEntries(dir)
	if err != nil {
		return nil, err
	}
	names := make([]managedEntry, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if !validManagedFileName(name) {
			return nil, ErrOwnership
		}
		mode, err := managedFileModeAt(dir, name)
		if err != nil {
			return nil, err
		}
		file, _, err := openOwnedRegularAt(dir, name, unix.O_RDONLY, owner, mode)
		if err != nil {
			return nil, err
		}
		_ = file.Close()
		names = append(names, managedEntry{name: name, mode: mode})
	}
	if requireOwner {
		record, err := readArtifactOwnerAt(dir, owner)
		if err != nil {
			return nil, err
		}
		if record.RunID != runID || record.ID != id {
			return nil, ErrOwnership
		}
	}
	return names, nil
}

func managedFileModeAt(dir *trustedDirectory, name string) (os.FileMode, error) {
	if name != snapshotImage {
		return 0o600, nil
	}
	stat, err := statxAt(int(dir.file.Fd()), name)
	if err != nil {
		return 0, err
	}
	mode := os.FileMode(stat.Mode & 0o7777)
	if mode != 0o400 && mode != 0o600 {
		return 0, ErrOwnership
	}
	return mode, nil
}

func unlinkOwnedRegularAt(parent *trustedDirectory, name string, owner Ownership, mode os.FileMode) error {
	file, opened, err := openOwnedRegularAt(parent, name, unix.O_RDONLY, owner, mode)
	if err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	current, err := statxAt(int(parent.file.Fd()), name)
	if err != nil || !sameStatxIdentity(opened, current) {
		return ErrOwnership
	}
	if err := validateStatxOwnerMode(current, owner, mode, unix.S_IFREG, true); err != nil {
		return err
	}
	return unix.Unlinkat(int(parent.file.Fd()), name, 0)
}

func unlinkOwnedRegularPath(path string, owner Ownership, mode os.FileMode) error {
	parent, err := openOwnedDirectoryPath(filepath.Dir(path), owner, 0o700)
	if err != nil {
		return err
	}
	defer parent.file.Close()
	return unlinkOwnedRegularAt(parent, filepath.Base(path), owner, mode)
}

func containsName(names []string, want string) bool {
	for _, name := range names {
		if name == want {
			return true
		}
	}
	return false
}

func containsManagedEntry(entries []managedEntry, want string) bool {
	for _, entry := range entries {
		if entry.name == want {
			return true
		}
	}
	return false
}

func removeEmptyDirectoryAt(parent *trustedDirectory, name string, owner Ownership) error {
	dir, err := openOwnedDirectoryAt(parent, name, owner, 0o700)
	if err != nil {
		return err
	}
	defer dir.file.Close()
	entries, err := readDirectoryEntries(dir)
	if err != nil || len(entries) != 0 {
		return ErrOwnership
	}
	current, err := statxAt(int(parent.file.Fd()), name)
	if err != nil || !sameStatxIdentity(dir.stat, current) {
		return ErrOwnership
	}
	if err := unix.Unlinkat(int(parent.file.Fd()), name, unix.AT_REMOVEDIR); err != nil {
		return err
	}
	return parent.file.Sync()
}

func removeEmptyOwnedDirectoryPath(path string, owner Ownership) error {
	parent, err := openOwnedDirectoryPath(filepath.Dir(path), owner, 0o700)
	if err != nil {
		return err
	}
	defer parent.file.Close()
	return removeEmptyDirectoryAt(parent, filepath.Base(path), owner)
}

func removeDetachedStore(identity StoreIdentity) error {
	identity, err := validateStoreIdentity(identity)
	if err != nil {
		return err
	}
	parent, err := openDirectoryPath(filepath.Dir(identity.Root))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer parent.file.Close()
	tombName := filepath.Base(identity.Tombstone)
	tomb, err := openOwnedDirectoryAt(parent, tombName, identity.Ownership, 0o700)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer tomb.file.Close()
	entries, err := readDirectoryEntries(tomb)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		switch entry.Name() {
		case "drives", "snapshots", storeMarkerName, lockFileName:
			names = append(names, entry.Name())
		default:
			return ErrOwnership
		}
	}
	markerPresent := containsName(names, storeMarkerName)
	if markerPresent {
		marker, err := loadStoreMarkerAt(tomb, identity.Ownership)
		if err != nil || marker.RunID != identity.RunID {
			return ErrOwnership
		}
	} else if len(names) != 0 {
		return ErrOwnership
	}
	for _, name := range []string{"drives", "snapshots"} {
		if containsName(names, name) {
			if err := removeEmptyDirectoryAt(tomb, name, identity.Ownership); err != nil {
				return err
			}
		}
	}
	if containsName(names, lockFileName) {
		if err := unlinkOwnedRegularAt(tomb, lockFileName, identity.Ownership, 0o600); err != nil {
			return err
		}
	}
	if markerPresent {
		if err := unlinkOwnedRegularAt(tomb, storeMarkerName, identity.Ownership, 0o600); err != nil {
			return err
		}
	}
	if err := tomb.file.Sync(); err != nil {
		return fmt.Errorf("%w: sync detached store: %v", ErrDurabilityUncertain, err)
	}
	current, err := statxAt(int(parent.file.Fd()), tombName)
	if err != nil || !sameStatxIdentity(tomb.stat, current) {
		return ErrOwnership
	}
	if err := unix.Unlinkat(int(parent.file.Fd()), tombName, unix.AT_REMOVEDIR); err != nil {
		return err
	}
	if err := parent.file.Sync(); err != nil {
		return fmt.Errorf("%w: remove detached store: %v", ErrDurabilityUncertain, err)
	}
	return nil
}

func renameStoreToTombstone(identity StoreIdentity, expectedLock *os.File) error {
	identity, err := validateStoreIdentity(identity)
	if err != nil {
		return err
	}
	if expectedLock == nil {
		return ErrOwnership
	}
	parent, err := openDirectoryPath(filepath.Dir(identity.Root))
	if err != nil {
		return err
	}
	defer parent.file.Close()
	rootName := filepath.Base(identity.Root)
	root, err := openOwnedDirectoryAt(parent, rootName, identity.Ownership, 0o700)
	if err != nil {
		return err
	}
	defer root.file.Close()
	entries, err := readDirectoryEntries(root)
	if err != nil || len(entries) != 4 {
		return ErrOwnership
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		switch entry.Name() {
		case "drives", "snapshots", storeMarkerName, lockFileName:
			names = append(names, entry.Name())
		default:
			return ErrOwnership
		}
	}
	marker, err := loadStoreMarkerAt(root, identity.Ownership)
	if err != nil || marker.RunID != identity.RunID {
		return ErrOwnership
	}
	lock, lockStat, err := openOwnedRegularAt(root, lockFileName, unix.O_RDONLY, identity.Ownership, 0o600)
	if err != nil {
		return err
	}
	_ = lock.Close()
	expectedLockStat, err := statxFile(expectedLock)
	if err != nil || !sameStatxIdentity(lockStat, expectedLockStat) {
		return ErrOwnership
	}
	for _, name := range []string{"drives", "snapshots"} {
		if !containsName(names, name) {
			return ErrOwnership
		}
		dir, err := openOwnedDirectoryAt(root, name, identity.Ownership, 0o700)
		if err != nil {
			return err
		}
		children, readErr := readDirectoryEntries(dir)
		_ = dir.file.Close()
		if readErr != nil || len(children) != 0 {
			return ErrOwnership
		}
	}
	tombName := filepath.Base(identity.Tombstone)
	if _, err := statxAt(int(parent.file.Fd()), tombName); err == nil {
		return ErrCleanupPending
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	current, err := statxAt(int(parent.file.Fd()), rootName)
	if err != nil || !sameStatxIdentity(root.stat, current) {
		return ErrOwnership
	}
	if err := unix.Renameat2(int(parent.file.Fd()), rootName, int(parent.file.Fd()), tombName, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	if err := parent.file.Sync(); err != nil {
		return fmt.Errorf("%w: detach store root: %v", ErrDurabilityUncertain, err)
	}
	return nil
}

func pendingDetachedStore(root string) error {
	parent, err := openDirectoryPath(filepath.Dir(root))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer parent.file.Close()
	entries, err := readDirectoryEntries(parent)
	if err != nil {
		return err
	}
	prefix := "." + filepath.Base(root) + ".vmdisk-remove-"
	for _, entry := range entries {
		if len(entry.Name()) > len(prefix) && entry.Name()[:len(prefix)] == prefix {
			return ErrCleanupPending
		}
	}
	return nil
}

func validateStoreIdentity(identity StoreIdentity) (StoreIdentity, error) {
	planned, err := PlanStoreIdentity(identity.Root, identity.RunID, identity.Ownership)
	if err != nil {
		return StoreIdentity{}, err
	}
	if identity != planned {
		return StoreIdentity{}, ErrOutsideRoot
	}
	return planned, nil
}

func readArtifactOwnerAt(dir *trustedDirectory, owner Ownership) (artifactOwner, error) {
	var record artifactOwner
	if err := readStrictJSONAt(dir, ownerFileName, owner, 0o600, &record); err != nil {
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

func loadStoreMarkerAt(dir *trustedDirectory, owner Ownership) (storeMarker, error) {
	var marker storeMarker
	if err := readStrictJSONAt(dir, storeMarkerName, owner, 0o600, &marker); err != nil {
		return storeMarker{}, err
	}
	if !validStoreMarker(marker, owner) {
		return storeMarker{}, ErrOwnership
	}
	return marker, nil
}
