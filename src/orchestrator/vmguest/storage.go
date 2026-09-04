package vmguest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	MaxInboxStorageBytes      = 128 << 20
	MaxInboxStorageFiles      = 64
	MaxPersistentStorageBytes = 32 << 20
	MaxPersistentStorageFiles = 128
	directoryOpenFlags        = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW
	storageIOChunk            = 64 << 10
	// A four-part admitted file path has at most three parent directories.
	// Deeper directories cannot contain a temporary created by this helper.
	maxStorageDirectoryDepth = 3
)

var storageWriteGate = make(chan struct{}, 1)

var errStorageDirectoryMissing = errors.New("vmguest: storage directory does not exist")

type storageCauseError struct {
	message string
	cause   error
}

func (err storageCauseError) Error() string { return err.message }

func (err storageCauseError) Unwrap() error { return err.cause }

func storageFailure(message string, cause error) error {
	if errors.Is(cause, unix.ENOSPC) || errors.Is(cause, unix.EIO) || errors.Is(cause, unix.EROFS) ||
		errors.Is(cause, unix.ENODEV) || errors.Is(cause, unix.ENOENT) {
		return storageCauseError{message: message, cause: cause}
	}
	return errors.New(message)
}

type storageQuota struct {
	maxBytes int64
	maxFiles int64
}

var (
	inboxStorageQuota      = storageQuota{maxBytes: MaxInboxStorageBytes, maxFiles: MaxInboxStorageFiles}
	persistentStorageQuota = storageQuota{maxBytes: MaxPersistentStorageBytes, maxFiles: MaxPersistentStorageFiles}
)

func atomicWrite(ctx context.Context, rootPath, relative string, data []byte, mode os.FileMode) error {
	return atomicWriteWithinQuota(ctx, rootPath, relative, data, mode, inboxStorageQuota)
}

func atomicWriteWithinQuota(ctx context.Context, rootPath, relative string, data []byte, mode os.FileMode, quota storageQuota) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if !validRelativePath(relative) || len(data) == 0 || mode.Perm() != mode || mode&^0o777 != 0 || quota.maxBytes <= 0 || quota.maxFiles <= 0 {
		return errors.New("vmguest: write parameters are invalid")
	}
	if err := acquireStorageWrite(ctx); err != nil {
		return err
	}
	defer releaseStorageWrite()
	rootFD, err := openStorageRoot(ctx, rootPath, true)
	if err != nil {
		return err
	}
	defer unix.Close(rootFD)
	rootMount, err := descriptorMountID(rootFD)
	if err != nil {
		return err
	}
	var rootStat unix.Stat_t
	if err := unix.Fstat(rootFD, &rootStat); err != nil {
		return errors.New("vmguest: inspect storage root")
	}
	if err := cleanupStorageDirectory(ctx, rootFD, rootMount, 0, true); err != nil {
		return err
	}
	usage, err := scanStorageUsage(ctx, rootFD, rootStat, rootMount, 0)
	if err != nil {
		return err
	}
	parentFD, name, err := openStorageParent(ctx, rootFD, relative, false)
	if errors.Is(err, errStorageDirectoryMissing) {
		if err := validateStorageQuota(usage, false, 0, len(data), quota); err != nil {
			return err
		}
		parentFD, name, err = openStorageParent(ctx, rootFD, relative, true)
	}
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	if err := ctx.Err(); err != nil {
		return err
	}
	targetExists := false
	var target unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &target, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		targetExists = true
		targetMount, mountErr := pathMountID(parentFD, name, unix.AT_SYMLINK_NOFOLLOW)
		if !safeStorageFile(target, rootStat, mode) || mountErr != nil || targetMount != rootMount {
			return errors.New("vmguest: write target owner, mode, links, or mount is unsafe")
		}
	} else if !errors.Is(err, unix.ENOENT) {
		return errors.New("vmguest: inspect write target")
	}
	if err := validateStorageQuota(usage, targetExists, target.Size, len(data), quota); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	temporary, file, err := createStorageTemp(ctx, parentFD, rootStat, rootMount)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = unix.Unlinkat(parentFD, temporary, 0)
		}
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := file.Chmod(mode); err != nil {
		return errors.New("vmguest: set temporary file mode")
	}
	temporaryStat, err := validateOpenedStorageFile(int(file.Fd()), rootStat, rootMount, mode)
	if err != nil {
		return err
	}
	if err := writeStorageFile(ctx, file, data); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("vmguest: write temporary file")
	}
	if err := file.Sync(); err != nil {
		return errors.New("vmguest: sync temporary file")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := unix.Renameat(parentFD, temporary, parentFD, name); err != nil {
		return errors.New("vmguest: publish file")
	}
	var published unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &published, unix.AT_SYMLINK_NOFOLLOW); err != nil || !safeStorageFile(published, rootStat, mode) || published.Dev != temporaryStat.Dev || published.Ino != temporaryStat.Ino {
		return errors.New("vmguest: verify published file")
	}
	publishedMount, err := pathMountID(parentFD, name, unix.AT_SYMLINK_NOFOLLOW)
	if err != nil || publishedMount != rootMount {
		return errors.New("vmguest: verify published file mount")
	}
	if err := unix.Fsync(parentFD); err != nil {
		return errors.New("vmguest: sync storage directory")
	}
	ok = true
	return nil
}

type storageUsage struct {
	bytes int64
	files int64
}

func validateStorageQuota(usage storageUsage, targetExists bool, targetBytes int64, replacementBytes int, quota storageQuota) error {
	files := usage.files
	bytesWithoutTarget := usage.bytes
	if targetExists {
		bytesWithoutTarget -= targetBytes
	} else {
		files++
	}
	if bytesWithoutTarget < 0 || files < 0 || files > quota.maxFiles || bytesWithoutTarget > quota.maxBytes || int64(replacementBytes) > quota.maxBytes-bytesWithoutTarget {
		return errors.New("vmguest: storage quota exceeded")
	}
	return nil
}

func scanStorageUsage(ctx context.Context, directoryFD int, rootStat unix.Stat_t, rootMount uint64, depth int) (storageUsage, error) {
	if err := ctx.Err(); err != nil {
		return storageUsage{}, err
	}
	duplicate, err := unix.Openat(directoryFD, ".", directoryOpenFlags, 0)
	if err != nil {
		return storageUsage{}, errors.New("vmguest: reopen storage directory for quota")
	}
	directory := os.NewFile(uintptr(duplicate), "vmguest-storage-quota-directory")
	if directory == nil {
		_ = unix.Close(duplicate)
		return storageUsage{}, errors.New("vmguest: wrap storage directory for quota")
	}
	defer directory.Close()
	var usage storageUsage
	for {
		if err := ctx.Err(); err != nil {
			return storageUsage{}, err
		}
		names, readErr := directory.Readdirnames(64)
		for _, name := range names {
			if err := ctx.Err(); err != nil {
				return storageUsage{}, err
			}
			var stat unix.Stat_t
			if err := unix.Fstatat(directoryFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
				continue
			} else if err != nil {
				return storageUsage{}, errors.New("vmguest: inspect storage quota entry")
			}
			if depth == 0 && name == storageFillName {
				mount, mountErr := pathMountID(directoryFD, name, unix.AT_SYMLINK_NOFOLLOW)
				if !safeStorageFile(stat, rootStat, 0o600) || mountErr != nil || mount != rootMount {
					return storageUsage{}, errors.New("vmguest: reserved storage fill file is unsafe")
				}
				continue
			}
			switch stat.Mode & unix.S_IFMT {
			case unix.S_IFDIR:
				if depth >= maxStorageDirectoryDepth {
					continue
				}
				childFD, err := unix.Openat(directoryFD, name, directoryOpenFlags, 0)
				if err != nil {
					return storageUsage{}, errors.New("vmguest: open storage quota directory")
				}
				if err := validateOwnedDirectory(childFD, rootMount); err != nil {
					_ = unix.Close(childFD)
					return storageUsage{}, err
				}
				childUsage, err := scanStorageUsage(ctx, childFD, rootStat, rootMount, depth+1)
				_ = unix.Close(childFD)
				if err != nil {
					return storageUsage{}, err
				}
				if usage.bytes > math.MaxInt64-childUsage.bytes || usage.files > math.MaxInt64-childUsage.files {
					return storageUsage{}, errors.New("vmguest: storage quota accounting overflow")
				}
				usage.bytes += childUsage.bytes
				usage.files += childUsage.files
			case unix.S_IFREG:
				mount, mountErr := pathMountID(directoryFD, name, unix.AT_SYMLINK_NOFOLLOW)
				if !safeQuotaStorageFile(stat, rootStat) || mountErr != nil || mount != rootMount {
					return storageUsage{}, errors.New("vmguest: storage quota file owner, mode, links, or mount is unsafe")
				}
				if stat.Size < 0 || usage.bytes > math.MaxInt64-stat.Size || usage.files == math.MaxInt64 {
					return storageUsage{}, errors.New("vmguest: storage quota accounting overflow")
				}
				usage.bytes += stat.Size
				usage.files++
			default:
				return storageUsage{}, errors.New("vmguest: storage quota entry is unsafe")
			}
		}
		if errors.Is(readErr, io.EOF) {
			return usage, nil
		}
		if readErr != nil {
			return storageUsage{}, errors.New("vmguest: scan storage quota")
		}
		if len(names) == 0 {
			return usage, nil
		}
	}
}

func safeQuotaStorageFile(stat, root unix.Stat_t) bool {
	mode := stat.Mode & 0o7777
	return int(stat.Uid) == os.Geteuid() &&
		(mode == 0o600 || mode == 0o644) &&
		stat.Nlink == 1 &&
		stat.Dev == root.Dev
}

func boundedRead(ctx context.Context, rootPath, relative string, limit int) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if !validRelativePath(relative) || limit <= 0 || uint64(limit) >= uint64(math.MaxInt64) {
		return nil, errors.New("vmguest: read parameters are invalid")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rootFD, err := openStorageRoot(ctx, rootPath, false)
	if err != nil {
		return nil, err
	}
	defer unix.Close(rootFD)
	parentFD, name, err := openStorageParent(ctx, rootFD, relative, false)
	if err != nil {
		return nil, err
	}
	defer unix.Close(parentFD)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var rootStat unix.Stat_t
	if err := unix.Fstat(rootFD, &rootStat); err != nil {
		return nil, errors.New("vmguest: inspect storage root")
	}
	rootMount, err := descriptorMountID(rootFD)
	if err != nil {
		return nil, err
	}
	var before unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &before, unix.AT_SYMLINK_NOFOLLOW); err != nil || !safeReadableStorageFile(before, rootStat) {
		return nil, errors.New("vmguest: read target is not a regular file")
	}
	beforeMount, err := pathMountID(parentFD, name, unix.AT_SYMLINK_NOFOLLOW)
	if err != nil || beforeMount != rootMount {
		return nil, errors.New("vmguest: read target crosses a storage mount")
	}
	if before.Size < 0 || before.Size > int64(limit) {
		return nil, errors.New("vmguest: read target exceeds the size limit")
	}
	fileFD, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("vmguest: open read target")
	}
	file := os.NewFile(uintptr(fileFD), name)
	if file == nil {
		_ = unix.Close(fileFD)
		return nil, errors.New("vmguest: wrap read target")
	}
	defer file.Close()
	after, err := validateOpenedReadableStorageFile(fileFD, rootStat, rootMount)
	if err != nil || !sameStorageFileSnapshot(before, after) {
		return nil, errors.New("vmguest: read target changed during open")
	}
	data, err := readStorageFile(ctx, file, limit)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("vmguest: read target")
	}
	if len(data) > limit {
		return nil, errors.New("vmguest: read target exceeds the size limit")
	}
	final, err := validateOpenedReadableStorageFile(fileFD, rootStat, rootMount)
	if err != nil || !sameStorageFileSnapshot(after, final) || final.Size != int64(len(data)) {
		return nil, errors.New("vmguest: read target changed while reading")
	}
	return data, nil
}

func openStorageRoot(ctx context.Context, path string, create bool) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return -1, errors.New("vmguest: storage root path is invalid")
	}
	if err := ctx.Err(); err != nil {
		return -1, err
	}
	current, err := unix.Open(string(filepath.Separator), directoryOpenFlags, 0)
	if err != nil {
		return -1, storageFailure("vmguest: open filesystem root", err)
	}
	parts := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	for index, part := range parts {
		if err := ctx.Err(); err != nil {
			_ = unix.Close(current)
			return -1, err
		}
		last := index == len(parts)-1
		next, openErr := unix.Openat(current, part, directoryOpenFlags, 0)
		if errors.Is(openErr, unix.ENOENT) && create {
			if err := validateCreateParent(current); err != nil {
				_ = unix.Close(current)
				return -1, err
			}
			if err := unix.Mkdirat(current, part, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
				_ = unix.Close(current)
				return -1, storageFailure("vmguest: create storage directory", err)
			}
			if err := unix.Fsync(current); err != nil {
				_ = unix.Close(current)
				return -1, storageFailure("vmguest: sync storage directory parent", err)
			}
			if err := ctx.Err(); err != nil {
				_ = unix.Close(current)
				return -1, err
			}
			next, openErr = unix.Openat(current, part, directoryOpenFlags, 0)
		}
		if openErr != nil {
			_ = unix.Close(current)
			return -1, storageFailure("vmguest: open storage directory", openErr)
		}
		if err := validateTraversedDirectory(next, last); err != nil {
			_ = unix.Close(next)
			_ = unix.Close(current)
			return -1, err
		}
		_ = unix.Close(current)
		current = next
	}
	if err := ctx.Err(); err != nil {
		_ = unix.Close(current)
		return -1, err
	}
	return current, nil
}

func openStorageParent(ctx context.Context, rootFD int, relative string, create bool) (int, string, error) {
	parts := strings.Split(relative, string(filepath.Separator))
	rootMount, err := descriptorMountID(rootFD)
	if err != nil {
		return -1, "", err
	}
	current, err := unix.FcntlInt(uintptr(rootFD), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return -1, "", errors.New("vmguest: duplicate storage root")
	}
	for _, part := range parts[:len(parts)-1] {
		if err := ctx.Err(); err != nil {
			_ = unix.Close(current)
			return -1, "", err
		}
		next, openErr := unix.Openat(current, part, directoryOpenFlags, 0)
		if errors.Is(openErr, unix.ENOENT) && create {
			if err := unix.Mkdirat(current, part, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
				_ = unix.Close(current)
				return -1, "", errors.New("vmguest: create storage directory")
			}
			if err := unix.Fsync(current); err != nil {
				_ = unix.Close(current)
				return -1, "", errors.New("vmguest: sync storage directory parent")
			}
			if err := ctx.Err(); err != nil {
				_ = unix.Close(current)
				return -1, "", err
			}
			next, openErr = unix.Openat(current, part, directoryOpenFlags, 0)
		}
		if errors.Is(openErr, unix.ENOENT) {
			_ = unix.Close(current)
			return -1, "", errStorageDirectoryMissing
		}
		if openErr != nil {
			_ = unix.Close(current)
			return -1, "", errors.New("vmguest: open storage directory")
		}
		if err := validateOwnedDirectory(next, rootMount); err != nil {
			_ = unix.Close(next)
			_ = unix.Close(current)
			return -1, "", err
		}
		_ = unix.Close(current)
		current = next
	}
	if err := ctx.Err(); err != nil {
		_ = unix.Close(current)
		return -1, "", err
	}
	return current, parts[len(parts)-1], nil
}

func validateTraversedDirectory(fd int, final bool) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errors.New("vmguest: storage path component is not a directory")
	}
	mode := stat.Mode & 0o7777
	if final {
		if int(stat.Uid) != os.Geteuid() || mode&0o022 != 0 {
			return errors.New("vmguest: storage root owner or mode is unsafe")
		}
		return nil
	}
	if int(stat.Uid) != 0 && int(stat.Uid) != os.Geteuid() {
		return errors.New("vmguest: storage ancestor owner is unsafe")
	}
	if mode&0o022 != 0 && !(stat.Uid == 0 && mode&unix.S_ISVTX != 0) {
		return errors.New("vmguest: storage ancestor mode is unsafe")
	}
	return nil
}

func validateCreateParent(fd int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || int(stat.Uid) != os.Geteuid() || stat.Mode&0o022 != 0 {
		return errors.New("vmguest: storage directory parent is unsafe for creation")
	}
	return nil
}

func validateOwnedDirectory(fd int, rootMount uint64) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || int(stat.Uid) != os.Geteuid() || stat.Mode&0o022 != 0 {
		return errors.New("vmguest: storage directory owner or mode is unsafe")
	}
	mount, err := descriptorMountID(fd)
	if err != nil || mount != rootMount {
		return errors.New("vmguest: storage directory crosses a nested mount")
	}
	return nil
}

func safeStorageFile(stat, root unix.Stat_t, mode os.FileMode) bool {
	return stat.Mode&unix.S_IFMT == unix.S_IFREG &&
		int(stat.Uid) == os.Geteuid() &&
		stat.Mode&0o7777 == uint32(mode.Perm()) &&
		stat.Nlink == 1 &&
		stat.Dev == root.Dev
}

func safeReadableStorageFile(stat, root unix.Stat_t) bool {
	return stat.Mode&unix.S_IFMT == unix.S_IFREG &&
		int(stat.Uid) == os.Geteuid() &&
		stat.Mode&0o7777 == 0o600 &&
		stat.Nlink == 1 &&
		stat.Dev == root.Dev
}

func validateOpenedStorageFile(fd int, root unix.Stat_t, rootMount uint64, mode os.FileMode) (unix.Stat_t, error) {
	var stat unix.Stat_t
	mount, mountErr := descriptorMountID(fd)
	if err := unix.Fstat(fd, &stat); err != nil {
		return unix.Stat_t{}, storageFailure("vmguest: inspect opened storage file", err)
	}
	if mountErr != nil {
		return unix.Stat_t{}, mountErr
	}
	if !safeStorageFile(stat, root, mode) || mount != rootMount {
		return unix.Stat_t{}, errors.New("vmguest: opened storage file owner, mode, links, or mount is unsafe")
	}
	return stat, nil
}

func validateOpenedReadableStorageFile(fd int, root unix.Stat_t, rootMount uint64) (unix.Stat_t, error) {
	var stat unix.Stat_t
	mount, mountErr := descriptorMountID(fd)
	if err := unix.Fstat(fd, &stat); err != nil || !safeReadableStorageFile(stat, root) || mountErr != nil || mount != rootMount {
		return unix.Stat_t{}, errors.New("vmguest: opened read target owner, mode, links, or mount is unsafe")
	}
	return stat, nil
}

func sameStorageFileSnapshot(first, second unix.Stat_t) bool {
	return first.Dev == second.Dev &&
		first.Ino == second.Ino &&
		first.Size == second.Size &&
		first.Mtim.Sec == second.Mtim.Sec &&
		first.Mtim.Nsec == second.Mtim.Nsec &&
		first.Ctim.Sec == second.Ctim.Sec &&
		first.Ctim.Nsec == second.Ctim.Nsec
}

func descriptorMountID(fd int) (uint64, error) {
	return pathMountID(fd, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
}

func pathMountID(directoryFD int, path string, flags int) (uint64, error) {
	var stat unix.Statx_t
	if err := unix.Statx(directoryFD, path, flags, unix.STATX_MNT_ID, &stat); err != nil {
		return 0, storageFailure("vmguest: inspect storage mount", err)
	}
	if stat.Mask&unix.STATX_MNT_ID == 0 {
		return 0, errors.New("vmguest: inspect storage mount")
	}
	return stat.Mnt_id, nil
}

func acquireStorageWrite(ctx context.Context) error {
	select {
	case storageWriteGate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func releaseStorageWrite() { <-storageWriteGate }

func writeStorageFile(ctx context.Context, file *os.File, data []byte) error {
	for len(data) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		chunk := data
		if len(chunk) > storageIOChunk {
			chunk = chunk[:storageIOChunk]
		}
		written, err := file.Write(chunk)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return ctx.Err()
}

func readStorageFile(ctx context.Context, file *os.File, limit int) ([]byte, error) {
	data := make([]byte, 0, min(limit+1, storageIOChunk))
	buffer := make([]byte, min(limit+1, storageIOChunk))
	for len(data) <= limit {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		remaining := limit + 1 - len(data)
		readBuffer := buffer
		if len(readBuffer) > remaining {
			readBuffer = readBuffer[:remaining]
		}
		read, err := file.Read(readBuffer)
		if read > 0 {
			data = append(data, readBuffer[:read]...)
		}
		if errors.Is(err, io.EOF) {
			return data, ctx.Err()
		}
		if err != nil {
			return nil, err
		}
		if read == 0 {
			return nil, io.ErrNoProgress
		}
	}
	return data, nil
}

func createStorageTemp(ctx context.Context, parentFD int, rootStat unix.Stat_t, rootMount uint64) (string, *os.File, error) {
	for range 10 {
		if err := ctx.Err(); err != nil {
			return "", nil, err
		}
		random := make([]byte, 16)
		if _, err := rand.Read(random); err != nil {
			return "", nil, errors.New("vmguest: generate temporary file name")
		}
		name := ".vmguest-write-" + hex.EncodeToString(random)
		fd, err := unix.Openat(parentFD, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
		if err == nil {
			file := os.NewFile(uintptr(fd), name)
			if file == nil {
				_ = unix.Close(fd)
				return "", nil, errors.New("vmguest: wrap temporary file")
			}
			if _, err := validateOpenedStorageFile(fd, rootStat, rootMount, 0o600); err != nil {
				_ = file.Close()
				_ = unix.Unlinkat(parentFD, name, 0)
				return "", nil, err
			}
			return name, file, nil
		}
		if !errors.Is(err, unix.EEXIST) {
			return "", nil, errors.New("vmguest: create temporary file")
		}
	}
	return "", nil, errors.New("vmguest: allocate temporary file name")
}

func cleanupStorageRoot(ctx context.Context, rootPath string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, err := os.Lstat(rootPath); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return errors.New("vmguest: inspect storage root for cleanup")
	}
	if err := acquireStorageWrite(ctx); err != nil {
		return err
	}
	defer releaseStorageWrite()
	rootFD, err := openStorageRoot(ctx, rootPath, false)
	if err != nil {
		return err
	}
	defer unix.Close(rootFD)
	rootMount, err := descriptorMountID(rootFD)
	if err != nil {
		return err
	}
	return cleanupStorageDirectory(ctx, rootFD, rootMount, 0, true)
}

func cleanupStorageTemps(ctx context.Context, parentFD int, rootMount uint64) error {
	return cleanupStorageDirectory(ctx, parentFD, rootMount, maxStorageDirectoryDepth, false)
}

func cleanupStorageDirectory(ctx context.Context, parentFD int, rootMount uint64, depth int, recurse bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	fd, err := unix.Openat(parentFD, ".", directoryOpenFlags, 0)
	if err != nil {
		return errors.New("vmguest: reopen storage directory for cleanup")
	}
	directory := os.NewFile(uintptr(fd), "vmguest-storage-directory")
	if directory == nil {
		_ = unix.Close(fd)
		return errors.New("vmguest: wrap storage directory for cleanup")
	}
	defer directory.Close()
	removed := false
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		names, readErr := directory.Readdirnames(64)
		for _, name := range names {
			if err := ctx.Err(); err != nil {
				return err
			}
			if isStorageTemp(name) {
				if err := unix.Unlinkat(parentFD, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
					return errors.New("vmguest: remove stale temporary file")
				}
				removed = true
				continue
			}
			if !recurse {
				continue
			}
			var stat unix.Stat_t
			if err := unix.Fstatat(parentFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
				continue
			} else if err != nil {
				return errors.New("vmguest: inspect storage cleanup entry")
			}
			if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
				continue
			}
			if depth >= maxStorageDirectoryDepth {
				continue
			}
			childFD, err := unix.Openat(parentFD, name, directoryOpenFlags, 0)
			if err != nil {
				return errors.New("vmguest: open storage cleanup directory")
			}
			if err := validateOwnedDirectory(childFD, rootMount); err != nil {
				_ = unix.Close(childFD)
				return err
			}
			if err := cleanupStorageDirectory(ctx, childFD, rootMount, depth+1, true); err != nil {
				_ = unix.Close(childFD)
				return err
			}
			_ = unix.Close(childFD)
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return errors.New("vmguest: scan stale temporary files")
		}
		if len(names) == 0 {
			break
		}
	}
	if removed {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := unix.Fsync(parentFD); err != nil {
			return errors.New("vmguest: sync stale temporary cleanup")
		}
	}
	return ctx.Err()
}

func isStorageTemp(name string) bool {
	const prefix = ".vmguest-write-"
	if !strings.HasPrefix(name, prefix) || len(name) != len(prefix)+32 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(name, prefix))
	return err == nil
}
