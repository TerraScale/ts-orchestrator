package vmguest

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

const directoryOpenFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW

var storageWriteMu sync.Mutex

func atomicWrite(rootPath, relative string, data []byte, mode os.FileMode) error {
	if !validRelativePath(relative) || len(data) == 0 || mode.Perm() != mode || mode&^0o777 != 0 {
		return errors.New("vmguest: write parameters are invalid")
	}
	storageWriteMu.Lock()
	defer storageWriteMu.Unlock()
	rootFD, err := openStorageRoot(rootPath, true)
	if err != nil {
		return err
	}
	defer unix.Close(rootFD)
	parentFD, name, err := openStorageParent(rootFD, relative, true)
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	if err := cleanupStorageTemps(parentFD); err != nil {
		return err
	}
	var target unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &target, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		if target.Mode&unix.S_IFMT != unix.S_IFREG {
			return errors.New("vmguest: write target is not a regular file")
		}
	} else if !errors.Is(err, unix.ENOENT) {
		return errors.New("vmguest: inspect write target")
	}
	temporary, file, err := createStorageTemp(parentFD)
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
	if err := file.Chmod(mode); err != nil {
		return errors.New("vmguest: set temporary file mode")
	}
	if _, err := file.Write(data); err != nil {
		return errors.New("vmguest: write temporary file")
	}
	if err := file.Sync(); err != nil {
		return errors.New("vmguest: sync temporary file")
	}
	if err := file.Close(); err != nil {
		return errors.New("vmguest: close temporary file")
	}
	if err := unix.Renameat(parentFD, temporary, parentFD, name); err != nil {
		return errors.New("vmguest: publish file")
	}
	if err := unix.Fsync(parentFD); err != nil {
		return errors.New("vmguest: sync storage directory")
	}
	ok = true
	return nil
}

func boundedRead(rootPath, relative string, limit int) ([]byte, error) {
	if !validRelativePath(relative) || limit <= 0 || uint64(limit) >= uint64(math.MaxInt64) {
		return nil, errors.New("vmguest: read parameters are invalid")
	}
	rootFD, err := openStorageRoot(rootPath, false)
	if err != nil {
		return nil, err
	}
	defer unix.Close(rootFD)
	parentFD, name, err := openStorageParent(rootFD, relative, false)
	if err != nil {
		return nil, err
	}
	defer unix.Close(parentFD)
	var before unix.Stat_t
	var rootStat unix.Stat_t
	if err := unix.Fstat(rootFD, &rootStat); err != nil {
		return nil, errors.New("vmguest: inspect storage root")
	}
	if err := unix.Fstatat(parentFD, name, &before, unix.AT_SYMLINK_NOFOLLOW); err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || int(before.Uid) != os.Geteuid() || before.Mode&0o077 != 0 || before.Nlink != 1 || before.Dev != rootStat.Dev {
		return nil, errors.New("vmguest: read target is not a regular file")
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
	var after unix.Stat_t
	if err := unix.Fstat(fileFD, &after); err != nil || after.Mode&unix.S_IFMT != unix.S_IFREG || before.Dev != after.Dev || before.Ino != after.Ino {
		return nil, errors.New("vmguest: read target changed during open")
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return nil, errors.New("vmguest: read target")
	}
	if len(data) > limit {
		return nil, errors.New("vmguest: read target exceeds the size limit")
	}
	return data, nil
}

func openStorageRoot(path string, create bool) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return -1, errors.New("vmguest: storage root path is invalid")
	}
	current, err := unix.Open(string(filepath.Separator), directoryOpenFlags, 0)
	if err != nil {
		return -1, errors.New("vmguest: open filesystem root")
	}
	parts := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	for index, part := range parts {
		last := index == len(parts)-1
		next, openErr := unix.Openat(current, part, directoryOpenFlags, 0)
		if errors.Is(openErr, unix.ENOENT) && create {
			if err := validateCreateParent(current); err != nil {
				_ = unix.Close(current)
				return -1, err
			}
			if err := unix.Mkdirat(current, part, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
				_ = unix.Close(current)
				return -1, errors.New("vmguest: create storage directory")
			}
			if err := unix.Fsync(current); err != nil {
				_ = unix.Close(current)
				return -1, errors.New("vmguest: sync storage directory parent")
			}
			next, openErr = unix.Openat(current, part, directoryOpenFlags, 0)
		}
		if openErr != nil {
			_ = unix.Close(current)
			return -1, errors.New("vmguest: open storage directory")
		}
		if err := validateTraversedDirectory(next, last); err != nil {
			_ = unix.Close(next)
			_ = unix.Close(current)
			return -1, err
		}
		_ = unix.Close(current)
		current = next
	}
	return current, nil
}

func openStorageParent(rootFD int, relative string, create bool) (int, string, error) {
	parts := strings.Split(relative, string(filepath.Separator))
	current, err := unix.FcntlInt(uintptr(rootFD), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return -1, "", errors.New("vmguest: duplicate storage root")
	}
	for _, part := range parts[:len(parts)-1] {
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
			next, openErr = unix.Openat(current, part, directoryOpenFlags, 0)
		}
		if openErr != nil {
			_ = unix.Close(current)
			return -1, "", errors.New("vmguest: open storage directory")
		}
		if err := validateOwnedDirectory(next); err != nil {
			_ = unix.Close(next)
			_ = unix.Close(current)
			return -1, "", err
		}
		_ = unix.Close(current)
		current = next
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

func validateOwnedDirectory(fd int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || int(stat.Uid) != os.Geteuid() || stat.Mode&0o022 != 0 {
		return errors.New("vmguest: storage directory owner or mode is unsafe")
	}
	return nil
}

func createStorageTemp(parentFD int) (string, *os.File, error) {
	for range 10 {
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
			return name, file, nil
		}
		if !errors.Is(err, unix.EEXIST) {
			return "", nil, errors.New("vmguest: create temporary file")
		}
	}
	return "", nil, errors.New("vmguest: allocate temporary file name")
}

func cleanupStorageTemps(parentFD int) error {
	fd, err := unix.FcntlInt(uintptr(parentFD), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return errors.New("vmguest: duplicate storage directory for cleanup")
	}
	directory := os.NewFile(uintptr(fd), "vmguest-storage-directory")
	if directory == nil {
		_ = unix.Close(fd)
		return errors.New("vmguest: wrap storage directory for cleanup")
	}
	defer directory.Close()
	removed := false
	for scanned := 0; scanned < 4096; {
		names, readErr := directory.Readdirnames(64)
		for _, name := range names {
			scanned++
			if !isStorageTemp(name) {
				continue
			}
			if err := unix.Unlinkat(parentFD, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
				return errors.New("vmguest: remove stale temporary file")
			}
			removed = true
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
		if err := unix.Fsync(parentFD); err != nil {
			return errors.New("vmguest: sync stale temporary cleanup")
		}
	}
	return nil
}

func isStorageTemp(name string) bool {
	const prefix = ".vmguest-write-"
	if !strings.HasPrefix(name, prefix) || len(name) != len(prefix)+32 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(name, prefix))
	return err == nil
}
