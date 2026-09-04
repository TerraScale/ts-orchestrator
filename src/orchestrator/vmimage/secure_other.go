//go:build !linux

package vmimage

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

type secureFileMetadata struct {
	device      uint64
	inode       uint64
	links       uint64
	uid         uint32
	gid         uint32
	size        int64
	mtimeSec    int64
	mtimeNsec   int64
	ctimeSec    int64
	ctimeNsec   int64
	permissions os.FileMode
	regular     bool
	directory   bool
	special     bool
}

func secureOpenPath(path string, flags int, mode os.FileMode) (*os.File, secureFileMetadata, error) {
	if !filepath.IsAbs(path) || strings.ContainsRune(path, 0) {
		return nil, secureFileMetadata{}, errors.New("vmimage: secure path must be absolute")
	}
	if err := rejectSymlinkAncestors(filepath.Dir(path)); err != nil {
		return nil, secureFileMetadata{}, err
	}
	before, err := os.Lstat(path)
	if err != nil && flags&os.O_CREATE == 0 {
		return nil, secureFileMetadata{}, err
	}
	if err == nil && before.Mode()&os.ModeSymlink != 0 {
		return nil, secureFileMetadata{}, errors.New("vmimage: secure path is a symlink")
	}
	file, err := os.OpenFile(path, flags, mode)
	if err != nil {
		return nil, secureFileMetadata{}, err
	}
	metadata, err := secureMetadata(file)
	if err != nil {
		_ = file.Close()
		return nil, secureFileMetadata{}, err
	}
	if before != nil {
		after, statErr := file.Stat()
		if statErr != nil || !os.SameFile(before, after) {
			_ = file.Close()
			return nil, secureFileMetadata{}, errors.New("vmimage: secure path changed while opening")
		}
	}
	return file, metadata, nil
}

func secureOpenAt(directory *os.File, name string, flags int, mode os.FileMode) (*os.File, secureFileMetadata, error) {
	if directory == nil || !safeChildName(name) {
		return nil, secureFileMetadata{}, errors.New("vmimage: secure child name is invalid")
	}
	return secureOpenPath(filepath.Join(directory.Name(), name), flags, mode)
}

func secureMetadata(file *os.File) (secureFileMetadata, error) {
	info, err := file.Stat()
	if err != nil {
		return secureFileMetadata{}, err
	}
	metadata := secureFileMetadata{
		size: info.Size(), permissions: info.Mode().Perm(), regular: info.Mode().IsRegular(),
		directory: info.IsDir(), special: info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0,
		mtimeSec: info.ModTime().Unix(), mtimeNsec: int64(info.ModTime().Nanosecond()),
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		metadata.device = uint64(stat.Dev)
		metadata.inode = uint64(stat.Ino)
		metadata.links = uint64(stat.Nlink)
		metadata.uid = stat.Uid
		metadata.gid = stat.Gid
	}
	return metadata, nil
}

func safeChildName(name string) bool {
	return name != "" && name != "." && name != ".." && filepath.Base(name) == name && !strings.ContainsRune(name, 0)
}

func lockExclusive(_ *os.File) error {
	return errors.New("vmimage: cache locking requires Linux")
}

func unlockFile(_ *os.File) error { return nil }

func unlinkChild(directory *os.File, name string, directoryEntry bool) error {
	path := filepath.Join(directory.Name(), name)
	if directoryEntry {
		return os.Remove(path)
	}
	return os.Remove(path)
}

func makeDirectoryChild(directory *os.File, name string, mode os.FileMode) error {
	if directory == nil || !safeChildName(name) {
		return errors.New("vmimage: secure directory child name is invalid")
	}
	return os.Mkdir(filepath.Join(directory.Name(), name), mode)
}

func ensurePrivateTreePlatform(root, target string) error {
	return ensurePrivateTreeFallback(root, target)
}
