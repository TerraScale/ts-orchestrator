//go:build linux

package vmimage

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
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
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) || strings.ContainsRune(path, 0) {
		return nil, secureFileMetadata{}, errors.New("vmimage: secure path must be an absolute non-root path")
	}
	if path == string(filepath.Separator) {
		fd, err := unix.Open(path, flags|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, uint32(mode.Perm()))
		if err != nil {
			return nil, secureFileMetadata{}, err
		}
		file := os.NewFile(uintptr(fd), path)
		metadata, err := secureMetadata(file)
		if err != nil {
			_ = file.Close()
			return nil, secureFileMetadata{}, err
		}
		return file, metadata, nil
	}
	rootFD, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, secureFileMetadata{}, err
	}
	defer unix.Close(rootFD)
	return secureOpenAtFD(rootFD, strings.TrimPrefix(path, string(filepath.Separator)), path, flags, mode)
}

func secureOpenAt(directory *os.File, name string, flags int, mode os.FileMode) (*os.File, secureFileMetadata, error) {
	if directory == nil || !safeChildName(name) {
		return nil, secureFileMetadata{}, errors.New("vmimage: secure child name is invalid")
	}
	return secureOpenAtFD(int(directory.Fd()), name, name, flags, mode)
}

func secureOpenAtFD(directoryFD int, relative, display string, flags int, mode os.FileMode) (*os.File, secureFileMetadata, error) {
	how := &unix.OpenHow{
		Flags: uint64(flags | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK),
		Mode:  uint64(mode.Perm()),
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS |
			unix.RESOLVE_NO_SYMLINKS,
	}
	fd, err := unix.Openat2(directoryFD, relative, how)
	if err != nil {
		return nil, secureFileMetadata{}, err
	}
	file := os.NewFile(uintptr(fd), display)
	metadata, err := secureMetadata(file)
	if err != nil {
		_ = file.Close()
		return nil, secureFileMetadata{}, err
	}
	return file, metadata, nil
}

func secureMetadata(file *os.File) (secureFileMetadata, error) {
	var stat unix.Stat_t
	if file == nil {
		return secureFileMetadata{}, errors.New("vmimage: secure file is nil")
	}
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return secureFileMetadata{}, err
	}
	typeBits := stat.Mode & unix.S_IFMT
	return secureFileMetadata{
		device:      uint64(stat.Dev),
		inode:       stat.Ino,
		links:       uint64(stat.Nlink),
		uid:         stat.Uid,
		gid:         stat.Gid,
		size:        stat.Size,
		mtimeSec:    stat.Mtim.Sec,
		mtimeNsec:   stat.Mtim.Nsec,
		ctimeSec:    stat.Ctim.Sec,
		ctimeNsec:   stat.Ctim.Nsec,
		permissions: os.FileMode(stat.Mode & 0o777),
		regular:     typeBits == unix.S_IFREG,
		directory:   typeBits == unix.S_IFDIR,
		special:     stat.Mode&(unix.S_ISUID|unix.S_ISGID|unix.S_ISVTX) != 0,
	}, nil
}

func safeChildName(name string) bool {
	return name != "" && name != "." && name != ".." && filepath.Base(name) == name && !strings.ContainsRune(name, 0)
}

func lockExclusive(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_EX)
}

func unlockFile(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_UN)
}

func unlinkChild(directory *os.File, name string, directoryEntry bool) error {
	flags := 0
	if directoryEntry {
		flags = unix.AT_REMOVEDIR
	}
	return unix.Unlinkat(int(directory.Fd()), name, flags)
}

func makeDirectoryChild(directory *os.File, name string, mode os.FileMode) error {
	if directory == nil || !safeChildName(name) {
		return errors.New("vmimage: secure directory child name is invalid")
	}
	return unix.Mkdirat(int(directory.Fd()), name, uint32(mode.Perm()))
}

func ensurePrivateTreePlatform(root, target string) error {
	rootParts := strings.Split(strings.TrimPrefix(root, string(filepath.Separator)), string(filepath.Separator))
	targetParts := strings.Split(strings.TrimPrefix(target, string(filepath.Separator)), string(filepath.Separator))
	if len(rootParts) == 0 || len(targetParts) < len(rootParts) {
		return errors.New("vmimage: private directory path is invalid")
	}
	current, _, err := secureOpenPath(string(filepath.Separator), os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer func() { _ = current.Close() }()
	var cacheDevice uint64
	for index, element := range targetParts {
		if !safeChildName(element) {
			return errors.New("vmimage: private directory contains an unsafe component")
		}
		child, childMetadata, openErr := secureOpenAt(current, element, os.O_RDONLY, 0)
		created := false
		if errors.Is(openErr, os.ErrNotExist) {
			if err := makeDirectoryChild(current, element, 0o700); err != nil {
				return fmt.Errorf("vmimage: create private directory: %w", err)
			}
			created = true
			child, childMetadata, openErr = secureOpenAt(current, element, os.O_RDONLY, 0)
		}
		if openErr != nil {
			return fmt.Errorf("vmimage: open private directory: %w", openErr)
		}
		if !childMetadata.directory {
			_ = child.Close()
			return errors.New("vmimage: private path component is not a directory")
		}
		owned := index >= len(rootParts)-1
		if created {
			if err := child.Chmod(0o700); err != nil {
				_ = child.Close()
				return err
			}
			childMetadata, err = secureMetadata(child)
			if err != nil {
				_ = child.Close()
				return err
			}
			if err := child.Sync(); err != nil {
				_ = child.Close()
				return fmt.Errorf("vmimage: sync private directory: %w", err)
			}
			if err := current.Sync(); err != nil {
				_ = child.Close()
				return fmt.Errorf("vmimage: sync private directory parent: %w", err)
			}
		}
		if owned {
			if index == len(rootParts)-1 {
				cacheDevice = childMetadata.device
			}
			if childMetadata.special || childMetadata.permissions != 0o700 || childMetadata.uid != uint32(os.Geteuid()) || childMetadata.device != cacheDevice {
				_ = child.Close()
				return errors.New("vmimage: private directory metadata is unsafe")
			}
		}
		_ = current.Close()
		current = child
	}
	return nil
}
