package app

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func openControllerConfigDirectory(path string) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return -1, errors.New("controller config directory must be absolute and clean")
	}
	dir, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if part == "" || part == "." || part == ".." {
			unix.Close(dir)
			return -1, errors.New("invalid controller config directory")
		}
		next, err := unix.Openat(dir, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(dir)
		if err != nil {
			return -1, err
		}
		dir = next
		var ancestor unix.Stat_t
		if err := unix.Fstat(dir, &ancestor); err != nil || ancestor.Uid != 0 || ancestor.Gid != 0 ||
			ancestor.Mode&0o777 != 0o755 {
			unix.Close(dir)
			return -1, errors.New("controller config path ancestor ownership or mode is invalid")
		}
	}
	return dir, nil
}

func readInstalledControllerFile(directory, name string, uid, gid, mode uint32, maximum int) ([]byte, error) {
	dir, err := openControllerConfigDirectory(directory)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dir)
	return readExactControllerFile(dir, name, uid, gid, mode, maximum)
}

func readExactControllerFile(dir int, name string, uid, gid, mode uint32, maximum int) ([]byte, error) {
	if name == "" || name != filepath.Base(name) || maximum <= 0 {
		return nil, errors.New("invalid controller config file name or bound")
	}
	fd, err := unix.Openat(dir, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Nlink != 1 || stat.Uid != uid || stat.Gid != gid || stat.Mode&0o777 != mode ||
		stat.Size <= 0 || stat.Size > int64(maximum) {
		return nil, errors.New("controller config file ownership, mode, or size is invalid")
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil || len(data) == 0 || len(data) > maximum {
		return nil, errors.New("controller config file exceeds bound")
	}
	var after unix.Stat_t
	if err := unix.Fstatat(dir, name, &after, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
		after.Dev != stat.Dev || after.Ino != stat.Ino || after.Size != stat.Size || len(data) != int(stat.Size) ||
		after.Mode != stat.Mode || after.Uid != stat.Uid || after.Gid != stat.Gid || after.Nlink != 1 {
		return nil, errors.New("controller config file changed while reading")
	}
	return data, nil
}

func installExactControllerFile(dir int, name string, wire []byte, uid, gid, mode uint32) error {
	if len(wire) == 0 || name == "" || name != filepath.Base(name) {
		return errors.New("invalid signed controller file")
	}
	existing, err := readExactControllerFile(dir, name, uid, gid, mode, len(wire))
	if err == nil {
		if bytes.Equal(existing, wire) {
			return nil
		}
		return fmt.Errorf("existing controller file %s differs from signed bytes", name)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect existing controller file %s: %w", name, err)
	}
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	temporary := "." + name + "." + hex.EncodeToString(nonce[:])
	fd, err := unix.Openat(dir, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, mode)
	if err != nil {
		return err
	}
	defer unix.Unlinkat(dir, temporary, 0)
	file := os.NewFile(uintptr(fd), temporary)
	if err := unix.Fchown(fd, int(uid), int(gid)); err != nil {
		file.Close()
		return err
	}
	if err := unix.Fchmod(fd, mode); err != nil {
		file.Close()
		return err
	}
	if count, err := file.Write(wire); err != nil || count != len(wire) {
		file.Close()
		if err != nil {
			return err
		}
		return io.ErrShortWrite
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := unix.Renameat2(dir, temporary, dir, name, unix.RENAME_NOREPLACE); err != nil {
		return fmt.Errorf("install signed controller file %s: %w", name, err)
	}
	return unix.Fsync(dir)
}
