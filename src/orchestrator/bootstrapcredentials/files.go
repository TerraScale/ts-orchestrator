// Package bootstrapcredentials captures explicit bootstrap credential files.
package bootstrapcredentials

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const MaximumFileBytes int64 = 4 << 20

// ReadFile captures a bounded regular file owned by the caller. Descriptor
// traversal rejects symlinks without reopening an already checked pathname.
func ReadFile(path string, private bool, limit int64) ([]byte, error) {
	invalid := errors.New("bootstrapcredentials: bounded owned regular file required")
	if limit <= 0 || limit > MaximumFileBytes || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\x00\r\n") {
		return nil, invalid
	}
	parent, err := OpenProtectedDirectory(filepath.Dir(path), false)
	if err != nil {
		return nil, invalid
	}
	defer parent.Close()
	directory := int(parent.Fd())
	fd, err := unix.Openat(directory, filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, invalid
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	before, err := file.Stat()
	if err != nil {
		return nil, invalid
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	mask := os.FileMode(0022)
	if private {
		mask = 0077
	}
	if !ok || !before.Mode().IsRegular() || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || before.Mode().Perm()&mask != 0 || before.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || before.Size() < 1 || before.Size() > limit {
		return nil, invalid
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	after, statErr := file.Stat()
	if err != nil || statErr != nil || !os.SameFile(before, after) || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) || int64(len(data)) != before.Size() || int64(len(data)) > limit {
		clear(data)
		return nil, invalid
	}
	current, ok := after.Sys().(*syscall.Stat_t)
	if !ok || current.Uid != stat.Uid || current.Nlink != 1 || after.Mode() != before.Mode() {
		clear(data)
		return nil, invalid
	}
	return data, nil
}
