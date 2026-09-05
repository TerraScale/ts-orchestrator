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
	directory, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, invalid
	}
	defer func() { unix.Close(directory) }()
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i := 0; ; i++ {
		var stat unix.Stat_t
		if unix.Fstat(directory, &stat) != nil {
			return nil, invalid
		}
		owner := stat.Uid == 0 || stat.Uid == uint32(os.Geteuid())
		stickyRoot := stat.Uid == 0 && stat.Mode&unix.S_ISVTX != 0
		if !owner || (stat.Mode&0022 != 0 && !stickyRoot) {
			return nil, invalid
		}
		if i == len(parts)-1 {
			break
		}
		next, e := unix.Openat(directory, parts[i], unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			return nil, invalid
		}
		unix.Close(directory)
		directory = next
	}
	fd, err := unix.Openat(directory, parts[len(parts)-1], unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
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
