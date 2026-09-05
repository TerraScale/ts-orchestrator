//go:build unix

package globalclient

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// Read through directory descriptors so neither ancestor nor leaf symlink
// replacement can redirect admission. Nonblocking open rejects FIFOs promptly.
func readIdentityFile(ctx context.Context, path string, maximum int64, private bool) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(path) {
		return nil, errIdentityFiles
	}
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(path), "/"), "/")
	parent, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errIdentityFiles
	}
	defer func() { unix.Close(parent) }()
	for _, part := range parts[:len(parts)-1] {
		next, err := unix.Openat(parent, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, errIdentityFiles
		}
		unix.Close(parent)
		parent = next
	}
	fd, err := unix.Openat(parent, parts[len(parts)-1], unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errIdentityFiles
	}
	file := os.NewFile(uintptr(fd), "global-worker-identity")
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > maximum || (private && before.Mode().Perm()&0077 != 0) {
		return nil, errIdentityFiles
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) != before.Size() {
		clear(data)
		return nil, errIdentityFiles
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || after.Mode() != before.Mode() || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		clear(data)
		return nil, errIdentityFiles
	}
	if err := ctx.Err(); err != nil {
		clear(data)
		return nil, err
	}
	return data, nil
}

var errIdentityFiles = errors.New("global worker identity requires bounded regular files without symlinks and private seed/key permissions")
