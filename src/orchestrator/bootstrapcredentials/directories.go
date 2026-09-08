package bootstrapcredentials

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// OpenProtectedDirectory traverses by descriptor without following symlinks.
// Only root/the current user may own ancestors; writable ancestors are refused
// except root-owned sticky directories such as /tmp. Newly created directories
// are private. The caller owns the returned directory descriptor.
func OpenProtectedDirectory(path string, create bool) (*os.File, error) {
	invalid := errors.New("bootstrapcredentials: protected owned directory required")
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\x00\r\n") {
		return nil, invalid
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*os.File, error) { unix.Close(fd); return nil, err }
	validate := func() error {
		var stat unix.Stat_t
		if unix.Fstat(fd, &stat) != nil {
			return invalid
		}
		owner := stat.Uid == 0 || stat.Uid == uint32(os.Geteuid())
		stickyRoot := stat.Uid == 0 && stat.Mode&unix.S_ISVTX != 0
		if !owner || (stat.Mode&0022 != 0 && !stickyRoot) {
			return invalid
		}
		return nil
	}
	if err := validate(); err != nil {
		return fail(err)
	}
	if path != "/" {
		for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
			next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if errors.Is(err, unix.ENOENT) && create {
				if err := unix.Mkdirat(fd, part, 0700); err != nil && !errors.Is(err, unix.EEXIST) {
					return fail(err)
				}
				if err := unix.Fsync(fd); err != nil {
					return fail(err)
				}
				next, err = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			}
			if err != nil {
				return fail(err)
			}
			unix.Close(fd)
			fd = next
			if err := validate(); err != nil {
				return fail(err)
			}
		}
	}
	return os.NewFile(uintptr(fd), path), nil
}
