package nodeauthority

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// WithInitialAuthority executes initial credential provisioning only while no
// real regional epoch has retired bootstrap. Ownership spans the check and all
// callback effects, preventing a concurrent receiver handoff from racing them.
func WithInitialAuthority(directory, node string, provision func() error) error {
	if provision == nil || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return errors.New("nodeauthority: invalid initial credential scope")
	}
	if err := prepareAuthorityDirectory(directory); err != nil {
		return err
	}
	store, err := NewEpochStore(directory, node)
	if err != nil {
		return err
	}
	defer store.Close()
	floor, err := store.load()
	if err != nil {
		return err
	}
	if _, _, err = store.loadManifestAdmission(); err != nil {
		return err
	}
	if err = syncEpochDirectory(directory); err != nil {
		return err
	}
	if floor.Epoch > 0 {
		return nil
	}
	return provision()
}
func prepareAuthorityDirectory(path string) error {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(err, unix.ENOENT) {
			if err = unix.Mkdirat(fd, part, 0700); err != nil && !errors.Is(err, unix.EEXIST) {
				return err
			}
			next, err = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		}
		if err != nil {
			return err
		}
		if err = unix.Fsync(fd); err != nil {
			unix.Close(next)
			return err
		}
		unix.Close(fd)
		fd = next
	}
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0077 != 0 {
		return errors.New("nodeauthority: initial credential state directory is not private")
	}
	return unix.Fsync(fd)
}
