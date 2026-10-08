package agent

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// spool anchors every operation to the opened directory inode, even when
// the relay renames a path component or replaces it with a symlink.
type spool struct{ directory *os.File }

func openSpool(directory string, create bool) (*spool, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || directory == "/" {
		return nil, errors.New("invalid NetBird spool path")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for _, component := range strings.Split(strings.TrimPrefix(directory, "/"), "/") {
		next, err := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(err, unix.ENOENT) && create {
			var parent unix.Stat_t
			if err = unix.Fstat(fd, &parent); err != nil {
				unix.Close(fd)
				return nil, err
			}
			created := false
			if err = unix.Mkdirat(fd, component, 0700); err == nil || errors.Is(err, unix.EEXIST) {
				created = err == nil
				next, err = unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			}
			if err == nil && created && os.Geteuid() == 0 {
				// Root-first startup must preserve the relay's inherited ownership.
				if err = unix.Fchown(next, int(parent.Uid), int(parent.Gid)); err != nil {
					unix.Close(next)
				}
			}
		}
		unix.Close(fd)
		if err != nil {
			return nil, err
		}
		fd = next
	}
	file := os.NewFile(uintptr(fd), "NetBird spool directory")
	info, err := file.Stat()
	if err != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
		file.Close()
		return nil, errors.New("unsafe NetBird spool directory")
	}
	return &spool{file}, nil
}

func (s *spool) close() error { return s.directory.Close() }

func spoolName(name string) bool {
	return name != "" && name != "." && name != ".." && !filepath.IsAbs(name) && filepath.Base(name) == name
}

// path lets the existing binary verifier and installer open a staged file
// under this same held directory descriptor, without resolving the relay path.
func (s *spool) path(name string) string {
	return fmt.Sprintf("/proc/self/fd/%d/%s", s.directory.Fd(), name)
}

func (s *spool) temporary() (*os.File, string, error) {
	name := ".netbird-" + rand.Text()
	fd, err := unix.Openat(int(s.directory.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, "", err
	}
	return os.NewFile(uintptr(fd), "NetBird spool temporary"), name, nil
}

func (s *spool) remove(name string) { _ = unix.Unlinkat(int(s.directory.Fd()), name, 0) }

func (s *spool) rename(source, destination string) error {
	if !spoolName(source) || !spoolName(destination) {
		return errors.New("invalid NetBird spool filename")
	}
	fd := int(s.directory.Fd())
	if err := unix.Renameat(fd, source, fd, destination); err != nil {
		return err
	}
	return s.directory.Sync()
}

func (s *spool) write(name string, wire []byte) error {
	if !spoolName(name) {
		return errors.New("invalid NetBird spool filename")
	}
	file, temporary, err := s.temporary()
	if err != nil {
		return err
	}
	defer s.remove(temporary)
	if _, err = file.Write(wire); err == nil {
		if name == "status.json" || name == "result.json" {
			err = file.Chmod(0644)
		}
		if err == nil {
			err = file.Sync()
		}
	}
	err = errors.Join(err, file.Close())
	if err != nil {
		return err
	}
	return s.rename(temporary, name)
}

func (s *spool) sync(name string, limit int64) error {
	if !spoolName(name) || limit < 0 {
		return errors.New("invalid NetBird spool sync")
	}
	fd, err := unix.Openat(int(s.directory.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "NetBird spool file")
	info, err := file.Stat()
	if err == nil && (!info.Mode().IsRegular() || info.Size() > limit || info.Mode().Perm()&0022 != 0) {
		err = errors.New("unsafe NetBird spool file")
	}
	if err == nil {
		err = file.Sync()
	}
	if err = errors.Join(err, file.Close()); err != nil {
		return err
	}
	return s.directory.Sync()
}

func (s *spool) read(name string, limit int64) ([]byte, error) {
	if !spoolName(name) || limit < 0 {
		return nil, errors.New("invalid NetBird spool read")
	}
	fd, err := unix.Openat(int(s.directory.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "NetBird spool file")
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit || info.Mode().Perm()&0022 != 0 {
		return nil, errors.New("unsafe NetBird spool file")
	}
	wire, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(wire)) > limit {
		return nil, errors.New("unsafe NetBird spool file")
	}
	return wire, nil
}
