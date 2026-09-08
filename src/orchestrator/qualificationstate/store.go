// Package qualificationstate persists immutable local qualification admissions.
// A damaged or mismatched prior record is never replaced with newly issued keys.
package qualificationstate

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

var recordName = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,126}[a-z0-9]$`)
var ErrState = errors.New("qualificationstate: protected immutable admission unavailable")

type Store struct {
	mu        sync.Mutex
	directory *os.File
}

// Open creates missing protected directories while traversing verified directory
// descriptors. No symlink or writable untrusted ancestor is followed.
func Open(path string) (*Store, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || strings.ContainsAny(path, "\x00\r\n") {
		return nil, ErrState
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrState
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for index, part := range parts {
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(err, unix.ENOENT) {
			if err = unix.Mkdirat(fd, part, 0700); err != nil && !errors.Is(err, unix.EEXIST) {
				unix.Close(fd)
				return nil, ErrState
			}
			if unix.Fsync(fd) != nil {
				unix.Close(fd)
				return nil, ErrState
			}
			next, err = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		}
		unix.Close(fd)
		if err != nil {
			return nil, ErrState
		}
		fd = next
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Uid != 0 && st.Uid != uint32(os.Geteuid()) || st.Mode&0022 != 0 && !(st.Uid == 0 && st.Mode&unix.S_ISVTX != 0) || index == len(parts)-1 && (st.Uid != uint32(os.Geteuid()) || st.Mode&07777 != 0700) {
			unix.Close(fd)
			return nil, ErrState
		}
	}
	return &Store{directory: os.NewFile(uintptr(fd), path)}, nil
}
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.directory == nil {
		return nil
	}
	err := s.directory.Close()
	s.directory = nil
	return err
}

// LoadOrCreate returns exactly the existing admitted bytes, or publishes newly
// created bytes once. A valid pending record from interrupted publication is
// recovered; an incomplete pending record fails closed and is never regenerated.
func (s *Store) LoadOrCreate(name string, maximum int64, create func() ([]byte, error), validate func([]byte) error) ([]byte, error) {
	if s == nil {
		return nil, ErrState
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.directory == nil || !recordName.MatchString(name) || strings.HasSuffix(name, ".pending") || maximum <= 0 || maximum > 16<<20 || create == nil || validate == nil {
		return nil, ErrState
	}
	fd := int(s.directory.Fd())
	var directoryStat unix.Stat_t
	if unix.Fstat(fd, &directoryStat) != nil || directoryStat.Uid != uint32(os.Geteuid()) || directoryStat.Mode&07777 != 0700 {
		return nil, ErrState
	}
	lockFD, err := unix.Openat(fd, ".admission.lock", unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, ErrState
	}
	defer unix.Close(lockFD)
	var lockStat unix.Stat_t
	if unix.Fstat(lockFD, &lockStat) != nil || lockStat.Mode&unix.S_IFMT != unix.S_IFREG || lockStat.Mode&07777 != 0600 || lockStat.Uid != uint32(os.Geteuid()) || lockStat.Nlink != 1 {
		return nil, ErrState
	}
	if unix.Flock(lockFD, unix.LOCK_EX|unix.LOCK_NB) != nil {
		return nil, ErrState
	}
	defer unix.Flock(lockFD, unix.LOCK_UN)
	if raw, err := s.read(name, maximum); err == nil {
		if validate(raw) != nil {
			clear(raw)
			return nil, ErrState
		}
		return raw, nil
	} else if !errors.Is(err, unix.ENOENT) {
		return nil, ErrState
	}
	pending := name + ".pending"
	raw, err := s.read(pending, maximum)
	if err != nil && !errors.Is(err, unix.ENOENT) {
		return nil, ErrState
	}
	if errors.Is(err, unix.ENOENT) {
		raw, err = create()
		if err != nil {
			clear(raw)
			return nil, err
		}
		if len(raw) == 0 || int64(len(raw)) > maximum || validate(raw) != nil {
			clear(raw)
			return nil, ErrState
		}
		fileFD, err := unix.Openat(fd, pending, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
		if err != nil {
			clear(raw)
			return nil, ErrState
		}
		file := os.NewFile(uintptr(fileFD), pending)
		// Once the pending name is durable, a retry must inspect it instead of
		// issuing another identity, even if this process stops during the write.
		if unix.Fsync(fd) != nil {
			file.Close()
			clear(raw)
			return nil, ErrState
		}
		written, writeErr := file.Write(raw)
		syncErr := file.Sync()
		closeErr := file.Close()
		if writeErr != nil || written != len(raw) || syncErr != nil || closeErr != nil {
			clear(raw)
			return nil, ErrState
		}
	}
	if validate(raw) != nil {
		clear(raw)
		return nil, ErrState
	}
	if unix.Renameat2(fd, pending, fd, name, unix.RENAME_NOREPLACE) != nil {
		clear(raw)
		return nil, ErrState
	}
	if unix.Fsync(fd) != nil {
		clear(raw)
		return nil, ErrState
	}
	return raw, nil
}

func (s *Store) read(name string, maximum int64) ([]byte, error) {
	fd, err := unix.Openat(int(s.directory.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var before unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Mode&07777 != 0600 || before.Uid != uint32(os.Geteuid()) || before.Nlink != 1 || before.Size <= 0 || before.Size > maximum {
		return nil, ErrState
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		clear(raw)
		return nil, ErrState
	}
	var after unix.Stat_t
	if unix.Fstat(fd, &after) != nil || before.Ino != after.Ino || before.Dev != after.Dev || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim || int64(len(raw)) != before.Size {
		clear(raw)
		return nil, ErrState
	}
	if err := file.Sync(); err != nil {
		clear(raw)
		return nil, ErrState
	}
	return raw, nil
}
