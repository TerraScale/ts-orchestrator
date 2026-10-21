package manager

import (
	"crypto/rand"
	"encoding/json/v2"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

type enrollmentState struct {
	Origin, Group, Name, Operation           string
	Vault, VaultName, Compartment, MasterKey string
	Attempted                                bool
	KeyID, Key, SecretID                     string
}

// enrollmentStore holds the lock and anchors secret IO to the directory inode.
type enrollmentStore struct{ directory, lock *os.File }

func openEnrollmentStore(path string) (*enrollmentStore, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, errors.New("invalid NetBird enrollment state directory")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for _, component := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		next, openErr := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(openErr, unix.ENOENT) {
			openErr = unix.Mkdirat(fd, component, 0700)
			if openErr == nil || errors.Is(openErr, unix.EEXIST) {
				if err := unix.Fsync(fd); err != nil {
					unix.Close(fd)
					return nil, errors.New("cannot persist NetBird enrollment directory")
				}
				next, openErr = unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			}
		}
		unix.Close(fd)
		if openErr != nil {
			return nil, errors.New("cannot open NetBird enrollment state directory")
		}
		fd = next
	}
	store := &enrollmentStore{directory: os.NewFile(uintptr(fd), "NetBird enrollment state")}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0777 != 0700 {
		store.close()
		return nil, errors.New("NetBird enrollment state must be owned by the service with mode 0700")
	}
	lockFD, err := unix.Openat(fd, "enrollment.lock", unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		store.close()
		return nil, errors.New("cannot open NetBird enrollment lock")
	}
	store.lock = os.NewFile(uintptr(lockFD), "NetBird enrollment lock")
	if !privateEnrollmentFile(lockFD) || unix.Flock(lockFD, unix.LOCK_EX|unix.LOCK_NB) != nil {
		store.close()
		return nil, errors.New("NetBird enrollment state is unsafe or already locked")
	}
	return store, nil
}

func privateEnrollmentFile(fd int) bool {
	var stat unix.Stat_t
	return unix.Fstat(fd, &stat) == nil && stat.Mode&unix.S_IFMT == unix.S_IFREG &&
		stat.Mode&0777 == 0600 && stat.Uid == uint32(os.Geteuid()) && stat.Nlink == 1
}

func (s *enrollmentStore) close() {
	if s.lock != nil {
		s.lock.Close()
	}
	s.directory.Close()
}

func (s *enrollmentStore) read() (enrollmentState, error) {
	var state enrollmentState
	fd, err := unix.Openat(int(s.directory.Fd()), "enrollment.json", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return state, nil
	}
	if err != nil {
		return state, errors.New("cannot read NetBird enrollment state")
	}
	file := os.NewFile(uintptr(fd), "NetBird enrollment state")
	defer file.Close()
	if !privateEnrollmentFile(fd) {
		return state, errors.New("unsafe NetBird enrollment state file")
	}
	wire, err := io.ReadAll(io.LimitReader(file, 8193))
	defer clear(wire)
	if err != nil || len(wire) > 8192 || json.Unmarshal(wire, &state, json.RejectUnknownMembers(true)) != nil || state.Operation == "" {
		return enrollmentState{}, errors.New("invalid NetBird enrollment state")
	}
	return state, nil
}

func (s *enrollmentStore) write(state enrollmentState) error {
	wire, err := json.Marshal(state)
	if err != nil {
		return errors.New("cannot encode NetBird enrollment state")
	}
	defer clear(wire)
	name := ".enrollment-" + rand.Text()
	fd, err := unix.Openat(int(s.directory.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return errors.New("cannot stage NetBird enrollment state")
	}
	defer unix.Unlinkat(int(s.directory.Fd()), name, 0)
	file := os.NewFile(uintptr(fd), "NetBird enrollment state")
	if _, err = file.Write(wire); err == nil {
		err = file.Sync()
	}
	err = errors.Join(err, file.Close())
	if err == nil {
		err = unix.Renameat(int(s.directory.Fd()), name, int(s.directory.Fd()), "enrollment.json")
	}
	if err == nil {
		err = s.directory.Sync()
	}
	if err != nil {
		return errors.New("cannot persist NetBird enrollment state")
	}
	return nil
}
