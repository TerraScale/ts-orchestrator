package candidatesync

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type stage struct {
	dir, lock *os.File
	check     func() error
}

func (s *stage) mutationCheck(ctx context.Context) error {
	if ctx == nil {
		return errors.New("candidatesync: context required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.check()
}
func (s *stage) close() {
	if s.lock != nil {
		s.lock.Close()
	}
	s.dir.Close()
}
func newStage(path string, check func() error) (*stage, error) {
	d, e := openOutput(path, check)
	if e != nil {
		return nil, e
	}
	s := &stage{dir: d, check: check}
	s.lock, e = s.openFile(".lock", unix.O_RDWR|unix.O_CREAT)
	if e == nil {
		e = unix.Flock(int(s.lock.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	}
	if e != nil {
		s.close()
		return nil, e
	}
	return s, nil
}
func openOutput(path string, check func() error) (*os.File, error) {
	return openOutputMode(path, check, true)
}

func openOutputMode(path string, check func() error, create bool) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, errors.New("candidatesync: explicit absolute output directory required")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for index, part := range parts {
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if create && errors.Is(e, unix.ENOENT) && index == len(parts)-1 {
			if e = check(); e != nil {
				unix.Close(fd)
				return nil, e
			}
			if e = unix.Mkdirat(fd, part, 0700); e == nil {
				e = unix.Fsync(fd)
			}
			if e == nil {
				next, e = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			}
		}
		unix.Close(fd)
		if e != nil {
			return nil, e
		}
		fd = next
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) || (st.Mode&0022 != 0 && !(st.Uid == 0 && st.Mode&unix.S_ISVTX != 0)) || (index == len(parts)-1 && (st.Uid != uint32(os.Geteuid()) || st.Mode&0777 != 0700)) {
			unix.Close(fd)
			return nil, errors.New("candidatesync: output ancestry or ownership refused")
		}
	}
	return os.NewFile(uintptr(fd), path), nil
}
func (s *stage) openFile(name string, flags int) (*os.File, error) {
	fd, err := unix.Openat(int(s.dir.Fd()), name, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 || st.Mode&0777 != 0600 {
		f.Close()
		return nil, errors.New("candidatesync: staging file ownership/type refused")
	}
	return f, nil
}
func (s *stage) read(name string, limit int64) ([]byte, bool, error) {
	f, err := s.openFile(name, unix.O_RDONLY)
	if errors.Is(err, unix.ENOENT) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, false, err
	}
	if info.Size() > limit {
		return nil, false, errors.New("candidatesync: artifact exceeds bound")
	}
	body, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(body)) > limit {
		return nil, false, errors.Join(errors.New("candidatesync: artifact read refused"), err)
	}
	return body, true, nil
}
func (s *stage) entries() ([]os.DirEntry, error) {
	fd, err := unix.Openat(int(s.dir.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "staging inventory")
	defer f.Close()
	return f.ReadDir(-1)
}
func (s *stage) publish(ctx context.Context, name string, body []byte) error {
	if err := s.mutationCheck(ctx); err != nil {
		return err
	}
	existing, found, err := s.read(name, int64(len(body)))
	if err != nil {
		return err
	}
	if found {
		if !bytes.Equal(existing, body) {
			return errors.New("candidatesync: immutable artifact conflict")
		}
		if err := s.dir.Sync(); err != nil {
			return err
		}
		return s.mutationCheck(ctx)
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	temporary := ".staging-" + hex.EncodeToString(nonce[:])
	f, err := s.openFile(temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL)
	if err != nil {
		return err
	}
	defer unix.Unlinkat(int(s.dir.Fd()), temporary, 0)
	if _, err = f.Write(body); err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if err := s.mutationCheck(ctx); err != nil {
		return err
	}
	if err = unix.Renameat2(int(s.dir.Fd()), temporary, int(s.dir.Fd()), name, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	if err := s.dir.Sync(); err != nil {
		return err
	}
	return s.mutationCheck(ctx)
}
