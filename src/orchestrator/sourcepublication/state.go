package sourcepublication

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"terrascale.tech/orchestrator/src/orchestrator/preliminarytransfer"
)

type acceptance struct {
	Version      int             `json:"version"`
	ScopeSHA256  string          `json:"scopeSha256"`
	OwnerKeyID   string          `json:"ownerKeyId"`
	Scope        json.RawMessage `json:"scope"`
	ControlEpoch uint64          `json:"controlEpoch"`
	IssuedAt     time.Time       `json:"issuedAt"`
	ExpiresAt    time.Time       `json:"expiresAt"`
}

// State owns one publication scope and its durable renewal floor. An expired
// authorization can never resume work, even when its scope remains unchanged.
type State struct {
	mu        sync.Mutex
	dir, lock *os.File
	context   context.Context
	upload    preliminarytransfer.VerifiedUpload
	guard     func(context.Context) error
	closed    bool
}

func OpenState(ctx context.Context, dir string, upload preliminarytransfer.VerifiedUpload, guard func(context.Context) error) (_ *State, resultErr error) {
	s := &State{context: ctx, upload: upload, guard: guard}
	if err := s.check(ctx); err != nil {
		return nil, err
	}
	var err error
	s.dir, err = openStateDirectory(dir, func() error { return s.check(ctx) })
	if err != nil {
		return nil, err
	}
	defer func() {
		if resultErr != nil {
			s.Close()
		}
	}()
	s.lock, err = s.open(".lock", unix.O_RDWR|unix.O_CREAT)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(int(s.lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, err
	}
	entries, err := s.dir.ReadDir(5)
	if err != nil && err != io.EOF {
		return nil, err
	}
	for _, entry := range entries {
		switch entry.Name() {
		case ".lock", "acceptance.json", "receipt.json", ".pending":
		default:
			return nil, errors.New("sourcepublication: unexpected state entry")
		}
	}
	if len(entries) > 4 {
		return nil, errors.New("sourcepublication: unexpected state inventory")
	}
	scope, err := preliminarytransfer.CanonicalScope(upload.Scope.Scope)
	if err != nil {
		return nil, err
	}
	next := acceptance{Version: 1, ScopeSHA256: upload.Scope.Digest, OwnerKeyID: upload.Scope.OwnerKeyID, Scope: scope, ControlEpoch: upload.Authorization.ControlEpoch, IssuedAt: upload.Authorization.IssuedAt, ExpiresAt: upload.Authorization.ExpiresAt}
	raw, found, err := s.read("acceptance.json")
	if err != nil {
		return nil, err
	}
	if found {
		var prior acceptance
		if err := decodeState(raw, &prior); err != nil {
			return nil, err
		}
		if prior.Version != 1 || prior.ScopeSHA256 != next.ScopeSHA256 || prior.OwnerKeyID != next.OwnerKeyID || !bytes.Equal(prior.Scope, next.Scope) || prior.ControlEpoch == 0 || prior.IssuedAt.IsZero() || !prior.ExpiresAt.After(prior.IssuedAt) || next.ExpiresAt.Before(prior.ExpiresAt) || next.ControlEpoch < prior.ControlEpoch || next.IssuedAt.Before(prior.IssuedAt) {
			return nil, errors.New("sourcepublication: scope changed or authorization regressed")
		}
	} else {
		if _, exists, err := s.read("receipt.json"); err != nil || exists {
			return nil, errors.Join(errors.New("sourcepublication: receipt without acceptance pin"), err)
		}
	}
	// A fixed pending file is only an uncommitted atomic-write attempt. Validate
	// its protected type before cleanup, under the exclusive process lock.
	if _, exists, err := s.read(".pending"); err != nil {
		return nil, err
	} else if exists {
		if err := s.check(ctx); err != nil {
			return nil, err
		}
		if err := unix.Unlinkat(int(s.dir.Fd()), ".pending", 0); err != nil {
			return nil, err
		}
		if err := s.dir.Sync(); err != nil {
			return nil, err
		}
	}
	body, err := json.Marshal(next)
	if err != nil {
		return nil, err
	}
	if found && bytes.Equal(raw, body) {
		if err := s.dir.Sync(); err != nil {
			return nil, err
		}
	} else if err := s.write(ctx, "acceptance.json", body); err != nil {
		return nil, err
	}
	if _, err := s.ReadReceipt(ctx); err != nil {
		return nil, err
	}
	if err := s.check(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *State) check(ctx context.Context) error {
	if s == nil || ctx == nil || s.context == nil || s.guard == nil {
		return errors.New("sourcepublication: state context and authorization guard required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.context.Err(); err != nil {
		return err
	}
	if err := s.upload.Check(time.Now()); err != nil {
		return err
	}
	return s.guard(ctx)
}
func decodeState(raw []byte, v any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(v) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("sourcepublication: malformed acceptance")
	}
	canonical, err := json.Marshal(v)
	if err != nil || !bytes.Equal(raw, canonical) {
		return errors.New("sourcepublication: noncanonical acceptance")
	}
	return nil
}
func openStateDirectory(path string, check func() error) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, errors.New("sourcepublication: absolute protected state directory required")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for index, part := range parts {
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(e, unix.ENOENT) && index == len(parts)-1 {
			if e = check(); e == nil {
				e = unix.Mkdirat(fd, part, 0700)
			}
			if e == nil {
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
			return nil, errors.New("sourcepublication: state directory ownership refused")
		}
	}
	return os.NewFile(uintptr(fd), path), nil
}
func (s *State) open(name string, flags int) (*os.File, error) {
	fd, err := unix.Openat(int(s.dir.Fd()), name, flags|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != uint32(os.Geteuid()) || st.Mode&0777 != 0600 || st.Nlink != 1 {
		f.Close()
		return nil, errors.New("sourcepublication: state file ownership refused")
	}
	return f, nil
}
func (s *State) read(name string) ([]byte, bool, error) {
	f, err := s.open(name, unix.O_RDONLY)
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
	if info.Size() > preliminarytransfer.MaximumBytes {
		return nil, false, errors.New("sourcepublication: state artifact exceeds bound")
	}
	raw, err := io.ReadAll(io.LimitReader(f, preliminarytransfer.MaximumBytes+1))
	if err != nil || len(raw) > preliminarytransfer.MaximumBytes {
		return nil, false, errors.Join(errors.New("sourcepublication: state read refused"), err)
	}
	return raw, true, nil
}
func (s *State) write(ctx context.Context, name string, raw []byte) error {
	if len(raw) > preliminarytransfer.MaximumBytes {
		return errors.New("sourcepublication: state artifact exceeds bound")
	}
	if err := s.check(ctx); err != nil {
		return err
	}
	f, err := s.open(".pending", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL)
	if err != nil {
		return err
	}
	defer unix.Unlinkat(int(s.dir.Fd()), ".pending", 0)
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if err := s.check(ctx); err != nil {
		return err
	}
	if err := unix.Renameat(int(s.dir.Fd()), ".pending", int(s.dir.Fd()), name); err != nil {
		return err
	}
	if err := s.dir.Sync(); err != nil {
		return err
	}
	return s.check(ctx)
}
func (s *State) ReadReceipt(ctx context.Context) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errors.New("sourcepublication: state closed")
	}
	if err := s.check(ctx); err != nil {
		return nil, err
	}
	raw, found, err := s.read("receipt.json")
	if err != nil {
		return nil, err
	}
	if found {
		if _, err := preliminarytransfer.CheckPublicationForScope(s.upload.Scope, raw); err != nil {
			return nil, err
		}
		if err := s.dir.Sync(); err != nil {
			return nil, err
		}
	}
	if err := s.check(ctx); err != nil {
		return nil, err
	}
	return raw, nil
}
func (s *State) SaveReceipt(ctx context.Context, raw []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("sourcepublication: state closed")
	}
	if err := s.check(ctx); err != nil {
		return err
	}
	if _, err := preliminarytransfer.CheckPublicationForScope(s.upload.Scope, raw); err != nil {
		return err
	}
	existing, found, err := s.read("receipt.json")
	if err != nil {
		return err
	}
	if found {
		if !bytes.Equal(existing, raw) {
			return errors.New("sourcepublication: immutable publication receipt conflict")
		}
		if err := s.dir.Sync(); err != nil {
			return err
		}
		return s.check(ctx)
	}
	return s.write(ctx, "receipt.json", raw)
}
func (s *State) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var err error
	if s.lock != nil {
		err = s.lock.Close()
	}
	if s.dir != nil {
		err = errors.Join(err, s.dir.Close())
	}
	return err
}
