package preliminarycapture

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	"terrascale.tech/orchestrator/src/orchestrator/restoredrill"
)

type StoreConfig struct {
	Context                         context.Context `json:"-"`
	OutputDir                       string
	Request                         VerifiedRequest
	SignedRequest                   []byte
	MaxSnapshotBytes, MaxTotalBytes int64
}
type Store struct {
	mu                    sync.Mutex
	dir, lock             *os.File
	request               VerifiedRequest
	maximum, totalMaximum int64
	allowed               map[string]string
	closed                bool
}

var _ restoredrill.SnapshotObjectStore = (*Store)(nil)

func ObjectKey(account, stream string, epoch uint64) (string, error) {
	if !name(account) || !name(stream) || epoch == 0 {
		return "", errors.New("preliminarycapture: invalid object identity")
	}
	return account + "/" + stream + ".epoch-" + strconv.FormatUint(epoch, 10) + ".snapshot", nil
}
func objectFile(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:]) + ".snapshot"
}

func NewStore(c StoreConfig) (result *Store, resultErr error) {
	if c.Context == nil || c.Context.Err() != nil || c.Request.Check(time.Now()) != nil || !bytes.Equal(c.SignedRequest, c.Request.Signed) || c.MaxSnapshotBytes < 1024 || c.MaxSnapshotBytes > 1<<30 || c.MaxTotalBytes < c.MaxSnapshotBytes || c.MaxTotalBytes > 256<<30 {
		return nil, errors.New("preliminarycapture: invalid admitted staging configuration")
	}
	check := func() error {
		if err := c.Context.Err(); err != nil {
			return err
		}
		return c.Request.Check(time.Now())
	}
	dir, err := openOutput(c.OutputDir, check)
	if err != nil {
		return nil, err
	}
	s := &Store{dir: dir, request: c.Request, maximum: c.MaxSnapshotBytes, totalMaximum: c.MaxTotalBytes, allowed: map[string]string{}}
	defer func() {
		if resultErr != nil {
			s.Close()
		}
	}()
	s.lock, err = s.openFile(".lock", unix.O_RDWR|unix.O_CREAT)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(int(s.lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, fmt.Errorf("preliminarycapture: staging request already owned: %w", err)
	}
	for _, a := range c.Request.Request.Accounts {
		for _, stream := range a.Streams {
			key, _ := ObjectKey(a.Account, stream, c.Request.Request.ControlEpoch)
			s.allowed[key] = a.Account
		}
	}
	entries, err := s.entries()
	if err != nil {
		return nil, err
	}
	pinned, found, err := s.read("request.json", MaximumBytes)
	if err != nil {
		return nil, err
	}
	if found && !bytes.Equal(pinned, c.SignedRequest) {
		return nil, errors.New("preliminarycapture: output pinned to a different request")
	}
	allowedFiles := map[string]bool{".lock": true, "request.json": true, "receipt.json": true}
	for key := range s.allowed {
		allowedFiles[objectFile(key)] = true
	}
	var total int64
	for _, entry := range entries {
		if entry.Name() == ".lock" {
			continue
		}
		if validStagingName(entry.Name()) {
			// Exclusive ownership proves no live writer uses this unreferenced
			// temporary file. Never remove links, foreign files or large entries.
			f, err := s.openFile(entry.Name(), unix.O_RDONLY)
			if err != nil {
				return nil, err
			}
			info, err := f.Stat()
			f.Close()
			limit := s.maximum
			if limit < MaximumBytes {
				limit = MaximumBytes
			}
			if err != nil || info.Size() > limit {
				return nil, errors.New("preliminarycapture: invalid stale staging file")
			}
			if err := s.mutationCheck(c.Context); err != nil {
				return nil, err
			}
			if err := unix.Unlinkat(int(s.dir.Fd()), entry.Name(), 0); err != nil {
				return nil, err
			}
			if err := s.dir.Sync(); err != nil {
				return nil, err
			}
			continue
		}
		if !found {
			return nil, errors.New("preliminarycapture: unpinned output is not empty")
		}
		if !allowedFiles[entry.Name()] {
			return nil, errors.New("preliminarycapture: unadmitted staging entry")
		}
		limit := s.maximum
		if entry.Name() == "request.json" || entry.Name() == "receipt.json" {
			limit = MaximumBytes
		}
		body, exists, err := s.read(entry.Name(), limit)
		if err != nil || !exists {
			return nil, errors.Join(errors.New("preliminarycapture: invalid retained artifact"), err)
		}
		if strings.HasSuffix(entry.Name(), ".snapshot") {
			if total > s.totalMaximum-int64(len(body)) {
				return nil, errors.New("preliminarycapture: retained inventory exceeds budget")
			}
			total += int64(len(body))
		}
	}
	if !found {
		if err := s.publish(c.Context, "request.json", c.SignedRequest); err != nil {
			return nil, err
		}
	}
	if err := s.dir.Sync(); err != nil {
		return nil, err
	}
	if err := s.mutationCheck(c.Context); err != nil {
		return nil, err
	}
	return s, nil
}

func openOutput(path string, check func() error) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, errors.New("preliminarycapture: explicit absolute output directory required")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for index, part := range parts {
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(e, unix.ENOENT) && index == len(parts)-1 {
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
			return nil, errors.New("preliminarycapture: output ancestry or ownership refused")
		}
	}
	return os.NewFile(uintptr(fd), path), nil
}
func (s *Store) openFile(name string, flags int) (*os.File, error) {
	fd, err := unix.Openat(int(s.dir.Fd()), name, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 || st.Mode&0777 != 0600 {
		f.Close()
		return nil, errors.New("preliminarycapture: staging file ownership/type refused")
	}
	return f, nil
}
func (s *Store) read(name string, limit int64) ([]byte, bool, error) {
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
		return nil, false, errors.New("preliminarycapture: artifact exceeds bound")
	}
	body, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(body)) > limit {
		return nil, false, errors.Join(errors.New("preliminarycapture: artifact read refused"), err)
	}
	return body, true, nil
}
func (s *Store) entries() ([]os.DirEntry, error) {
	fd, err := unix.Openat(int(s.dir.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "staging inventory")
	defer f.Close()
	return f.ReadDir(-1)
}
func (s *Store) publish(ctx context.Context, name string, body []byte) error {
	if err := s.mutationCheck(ctx); err != nil {
		return err
	}
	existing, found, err := s.read(name, int64(len(body)))
	if err != nil {
		return err
	}
	if found {
		if !bytes.Equal(existing, body) {
			return errors.New("preliminarycapture: immutable artifact conflict")
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
func (s *Store) scope(ctx context.Context, region, bucket, key string) error {
	if s == nil || s.closed || ctx == nil {
		return errors.New("preliminarycapture: staging store closed or context missing")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if region != "gru" || s.allowed[key] != bucket || bucket == "" {
		return errors.New("preliminarycapture: unadmitted snapshot key")
	}
	return nil
}
func (s *Store) GetSnapshot(ctx context.Context, region, bucket, key string) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.scope(ctx, region, bucket, key); err != nil {
		return nil, false, err
	}
	body, found, err := s.read(objectFile(key), s.maximum)
	if err == nil && found {
		err = s.dir.Sync()
	}
	if err == nil {
		err = ctx.Err()
	}
	return body, found, err
}
func (s *Store) Head(ctx context.Context, region, bucket, key string) (delivery.ObjectIdentity, bool, error) {
	body, found, err := s.GetSnapshot(ctx, region, bucket, key)
	if err != nil || !found {
		return delivery.ObjectIdentity{}, found, err
	}
	sum := delivery.SHA256Digest(body)
	return delivery.ObjectIdentity{Digest: sum, Size: int64(len(body)), ETag: sum}, true, nil
}
func (s *Store) Put(ctx context.Context, region, bucket, key string, body []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.scope(ctx, region, bucket, key); err != nil {
		return err
	}
	if err := s.request.Check(time.Now()); err != nil {
		return err
	}
	if len(body) == 0 || int64(len(body)) > s.maximum {
		return errors.New("preliminarycapture: snapshot exceeds bound")
	}
	existing, found, err := s.read(objectFile(key), s.maximum)
	if err != nil {
		return err
	}
	if found {
		if !bytes.Equal(existing, body) {
			return errors.New("preliminarycapture: immutable snapshot conflict")
		}
		if err := s.dir.Sync(); err != nil {
			return err
		}
		return s.mutationCheck(ctx)
	}
	total := int64(len(body))
	for candidate := range s.allowed {
		data, found, err := s.read(objectFile(candidate), s.maximum)
		if err != nil {
			return err
		}
		if found {
			if total > s.totalMaximum-int64(len(data)) {
				return errors.New("preliminarycapture: total snapshot budget exceeded")
			}
			total += int64(len(data))
		}
	}
	return s.publish(ctx, objectFile(key), body)
}
func (s *Store) ReadReceipt() ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, false, errors.New("preliminarycapture: store closed")
	}
	raw, found, err := s.read("receipt.json", MaximumBytes)
	if err == nil && found {
		err = s.validateReceipt(raw)
		if err == nil {
			err = s.dir.Sync()
		}
	}
	return raw, found, err
}
func (s *Store) PublishReceipt(ctx context.Context, raw []byte) error {
	if ctx == nil || ctx.Err() != nil {
		return errors.New("preliminarycapture: receipt context unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("preliminarycapture: store closed")
	}
	if err := s.request.Check(time.Now()); err != nil {
		return err
	}
	if err := s.validateReceipt(raw); err != nil {
		return err
	}
	return s.publish(ctx, "receipt.json", raw)
}
func (s *Store) validateReceipt(raw []byte) error {
	var document signedDocument
	var r Receipt
	if canonicalDecode(raw, &document) != nil || canonicalDecode(document.Payload, &r) != nil {
		return errors.New("preliminarycapture: invalid receipt publication")
	}
	if _, err := canonicalReceipt(r); err != nil {
		return err
	}
	want := s.request.Request
	if r.RequestSHA256 != s.request.Digest || r.TransitionID != want.TransitionID || r.SourceNodeID != want.SourceNodeID || r.ControlEpoch != want.ControlEpoch || len(r.Objects) != len(s.allowed) {
		return errors.New("preliminarycapture: receipt scope differs")
	}
	for _, o := range r.Objects {
		if s.allowed[o.Key] != o.Account {
			return errors.New("preliminarycapture: receipt object not requested")
		}
		body, found, err := s.read(objectFile(o.Key), s.maximum)
		if err != nil {
			return err
		}
		if !found || int64(len(body)) != o.Size || delivery.SHA256Digest(body) != o.SHA256 {
			return errors.New("preliminarycapture: receipt bytes not durable")
		}
	}
	return nil
}
func (s *Store) Close() error {
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

func (s *Store) mutationCheck(ctx context.Context) error {
	if ctx == nil {
		return errors.New("preliminarycapture: mutation context required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.request.Check(time.Now())
}

func validStagingName(value string) bool {
	if !strings.HasPrefix(value, ".staging-") {
		return false
	}
	suffix := strings.TrimPrefix(value, ".staging-")
	raw, err := hex.DecodeString(suffix)
	return err == nil && len(raw) == 16 && hex.EncodeToString(raw) == suffix
}
