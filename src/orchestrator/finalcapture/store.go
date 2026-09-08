package finalcapture

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
	"terrascale.tech/orchestrator/src/orchestrator/controltransition"
	"terrascale.tech/orchestrator/src/orchestrator/delivery"
)

type archiveStore struct {
	dir                   *os.Root
	lock                  *os.File
	plan                  controltransition.VerifiedPlan
	allowed               map[string]string
	maximum, totalMaximum int64
}

func openArchives(ctx context.Context, v controltransition.VerifiedPlan, epoch uint64) (_ *archiveStore, err error) {
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	p, err := v.Plan()
	if err != nil {
		return nil, err
	}
	for path := p.Source.ArchiveDir; path != string(os.PathSeparator); path = filepath.Dir(path) {
		info, e := os.Lstat(path)
		if errors.Is(e, os.ErrNotExist) && path == p.Source.ArchiveDir {
			continue
		}
		if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0 {
			return nil, errors.New("finalcapture: unsafe archive ancestry")
		}
	}
	if err = os.Mkdir(p.Source.ArchiveDir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	info, err := os.Lstat(p.Source.ArchiveDir)
	if err != nil || info.Mode().Perm() != 0700 {
		return nil, errors.New("finalcapture: private archive directory required")
	}
	dir, err := os.OpenRoot(p.Source.ArchiveDir)
	if err != nil {
		return nil, err
	}
	s := &archiveStore{dir: dir, plan: v, allowed: map[string]string{}, maximum: p.Limits.MaxSnapshotBytes, totalMaximum: p.Limits.MaxTransferBytes}
	defer func() {
		if err != nil {
			s.close()
		}
	}()
	s.lock, err = dir.OpenFile(".lock", os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(int(s.lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, err
	}
	for _, a := range p.Accounts {
		for _, stream := range a.Streams {
			key, _ := controltransition.CaptureObjectKey(v, a.Role, stream.Name, epoch)
			s.allowed[key] = a.SourceName
		}
	}
	allowedFiles := map[string]bool{".lock": true, "plan.sha256": true, "receipt.json": true, "copy-final.sha256": true}
	for key := range s.allowed {
		allowedFiles[archiveFile(key)] = true
	}
	opened, err := dir.Open(".")
	if err != nil {
		return nil, err
	}
	entries, err := opened.ReadDir(-1)
	opened.Close()
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		name := entry.Name()
		committed, partial := strings.CutSuffix(name, ".partial")
		if !allowedFiles[name] && !(partial && allowedFiles[committed] && committed != ".lock") {
			return nil, errors.New("finalcapture: unknown archive entry")
		}
		if _, _, err := s.read(name, p.Limits.MaxSnapshotBytes); err != nil {
			return nil, err
		}
		if partial {
			if err := dir.Remove(name); err != nil {
				return nil, err
			}
		}
	}
	if err = s.publish(ctx, "plan.sha256", []byte(v.Digest())); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *archiveStore) close() error {
	if s == nil {
		return nil
	}
	var err error
	if s.lock != nil {
		err = s.lock.Close()
	}
	if s.dir != nil {
		err = errors.Join(err, s.dir.Close())
	}
	return err
}
func archiveFile(key string) string { return controltransition.Digest([]byte(key)) + ".snapshot" }
func (s *archiveStore) read(name string, maximum int64) ([]byte, bool, error) {
	info, err := s.dir.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > maximum {
		return nil, false, errors.New("finalcapture: unsafe or oversized archive")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 {
		return nil, false, errors.New("finalcapture: archive ownership or link count differs")
	}
	file, err := s.dir.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, false, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, false, errors.New("finalcapture: archive changed during open")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) > maximum {
		return nil, false, errors.New("finalcapture: bounded archive read failed")
	}
	return data, true, nil
}
func (s *archiveStore) publish(ctx context.Context, name string, body []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if old, found, err := s.read(name, int64(len(body))); err != nil {
		return err
	} else if found {
		if !bytes.Equal(old, body) {
			return errors.New("finalcapture: immutable archive conflict")
		}
		return s.sync()
	}
	file, err := s.dir.OpenFile(name+".partial", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer s.dir.Remove(name + ".partial")
	if _, err = file.Write(body); err == nil {
		err = file.Sync()
	}
	err = errors.Join(err, file.Close())
	if err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	// Exclusive directory ownership makes this link publication create-only.
	if err = s.dir.Link(name+".partial", name); err != nil {
		return err
	}
	if err = s.dir.Remove(name + ".partial"); err != nil {
		return err
	}
	return s.sync()
}
func (s *archiveStore) sync() error {
	file, err := s.dir.Open(".")
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}
func (s *archiveStore) scope(ctx context.Context, region, account, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if region != "gru" || account == "" || s.allowed[key] != account {
		return errors.New("finalcapture: unadmitted snapshot key")
	}
	return nil
}
func (s *archiveStore) GetSnapshot(ctx context.Context, region, account, key string) ([]byte, bool, error) {
	if err := s.scope(ctx, region, account, key); err != nil {
		return nil, false, err
	}
	return s.read(archiveFile(key), s.maximum)
}
func (s *archiveStore) Head(ctx context.Context, region, account, key string) (delivery.ObjectIdentity, bool, error) {
	body, found, err := s.GetSnapshot(ctx, region, account, key)
	if err != nil || !found {
		return delivery.ObjectIdentity{}, found, err
	}
	hash := delivery.SHA256Digest(body)
	return delivery.ObjectIdentity{Digest: hash, Size: int64(len(body)), ETag: hash}, true, nil
}
func (s *archiveStore) Put(ctx context.Context, region, account, key string, body []byte) error {
	if err := s.scope(ctx, region, account, key); err != nil {
		return err
	}
	if len(body) == 0 || int64(len(body)) > s.maximum {
		return errors.New("finalcapture: archive budget exceeded")
	}
	var total int64
	for allowed := range s.allowed {
		b, found, err := s.read(archiveFile(allowed), s.maximum)
		if err != nil {
			return err
		}
		if found && allowed != key {
			total += int64(len(b))
		}
	}
	if total > s.totalMaximum-int64(len(body)) {
		return errors.New("finalcapture: total archive budget exceeded")
	}
	return s.publish(ctx, archiveFile(key), body)
}

// ReadArchive verifies the source's exact final object digest before transfer.
func ReadArchive(ctx context.Context, v controltransition.VerifiedPlan, object controltransition.CaptureObject) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p, err := v.Plan()
	if err != nil {
		return nil, err
	}
	key, err := controltransition.CaptureObjectKey(v, object.Role, object.Stream, object.ControlEpoch)
	if err != nil || key != object.Key {
		return nil, errors.New("finalcapture: invalid object identity")
	}
	rawHash, err := hex.DecodeString(object.SHA256)
	if err != nil || len(rawHash) != 32 || strings.ToLower(object.SHA256) != object.SHA256 {
		return nil, errors.New("finalcapture: invalid object digest")
	}
	dir, err := os.OpenRoot(p.Source.ArchiveDir)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	body, found, err := (&archiveStore{dir: dir}).read(archiveFile(key), p.Limits.MaxSnapshotBytes)
	if err != nil || !found || int64(len(body)) != object.Size || controltransition.Digest(body) != object.SHA256 {
		return nil, errors.New("finalcapture: archive differs from final receipt")
	}
	return body, nil
}
