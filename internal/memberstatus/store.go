package memberstatus

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

const maxRecordBytes = 4096

// FileStore is one durable drain intent per member seat. The caller supplies
// a root-owned 0700 directory on retained host state, outside ephemeral /run.
type FileStore struct{ path string }

func NewFileStore(path string) (*FileStore, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("member drain record path must be absolute and clean")
	}
	dir, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	stat, ok := dir.Sys().(*syscall.Stat_t)
	if !ok || !dir.IsDir() || stat.Uid != uint32(os.Geteuid()) || dir.Mode().Perm() != 0o700 {
		return nil, errors.New("member drain record directory ownership or mode is unsafe")
	}
	return &FileStore{path: path}, nil
}

func (s *FileStore) Load() (DrainRecord, bool, error) {
	var record DrainRecord
	var found bool
	err := s.locked(func() error {
		var err error
		record, found, err = s.loadUnlocked()
		return err
	})
	return record, found, err
}

func (s *FileStore) Create(record DrainRecord) error {
	if !record.valid(record.Request.Expected.Scope, record.Request.Expected.Authority) {
		return ErrStaleBinding
	}
	return s.locked(func() error {
		current, found, err := s.loadUnlocked()
		if err != nil {
			return err
		}
		if found {
			if current != record {
				return ErrOperationConflict
			}
			return nil
		}
		data, err := json.Marshal(record)
		if err != nil {
			return err
		}
		if len(data) > maxRecordBytes {
			return errors.New("member drain record exceeds bound")
		}
		directory := filepath.Dir(s.path)
		temp, err := os.CreateTemp(directory, ".member-drain-*")
		if err != nil {
			return err
		}
		defer os.Remove(temp.Name())
		if err := temp.Chmod(0o600); err != nil {
			_ = temp.Close()
			return err
		}
		if _, err := temp.Write(data); err != nil {
			_ = temp.Close()
			return err
		}
		if err := temp.Sync(); err != nil {
			_ = temp.Close()
			return err
		}
		if err := temp.Close(); err != nil {
			return err
		}
		if err := os.Rename(temp.Name(), s.path); err != nil {
			return err
		}
		dir, err := os.Open(directory)
		if err != nil {
			return err
		}
		defer dir.Close()
		return dir.Sync()
	})
}

func (s *FileStore) loadUnlocked() (DrainRecord, bool, error) {
	info, err := os.Lstat(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return DrainRecord{}, false, nil
	}
	if err != nil {
		return DrainRecord{}, false, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm() != 0o600 || info.Size() > maxRecordBytes {
		return DrainRecord{}, false, errors.New("unsafe member drain record")
	}
	file, err := os.Open(s.path)
	if err != nil {
		return DrainRecord{}, false, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxRecordBytes+1))
	if err != nil || len(data) > maxRecordBytes {
		return DrainRecord{}, false, errors.New("invalid member drain record length")
	}
	var record DrainRecord
	if err := decodeRequired(data, &record, "request.schema_version", "request.operation_id", "request.nonce",
		"request.expected.process.pid", "request.expected.process.start_nonce",
		"request.expected.scope.cluster_id", "request.expected.scope.tenant_id", "request.expected.scope.database_id",
		"request.expected.scope.shard_id", "request.expected.scope.member_id", "request.expected.scope.incarnation",
		"request.expected.authority.epoch", "request.expected.authority.configuration_id",
		"request.expected.authority.certificate_sha256", "request.expected.authority.tls_leaf_sha256",
		"survivor.member_id", "survivor.incarnation", "source_sequence"); err != nil {
		return DrainRecord{}, false, err
	}
	if !record.valid(record.Request.Expected.Scope, record.Request.Expected.Authority) {
		return DrainRecord{}, false, ErrStaleBinding
	}
	return record, true, nil
}

func (s *FileStore) locked(action func() error) error {
	lock, err := os.OpenFile(s.path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	info, err := lock.Stat()
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm() != 0o600 {
		return errors.New("unsafe member drain lock")
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		return fmt.Errorf("lock member drain: %w", err)
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	return action()
}
