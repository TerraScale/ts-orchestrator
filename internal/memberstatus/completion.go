package memberstatus

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
)

// RetainComplete saves only a receipt validated by the real member client. The
// request and final receipt survive host-process restarts before container removal.
func (s *FileStore) RetainComplete(envelope DrainEnvelope) error {
	if !envelope.verified {
		return ErrOutcomeUnknown
	}
	return s.locked(func() error {
		record, found, err := s.loadUnlocked()
		if err != nil || !found {
			return errors.Join(ErrStaleBinding, err)
		}
		wire, err := json.Marshal(envelope)
		if err != nil || len(wire) > maxEvidenceBytes {
			return errors.Join(ErrOutcomeUnknown, err)
		}
		if _, err := validateDrainEnvelope(wire, http.StatusOK, envelope.Nonce, Status{Process: envelope.Process}, record); err != nil {
			return err
		}
		if current, found, err := s.readCompleteUnlocked(record); err != nil {
			return err
		} else if found {
			if current.ReceiptSHA256 == nil || envelope.ReceiptSHA256 == nil || *current.ReceiptSHA256 != *envelope.ReceiptSHA256 {
				return ErrOperationConflict
			}
			return nil
		}
		file, err := os.CreateTemp(filepath.Dir(s.path), ".member-complete-*")
		if err != nil {
			return err
		}
		defer os.Remove(file.Name())
		if err := file.Chmod(0o600); err != nil {
			file.Close()
			return err
		}
		if _, err := file.Write(wire); err != nil {
			file.Close()
			return err
		}
		if err := file.Sync(); err != nil {
			file.Close()
			return err
		}
		if err := file.Close(); err != nil {
			return err
		}
		if err := os.Rename(file.Name(), s.path+".complete"); err != nil {
			return err
		}
		directory, err := os.Open(filepath.Dir(s.path))
		if err != nil {
			return err
		}
		defer directory.Close()
		return directory.Sync()
	})
}

// ReadComplete authenticates the retained receipt against the original durable
// request and survivor frontier without querying a process that has stopped.
func (s *FileStore) ReadComplete() (DrainEnvelope, bool, error) {
	var envelope DrainEnvelope
	var found bool
	err := s.locked(func() error {
		record, present, err := s.loadUnlocked()
		if err != nil {
			return err
		}
		if !present {
			return nil
		}
		envelope, found, err = s.readCompleteUnlocked(record)
		return err
	})
	return envelope, found, err
}

func (s *FileStore) readCompleteUnlocked(record DrainRecord) (DrainEnvelope, bool, error) {
	path := s.path + ".complete"
	before, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return DrainEnvelope{}, false, nil
	}
	if err != nil {
		return DrainEnvelope{}, false, err
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || !before.Mode().IsRegular() || stat.Uid != uint32(os.Geteuid()) || before.Mode().Perm() != 0o600 || before.Size() <= 0 || before.Size() > maxEvidenceBytes {
		return DrainEnvelope{}, false, errors.New("unsafe retained member drain receipt")
	}
	wire, err := os.ReadFile(path)
	if err != nil {
		return DrainEnvelope{}, false, err
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) || int64(len(wire)) != before.Size() {
		return DrainEnvelope{}, false, ErrStaleBinding
	}
	var envelope DrainEnvelope
	if err := json.Unmarshal(wire, &envelope, json.RejectUnknownMembers(true)); err != nil {
		return DrainEnvelope{}, false, err
	}
	verified, err := validateDrainEnvelope(wire, http.StatusOK, envelope.Nonce, Status{Process: envelope.Process}, record)
	if err != nil {
		return DrainEnvelope{}, false, fmt.Errorf("retained final drain receipt: %w", err)
	}
	return verified, true, nil
}
