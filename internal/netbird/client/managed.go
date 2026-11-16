package client

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

var managedVersionPattern = regexp.MustCompile(`^0\.80\.[0-9]+$`)

func ValidateManagedVersion(version string) error {
	if !managedVersionPattern.MatchString(version) {
		return errors.New("managed NetBird pin must be a 0.80.x release")
	}
	return nil
}

type ManagedOptions struct {
	// BinaryPath is an already staged artifact on nodes without Internet
	// access. It is verified against the pin before any service mutation.
	BinaryPath    string
	TransactionID string
	Bootstrap     bool
	// Prepare records the existing journal under the operation lock before
	// any installation effects, so the worker can prove a failed first attempt.
	Prepare func(ManagedResult) error
}

type ManagedResult struct {
	TransactionID    string    `json:"transaction_id"`
	Bootstrap        bool      `json:"bootstrap,omitempty"`
	Version          string    `json:"version"`
	PreviousVersion  string    `json:"previous_version,omitempty"`
	RollbackDeadline time.Time `json:"rollback_deadline"`
	Pending          bool      `json:"pending"`
	RolledBack       bool      `json:"rolled_back,omitempty"`
}

func syncManagedDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func installManagedBinary(source, destination, digest, architecture string) error {
	if info, err := os.Lstat(destination); err == nil && !info.Mode().IsRegular() {
		return errors.New("managed NetBird destination must be a direct regular file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(destination), ".netbird-managed-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err := copyFile(source, file.Name(), 0600); err != nil {
		return err
	}
	// The spool may change after its first verification. Verify the private
	// copy before making any bytes executable at the live service path.
	if err := VerifyBinary(file.Name(), digest, architecture); err != nil {
		return err
	}
	if err := file.Chmod(0755); err != nil {
		return err
	}
	err = errors.Join(file.Sync(), file.Close())
	if err != nil {
		return err
	}
	if err := os.Rename(file.Name(), destination); err != nil {
		return err
	}
	return syncManagedDirectory(filepath.Dir(destination))
}
