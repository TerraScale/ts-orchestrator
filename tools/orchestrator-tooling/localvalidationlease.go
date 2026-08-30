// Port of tools/TerraScale.Orchestrator.Tooling/LocalValidationLease.cs: a
// single-writer lock file in the temp directory that serializes local
// validation runs and recovers stale holders after a bulk stop.
package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// LocalValidationLease mirrors the C# LocalValidationLease class. Acquire maps
// the C# FileShare.None stream onto an exclusive flock held for the process
// lifetime.
type LocalValidationLease struct {
	file *os.File
}

// AcquireLocalValidationLease mirrors LocalValidationLease.Acquire; an empty
// scope selects the user-name scope used by the development attestation.
func AcquireLocalValidationLease(scope string) (*LocalValidationLease, error) {
	if scope == "" {
		scope = envUserName()
	}
	path := filepath.Join(os.TempDir(), fmt.Sprintf("terrascale-orchestrator-validation-%s.lock", scope))
	lease, err := acquireExclusiveLease(path)
	if err == nil {
		return lease, nil
	}
	// The C# code only enters the recovery branch for IOException; other
	// failures (for example a read-only temp directory) propagate unchanged.
	if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
		return nil, err
	}
	holder, readable := tryReadLeaseHolder(path)
	holderAlive := readable && holder != nil && isProcessAlive(*holder)
	if !readable || holderAlive {
		holderDisplay := "unknown"
		if readable && holder != nil {
			holderDisplay = strconv.Itoa(*holder)
		}
		return nil, fmt.Errorf(
			"Another TerraScale Orchestrator test or lab run is already active (holder process %s).", holderDisplay)
	}

	holderValue := 0
	if holder != nil {
		holderValue = *holder
	}
	if removeErr := os.Remove(path); removeErr != nil {
		return nil, fmt.Errorf(
			"A stale TerraScale Orchestrator validation lease from process %d could not be cleared: %s", holderValue, path)
	}

	lease, retryErr := acquireExclusiveLease(path)
	if retryErr != nil {
		return nil, errors.New("Another TerraScale Orchestrator test or lab run is already active.")
	}
	return lease, nil
}

func acquireExclusiveLease(path string) (*LocalValidationLease, error) {
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_SYNC, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, err
	}
	if err := file.Truncate(0); err != nil {
		file.Close()
		return nil, err
	}
	if _, err := file.Write([]byte(strconv.Itoa(os.Getpid()))); err != nil {
		file.Close()
		return nil, err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return nil, err
	}
	return &LocalValidationLease{file: file}, nil
}

func tryReadLeaseHolder(path string) (*int, bool) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	parsed, err := strconv.Atoi(strings.TrimSpace(string(content)))
	if err != nil {
		return nil, true
	}
	return &parsed, true
}

func isProcessAlive(processId int) bool {
	if err := syscall.Kill(processId, 0); err == nil || errors.Is(err, syscall.EPERM) {
		return true
	}
	return false
}

// Close mirrors LocalValidationLease.Dispose.
func (lease *LocalValidationLease) Close() error {
	if lease == nil || lease.file == nil {
		return nil
	}
	err := lease.file.Close()
	lease.file = nil
	return err
}
