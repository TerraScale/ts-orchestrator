//go:build linux

package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const maxManagedCredentialStateBytes = 512 << 10

type managedCredentialState struct {
	Version              uint64 `json:"version"`
	Generation           uint64 `json:"generation"`
	InitialReceiptSHA256 string `json:"initial_receipt_sha256"`
	RegistrySHA256       string `json:"registry_sha256"`
	Registry             []byte `json:"registry"`
	Signature            string `json:"signature"`
}

func decodeManagedCredentialState(data []byte) (managedCredentialState, error) {
	var state managedCredentialState
	if len(data) == 0 || len(data) > maxManagedCredentialStateBytes ||
		json.Unmarshal(data, &state, json.RejectUnknownMembers(true)) != nil ||
		state.Version != 1 || state.Generation == 0 ||
		!lowerHex(state.InitialReceiptSHA256, 64) || !lowerHex(state.RegistrySHA256, 64) ||
		len(state.Registry) == 0 || len(state.Registry) > 256<<10 || state.Signature == "" {
		return managedCredentialState{}, errors.New("managed credential generation is invalid")
	}
	sum := sha256.Sum256(state.Registry)
	if hex.EncodeToString(sum[:]) != state.RegistrySHA256 {
		return managedCredentialState{}, errors.New("managed credential registry digest changed")
	}
	return state, nil
}

func readManagedCredentialState(path string, identity WorkloadIdentity) ([]byte, managedCredentialState, error) {
	before, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, managedCredentialState{}, nil
	}
	if err != nil {
		return nil, managedCredentialState{}, err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, managedCredentialState{}, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	after, err := file.Stat()
	if err != nil {
		return nil, managedCredentialState{}, err
	}
	stat, ok := after.Sys().(*syscall.Stat_t)
	if !ok || !before.Mode().IsRegular() || !after.Mode().IsRegular() ||
		!os.SameFile(before, after) || stat.Uid != 0 || stat.Gid != identity.GID ||
		stat.Mode&07777 != 0440 || after.Size() <= 0 || after.Size() > maxManagedCredentialStateBytes {
		return nil, managedCredentialState{}, errors.New("managed credential state has unsafe ownership")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxManagedCredentialStateBytes+1))
	if err != nil || int64(len(data)) != after.Size() {
		return nil, managedCredentialState{}, errors.New("managed credential state changed while reading")
	}
	state, err := decodeManagedCredentialState(data)
	return data, state, err
}

// installManagedCredentialState preserves a durable monotonic local floor. The
// controller's signed R3 state is fetched before launch, even after recovery.
func installManagedCredentialState(directory string, data []byte, identity WorkloadIdentity) (uint64, bool, error) {
	state, err := decodeManagedCredentialState(data)
	if err != nil {
		return 0, false, err
	}
	path := filepath.Join(directory, managedCredentialFileName)
	oldBytes, old, err := readManagedCredentialState(path, identity)
	if err != nil {
		return 0, false, err
	}
	if old.Generation > state.Generation || old.Generation != 0 &&
		old.InitialReceiptSHA256 != state.InitialReceiptSHA256 {
		return 0, false, errors.New("managed credential generation regressed")
	}
	if old.Generation == state.Generation {
		if !bytes.Equal(oldBytes, data) {
			return 0, false, errors.New("managed credential generation was replayed with different bytes")
		}
		return state.Generation, false, nil
	}
	dirFD, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, false, err
	}
	defer unix.Close(dirFD)
	token, err := randomID()
	if err != nil {
		return 0, false, err
	}
	temporary := "." + managedCredentialFileName + "." + token
	fileFD, err := unix.Openat(dirFD, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0440)
	if err != nil {
		return 0, false, err
	}
	defer unix.Unlinkat(dirFD, temporary, 0)
	file := os.NewFile(uintptr(fileFD), temporary)
	if err := unix.Fchown(fileFD, 0, int(identity.GID)); err != nil {
		file.Close()
		return 0, false, err
	}
	if err := file.Chmod(0440); err != nil {
		file.Close()
		return 0, false, err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return 0, false, err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return 0, false, err
	}
	if err := file.Close(); err != nil {
		return 0, false, err
	}
	if err := unix.Renameat(dirFD, temporary, dirFD, managedCredentialFileName); err != nil {
		return 0, false, err
	}
	if err := unix.Fsync(dirFD); err != nil {
		return 0, false, fmt.Errorf("sync managed credential generation: %w", err)
	}
	return state.Generation, true, nil
}

func (a *Agent) fetchManagedCredentials(ctx context.Context, desired Desired, registration Registration) (uint64, uint64, bool, error) {
	paths, err := runtimePaths(a.cfg.ManagedRuntimeRoot, *desired.ManagedMember)
	if err != nil {
		return 0, 0, false, err
	}
	_, previous, err := readManagedCredentialState(filepath.Join(paths.material, managedCredentialFileName), a.cfg.WorkloadIdentity)
	if err != nil {
		return 0, 0, false, err
	}
	fingerprint, err := desiredFingerprint(desired)
	if err != nil {
		return 0, 0, false, err
	}
	data, _, err := a.downloadManagedFile(ctx, desired, registration, fingerprint, managedCredentialFileName)
	if err != nil {
		return 0, 0, false, err
	}
	generation, changed, err := installManagedCredentialState(paths.material, data, a.cfg.WorkloadIdentity)
	return previous.Generation, generation, changed, err
}

// The optional runner capability only signals the process recorded for this
// role. Native status must then prove that same process installed the overlay.
func (a *Agent) reloadManagedCredentials(ctx context.Context, desired Desired, socket string, generation uint64) error {
	reloader, ok := a.runner.(interface {
		SignalManagedReload(context.Context, string) error
	})
	if !ok {
		return errors.New("native runner cannot signal a managed credential reload")
	}
	reloadCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := reloader.SignalManagedReload(reloadCtx, desired.Role); err != nil {
		return fmt.Errorf("signal managed credential reload: %w", err)
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		status, _, _, err := readManagedStatus(reloadCtx, a.runner, desired, socket)
		if err == nil && status.CredentialGeneration == generation {
			return nil
		}
		select {
		case <-reloadCtx.Done():
			return fmt.Errorf("native credential generation %d was not observed: %w", generation, reloadCtx.Err())
		case <-ticker.C:
		}
	}
}

func (c *Controller) verifyCredentialProtocol(ctx context.Context, request request, registration Registration) error {
	if registration.ManagedPlacement == nil || c.credentialFloor == nil {
		return nil
	}
	generation, err := c.credentialFloor(ctx, registration)
	if err != nil || generation == 0 {
		return errors.New("managed credential floor is unavailable")
	}
	if generation > 1 && request.CredentialProtocol < 1 {
		return errors.New("host credential protocol cannot enforce the committed generation")
	}
	return nil
}
