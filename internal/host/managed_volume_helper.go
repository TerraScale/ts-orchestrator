//go:build linux

package host

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

const volumeInitSocketPath = "/run/terrascale-orchestrator-volume-init.sock"

const ()

func managedVolumeHasExactClaim(paths managedRuntimePaths, launch ManagedMemberLaunch) (bool, error) {
	path := filepath.Join(paths.mount, managedVolumeClaimName)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		owner.Uid != 0 || info.Mode().Perm() != 0600 || info.Size() > 4096 {
		return false, errors.New("managed volume claim has unsafe metadata")
	}
	wire, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	if !bytes.Equal(wire, managedVolumeClaimBytes(launch)) {
		return false, errors.New("managed volume claim differs from signed member")
	}
	return true, nil
}
