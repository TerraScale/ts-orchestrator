//go:build linux

package cli

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/selfupdate"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

// hostConfigFile is the host agent's config, which names its runtime roots.
const hostConfigFile = "/etc/terrascale-orchestrator/host.json"

// memoryRuntime mounts unit's runtime secret directories as tmpfs before its
// process starts, deleting what an earlier release kept there on disk: the
// host's role NATS identities and TerraBase member TLS key are issued again,
// its _FILE secrets are read again from Vault, and a staged material
// generation is staged again. A directory already in memory is left alone.
// The units' own sandboxes already let them write these paths, so no unit
// setting changes. The host agent refuses to write them anywhere else.
var memoryRuntime = func(unit string) error {
	switch unit {
	case selfupdate.HostUnit:
		// Written first, so a mount that fails below fails the host closed.
		if err := os.WriteFile(selfupdate.MemoryPrepareMarker, nil, 0o644); err != nil {
			return err
		}
		host, err := readHostRuntime(hostConfigFile)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		var errs []error
		if host.ManagedRuntimeRoot != "" {
			errs = append(errs, mountRuntime(filepath.Join(host.ManagedRuntimeRoot, "roles"), 0, host.WorkloadGID, 0o750, ",size=16m"))
		}
		if host.TerraBaseRoot != "" {
			errs = append(errs, mountRuntime(filepath.Join(host.TerraBaseRoot, "tls"), 0, host.WorkloadGID, 0o750, ",size=16m"))
		}
		return errors.Join(errs...)
	case selfupdate.ControllerUnit:
		account, err := user.Lookup("terrascale-orchestrator")
		if err != nil {
			return err
		}
		uid, uidErr := strconv.ParseUint(account.Uid, 10, 32)
		gid, gidErr := strconv.ParseUint(account.Gid, 10, 32)
		if uidErr != nil || gidErr != nil {
			return errors.New("controller service UID/GID is invalid")
		}
		// A staged generation may be far larger than 16 MiB: keep tmpfs's
		// default cap, as the credential directory does.
		return mountRuntime(bootstrapstart.GenerationSpoolDirectory, uint32(uid), uint32(gid), 0o700, "")
	}
	return nil
}

type hostRuntime struct {
	ManagedRuntimeRoot string `json:"managed_runtime_root"`
	TerraBaseRoot      string `json:"terrabase_root"`
	WorkloadGID        uint32 `json:"workload_gid"`
}

func readHostRuntime(path string) (hostRuntime, error) {
	file, err := os.Open(path)
	if err != nil {
		return hostRuntime{}, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxRoleConfigBytes+1))
	if err != nil || len(data) > maxRoleConfigBytes {
		return hostRuntime{}, errors.Join(err, errors.New("host config is unreadable or too large"))
	}
	var config struct {
		Host hostRuntime `json:"host"`
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return hostRuntime{}, err
	}
	for _, root := range []string{config.Host.ManagedRuntimeRoot, config.Host.TerraBaseRoot} {
		if root != "" && (!filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/") {
			return hostRuntime{}, fmt.Errorf("host runtime root %q is not clean and absolute", root)
		}
	}
	if config.Host.WorkloadGID == 0 && (config.Host.ManagedRuntimeRoot != "" || config.Host.TerraBaseRoot != "") {
		return hostRuntime{}, errors.New("host config has no workload group")
	}
	return config.Host, nil
}

// mountRuntime mounts an owner-only tmpfs at path unless one is there. Swap
// must be off, so nothing in it is paged to disk. Root runs it on paths a
// service or workload owns, so no component may be a symlink, and every step
// acts on the opened directory, never on its name again.
func mountRuntime(path string, uid, gid uint32, mode os.FileMode, size string) error {
	if !vaultsecret.SwapOff() {
		return errors.New("runtime secrets need swap disabled")
	}
	fd, err := openDirectoryNoFollow(path, uint32(mode.Perm()))
	if err != nil {
		return err
	}
	dir := os.NewFile(uintptr(fd), path)
	defer dir.Close()
	var fs unix.Statfs_t
	if err := unix.Fstatfs(fd, &fs); err != nil {
		return err
	}
	if fs.Type == unix.TMPFS_MAGIC {
		// Already in memory, perhaps beneath a parent tmpfs: give it its owner.
		if err := dir.Chown(int(uid), int(gid)); err != nil {
			return err
		}
		return dir.Chmod(mode)
	}
	if err := clearDirectory(fd); err != nil {
		return err
	}
	return unix.Mount("tmpfs", fmt.Sprintf("/proc/self/fd/%d", fd), "tmpfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC,
		fmt.Sprintf("mode=%o,uid=%d,gid=%d%s", mode.Perm(), uid, gid, size))
}

// openDirectoryNoFollow opens the clean absolute directory path, creating
// missing components with mode, and refuses a symlink in any component.
func openDirectoryNoFollow(path string, mode uint32) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return -1, fmt.Errorf("runtime directory %q is not clean and absolute", path)
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, name := range strings.Split(path[1:], "/") {
		if err := unix.Mkdirat(fd, name, mode); err != nil && !errors.Is(err, unix.EEXIST) {
			unix.Close(fd)
			return -1, err
		}
		next, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if err != nil {
			return -1, fmt.Errorf("open %s without following symlinks: %w", path, err)
		}
		fd = next
	}
	return fd, nil
}

// clearDirectory deletes everything in the directory fd, removing symlinks
// themselves and never following one.
func clearDirectory(fd int) error {
	dup, err := unix.Dup(fd)
	if err != nil {
		return err
	}
	dir := os.NewFile(uintptr(dup), "")
	names, err := dir.Readdirnames(-1)
	dir.Close()
	if err != nil {
		return err
	}
	for _, name := range names {
		err := unix.Unlinkat(fd, name, 0)
		if errors.Is(err, unix.EISDIR) {
			child, openErr := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if openErr != nil {
				return openErr
			}
			err = clearDirectory(child)
			unix.Close(child)
			if err == nil {
				err = unix.Unlinkat(fd, name, unix.AT_REMOVEDIR)
			}
		}
		if err != nil {
			return err
		}
	}
	return nil
}
