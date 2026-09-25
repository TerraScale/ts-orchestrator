//go:build linux

package host

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const cgroup2SuperMagic = 0x63677270

var errNativeSubgroupRequired = errors.New("native runtime requires systemd DelegateSubgroup=supervisor")

func validateWorkloadIdentity(identity WorkloadIdentity) error {
	if identity.UID == 0 || identity.GID == 0 {
		return errors.New("native workload requires nonzero UID and GID")
	}
	if os.Geteuid() == int(identity.UID) || os.Getegid() == int(identity.GID) {
		return errors.New("native workload identity must differ from supervisor")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("native supervisor requires root to drop workload identity: %w", os.ErrPermission)
	}
	return requireNativeSupervisorKillCapability()
}

// Linux checks the dying parent's signal permission when delivering
// PR_SET_PDEATHSIG. Root without CAP_KILL cannot signal a different tenant UID.
func requireNativeSupervisorKillCapability() error {
	var capabilities [2]unix.CapUserData
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	if err := unix.Capget(&header, &capabilities[0]); err != nil {
		return fmt.Errorf("inspect native supervisor capabilities: %w", err)
	}
	mask := uint32(1 << unix.CAP_KILL)
	if capabilities[0].Effective&mask == 0 || capabilities[0].Permitted&mask == 0 {
		return fmt.Errorf("native supervisor requires effective and permitted CAP_KILL for tenant parent-death signal: %w", os.ErrPermission)
	}
	bounded, err := unix.PrctlRetInt(unix.PR_CAPBSET_READ, unix.CAP_KILL, 0, 0, 0)
	if err != nil {
		return fmt.Errorf("inspect native supervisor CAP_KILL bound: %w", err)
	}
	if bounded != 1 {
		return fmt.Errorf("native supervisor requires bounded CAP_KILL for tenant parent-death signal: %w", os.ErrPermission)
	}
	return nil
}

func validatePrivateStateRoot(root string) error {
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 || owner.Uid != uint32(os.Geteuid()) {
		return errors.New("native state root must be a private supervisor-owned directory")
	}
	return nil
}

func validateTenantExecutable(path string, identity WorkloadIdentity) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("native executable path must be absolute and clean")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || owner.Uid != 0 || owner.Gid != identity.GID || info.Mode().Perm()&0010 == 0 || info.Mode().Perm()&0022 != 0 {
		return errors.New("native executable must be root-owned, tenant-group executable, and unwritable by tenants")
	}
	for directory := filepath.Dir(path); ; directory = filepath.Dir(directory) {
		info, err := os.Lstat(directory)
		if err != nil {
			return err
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		mode := info.Mode().Perm()
		if !ok || !info.IsDir() {
			return fmt.Errorf("native executable parent %s is not a directory", directory)
		}
		writableByTenant := mode&0022 != 0 && (info.Mode()&os.ModeSticky == 0 || owner.Uid != 0)
		if owner.Uid != 0 || writableByTenant || mode&0001 == 0 && (owner.Gid != identity.GID || mode&0010 == 0) {
			return fmt.Errorf("native executable parent %s is not safely traversable by tenant", directory)
		}
		if directory == "/" {
			break
		}
	}
	return nil
}

// The supervisor runs in systemd's subgroup, leaving its delegated service
// cgroup process-free so domain controllers can be enabled for sibling roles.
func nativeCgroupRoot(stateRoot string) (string, error) {
	var filesystem syscall.Statfs_t
	if err := syscall.Statfs("/sys/fs/cgroup", &filesystem); err != nil {
		return "", fmt.Errorf("inspect cgroup mount: %w", err)
	}
	if filesystem.Type != cgroup2SuperMagic {
		return "", errors.New("native runtime requires unified cgroup v2")
	}
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", fmt.Errorf("read supervisor cgroup: %w", err)
	}
	var membership string
	for line := range strings.SplitSeq(strings.TrimSpace(string(data)), "\n") {
		path, ok := strings.CutPrefix(line, "0::")
		if !ok {
			continue
		}
		if membership != "" {
			return "", errors.New("native runtime has multiple unified cgroup memberships")
		}
		membership = path
	}
	if membership == "" {
		return "", errors.New("native runtime cannot identify its delegated service cgroup")
	}
	parent, err := nativeDelegatedServiceRoot(membership)
	if err != nil {
		return "", err
	}
	if err := requireEmptyCgroup(parent); err != nil {
		return "", fmt.Errorf("native service cgroup must be process-free: %w", err)
	}
	controllers, err := os.ReadFile(filepath.Join(parent, "cgroup.controllers"))
	if err != nil {
		return "", fmt.Errorf("read delegated service controllers: %w", err)
	}
	if !slices.Contains(strings.Fields(string(controllers)), "memory") {
		return "", errors.New("native service cgroup lacks delegated memory controller")
	}
	return filepath.Join(parent, nativeCgroupName(stateRoot)), nil
}

func nativeDelegatedServiceRoot(membership string) (string, error) {
	if !filepath.IsAbs(membership) || filepath.Clean(membership) != membership {
		return "", errNativeSubgroupRequired
	}
	service, ok := strings.CutSuffix(membership, "/supervisor")
	if !ok || service == "" || service == "/" || !strings.HasSuffix(filepath.Base(service), ".service") {
		return "", errNativeSubgroupRequired
	}
	return filepath.Join("/sys/fs/cgroup", service), nil
}

func requireEmptyCgroup(path string) error {
	procs, err := os.ReadFile(filepath.Join(path, "cgroup.procs"))
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(procs)) != "" {
		return errors.New("cgroup contains processes")
	}
	return nil
}

func prepareNativeCgroupRoot(root string) error {
	parent := filepath.Dir(root)
	if err := requireEmptyCgroup(parent); err != nil {
		return fmt.Errorf("native service cgroup must stay process-free: %w", err)
	}
	if err := enableCgroupMemoryController(parent); err != nil {
		return fmt.Errorf("enable native service memory controller: %w", err)
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return fmt.Errorf("create native runner cgroup: %w", err)
	}
	if err := requireEmptyCgroup(root); err != nil {
		return fmt.Errorf("native runner cgroup must be process-free: %w", err)
	}
	if err := enableCgroupMemoryController(root); err != nil {
		return fmt.Errorf("enable native runner memory controller: %w", err)
	}
	return nil
}
