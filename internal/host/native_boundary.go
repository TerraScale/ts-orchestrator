//go:build linux

package host

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const cgroup2SuperMagic = 0x63677270
const nativeSupervisorCPUWeight = 10000
const nativeWorkloadCPUWeight = 1000
const nativeCPUPeriod = uint64(100000)

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
	for _, controller := range []string{"memory", "cpu", "io"} {
		if !slices.Contains(strings.Fields(string(controllers)), controller) {
			return "", fmt.Errorf("native service cgroup lacks delegated %s controller", controller)
		}
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
	if err := enableCgroupCPUController(parent); err != nil {
		return fmt.Errorf("enable native service CPU controller: %w", err)
	}
	if err := enableCgroupIOController(parent); err != nil {
		return fmt.Errorf("enable native service I/O controller: %w", err)
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
	if err := enableCgroupCPUController(root); err != nil {
		return fmt.Errorf("enable native runner CPU controller: %w", err)
	}
	if err := enableCgroupIOController(root); err != nil {
		return fmt.Errorf("enable native runner I/O controller: %w", err)
	}
	if err := configureNativeSiblingResources(parent, root); err != nil {
		return err
	}
	quota, err := deriveNativeWorkloadCPUQuota(parent)
	if err != nil {
		return err
	}
	return setNativeCPUMax(filepath.Join(root, "cpu.max"), quota)
}

// The service unit's memory protection is an ancestor budget. Assign its
// exact configured amount to the supervisor subgroup, never to a workload.
// CPU weights reserve scheduling share under contention without throttling an
// otherwise idle host's database process.
func configureNativeSiblingResources(serviceRoot, runnerRoot string) error {
	supervisor := filepath.Join(serviceRoot, "supervisor")
	if err := requireNativeSupervisorSubgroup(supervisor); err != nil {
		return err
	}
	for _, name := range []string{"memory.min", "memory.low"} {
		value, err := readNativeResourceValue(filepath.Join(serviceRoot, name))
		if err != nil {
			return fmt.Errorf("read native service %s: %w", name, err)
		}
		if err := setNativeResourceValue(filepath.Join(supervisor, name), value); err != nil {
			return fmt.Errorf("reserve native supervisor %s: %w", name, err)
		}
		if err := setNativeResourceValue(filepath.Join(runnerRoot, name), 0); err != nil {
			return fmt.Errorf("remove native runner %s protection: %w", name, err)
		}
	}
	if err := setNativeResourceValue(filepath.Join(supervisor, "cpu.weight"), nativeSupervisorCPUWeight); err != nil {
		return fmt.Errorf("weight native supervisor CPU: %w", err)
	}
	if err := setNativeResourceValue(filepath.Join(runnerRoot, "cpu.weight"), nativeWorkloadCPUWeight); err != nil {
		return fmt.Errorf("weight native runner CPU: %w", err)
	}
	if err := setNativeIOWeight(filepath.Join(supervisor, "io.weight"), nativeSupervisorCPUWeight); err != nil {
		return fmt.Errorf("weight native supervisor I/O: %w", err)
	}
	if err := setNativeIOWeight(filepath.Join(runnerRoot, "io.weight"), nativeWorkloadCPUWeight); err != nil {
		return fmt.Errorf("weight native runner I/O: %w", err)
	}
	if err := setNativeSupervisorOOMPreference(supervisor); err != nil {
		return fmt.Errorf("protect native supervisor from systemd-oomd: %w", err)
	}
	if err := clearNativeWorkloadOOMPreference(runnerRoot); err != nil {
		return fmt.Errorf("keep native runner eligible for systemd-oomd: %w", err)
	}
	return nil
}

func requireNativeSupervisorSubgroup(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect native supervisor subgroup: %w", err)
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || owner.Uid != 0 {
		return errors.New("native supervisor subgroup must be a root-owned direct directory")
	}
	return nil
}

func configureNativeRoleResources(path string, quota uint64) error {
	for _, name := range []string{"memory.min", "memory.low"} {
		if err := setNativeResourceValue(filepath.Join(path, name), 0); err != nil {
			return fmt.Errorf("remove native workload %s protection: %w", name, err)
		}
	}
	if err := setNativeResourceValue(filepath.Join(path, "cpu.weight"), nativeWorkloadCPUWeight); err != nil {
		return fmt.Errorf("weight native workload CPU: %w", err)
	}
	if err := setNativeIOWeight(filepath.Join(path, "io.weight"), nativeWorkloadCPUWeight); err != nil {
		return fmt.Errorf("weight native workload I/O: %w", err)
	}
	if err := clearNativeWorkloadOOMPreference(path); err != nil {
		return fmt.Errorf("keep native workload eligible for systemd-oomd: %w", err)
	}
	return setNativeCPUMax(filepath.Join(path, "cpu.max"), quota)
}

func setNativeSupervisorOOMPreference(path string) error {
	if err := unix.Setxattr(path, "user.oomd_omit", []byte("1"), 0); err != nil {
		return err
	}
	if err := removeNativeOOMXattr(path, "user.oomd_avoid"); err != nil {
		return err
	}
	value, present, err := readNativeOOMXattr(path, "user.oomd_omit")
	if err != nil {
		return err
	}
	if !present || value != "1" {
		return errors.New("native supervisor omit xattr readback differs")
	}
	return nil
}

func clearNativeWorkloadOOMPreference(path string) error {
	for _, name := range []string{"user.oomd_omit", "user.oomd_avoid"} {
		if err := removeNativeOOMXattr(path, name); err != nil {
			return err
		}
		_, present, err := readNativeOOMXattr(path, name)
		if err != nil {
			return err
		}
		if present {
			return fmt.Errorf("native workload retained %s xattr", name)
		}
	}
	return nil
}

func removeNativeOOMXattr(path, name string) error {
	err := unix.Removexattr(path, name)
	if err != nil && !errors.Is(err, unix.ENODATA) {
		return err
	}
	return nil
}

func readNativeOOMXattr(path, name string) (string, bool, error) {
	var value [16]byte
	count, err := unix.Getxattr(path, name, value[:])
	if errors.Is(err, unix.ENODATA) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return string(value[:count]), true, nil
}

func deriveNativeWorkloadCPUQuota(serviceRoot string) (uint64, error) {
	var affinity unix.CPUSet
	if err := unix.SchedGetaffinity(0, &affinity); err != nil {
		return 0, fmt.Errorf("read native supervisor CPU affinity: %w", err)
	}
	return deriveNativeWorkloadCPUQuotaAt("/sys/fs/cgroup", serviceRoot, affinity.Count())
}

func deriveNativeWorkloadCPUQuotaAt(mountRoot, serviceRoot string, availableCPUs int) (uint64, error) {
	if availableCPUs <= 0 || availableCPUs > 1024 || !strings.HasPrefix(serviceRoot, mountRoot+string(filepath.Separator)) {
		return 0, errors.New("native CPU quota has invalid cgroup root or affinity")
	}
	available := uint64(availableCPUs) * nativeCPUPeriod
	for ancestor := serviceRoot; ancestor != mountRoot; ancestor = filepath.Dir(ancestor) {
		data, err := os.ReadFile(filepath.Join(ancestor, "cpu.max"))
		if err != nil {
			return 0, fmt.Errorf("read native ancestor CPU cap: %w", err)
		}
		fields := strings.Fields(string(data))
		if len(fields) != 2 {
			return 0, errors.New("native ancestor CPU cap is malformed")
		}
		period, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil || period < 1000 || period > 1000000 {
			return 0, errors.New("native ancestor CPU period is malformed")
		}
		if fields[0] != "max" {
			quota, err := strconv.ParseUint(fields[0], 10, 64)
			if err != nil || quota == 0 {
				return 0, errors.New("native ancestor CPU quota is malformed")
			}
			// Quotas greater than CPU affinity cannot narrow the effective cap.
			// This comparison also bounds multiplication in the next branch.
			if quota < uint64(availableCPUs)*period {
				available = min(available, quota*nativeCPUPeriod/period)
			}
		}
	}
	// Bound the aggregate runner and each role to 75% of the effective
	// ancestor/affinity budget. The remaining quarter is left for the manager.
	quota := available * 3 / 4
	if quota < 1000 || quota >= available {
		return 0, errors.New("native CPU budget leaves no safe supervisor headroom")
	}
	return quota, nil
}

func setNativeCPUMax(path string, quota uint64) error {
	if quota < 1000 {
		return errors.New("native CPU cap is below the kernel minimum")
	}
	want := strconv.FormatUint(quota, 10) + " " + strconv.FormatUint(nativeCPUPeriod, 10)
	if err := os.WriteFile(path, []byte(want), 0600); err != nil {
		return err
	}
	readback, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if strings.Join(strings.Fields(string(readback)), " ") != want {
		return errors.New("native CPU cap readback differs from requested value")
	}
	return nil
}

func validateNativeSupervisorReservation(serviceRoot, runnerRoot string, signedReserve uint64) error {
	return validateNativeSupervisorReservationAt("/sys/fs/cgroup", serviceRoot, runnerRoot, signedReserve)
}

func validateNativeSupervisorReservationAt(mountRoot, serviceRoot, runnerRoot string, signedReserve uint64) error {
	if !filepath.IsAbs(serviceRoot) || filepath.Dir(runnerRoot) != serviceRoot ||
		!strings.HasPrefix(serviceRoot, mountRoot+string(filepath.Separator)) {
		return errors.New("native supervisor reservation has invalid cgroup roots")
	}
	if signedReserve == 0 || signedReserve%uint64(os.Getpagesize()) != 0 {
		return errors.New("managed system reserve must be positive and page-aligned")
	}
	supervisor := filepath.Join(serviceRoot, "supervisor")
	minimum, err := readNativeResourceValue(filepath.Join(serviceRoot, "memory.min"))
	if err != nil {
		return fmt.Errorf("read native service memory.min: %w", err)
	}
	low, err := readNativeResourceValue(filepath.Join(serviceRoot, "memory.low"))
	if err != nil {
		return fmt.Errorf("read native service memory.low: %w", err)
	}
	if minimum == 0 || minimum%uint64(os.Getpagesize()) != 0 || low%uint64(os.Getpagesize()) != 0 ||
		minimum > low || low > signedReserve {
		return errors.New("native service memory protection is absent or exceeds the signed reserve")
	}
	for ancestor := filepath.Dir(serviceRoot); ancestor != mountRoot; ancestor = filepath.Dir(ancestor) {
		for _, protection := range []struct {
			name string
			want uint64
		}{{"memory.min", minimum}, {"memory.low", low}} {
			value, err := readNativeResourceValue(filepath.Join(ancestor, protection.name))
			if err != nil {
				return fmt.Errorf("read native ancestor %s: %w", protection.name, err)
			}
			if value < protection.want {
				return fmt.Errorf("native ancestor %s does not preserve supervisor reservation", protection.name)
			}
		}
	}
	for _, name := range []string{"memory.min", "memory.low"} {
		serviceValue, err := readNativeResourceValue(filepath.Join(serviceRoot, name))
		if err != nil {
			return err
		}
		supervisorValue, err := readNativeResourceValue(filepath.Join(supervisor, name))
		if err != nil {
			return err
		}
		if supervisorValue != serviceValue {
			return fmt.Errorf("native supervisor %s differs from service protection", name)
		}
		runnerValue, err := readNativeResourceValue(filepath.Join(runnerRoot, name))
		if err != nil {
			return err
		}
		if runnerValue != 0 {
			return fmt.Errorf("native runner retained %s protection", name)
		}
	}
	return nil
}

func setNativeIOWeight(path string, value uint64) error {
	want := strconv.FormatUint(value, 10)
	if err := os.WriteFile(path, []byte("default "+want), 0600); err != nil {
		return err
	}
	readback, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	for line := range strings.SplitSeq(strings.TrimSpace(string(readback)), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "default" && fields[1] == want {
			return nil
		}
	}
	return errors.New("native cgroup I/O weight readback differs from requested value")
}

func readNativeResourceValue(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid native cgroup resource value: %w", err)
	}
	return value, nil
}

func setNativeResourceValue(path string, value uint64) error {
	if err := os.WriteFile(path, []byte(strconv.FormatUint(value, 10)), 0600); err != nil {
		return err
	}
	readback, err := readNativeResourceValue(path)
	if err != nil {
		return err
	}
	if readback != value {
		return fmt.Errorf("native cgroup resource readback %d differs from requested %d", readback, value)
	}
	return nil
}

// Only the configured workload group may traverse the runner's cgroups.
// Cgroup control files retain their kernel-provided root ownership and modes.
func configureTenantCgroupDirectory(path string, identity WorkloadIdentity) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || owner.Uid != 0 {
		return fmt.Errorf("native cgroup %s must be a root-owned directory", path)
	}
	if err := os.Chmod(path, 0700); err != nil {
		return fmt.Errorf("seal native cgroup %s before assigning workload group: %w", path, err)
	}
	if err := os.Chown(path, 0, int(identity.GID)); err != nil {
		return fmt.Errorf("assign native cgroup %s to workload group: %w", path, err)
	}
	if err := os.Chmod(path, 0710); err != nil {
		return fmt.Errorf("set native cgroup %s traversal mode: %w", path, err)
	}
	info, err = os.Lstat(path)
	if err != nil {
		return err
	}
	owner, ok = info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		owner.Uid != 0 || owner.Gid != identity.GID || info.Mode().Perm() != 0710 {
		return fmt.Errorf("native cgroup %s did not retain root-owned workload-group traversal", path)
	}
	return nil
}

func tenantCgroupMode(info os.FileInfo, identity WorkloadIdentity) (uint32, error) {
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("cannot inspect native cgroup ownership")
	}
	permissions := uint32(info.Mode().Perm())
	switch {
	case owner.Uid == identity.UID:
		return permissions >> 6 & 7, nil
	case owner.Gid == identity.GID:
		return permissions >> 3 & 7, nil
	default:
		return permissions & 7, nil
	}
}

// The workload has no supplementary groups or capabilities, so these mode
// checks match the credentials it will use after the native helper drops root.
func validateTenantCgroupTraversal(path string, identity WorkloadIdentity) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("native cgroup path must be absolute and clean")
	}
	for directory := path; ; directory = filepath.Dir(directory) {
		info, err := os.Lstat(directory)
		if err != nil {
			return fmt.Errorf("inspect native cgroup ancestor %s: %w", directory, err)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("native cgroup ancestor %s is not a directory", directory)
		}
		mode, err := tenantCgroupMode(info, identity)
		if err != nil {
			return fmt.Errorf("inspect native cgroup ancestor %s: %w", directory, err)
		}
		if mode&1 == 0 || mode&2 != 0 {
			return fmt.Errorf("workload cannot safely traverse native cgroup ancestor %s", directory)
		}
		if directory == "/" {
			return nil
		}
	}
}

func validateTenantCgroupAccounting(rolePath string, identity WorkloadIdentity) error {
	if err := validateTenantCgroupTraversal(rolePath, identity); err != nil {
		return err
	}
	for _, name := range []string{"memory.current", "memory.max"} {
		path := filepath.Join(rolePath, name)
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("inspect workload memory accounting %s: %w", path, err)
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || owner.Uid != 0 {
			return fmt.Errorf("workload memory accounting %s is not a root-owned file", path)
		}
		mode, err := tenantCgroupMode(info, identity)
		if err != nil {
			return fmt.Errorf("inspect workload memory accounting %s: %w", path, err)
		}
		if mode&4 == 0 || mode&2 != 0 {
			return fmt.Errorf("workload cannot safely read memory accounting %s", path)
		}
	}
	for _, path := range []string{
		filepath.Join(filepath.Dir(rolePath), "cgroup.subtree_control"),
		filepath.Join(rolePath, "cgroup.procs"),
	} {
		if err := validateTenantCgroupControl(path, identity); err != nil {
			return err
		}
	}
	return nil
}

func validateTenantCgroupControl(path string, identity WorkloadIdentity) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect native cgroup control %s: %w", path, err)
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || owner.Uid != 0 {
		return fmt.Errorf("native cgroup control %s is not a root-owned file", path)
	}
	mode, err := tenantCgroupMode(info, identity)
	if err != nil {
		return fmt.Errorf("inspect native cgroup control %s: %w", path, err)
	}
	if mode&2 != 0 {
		return fmt.Errorf("workload can write native cgroup control %s", path)
	}
	return nil
}
