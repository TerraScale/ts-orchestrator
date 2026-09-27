//go:build linux

package host

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestNativeOOMPreferenceAppliesOnlyToSupervisor(t *testing.T) {
	root := t.TempDir()
	supervisor := filepath.Join(root, "supervisor")
	role := filepath.Join(root, "role")
	for _, path := range []string{supervisor, role} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := unix.Setxattr(role, "user.oomd_omit", []byte("1"), 0); errors.Is(err, unix.EOPNOTSUPP) {
		t.Skip("test filesystem does not support user xattrs")
	} else if err != nil {
		t.Fatal(err)
	}
	if err := unix.Setxattr(role, "user.oomd_avoid", []byte("1"), 0); err != nil {
		t.Fatal(err)
	}
	if err := setNativeSupervisorOOMPreference(supervisor); err != nil {
		t.Fatal(err)
	}
	if err := clearNativeWorkloadOOMPreference(role); err != nil {
		t.Fatal(err)
	}
	if value, present, err := readNativeOOMXattr(supervisor, "user.oomd_omit"); err != nil || !present || value != "1" {
		t.Fatalf("supervisor omit = %q, present=%t, %v", value, present, err)
	}
	for _, name := range []string{"user.oomd_omit", "user.oomd_avoid"} {
		if value, present, err := readNativeOOMXattr(role, name); err != nil || present {
			t.Fatalf("role %s = %q, present=%t, %v", name, value, present, err)
		}
	}
}

func TestNativeSupervisorReservationFollowsAncestorsAndSignedBound(t *testing.T) {
	mount := t.TempDir()
	ancestor := filepath.Join(mount, "system.slice")
	service := filepath.Join(ancestor, "host.service")
	supervisor := filepath.Join(service, "supervisor")
	runner := filepath.Join(service, "terrascale-host-test")
	for _, path := range []string{supervisor, runner} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	const minimum = uint64(256 << 20)
	const low = uint64(512 << 20)
	write := func(directory, name string, value uint64) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(directory, name), []byte(strconv.FormatUint(value, 10)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{ancestor, service, supervisor} {
		write(path, "memory.min", minimum)
		write(path, "memory.low", low)
	}
	write(runner, "memory.min", 0)
	write(runner, "memory.low", 0)
	check := func(wantValid bool) {
		t.Helper()
		err := validateNativeSupervisorReservationAt(mount, service, runner, 1<<30)
		if (err == nil) != wantValid {
			t.Fatalf("reservation valid = %t, error = %v", wantValid, err)
		}
	}
	check(true)
	write(ancestor, "memory.min", 0)
	check(false)
	write(ancestor, "memory.min", minimum)
	write(supervisor, "memory.low", 0)
	check(false)
	write(supervisor, "memory.low", low)
	write(runner, "memory.min", minimum)
	check(false)
	write(runner, "memory.min", 0)
	write(service, "memory.low", 2<<30)
	check(false)
}

func TestNativeWorkloadCPUQuotaUsesTightestAncestor(t *testing.T) {
	mount := t.TempDir()
	ancestor := filepath.Join(mount, "system.slice")
	service := filepath.Join(ancestor, "host.service")
	if err := os.MkdirAll(service, 0700); err != nil {
		t.Fatal(err)
	}
	write := func(directory, value string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(directory, "cpu.max"), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(mount, "max 100000")
	write(ancestor, "200000 100000")
	write(service, "max 100000")
	if quota, err := deriveNativeWorkloadCPUQuotaAt(mount, service, 2); err != nil || quota != 150000 {
		t.Fatalf("two CPU quota = %d, %v; want 150000", quota, err)
	}
	write(ancestor, "100000 100000")
	if quota, err := deriveNativeWorkloadCPUQuotaAt(mount, service, 2); err != nil || quota != 75000 {
		t.Fatalf("ancestor-limited quota = %d, %v; want 75000", quota, err)
	}
	write(ancestor, "1000 100000")
	if _, err := deriveNativeWorkloadCPUQuotaAt(mount, service, 2); err == nil {
		t.Fatal("accepted ancestor quota without supervisor headroom")
	}
}

func TestNativeRoleResourcesHaveNoProtectionAndFiniteCPUCap(t *testing.T) {
	role := t.TempDir()
	for name, value := range map[string]string{
		"memory.min": "1234", "memory.low": "1234", "cpu.weight": "100", "io.weight": "default 100", "cpu.max": "max 100000",
	} {
		if err := os.WriteFile(filepath.Join(role, name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := configureNativeRoleResources(role, 75000); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"memory.min": "0", "memory.low": "0", "cpu.weight": "1000", "io.weight": "default 1000", "cpu.max": "75000 100000",
	} {
		data, err := os.ReadFile(filepath.Join(role, name))
		if err != nil || strings.TrimSpace(string(data)) != want {
			t.Fatalf("%s = %q, %v; want %q", name, data, err, want)
		}
	}
}

func nativeTestCgroupUnavailable(err error) bool {
	return errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EROFS) || errors.Is(err, errNativeSubgroupRequired)
}

func TestNativeDelegatedServiceRootRequiresExactSupervisorSubgroup(t *testing.T) {
	for _, test := range []struct {
		membership string
		service    string
	}{
		{"/system.slice/terrascale-orchestrator-host.service/supervisor", "/system.slice/terrascale-orchestrator-host.service"},
		{"/regional.slice/host.slice/ts-host@gru.service/supervisor", "/regional.slice/host.slice/ts-host@gru.service"},
		{"/system.slice/terrascale-orchestrator-host.service", ""},
		{"/system.slice/terrascale-orchestrator-host.service/supervisor/role", ""},
		{"/system.slice/terrascale-orchestrator-host.scope/supervisor", ""},
		{"/system.slice/terrascale-orchestrator-host.service/../other.service/supervisor", ""},
		{"/supervisor", ""},
		{"/", ""},
		{"", ""},
	} {
		t.Run(test.membership, func(t *testing.T) {
			got, err := nativeDelegatedServiceRoot(test.membership)
			if test.service == "" {
				if !errors.Is(err, errNativeSubgroupRequired) {
					t.Fatalf("membership %q: error = %v, want subgroup requirement", test.membership, err)
				}
				return
			}
			want := filepath.Join("/sys/fs/cgroup", test.service)
			if err != nil || got != want {
				t.Fatalf("membership %q: root = %q, %v; want %q", test.membership, got, err, want)
			}
		})
	}
}

func TestPrepareNativeCgroupRootRejectsOccupiedOrUndelegatedParent(t *testing.T) {
	for _, test := range []struct {
		name  string
		procs string
		want  string
	}{
		{"occupied", "123\n", "process-free"},
		{"missing-controller", "", "subtree_control"},
	} {
		t.Run(test.name, func(t *testing.T) {
			parent := t.TempDir()
			if err := os.WriteFile(filepath.Join(parent, "cgroup.procs"), []byte(test.procs), 0600); err != nil {
				t.Fatal(err)
			}
			root := filepath.Join(parent, "terrascale-host-test")
			if err := prepareNativeCgroupRoot(root); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("prepare with %s parent = %v", test.name, err)
			}
			if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("prepare with %s parent created runner cgroup: %v", test.name, err)
			}
		})
	}
}

func TestValidateTenantCgroupTraversalRejectsPrivateAncestor(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to create a synthetic cgroup path below /run")
	}
	root, err := os.MkdirTemp("/run", "ts-cgroup-traversal-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	identity := WorkloadIdentity{UID: 65534, GID: 65534}
	if err := os.Chown(root, 0, int(identity.GID)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0710); err != nil {
		t.Fatal(err)
	}
	role := filepath.Join(root, "runner", "terrabase")
	if err := os.MkdirAll(role, 0710); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Dir(role), role} {
		if err := os.Chown(path, 0, int(identity.GID)); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0710); err != nil {
			t.Fatal(err)
		}
	}
	if err := validateTenantCgroupTraversal(role, identity); err != nil {
		t.Fatalf("group-searchable cgroup path: %v", err)
	}
	if err := os.Chmod(filepath.Dir(role), 0700); err != nil {
		t.Fatal(err)
	}
	if err := validateTenantCgroupTraversal(role, identity); err == nil || !strings.Contains(err.Error(), filepath.Dir(role)) {
		t.Fatalf("private runner ancestor was accepted: %v", err)
	}
	if err := os.Chmod(filepath.Dir(role), 0710); err != nil {
		t.Fatal(err)
	}
	unrelated := filepath.Join(root, "other-tenant")
	if err := os.Mkdir(unrelated, 0700); err != nil {
		t.Fatal(err)
	}
	if err := validateTenantCgroupTraversal(unrelated, identity); err == nil || !strings.Contains(err.Error(), unrelated) {
		t.Fatalf("private sibling cgroup was accepted: %v", err)
	}
}

func TestValidateTenantCgroupTraversalRejectsStickyWritableAncestor(t *testing.T) {
	info, err := os.Stat("/tmp")
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSticky == 0 || info.Mode().Perm()&0002 == 0 {
		t.Skip("requires a sticky, world-writable /tmp")
	}
	root, err := os.MkdirTemp("/tmp", "ts-cgroup-sticky-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0710); err != nil {
		t.Fatal(err)
	}
	identity := WorkloadIdentity{UID: uint32(os.Getuid()) + 1, GID: uint32(os.Getgid())}
	if err := validateTenantCgroupTraversal(root, identity); err == nil || !strings.Contains(err.Error(), "/tmp") {
		t.Fatalf("sticky writable ancestor was accepted: %v", err)
	}
}
