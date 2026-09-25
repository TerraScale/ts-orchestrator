//go:build linux

package host

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

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
