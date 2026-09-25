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
