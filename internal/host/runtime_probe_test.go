//go:build linux

package host

import (
	"os"

	"path/filepath"
	"strings"
	"testing"
)

func TestNativeRuntimeProbeExecutesAndReplaces(t *testing.T) {
	stateRoot := filepath.Join(t.TempDir(), "runner")
	if err := ProbeNativeRuntime(t.Context(), stateRoot, testWorkloadIdentity); err != nil {
		if nativeTestCgroupUnavailable(err) {
			t.Skipf("requires systemd delegated writable cgroup v2: %v", err)
		}
		t.Fatal(err)
	}
	root, err := nativeCgroupRoot(stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "runtime-probe-") {
			t.Fatalf("runtime probe left cgroup %s behind", entry.Name())
		}
	}
	if err := os.Remove(root); err != nil {
		t.Fatalf("remove empty runtime cgroup root: %v", err)
	}
}
