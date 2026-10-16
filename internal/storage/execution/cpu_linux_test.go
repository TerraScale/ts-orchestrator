//go:build linux

package execution

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestHostCPUProfileProcIntegration(t *testing.T) {
	profile, err := HostCPUProfile()
	if err != nil || !profile.valid() {
		t.Fatalf("actual CPU inventory: %+v %v", profile, err)
	}
}

// HostCPUProfile keeps its production /proc path. Only this child process's
// private mount namespace substitutes controlled kernel-visible inventory.
func TestHostCPUInventoryMountIntegration(t *testing.T) {
	if os.Getenv("TS_CPU_INVENTORY_FIXTURE") != "private" {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		command := exec.CommandContext(t.Context(), "sudo", "-n", "env", "TS_CPU_INVENTORY_FIXTURE=private", "nice", "-n", "19", "unshare", "--mount", "--fork", executable, "-test.run=^TestHostCPUInventoryMountIntegration$", "-test.v")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("private actual CPU inventory boundary: %v\n%s", err, output)
		}
		return
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	read := func(name, wire string) (CPUProfile, error) {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte(wire), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := unix.Mount(path, "/proc/cpuinfo", "", unix.MS_BIND, ""); err != nil {
			t.Fatal(err)
		}
		profile, err := HostCPUProfile()
		if unmountErr := unix.Unmount("/proc/cpuinfo", 0); unmountErr != nil {
			t.Fatal(unmountErr)
		}
		return profile, err
	}
	first, err := read("first", "processor: 0\nflags: sse avx sse2\n\nprocessor: 1\nflags: sse2 sse\n")
	if err != nil {
		t.Fatal(err)
	}
	second, err := read("second", "processor: 1\nflags: sse sse2\n\nprocessor: 0\nflags: sse2 avx sse\n")
	if err != nil || first != second {
		t.Fatalf("mounted feature intersection depends on ordering: %+v %+v %v", first, second, err)
	}
	for _, test := range []struct{ name, wire string }{
		{"empty", ""}, {"missing-features", "processor: 0\n"},
		{"partial-inventory", "processor: 0\nflags: sse\n\nprocessor: 1\n"},
		{"no-common-features", "processor: 0\nflags: sse\n\nprocessor: 1\nflags: avx\n"},
		{"duplicate-features", "processor: 0\nflags: sse\nflags: avx\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := read(test.name, test.wire); err == nil {
				t.Fatal("unsafe actual mounted CPU inventory admitted")
			}
		})
	}
}
