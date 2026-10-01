package runtimepriority

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMemoryCaptureRejectsSymlinkedCgroupAncestor(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	system := filepath.Join(outside, "system.slice")
	host := filepath.Join(system, "host.service")
	writeMemoryCaptureFiles(t, host)
	writeMemoryCaptureFiles(t, system)
	if err := os.Symlink(outside, filepath.Join(root, "ancestor")); err != nil {
		t.Fatal(err)
	}
	probe := Qualifier{CgroupRoot: root}
	_, err := probe.CaptureMemorySample(map[string]string{"host_service": filepath.Join(root, "ancestor", "system.slice", "host.service"), "system_slice": filepath.Join(root, "ancestor", "system.slice")}, "systemd 252")
	if err == nil || ErrorType(err) != "QualificationError" || !strings.Contains(err.Error(), "cannot capture") {
		t.Fatalf("cgroup ancestor symlink was admitted: %v", err)
	}
}

func TestMemoryCaptureBindsChildEnumerationToSampledSystemSlice(t *testing.T) {
	root := t.TempDir()
	system := filepath.Join(root, "system.slice")
	host := filepath.Join(system, "host.service")
	writeMemoryCaptureFiles(t, host)
	writeMemoryCaptureFiles(t, system)
	replaced := false
	probe := Qualifier{CgroupRoot: root}
	probe.ChildVisited = func(string) {
		if replaced {
			return
		}
		replaced = true
		if err := os.Rename(system, system+"-old"); err != nil {
			t.Fatal(err)
		}
		writeMemoryCaptureFiles(t, system)
	}
	_, err := probe.CaptureMemorySample(map[string]string{"host_service": host, "system_slice": system}, "systemd 252")
	if !replaced || err == nil || ErrorType(err) != "QualificationError" || !strings.Contains(err.Error(), "changed during child enumeration") {
		t.Fatalf("enumeration replacement was admitted: replaced=%v err=%v", replaced, err)
	}
}

func writeMemoryCaptureFiles(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]string{"memory.current": "1\n", "memory.peak": "2\n", "memory.stat": "anon 1\n"} {
		if err := os.WriteFile(filepath.Join(path, name), []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
	}
}
