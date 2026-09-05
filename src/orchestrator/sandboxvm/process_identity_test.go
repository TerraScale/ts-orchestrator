//go:build linux

package sandboxvm

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProcessExecutableRequiresMatchingInodeAndJailRoot(t *testing.T) {
	executable, err := os.Readlink("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	matched, err := sameProcessExecutable(executable, os.Getpid(), executable)
	if err != nil || !matched {
		t.Fatalf("live executable identity = %v, %v", matched, err)
	}
	// A matching basename cannot turn a host process into an admitted jail.
	if matched, err := sameProcessExecutable(executable, os.Getpid(), "/"+filepath.Base(executable)); err == nil || matched {
		t.Fatalf("accepted executable without matching process root: %v, %v", matched, err)
	}
	other := filepath.Join(t.TempDir(), "firecracker")
	if err := os.WriteFile(other, []byte("different executable inode"), 0700); err != nil {
		t.Fatal(err)
	}
	if matched, err := sameProcessExecutable(other, os.Getpid(), other); err != nil || matched {
		t.Fatalf("different inode = %v, %v", matched, err)
	}
	if matched, err := sameProcessExecutable(executable, os.Getpid(), executable+" (deleted)"); err == nil || matched {
		t.Fatalf("accepted deleted executable: %v, %v", matched, err)
	}
}
