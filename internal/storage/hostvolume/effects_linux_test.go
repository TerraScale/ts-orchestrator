//go:build linux

package hostvolume

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestBlockDeviceMountedMatchesExactDevice(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mountinfo")
	if err := os.WriteFile(path, []byte(mountInfo), 0o600); err != nil {
		t.Fatal(err)
	}
	for rdev, want := range map[uint64]bool{unix.Mkdev(8, 16): true, unix.Mkdev(8, 32): true, unix.Mkdev(8, 48): false, unix.Mkdev(8, 1): true} {
		if got, err := BlockDeviceMounted(path, rdev); err != nil || got != want {
			t.Fatalf("BlockDeviceMounted(%d:%d) = %v, %v; want %v", unix.Major(rdev), unix.Minor(rdev), got, err, want)
		}
	}
}
