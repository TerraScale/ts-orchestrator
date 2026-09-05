package initialgrant

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func mountPublicationTestState(t *testing.T) {
	t.Helper()
	self, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil {
		t.Fatal(err)
	}
	host, err := os.Readlink("/proc/1/ns/mnt")
	if err != nil || self == host {
		t.Fatal("refusing to mount over the host namespace")
	}
	if err := unix.Mount("tmpfs", "/var/lib", "tmpfs", 0, "mode=0755,size=16m"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount("/var/lib", 0); err != nil {
			t.Error(err)
		}
	})
}
