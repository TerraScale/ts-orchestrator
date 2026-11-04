package dns

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestOperatorDNSPermissionsWithPrivateUmask(t *testing.T) {
	if filepath.Dir(subscriber) != "/etc" {
		t.Fatal("operator DNS must not create a runtime config directory")
	}
	root := t.TempDir()
	previous := syscall.Umask(0077)
	defer syscall.Umask(previous)
	owned := filepath.Join(root, "owned")
	if err := mkdir(owned); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(owned, "subscriber")
	if err := write(file, []byte("nameserver 127.0.0.53\n"), 0644); err != nil {
		t.Fatal(err)
	}
	for path, mode := range map[string]os.FileMode{owned: 0755} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != mode {
			t.Fatalf("%s must have permissions %o despite umask077", path, mode)
		}
	}
	private := filepath.Join(root, "existing")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	if err := mkdir(private); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(private)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatal("installer changed an existing private directory")
	}
}
