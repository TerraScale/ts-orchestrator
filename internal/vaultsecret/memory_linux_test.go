//go:build linux

package vaultsecret

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMemoryDeliveryRefusesUnsafeDirectories(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if root, err := openMemoryDirectory(directory); err == nil {
		root.Close()
		t.Fatal("accepted group/world traversal of service secrets")
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "secret-directory")
	if err := os.Symlink(directory, link); err != nil {
		t.Fatal(err)
	}
	if root, err := openMemoryDirectory(link); err == nil {
		root.Close()
		t.Fatal("followed a delivery-directory symlink")
	}
	if err := RequireMemoryFilesystem(directory); err != nil {
		if root, err := openMemoryDirectory(directory); err == nil {
			root.Close()
			t.Fatal("accepted persistent or swappable storage")
		}
	}
}

func TestMemoryFileReplacementDoesNotFollowSymlinks(t *testing.T) {
	directory := t.TempDir()
	outside := filepath.Join(t.TempDir(), "private")
	if err := os.WriteFile(outside, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(directory, "key_file")); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := writeMemoryFile(root, "key_file", []byte("new")); err != nil {
		t.Fatal(err)
	}
	if value, _ := os.ReadFile(outside); string(value) != "unchanged" {
		t.Fatal("wrote through a symlink")
	}
	if info, _ := os.Lstat(filepath.Join(directory, "key_file")); !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatal("replacement is not owner-only")
	}
	if err := writeMemoryFile(root, "../escape", []byte("new")); err == nil {
		t.Fatal("allowed a path escape")
	}
}
