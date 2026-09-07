package keylease

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInitializeCatalogCreateOnlyAndCorruptRefusal(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(home, ".keylease-init-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "catalog.json")
	if err := InitializeCatalog(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("catalog mode %o is not private", info.Mode().Perm())
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := InitializeCatalog(path); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("reinitialization replaced valid catalog")
	}
	if err := os.WriteFile(path, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := InitializeCatalog(path); err == nil {
		t.Fatal("corrupt catalog accepted")
	}
	corrupted, _ := os.ReadFile(path)
	if string(corrupted) != "corrupt" {
		t.Fatal("corrupt catalog was overwritten")
	}
}
