package runmaterial

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyBindsExactProtectedBytesAndRejectsReplacement(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "broker.conf")
	original := []byte(`{"server_name":"admitted-r3-gru"}`)
	if err := os.WriteFile(target, original, 0400); err != nil {
		t.Fatal(err)
	}
	path, raw, err := Build(map[string][]byte{target: original})
	if err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(dir, filepath.Base(path))
	if err := os.WriteFile(path, raw, 0400); err != nil {
		t.Fatal(err)
	}
	if err := Verify(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte(`{"server_name":"changed-r3-gru!"}`), 0400); err != nil {
		t.Fatal(err)
	}
	if Verify(path) == nil {
		t.Fatal("changed broker content accepted under signed inventory")
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(dir, "replacement.conf")
	if err := os.WriteFile(replacement, original, 0400); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(replacement, target); err != nil {
		t.Fatal(err)
	}
	if Verify(path) == nil {
		t.Fatal("symlink broker replacement accepted")
	}
}
func TestVerifyRejectsChangedInventoryAndWritableAncestry(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "runtime.json")
	if err := os.WriteFile(target, []byte("admitted"), 0400); err != nil {
		t.Fatal(err)
	}
	path, raw, err := Build(map[string][]byte{target: []byte("admitted")})
	if err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(dir, filepath.Base(path))
	if err := os.WriteFile(path, raw, 0400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}
	if Verify(path) == nil {
		t.Fatal("writable ancestry accepted")
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(raw, ' '), 0400); err != nil {
		t.Fatal(err)
	}
	if Verify(path) == nil {
		t.Fatal("modified inventory accepted under original digest filename")
	}
}
