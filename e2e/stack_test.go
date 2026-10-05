package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Inert bytes test admission and filesystem handling; no fake service runs.
func TestArtifactOverrideIsVerifiedAndInstalledWithoutChangingSource(t *testing.T) {
	var pins localPins
	pins.TerraBase.Commit = strings.Repeat("a", 40)
	pins.TerraBase.SHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	cache := t.TempDir()
	source := filepath.Join(t.TempDir(), "downloaded-release")
	if err := os.WriteFile(source, []byte("abc"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("E2E_TERRABASE_BINARY", source)
	installed, err := localTerraBaseBinary(t.Context(), cache, pins)
	if err != nil {
		t.Fatal(err)
	}
	if installed == source || filepath.Dir(installed) != cache {
		t.Fatalf("did not install owned copy: %s", installed)
	}
	info, err := os.Stat(installed)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0700 {
		t.Fatalf("artifact mode=%o", info.Mode().Perm())
	}
	original, err := os.Stat(source)
	if err != nil {
		t.Fatal(err)
	}
	if original.Mode().Perm() != 0600 {
		t.Fatal("source permissions changed")
	}
	if err = os.WriteFile(source, []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = localTerraBaseBinary(t.Context(), cache, pins); err == nil {
		t.Fatal("accepted corrupted override")
	}
	if err = verifyLocalBinary(installed, pins.TerraBase.SHA256); err != nil {
		t.Fatalf("failed override replaced admitted cache: %v", err)
	}
	files, err := os.ReadDir(cache)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("partial downloads leaked: %v", files)
	}
	t.Setenv("E2E_TERRABASE_BINARY", "")
	if err = os.WriteFile(installed, []byte("corrupt-cache"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err = localTerraBaseBinary(t.Context(), cache, pins); err == nil {
		t.Fatal("accepted corrupt cached binary")
	}
}
func TestSourceRevisionMustBeCompleteHash(t *testing.T) {
	for _, pin := range []string{"main", "abcd", strings.Repeat("z", 40)} {
		if err := localSource(t.Context(), t.TempDir(), t.TempDir(), "ts-auth", pin); err == nil {
			t.Fatalf("accepted unpinned source %q", pin)
		}
	}
}
