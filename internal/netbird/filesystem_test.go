package netbird

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHostsUpdateOwnsOnlyExactTaggedEntry(t *testing.T) {
	original := []byte("127.0.0.1 localhost\n\n# comment preserved\n10.250.1.2 git.terrascale.tech other\n10.250.10.10\tnetbird.terrascale.tech\t" + hostsMarker + "\n")
	updated, err := hostsContent(original, "10.250.10.155")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(updated, []byte("# comment preserved\n10.250.1.2 git.terrascale.tech other\n")) || bytes.Contains(updated, []byte("10.250.10.10")) {
		t.Fatalf("unexpected hosts update %q", updated)
	}
	again, err := hostsContent(updated, "10.250.10.155")
	if err != nil || !bytes.Equal(updated, again) {
		t.Fatalf("hosts update is not idempotent: %q %q %v", updated, again, err)
	}
	removed, err := hostsContent(updated, "")
	if err != nil || strings.Contains(string(removed), managerHostname) {
		t.Fatalf("managed hosts removal failed: %q %v", removed, err)
	}
	for _, conflict := range []string{
		"10.0.0.1 netbird.terrascale.tech unrelated\n",
		"10.0.0.1 netbird.terrascale.tech unrelated " + hostsMarker + "\n",
		"10.0.0.1 unrelated " + hostsMarker + "\n",
		"10.0.0.1 netbird.terrascale.tech " + hostsMarker + "\n10.0.0.2 netbird.terrascale.tech " + hostsMarker + "\n",
	} {
		if _, err := hostsContent([]byte(conflict), "10.250.10.155"); err == nil {
			t.Fatalf("accepted hosts conflict %q", conflict)
		}
	}
}

func TestAtomicHostsUpdatePreservesModeAndRejectsSymlinks(t *testing.T) {
	e := testEnroller(t)
	if err := updateHosts(e.hostsPath, "10.250.10.155"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(e.hostsPath)
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("mode was not preserved: %v %v", info, err)
	}
	link := filepath.Join(t.TempDir(), "hosts-link")
	if err := os.Symlink(e.hostsPath, link); err != nil {
		t.Fatal(err)
	}
	if err := updateHosts(link, "10.250.10.156"); err == nil {
		t.Fatal("followed hosts symlink")
	}
	body, err := os.ReadFile(e.hostsPath)
	if err != nil || bytes.Contains(body, []byte("10.250.10.156")) {
		t.Fatal("hosts symlink changed its target")
	}
}

func TestRuntimeLockAndTransientKeyCannotFollowSymlinks(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "run")
	first, err := lockRuntime(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if lock, err := lockRuntime(directory); err == nil {
		lock.Close()
		t.Fatal("allowed concurrent enrollment")
	}
	target := filepath.Join(t.TempDir(), "do-not-delete")
	if err := os.WriteFile(target, []byte("unrelated"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(directory, "setup-key")); err != nil {
		t.Fatal(err)
	}
	if err := removeSetupKey(directory); err == nil {
		t.Fatal("accepted setup-key symlink")
	}
	if _, err := writeSetupKey(directory, []byte(testSetupKey)); err == nil {
		t.Fatal("overwrote setup-key symlink")
	}
	if _, err := os.Stat(target); errors.Is(err, os.ErrNotExist) {
		t.Fatal("setup-key cleanup removed unrelated file")
	}
}
