package app

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestControllerInstallRetriesExactBytesAndRejectsChangedFiles(t *testing.T) {
	directory := t.TempDir()
	dir, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(dir)
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	config := []byte(`{"nats":{"cell":"gru"},"controller":{}}`)
	for range 2 {
		if err := installExactControllerFile(dir, controllerConfigFilename, config, uid, gid, 0o600); err != nil {
			t.Fatalf("install or exact retry: %v", err)
		}
	}
	loaded, err := LoadConfig(filepath.Join(directory, controllerConfigFilename))
	if err != nil || loaded.NATS.Cell != "gru" {
		t.Fatalf("installed config did not reach the real loader: cfg=%+v err=%v", loaded, err)
	}
	if err := installExactControllerFile(dir, controllerConfigFilename, []byte(`{"nats":{}}`), uid, gid, 0o600); err == nil {
		t.Fatal("retry replaced different installed config")
	}
	stored, err := os.ReadFile(filepath.Join(directory, controllerConfigFilename))
	if err != nil || !bytes.Equal(stored, config) {
		t.Fatal("failed retry changed installed config")
	}
	if err := os.Symlink(controllerConfigFilename, filepath.Join(directory, "placement.json")); err != nil {
		t.Fatal(err)
	}
	if err := installExactControllerFile(dir, "placement.json", []byte(`{}`), uid, gid, 0o600); err == nil {
		t.Fatal("installer followed or replaced an existing symlink")
	}
}
