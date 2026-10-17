//go:build linux

package swarmruntime

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func nativeMaintenanceTestDirectory(t *testing.T) (string, int) {
	t.Helper()
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		t.Skip("actual root-owned identity file checks require root")
	}
	path := t.TempDir()
	directory, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(directory) })
	return path, directory
}

func TestNativeMaintenanceIdentityFileRejectsUnsafeCustody(t *testing.T) {
	for _, kind := range []string{"readable-key", "symlink", "hardlink", "fifo", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			path, directory := nativeMaintenanceTestDirectory(t)
			name := filepath.Join(path, "swarm-node.key")
			if kind == "fifo" {
				if err := unix.Mkfifo(name, 0o600); err != nil {
					t.Fatal(err)
				}
			} else {
				wire := []byte("retained-key-bytes")
				if kind == "oversize" {
					wire = bytes.Repeat([]byte{'x'}, maxNativeMaintenanceIdentityFileBytes+1)
				}
				if err := os.WriteFile(name, wire, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			switch kind {
			case "readable-key":
				if err := os.Chmod(name, 0o644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(name, name+"-original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(name+"-original", name); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(name, name+"-alias"); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := readNativeMaintenanceIdentityFile(directory, "swarm-node.key", 0o600); err == nil {
				t.Fatal("unsafe identity file accepted")
			}
		})
	}
}

func TestNativeMaintenanceIdentityFilePinsOriginalInode(t *testing.T) {
	path, directory := nativeMaintenanceTestDirectory(t)
	name := filepath.Join(path, "swarm-node.key")
	wire := []byte("retained-key-bytes")
	if err := os.WriteFile(name, wire, 0o600); err != nil {
		t.Fatal(err)
	}
	original, err := readNativeMaintenanceIdentityFile(directory, "swarm-node.key", 0o600)
	if err != nil || !bytes.Equal(original.wire, wire) {
		t.Fatalf("read original root-owned identity: %v", err)
	}
	unchanged, err := readNativeMaintenanceIdentityFile(directory, "swarm-node.key", 0o600)
	if err != nil || unchanged.pin != original.pin {
		t.Fatalf("unchanged identity did not retain its original pin: %v", err)
	}
	if err := os.WriteFile(name+"-replacement", wire, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(name+"-replacement", name); err != nil {
		t.Fatal(err)
	}
	replacement, err := readNativeMaintenanceIdentityFile(directory, "swarm-node.key", 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.pin == original.pin {
		t.Fatal("identical bytes in a successor inode adopted the original identity")
	}
}

func TestNativeMaintenanceLifetimeCancelsBlockedReads(t *testing.T) {
	for _, cause := range []string{"node-stopped", "parent-cancelled", "deadline"} {
		t.Run(cause, func(t *testing.T) {
			parent, cancelParent := context.WithCancel(t.Context())
			defer cancelParent()
			done := make(chan struct{})
			lifetime, cancel := nativeMaintenanceLifetime(parent, done)
			defer cancel()
			if err := lifetime.Err(); err != nil {
				t.Fatalf("live native source was cancelled: %v", err)
			}
			read, cancelRead := context.WithCancel(t.Context())
			defer cancelRead()
			stop := context.AfterFunc(lifetime, cancelRead)
			defer stop()
			switch cause {
			case "node-stopped":
				close(done)
			case "parent-cancelled":
				cancelParent()
			case "deadline":
				bounded, cancelDeadline := context.WithDeadline(lifetime, time.Now().Add(-time.Second))
				defer cancelDeadline()
				context.AfterFunc(bounded, cancel)
			}
			select {
			case <-read.Done():
			case <-time.After(5 * time.Second):
				t.Fatal("native source termination did not cancel its blocked read")
			}
		})
	}
}
