package cellscale

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func provisionTestLock(t *testing.T, directory string, config FileConfig) {
	t.Helper()
	file, err := os.OpenFile(filepath.Join(directory, cellLockName(config)), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func testCellLock(t *testing.T, directory string, config FileConfig) *os.File {
	t.Helper()
	// The test process represents the trusted provisioner in its own fixture.
	lock, err := lockCellAt(config, directory, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lock.Close() })
	return lock
}

func TestCellLockRunScopeAndLifetime(t *testing.T) {
	directory := t.TempDir()
	config := FileConfig{Cell: "gru-100", IntervalSeconds: 60, Endpoint: "http://{node}:9440", Policy: testPolicy(), Template: testTemplate()}
	provisionTestLock(t, directory, config)
	first := testCellLock(t, directory, config)
	original, err := first.Stat()
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*FileConfig){
		"distinct config path": func(*FileConfig) {},
		"availability domain":  func(c *FileConfig) { c.Template.AvailabilityDomain = "AD-2" },
		"subnet":               func(c *FileConfig) { c.Template.SubnetID = "ocid1.subnet.other" },
		"shape":                func(c *FileConfig) { c.Template.Shape = "VM.Standard.E4.Flex" },
		"compartment":          func(c *FileConfig) { c.Template.CompartmentID += "-other" },
	} {
		t.Run(name, func(t *testing.T) {
			other := config
			mutate(&other)
			path := filepath.Join(t.TempDir(), "copied.json")
			data, err := json.Marshal(other)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			other, err = readConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			lock, err := lockCellAt(other, directory, uint32(os.Geteuid()))
			if lock != nil {
				_ = lock.Close()
			}
			if !errors.Is(err, syscall.EWOULDBLOCK) {
				t.Fatalf("same cell acquired another lock: %v", err)
			}
		})
	}
	for _, dimension := range []string{"cell", "region"} {
		other := config
		if dimension == "cell" {
			other.Cell = "gru-101"
		} else {
			other.Template.Region = "us-ashburn-1"
		}
		provisionTestLock(t, directory, other)
		if lock := testCellLock(t, directory, other); lock.Name() == first.Name() {
			t.Fatalf("different %s shares lock", dimension)
		}
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	remaining, err := os.Stat(first.Name())
	if err != nil || !os.SameFile(original, remaining) {
		t.Fatalf("closing replaced or removed inode: %v", err)
	}
	current, err := testCellLock(t, directory, config).Stat()
	if err != nil || !os.SameFile(original, current) {
		t.Fatalf("reacquiring changed inode: %v", err)
	}
}

func TestCellLockRejectsUnsafeFiles(t *testing.T) {
	for _, kind := range []string{"missing", "symlink", "fifo", "writable file", "writable directory", "sticky directory", "untrusted owner"} {
		t.Run(kind, func(t *testing.T) {
			directory := t.TempDir()
			config := FileConfig{Cell: "gru-100", Template: testTemplate()}
			path := filepath.Join(directory, cellLockName(config))
			owner := uint32(os.Geteuid())
			switch kind {
			case "symlink":
				if err := os.Symlink(filepath.Join(t.TempDir(), "target"), path); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := syscall.Mkfifo(path, 0o644); err != nil {
					t.Fatal(err)
				}
			case "missing":
			default:
				provisionTestLock(t, directory, config)
			}
			if kind == "writable file" {
				if err := os.Chmod(path, 0o666); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "writable directory" || kind == "sticky directory" {
				mode := os.FileMode(0o777)
				if kind == "sticky directory" {
					mode |= os.ModeSticky
				}
				if err := os.Chmod(directory, mode); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "untrusted owner" {
				owner++
			}
			lock, err := lockCellAt(config, directory, owner)
			if lock != nil {
				_ = lock.Close()
			}
			if err == nil {
				t.Fatalf("acquired unsafe lock: %s", kind)
			}
			if kind == "missing" {
				if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("runner created unprovisioned inode: %v", err)
				}
			}
		})
	}
}
