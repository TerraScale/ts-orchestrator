package vmimage

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestVerifyFileRejectsHardLinksAndSpecialBits(t *testing.T) {
	t.Parallel()
	directory := privateTempDir(t)
	data := []byte("artifact")
	path := filepath.Join(directory, "artifact")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	artifact := ArtifactManifest{Name: "artifact", Architecture: ArchitectureAMD64, Version: "1.0.0", Source: "/fixture", SHA256: digest(data), Size: int64(len(data)), Mode: 0o644}
	if err := VerifyFile(path, artifact); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "second-link")
	if err := os.Link(path, link); err != nil {
		t.Fatal(err)
	}
	if err := VerifyFile(path, artifact); err == nil {
		t.Fatal("multiply linked cache file was accepted")
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, os.ModeSetuid|0o644); err != nil {
		t.Fatal(err)
	}
	if err := VerifyFile(path, artifact); err == nil {
		t.Fatal("setuid cache file was accepted")
	}
}

func TestCacheLockSerializesStagingRecovery(t *testing.T) {
	t.Parallel()
	root := privateTempDir(t)
	parent := filepath.Join(root, "amd64", "release")
	if err := ensurePrivateTree(root, parent); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(parent, ".staging-0123456789abcdef")
	if err := os.Mkdir(stale, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stale, "artifact"), []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	ignored := filepath.Join(parent, ".staging-not-a-token")
	if err := os.Mkdir(ignored, 0o700); err != nil {
		t.Fatal(err)
	}
	lock, err := acquireCacheLock(root)
	if err != nil {
		t.Fatal(err)
	}
	acquired := make(chan *os.File, 1)
	errorsChannel := make(chan error, 1)
	go func() {
		second, lockErr := acquireCacheLock(root)
		if lockErr != nil {
			errorsChannel <- lockErr
			return
		}
		acquired <- second
	}()
	select {
	case second := <-acquired:
		releaseCacheLock(second)
		releaseCacheLock(lock)
		t.Fatal("second installer acquired the cache lock concurrently")
	case err := <-errorsChannel:
		releaseCacheLock(lock)
		t.Fatal(err)
	case <-time.After(50 * time.Millisecond):
	}
	if err := recoverStaging(parent); err != nil {
		releaseCacheLock(lock)
		t.Fatal(err)
	}
	releaseCacheLock(lock)
	select {
	case second := <-acquired:
		releaseCacheLock(second)
	case err := <-errorsChannel:
		t.Fatal(err)
	case <-time.After(2 * time.Second):
		t.Fatal("waiting installer did not acquire the released cache lock")
	}
	if _, err := os.Lstat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale staging directory remains: %v", err)
	}
	if _, err := os.Stat(ignored); err != nil {
		t.Fatalf("non-staging directory was removed: %v", err)
	}
}
