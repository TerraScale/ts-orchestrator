package vmimage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDownloadPinnedAcceptsExactSizeAndPublishesAtomically(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	target := filepath.Join(root, "kernel")
	data := []byte("pinned kernel")
	seenTargetDuringDownload := false
	downloader := DownloaderFunc(func(_ context.Context, _ string, destination io.Writer, _ int64) error {
		_, seenErr := os.Stat(target)
		seenTargetDuringDownload = !errors.Is(seenErr, os.ErrNotExist)
		_, err := destination.Write(data)
		return err
	})

	if err := downloadPinned(context.Background(), downloader, "https://images.example.test/release-v1/arm64/kernel", target, downloadDigest(data), int64(len(data)), 0o644); err != nil {
		t.Fatal(err)
	}
	if seenTargetDuringDownload {
		t.Fatal("destination became visible before the verified download completed")
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("downloaded bytes = %q, want %q", got, data)
	}
	info, err := os.Stat(target)
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("published mode = %v, err = %v", info.Mode(), err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "kernel" {
		t.Fatalf("staging files remain after publication: %#v", entries)
	}
}

func TestDownloadPinnedRejectsOverflowWithoutPartialFile(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	target := filepath.Join(root, "rootfs")
	data := []byte("too large")
	err := downloadPinned(context.Background(), DownloaderFunc(func(_ context.Context, _ string, destination io.Writer, _ int64) error {
		_, writeErr := destination.Write(data)
		return writeErr
	}), "https://images.example.test/release-v1/arm64/rootfs", target, downloadDigest(data), int64(len(data)-1), 0o644)
	if err == nil || !strings.Contains(err.Error(), "exceeds pinned size") {
		t.Fatalf("overflow error = %v", err)
	}
	assertNoDownloadedFile(t, target)
}

func TestDownloadPinnedRejectsShortInputWithoutPartialFile(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	target := filepath.Join(root, "rootfs")
	want := []byte("complete rootfs")
	err := downloadPinned(context.Background(), DownloaderFunc(func(_ context.Context, _ string, destination io.Writer, _ int64) error {
		_, writeErr := destination.Write(want[:len(want)-1])
		return writeErr
	}), "https://images.example.test/release-v1/arm64/rootfs", target, downloadDigest(want), int64(len(want)), 0o644)
	if err == nil || !strings.Contains(err.Error(), "do not match pinned size") {
		t.Fatalf("short-input error = %v", err)
	}
	assertNoDownloadedFile(t, target)
}

func TestDownloadPinnedCancellationRemovesStaging(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	target := filepath.Join(root, "kernel")
	ctx, cancel := context.WithCancel(context.Background())
	err := downloadPinned(ctx, DownloaderFunc(func(_ context.Context, _ string, destination io.Writer, _ int64) error {
		if _, writeErr := destination.Write([]byte("first")); writeErr != nil {
			return writeErr
		}
		cancel()
		_, writeErr := destination.Write([]byte("second"))
		return writeErr
	}), "https://images.example.test/release-v1/arm64/kernel", target, downloadDigest([]byte("firstsecond")), int64(len("firstsecond")), 0o644)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v", err)
	}
	assertNoDownloadedFile(t, target)
}

func TestDownloadPinnedRefusesExistingDestinationBeforeDownload(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	target := filepath.Join(root, "kernel")
	original := []byte("already installed")
	if err := os.WriteFile(target, original, 0o644); err != nil {
		t.Fatal(err)
	}
	called := false
	err := downloadPinned(context.Background(), DownloaderFunc(func(context.Context, string, io.Writer, int64) error {
		called = true
		return nil
	}), "https://images.example.test/release-v1/arm64/kernel", target, downloadDigest([]byte("new")), 3, 0o644)
	if !errors.Is(err, os.ErrExist) || called {
		t.Fatalf("existing destination error = %v, downloader called = %v", err, called)
	}
	got, readErr := os.ReadFile(target)
	if readErr != nil || !bytes.Equal(got, original) {
		t.Fatalf("existing destination changed: %q, err = %v", got, readErr)
	}
}

func TestDownloadPinnedDiagnosticsRedactSourceCredentialsAndSecrets(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	target := filepath.Join(root, "kernel")
	secret := "very-secret-token"
	source := "https://user:password@images.example.test/release-v1/arm64/kernel?token=" + secret
	err := downloadPinned(context.Background(), DownloaderFunc(func(context.Context, string, io.Writer, int64) error {
		return fmt.Errorf("GET %s: authorization=%s", source, secret)
	}), source, target, downloadDigest([]byte("kernel")), int64(len("kernel")), 0o644)
	if err == nil {
		t.Fatal("secret-bearing download error was accepted")
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "password") || strings.Contains(err.Error(), "?token") {
		t.Fatalf("download diagnostic leaked secret data: %q", err)
	}
	if !strings.Contains(err.Error(), "images.example.test/release-v1/arm64/kernel") {
		t.Fatalf("download diagnostic lost safe source identity: %q", err)
	}
}

func assertNoDownloadedFile(t *testing.T, target string) {
	t.Helper()
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial destination exists: err = %v", err)
	}
	entries, err := os.ReadDir(filepath.Dir(target))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("staging files remain after failed download: %#v", entries)
	}
}

func downloadDigest(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
