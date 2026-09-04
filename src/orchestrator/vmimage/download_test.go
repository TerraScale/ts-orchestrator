package vmimage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

func TestDownloadPinnedRejectsDigestMismatchWithoutPartialFile(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	target := filepath.Join(root, "rootfs")
	data := []byte("complete rootfs")
	err := downloadPinned(context.Background(), memoryDownloader(map[string][]byte{"https://images.example.test/rootfs": data}),
		"https://images.example.test/rootfs", target, downloadDigest([]byte("different bytes")), int64(len(data)), 0o644)
	if err == nil || !strings.Contains(err.Error(), "do not match pinned size and sha256") {
		t.Fatalf("digest mismatch error = %v", err)
	}
	assertNoDownloadedFile(t, target)
}

func TestHTTPDownloaderContentLengthContract(t *testing.T) {
	t.Parallel()
	data := []byte("artifact")
	for _, test := range []struct {
		name          string
		contentLength int64
		wantError     bool
	}{
		{name: "known exact", contentLength: int64(len(data))},
		{name: "unknown", contentLength: -1},
		{name: "known mismatch", contentLength: int64(len(data) + 1), wantError: true},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			downloader := httpDownloader{client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, ContentLength: test.contentLength, Body: io.NopCloser(bytes.NewReader(data)), Header: make(http.Header)}, nil
			})}}
			var output bytes.Buffer
			err := downloader.Download(context.Background(), "https://images.example.test/artifact", &output, int64(len(data)))
			if (err != nil) != test.wantError {
				t.Fatalf("Download error = %v, wantError=%v", err, test.wantError)
			}
			if !test.wantError && !bytes.Equal(output.Bytes(), data) {
				t.Fatalf("downloaded bytes = %q", output.Bytes())
			}
		})
	}
}

func TestHTTPDownloaderRedirectPolicies(t *testing.T) {
	t.Parallel()
	const source = "https://github.com/firecracker-microvm/firecracker/releases/download/v1.15.1/firecracker-v1.15.1-x86_64.tgz"
	request := mustHTTPRedirectRequest(t, "https://release-assets.githubusercontent.com/asset?sig=pinned", http.MethodGet)
	via := []*http.Request{mustHTTPRedirectRequest(t, source, http.MethodGet)}
	if err := (httpDownloader{}).redirectPolicy(source)(request, via); err == nil {
		t.Fatal("image downloader accepted a redirect")
	}
	policy := (httpDownloader{allowGitHubReleaseRedirect: true}).redirectPolicy(source)
	if err := policy(request, via); err != nil {
		t.Fatalf("exact GitHub release redirect rejected: %v", err)
	}
	tests := []struct {
		name   string
		target string
		method string
		via    []*http.Request
	}{
		{name: "downgrade", target: "http://release-assets.githubusercontent.com/asset", method: http.MethodGet, via: via},
		{name: "port", target: "https://release-assets.githubusercontent.com:443/asset", method: http.MethodGet, via: via},
		{name: "userinfo", target: "https://user@release-assets.githubusercontent.com/asset", method: http.MethodGet, via: via},
		{name: "fragment", target: "https://release-assets.githubusercontent.com/asset#fragment", method: http.MethodGet, via: via},
		{name: "suffix host", target: "https://release-assets.githubusercontent.com.evil.test/asset", method: http.MethodGet, via: via},
		{name: "wrong method", target: "https://release-assets.githubusercontent.com/asset", method: http.MethodPost, via: via},
		{name: "extra hop", target: "https://release-assets.githubusercontent.com/asset", method: http.MethodGet, via: append(append([]*http.Request(nil), via...), request)},
		{name: "wrong origin", target: "https://release-assets.githubusercontent.com/asset", method: http.MethodGet, via: []*http.Request{mustHTTPRedirectRequest(t, "https://github.com/other", http.MethodGet)}},
	}
	for _, test := range tests {
		if err := policy(mustHTTPRedirectRequest(t, test.target, test.method), test.via); err == nil {
			t.Fatalf("%s redirect was accepted", test.name)
		}
	}
}

func mustHTTPRedirectRequest(t *testing.T, value, method string) *http.Request {
	t.Helper()
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Request{Method: method, URL: parsed}
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
