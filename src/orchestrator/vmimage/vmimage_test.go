package vmimage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestManifestPairAndStrictFileVerification(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	kernel := []byte("kernel bytes")
	rootfs := []byte("rootfs bytes")
	kernelPath := filepath.Join(dir, "vmlinuz")
	rootfsPath := filepath.Join(dir, "rootfs.raw")
	if err := os.WriteFile(kernelPath, kernel, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootfsPath, rootfs, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(kernelPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(rootfsPath, 0o644); err != nil {
		t.Fatal(err)
	}
	manifest := testManifest(kernelPath, rootfsPath, kernel, rootfs)
	if err := manifest.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := VerifyFile(kernelPath, manifest.Kernel); err != nil {
		t.Fatal(err)
	}
	if err := VerifyFile(rootfsPath, manifest.RootFS); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(kernelPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyFile(kernelPath, manifest.Kernel); err == nil {
		t.Fatal("mode mismatch was accepted")
	}
	if err := os.Chmod(kernelPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(rootfsPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(kernelPath, rootfsPath); err != nil {
		t.Fatal(err)
	}
	if err := VerifyFile(rootfsPath, manifest.RootFS); err == nil {
		t.Fatal("symlink was accepted")
	}

	bad := manifest
	bad.RootFS.Architecture = ArchitectureAMD64
	bad.Architecture = ArchitectureARM64
	if err := bad.Validate(); err == nil {
		t.Fatal("mismatched kernel/rootfs pair was accepted")
	}
}

func TestCacheRejectsUnpinnedRootFS(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	kernel, rootfs := []byte("kernel"), []byte("rootfs")
	manifest := pinnedTestManifest(kernel, rootfs)
	cache, err := NewCache(filepath.Join(dir, "cache"))
	if err != nil {
		t.Fatal(err)
	}
	cache.Downloader = memoryDownloader(map[string][]byte{manifest.Kernel.Source: kernel, manifest.RootFS.Source: rootfs})
	cache.RootFSPreparer = testRootFSPreparer()
	if _, err := cache.Install(context.Background(), manifest); err == nil {
		t.Fatal("cache accepted an unpinned root filesystem")
	}
}

func TestCacheRejectsUnpinnedHTTPSRootFS(t *testing.T) {
	t.Parallel()
	kernel, rootfs := []byte("kernel over http"), []byte("rootfs over http")
	manifest := pinnedTestManifest(kernel, rootfs)
	cache, err := NewCache(filepath.Join(t.TempDir(), "cache"))
	if err != nil {
		t.Fatal(err)
	}
	cache.Client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		content, ok := map[string][]byte{manifest.Kernel.Source: kernel, manifest.RootFS.Source: rootfs}[request.URL.String()]
		if !ok {
			return nil, fmt.Errorf("unexpected source %s", request.URL)
		}
		return &http.Response{StatusCode: http.StatusOK, ContentLength: int64(len(content)), Body: io.NopCloser(strings.NewReader(string(content))), Header: make(http.Header)}, nil
	})}
	cache.RootFSPreparer = testRootFSPreparer()
	if _, err := cache.Install(context.Background(), manifest); err == nil {
		t.Fatal("cache accepted an unpinned HTTPS root filesystem")
	}
}

func TestSeedIsDeterministicAndRestrictsProductionArtifacts(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	kernel, rootfs := []byte("kernel"), []byte("rootfs")
	manifest := testManifest(writeTestFile(t, dir, "kernel", kernel), writeTestFile(t, dir, "rootfs", rootfs), kernel, rootfs)
	spec := GuestSeedSpec{
		Image: manifest, Hostname: "gru-member-1", InstanceID: "vm-001", Region: "gru", DataDiskPath: "/dev/vdb", NetworkExchangeEndpoint: "10.77.0.1:18080",
		Artifacts: []GuestArtifact{
			guestArtifact("terrabase", "3.0.0", "/fixtures/terrabase", []byte("tb")),
			guestArtifact("ts-node", "3.0.0", "/fixtures/ts-node", []byte("node")),
			guestArtifact("orchestrator", "3.0.0", "/fixtures/orchestrator", []byte("orch")),
		},
	}
	first, err := BuildGuestChannelSeed(spec)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildGuestChannelSeed(spec)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("guest seed is not deterministic")
	}
	decoded, err := DecodeGuestChannelSeed(first)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.Artifacts) != 3 || decoded.Artifacts[0].Component != "ts-node" || decoded.Artifacts[2].Component != "terrabase" {
		t.Fatalf("unexpected fixed artifact order: %#v", decoded.Artifacts)
	}
	cloudInit, err := BuildCloudInit(spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"#cloud-config", "path: " + GuestSeedPath, "ts-node", "orchestrator", "terrabase", GuestChannelSeedDigest(first)} {
		if !strings.Contains(string(cloudInit), value) {
			t.Fatalf("cloud-init does not carry %q", value)
		}
	}
	bad := spec
	bad.Artifacts = append([]GuestArtifact(nil), spec.Artifacts...)
	bad.Artifacts[0].Component = "docker"
	if _, err := BuildGuestChannelSeed(bad); err == nil {
		t.Fatal("unadmitted production component accepted")
	}
	for _, endpoint := range []string{"", "8.8.8.8:18080", "10.77.0.1:018080", "10.77.0.1", "10.77.0.1:18081", "10.77.0.1:65536"} {
		bad = spec
		bad.NetworkExchangeEndpoint = endpoint
		if _, err := BuildGuestChannelSeed(bad); err == nil {
			t.Fatalf("unadmitted network exchange endpoint %q accepted", endpoint)
		}
	}
}

func TestReadinessRequiresEveryRealGuestGate(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	kernel, rootfs := []byte("kernel"), []byte("rootfs")
	manifest := testManifest(writeTestFile(t, dir, "kernel", kernel), writeTestFile(t, dir, "rootfs", rootfs), kernel, rootfs)
	seedDigest := strings.Repeat("a", 64)
	services := []ServiceReadiness{
		{Component: "ts-node", Version: "3.0.0", SHA256: strings.Repeat("1", 64), Ready: true, Health: "healthy", PID1: 100},
		{Component: "orchestrator", Version: "3.0.0", SHA256: strings.Repeat("2", 64), Ready: true, Health: "healthy", PID1: 101},
		{Component: "terrabase", Version: "3.0.0", SHA256: strings.Repeat("3", 64), Ready: true, Health: "healthy", PID1: 102},
	}
	ready, err := NewReadinessMetadata(manifest, seedDigest, true, true, true, true, true, services, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if !ready.IsReady() || ready.Validate(manifest, seedDigest) != nil {
		t.Fatal("complete readiness was not accepted")
	}
	ready.NetworkReady = false
	ready.Ready = true
	if ready.Validate(manifest, seedDigest) == nil {
		t.Fatal("inconsistent readiness was accepted")
	}
}

func testManifest(kernelPath, rootfsPath string, kernel, rootfs []byte) GuestImageManifest {
	return GuestImageManifest{
		SchemaVersion: ManifestSchemaVersion, UbuntuRelease: "24.04.3", Architecture: ArchitectureARM64, Version: "24.04.3",
		Kernel: ArtifactManifest{Name: "vmlinuz", Architecture: ArchitectureARM64, Version: "24.04.3", Source: kernelPath, SHA256: digest(kernel), Size: int64(len(kernel)), Mode: 0o644},
		RootFS: ArtifactManifest{Name: "rootfs.raw", Architecture: ArchitectureARM64, Version: "24.04.3", Source: rootfsPath, SHA256: digest(rootfs), Size: int64(len(rootfs)), Mode: 0o644},
	}
}

func pinnedTestManifest(kernel, rootfs []byte) GuestImageManifest {
	const version = "24.04.3-fc1.15.1"
	return GuestImageManifest{
		SchemaVersion: ManifestSchemaVersion, UbuntuRelease: "24.04.3", Architecture: ArchitectureARM64, Version: version,
		Kernel: ArtifactManifest{Name: "vmlinux-6.1.155", Architecture: ArchitectureARM64, Version: version, Source: "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.15/aarch64/vmlinux-6.1.155", SHA256: digest(kernel), Size: int64(len(kernel)), Mode: 0o644},
		RootFS: ArtifactManifest{Name: "ubuntu-24.04.3-minimal-rootfs.ext4", Architecture: ArchitectureARM64, Version: version, Source: "https://cloud-images.ubuntu.com/minimal/releases/noble/release-20260101/ubuntu-24.04-minimal-cloudimg-arm64.img", SHA256: digest(rootfs), Size: int64(len(rootfs)), Mode: 0o644},
	}
}

func memoryDownloader(files map[string][]byte) Downloader {
	return DownloaderFunc(func(ctx context.Context, source string, destination io.Writer, maxBytes int64) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		content, ok := files[source]
		if !ok {
			return fmt.Errorf("unexpected source %s", source)
		}
		if int64(len(content)) > maxBytes {
			return errors.New("test download exceeds limit")
		}
		_, err := destination.Write(content)
		return err
	})
}

func testRootFSPreparer() RootFSPreparer {
	return RootFSPreparerFunc(func(ctx context.Context, _ string, release string) (RootFSInspection, error) {
		if err := ctx.Err(); err != nil {
			return RootFSInspection{}, err
		}
		series := release[:5]
		return RootFSInspection{OSID: "ubuntu", OSVersionID: series, OSVersion: release + " LTS (Noble Numbat)", SanitizedMounts: []string{"/boot", "/boot/efi"}, FilesystemCheck: "e2fsck -fn"}, nil
	})
}

func guestArtifact(component, version, source string, data []byte) GuestArtifact {
	return GuestArtifact{Component: component, Architecture: ArchitectureARM64, Version: version, Source: source, SHA256: digest(data), Size: int64(len(data)), Mode: 0o644}
}

func writeTestFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
