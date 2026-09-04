package vmimage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
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

func TestCacheInstallIsDigestKeyedAndIdempotent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	kernel, rootfs := []byte("kernel"), []byte("rootfs")
	kernelPath := writeTestFile(t, dir, "kernel", kernel)
	rootfsPath := writeTestFile(t, dir, "rootfs", rootfs)
	manifest := testManifest(kernelPath, rootfsPath, kernel, rootfs)
	cache, err := NewCache(filepath.Join(dir, "cache"))
	if err != nil {
		t.Fatal(err)
	}
	first, err := cache.Install(context.Background(), manifest)
	if err != nil {
		t.Fatal(err)
	}
	second, err := cache.Install(context.Background(), manifest)
	if err != nil {
		t.Fatal(err)
	}
	if first.Dir != second.Dir || first.Kernel != second.Kernel || first.RootFS != second.RootFS {
		t.Fatal("idempotent install changed immutable cache entry")
	}
	if err := cache.VerifyInstalled(first); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Dir(first.Dir))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("cache contains %d entries, want one", len(entries))
	}
	if info, err := os.Lstat(first.Dir); err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("cache entry is not a private directory: %v, %v", info, err)
	}
}

func TestCacheHTTPSourceUsesBoundedLocalServer(t *testing.T) {
	t.Parallel()
	kernel, rootfs := []byte("kernel over http"), []byte("rootfs over http")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/kernel":
			_, _ = writer.Write(kernel)
		case "/rootfs":
			_, _ = writer.Write(rootfs)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	manifest := testManifest(server.URL+"/kernel", server.URL+"/rootfs", kernel, rootfs)
	cache, err := NewCache(filepath.Join(t.TempDir(), "cache"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Install(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
}

func TestSeedIsDeterministicAndRestrictsProductionArtifacts(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	kernel, rootfs := []byte("kernel"), []byte("rootfs")
	manifest := testManifest(writeTestFile(t, dir, "kernel", kernel), writeTestFile(t, dir, "rootfs", rootfs), kernel, rootfs)
	spec := GuestSeedSpec{
		Image: manifest, Hostname: "gru-member-1", InstanceID: "vm-001", Region: "gru", DataDiskPath: "/dev/vdb",
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
	for _, value := range []string{"#cloud-config", "guest-seed.json", "ts-node", "orchestrator", "terrabase", GuestChannelSeedDigest(first)} {
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

func guestArtifact(component, version, source string, data []byte) GuestArtifact {
	return GuestArtifact{Component: component, Architecture: ArchitectureARM64, Version: version, Source: source, SHA256: digest(data), Size: int64(len(data)), Mode: 0o644}
}

func writeTestFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
