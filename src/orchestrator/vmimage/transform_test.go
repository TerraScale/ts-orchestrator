package vmimage

import (
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type recordingQEMUImg struct {
	raw        []byte
	err        error
	executable string
	args       []string
}

func (runner *recordingQEMUImg) Run(_ context.Context, executable string, args ...string) error {
	runner.executable = executable
	runner.args = append([]string(nil), args...)
	if runner.err != nil {
		return runner.err
	}
	return os.WriteFile(args[len(args)-1], runner.raw, 0o600)
}

func TestCacheTransformsPinnedQCOW2RootPartition(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	kernel := []byte("kernel")
	qcow2 := []byte("pinned qcow2 input")
	const version = "24.04.3-fc1.15.1"
	manifest := GuestImageManifest{
		SchemaVersion: ManifestSchemaVersion,
		UbuntuRelease: "24.04.3",
		Architecture:  ArchitectureAMD64,
		Version:       version,
		Kernel: ArtifactManifest{
			Name: "vmlinux-6.1.155", Architecture: ArchitectureAMD64, Version: version,
			Source: "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.15/x86_64/vmlinux-6.1.155", SHA256: digest(kernel), Size: int64(len(kernel)), Mode: 0o644,
		},
		RootFS: ArtifactManifest{
			Name: "ubuntu-24.04.3-rootfs.ext4", Architecture: ArchitectureAMD64, Version: version,
			Source: "https://cloud-images.ubuntu.com/minimal/releases/noble/release-20251001/ubuntu-24.04-minimal-cloudimg-amd64.img", SHA256: strings.Repeat("1", 64), Size: UbuntuRootFSSize, Mode: 0o644,
			InputSHA256: digest(qcow2), InputSize: int64(len(qcow2)),
			Transform: &Transform{Type: TransformQCOW2RootPartition, SectorSize: UbuntuRootSectorSize, StartSector: UbuntuRootStartSector, SectorCount: UbuntuRootSectorCount},
		},
	}
	wantErr := errors.New("stop after typed invocation")
	runner := &recordingQEMUImg{err: wantErr}
	cache, err := NewCache(filepath.Join(dir, "cache"))
	if err != nil {
		t.Fatal(err)
	}
	cache.QEMUImgPath = filepath.Join(dir, "qemu-img")
	if err := os.WriteFile(cache.QEMUImgPath, []byte("fake"), 0o700); err != nil {
		t.Fatal(err)
	}
	cache.Runner = runner
	cache.Downloader = memoryDownloader(map[string][]byte{manifest.Kernel.Source: kernel, manifest.RootFS.Source: qcow2})
	if _, err := cache.Install(context.Background(), manifest); !errors.Is(err, wantErr) {
		t.Fatalf("install error = %v, want runner error", err)
	}
	if runner.executable != cache.QEMUImgPath || len(runner.args) != 7 || !reflect.DeepEqual(runner.args[:5], []string{"convert", "-f", "qcow2", "-O", "raw"}) ||
		!strings.HasSuffix(runner.args[5], ".input") || !strings.HasSuffix(runner.args[6], ".raw") {
		t.Fatalf("qemu-img invocation = %q %#v", runner.executable, runner.args)
	}
	if entries, err := os.ReadDir(filepath.Join(dir, "cache", "amd64", version)); err != nil || len(entries) != 0 {
		t.Fatalf("failed transform left staging state: entries=%v err=%v", entries, err)
	}
}

func TestCopySparseSectionExtractsExactBytes(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	rootfs := []byte{1, 2, 0, 0, 3, 4, 0, 5}
	raw := append([]byte{9, 9}, rootfs...)
	raw = append(raw, 8, 8)
	source := filepath.Join(directory, "disk.raw")
	target := filepath.Join(directory, "root.ext4")
	if err := os.WriteFile(source, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copySparseSection(context.Background(), source, target, 2, int64(len(rootfs)), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(target)
	if err != nil || !reflect.DeepEqual(got, rootfs) {
		t.Fatalf("rootfs = %v, err = %v", got, err)
	}
}

func TestCheckedInGuestManifestsAreNativeBuildPlans(t *testing.T) {
	t.Parallel()
	manifests := make(map[Architecture]GuestImageManifest, 2)
	for _, architecture := range []Architecture{ArchitectureAMD64, ArchitectureARM64} {
		t.Run(string(architecture), func(t *testing.T) {
			data, err := os.ReadFile("ubuntu-24.04.3-" + string(architecture) + ".json")
			if err != nil {
				t.Fatal(err)
			}
			manifest, err := DecodeManifest(data)
			if err != nil {
				t.Fatal(err)
			}
			if manifest.Architecture != architecture || manifest.RootFS.Transform == nil {
				t.Fatalf("manifest architecture/transform = %q %#v", manifest.Architecture, manifest.RootFS.Transform)
			}
			manifests[architecture] = manifest
			for _, source := range []string{manifest.Kernel.Source, manifest.RootFS.Source} {
				parsed, err := url.Parse(source)
				if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
					t.Fatalf("source is not fixed HTTPS: %q", source)
				}
			}
			plan, err := NewBuildPlan(manifest, filepath.Join(t.TempDir(), "cache"))
			if err != nil {
				t.Fatal(err)
			}
			if len(plan.Steps) != 10 || plan.Steps[2].Name != "convert-qcow2-to-raw" || plan.Steps[3].Name != "extract-root-partition" || plan.Steps[7].Name != "verify-rootfs-output" {
				t.Fatalf("build plan steps = %#v", plan.Steps)
			}
		})
	}
	amd64, arm64 := manifests[ArchitectureAMD64], manifests[ArchitectureARM64]
	if amd64.UbuntuRelease != arm64.UbuntuRelease || amd64.Version != arm64.Version ||
		amd64.Kernel.Name != arm64.Kernel.Name || amd64.RootFS.Name != arm64.RootFS.Name ||
		amd64.RootFS.Size != arm64.RootFS.Size || amd64.RootFS.Mode != arm64.RootFS.Mode ||
		amd64.RootFS.Transform == nil || arm64.RootFS.Transform == nil || *amd64.RootFS.Transform != *arm64.RootFS.Transform {
		t.Fatalf("architecture-neutral image pins diverge: amd64=%#v arm64=%#v", amd64, arm64)
	}
}

func TestBuildPlanCanonicalJSONDoesNotContainHostPaths(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("ubuntu-24.04.3-amd64.json")
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := DecodeManifest(data)
	if err != nil {
		t.Fatal(err)
	}
	left, err := NewBuildPlan(manifest, "/var/cache/terrascale/vmimage")
	if err != nil {
		t.Fatal(err)
	}
	right, err := NewBuildPlan(manifest, filepath.Join(t.TempDir(), "cache"))
	if err != nil {
		t.Fatal(err)
	}
	leftJSON, err := left.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	rightJSON, err := right.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(leftJSON, rightJSON) {
		t.Fatalf("build plan bytes depend on cache root:\n%s\n%s", leftJSON, rightJSON)
	}
	if bytes := string(leftJSON); strings.Contains(bytes, left.CacheEntry) || strings.Contains(bytes, right.CacheEntry) {
		t.Fatalf("build plan leaked a host-local cache path: %s", bytes)
	}
	decoded, err := DecodeBuildPlan(leftJSON)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.CacheEntry != "" || decoded.CacheKey != left.CacheKey || !strings.HasSuffix(filepath.ToSlash(left.CacheEntry), "/"+left.CacheKey) {
		t.Fatalf("portable cache identity = key %q, decoded path %q, local path %q", decoded.CacheKey, decoded.CacheEntry, left.CacheEntry)
	}
}

func TestManifestRejectsZeroDigestAndBadPartitionGeometry(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	kernel, rootfs := []byte("kernel"), []byte("rootfs")
	manifest := testManifest(writeTestFile(t, dir, "kernel", kernel), writeTestFile(t, dir, "rootfs", rootfs), kernel, rootfs)
	manifest.Kernel.SHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
	if err := manifest.Validate(); err == nil {
		t.Fatal("all-zero artifact digest was accepted")
	}
	manifest = testManifest(writeTestFile(t, dir, "kernel-2", kernel), writeTestFile(t, dir, "rootfs-2", rootfs), kernel, rootfs)
	manifest.RootFS.InputSHA256 = digest([]byte("input"))
	manifest.RootFS.InputSize = 5
	manifest.RootFS.Transform = &Transform{Type: TransformQCOW2RootPartition, SectorSize: 512, StartSector: 1, SectorCount: 1}
	if err := manifest.Validate(); err == nil {
		t.Fatal("partition geometry that disagrees with output size was accepted")
	}
}
