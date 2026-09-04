package vmimage

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type recordingQEMUImg struct {
	raw        []byte
	executable string
	args       []string
}

func (runner *recordingQEMUImg) Run(_ context.Context, executable string, args ...string) error {
	runner.executable = executable
	runner.args = append([]string(nil), args...)
	return os.WriteFile(args[len(args)-1], runner.raw, 0o600)
}

func TestCacheTransformsPinnedQCOW2RootPartition(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	kernel := []byte("kernel")
	qcow2 := []byte("pinned qcow2 input")
	rootfs := []byte{1, 2, 0, 0, 3, 4, 0, 5}
	raw := append([]byte{9, 9}, rootfs...)
	raw = append(raw, 8, 8)
	kernelPath := writeTestFile(t, dir, "kernel-source", kernel)
	qcow2Path := filepath.Join(dir, "root-source.qcow2")
	if err := os.WriteFile(qcow2Path, qcow2, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := GuestImageManifest{
		SchemaVersion: ManifestSchemaVersion,
		UbuntuRelease: "24.04.3",
		Architecture:  ArchitectureAMD64,
		Version:       "24.04.3-fc1.15.1",
		Kernel: ArtifactManifest{
			Name: "vmlinux-6.1.155", Architecture: ArchitectureAMD64, Version: "24.04.3-fc1.15.1",
			Source: kernelPath, SHA256: digest(kernel), Size: int64(len(kernel)), Mode: 0o644,
		},
		RootFS: ArtifactManifest{
			Name: "ubuntu-24.04.3-rootfs.ext4", Architecture: ArchitectureAMD64, Version: "24.04.3-fc1.15.1",
			Source: qcow2Path, SHA256: digest(rootfs), Size: int64(len(rootfs)), Mode: 0o644,
			InputSHA256: digest(qcow2), InputSize: int64(len(qcow2)),
			Transform: &Transform{Type: TransformQCOW2RootPartition, SectorSize: 1, StartSector: 2, SectorCount: int64(len(rootfs))},
		},
	}
	runner := &recordingQEMUImg{raw: raw}
	cache, err := NewCache(filepath.Join(dir, "cache"))
	if err != nil {
		t.Fatal(err)
	}
	cache.QEMUImgPath = "/usr/bin/qemu-img"
	cache.Runner = runner
	installed, err := cache.Install(context.Background(), manifest)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(installed.RootFS)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, rootfs) {
		t.Fatalf("rootfs = %v, want %v", got, rootfs)
	}
	if runner.executable != cache.QEMUImgPath || !reflect.DeepEqual(runner.args[:5], []string{"convert", "-f", "qcow2", "-O", "raw"}) {
		t.Fatalf("qemu-img invocation = %q %#v", runner.executable, runner.args)
	}
	entries, err := os.ReadDir(installed.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 4 {
		t.Fatalf("cache entry contains %d files, want kernel, rootfs, manifest, and plan", len(entries))
	}
}

func TestCheckedInGuestManifestsAreNativeBuildPlans(t *testing.T) {
	t.Parallel()
	for _, architecture := range []Architecture{ArchitectureAMD64, ArchitectureARM64} {
		architecture := architecture
		t.Run(string(architecture), func(t *testing.T) {
			t.Parallel()
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
			if len(plan.Steps) != 5 || plan.Steps[2].Name != "convert-qcow2-to-raw" || plan.Steps[3].Name != "extract-root-partition" {
				t.Fatalf("build plan steps = %#v", plan.Steps)
			}
		})
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
