//go:build linux

package swarmruntime

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/json/v2"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	tasksapi "github.com/containerd/containerd/api/services/tasks/v1"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/opencontainers/go-digest"
	imagespec "github.com/opencontainers/image-spec/specs-go/v1"
)

const offlineSmokeBusybox = "/nix/store/b4zpmj5qfb4l4zjhilln6s7cyna9prym-busybox-1.37.0/bin/busybox"
const offlineSmokeBusyboxSHA256 = "0851d22f7ac81948916164c7a8822d3a65719d1f75d2b429af7bc1cb97c7cb3d"

// This is an actual offline runtime boundary, with test-only ownhost/material
// admission. It grants no production image, pool worker or ROOT source credit.
func TestContainerdOfflineLifecycleAgentRecovery(t *testing.T) {
	if *integrationSocket == "" || os.Geteuid() != 0 || runtime.GOARCH != "amd64" {
		t.Fatal("offline runtime requires an explicit private socket, root namespace and pinned amd64 asset")
	}
	ctx, cancel := context.WithTimeout(runtimeContext(t.Context()), 2*time.Minute)
	defer cancel()
	client, err := containerd.New(*integrationSocket, containerd.WithDefaultNamespace(runtimeNamespace))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	image := importOfflineSmokeImage(t, ctx, client)
	testContainerdLifecycleAgentRecovery(t, image.Name())
	if unpacked, err := image.IsUnpacked(ctx, "native"); err != nil || !unpacked {
		t.Fatalf("offline Prepare did not unpack actual local image: %t, %v", unpacked, err)
	}
	containers, err := client.Containers(ctx)
	if err != nil || len(containers) != 0 {
		t.Fatal("offline private namespace retains containers after lifecycle", err)
	}
	processes, err := client.TaskService().List(ctx, &tasksapi.ListTasksRequest{})
	if err != nil || len(processes.Tasks) != 0 {
		t.Fatal("offline private namespace retains tasks after lifecycle", err)
	}
}

func importOfflineSmokeImage(t *testing.T, ctx context.Context, client *containerd.Client) containerd.Image {
	t.Helper()
	binary, err := os.ReadFile(offlineSmokeBusybox)
	if err != nil {
		t.Fatal("read existing offline smoke asset", err)
	}
	if fmt.Sprintf("%x", sha256.Sum256(binary)) != offlineSmokeBusyboxSHA256 {
		t.Fatal("offline smoke asset differs from pinned actual bytes")
	}
	executable, err := elf.NewFile(bytes.NewReader(binary))
	if err != nil {
		t.Fatal(err)
	}
	if executable.Machine != elf.EM_X86_64 || executable.Class != elf.ELFCLASS64 {
		t.Fatal("offline smoke asset is not native amd64 ELF")
	}
	for _, program := range executable.Progs {
		if program.Type == elf.PT_INTERP {
			t.Fatal("offline smoke asset requires an external dynamic interpreter")
		}
	}
	var layer bytes.Buffer
	rootfs := tar.NewWriter(&layer)
	for _, directory := range []string{"bin/", "dev/", "proc/", "sys/", "tmp/"} {
		if err := rootfs.WriteHeader(&tar.Header{Name: directory, Mode: 0755, Typeflag: tar.TypeDir}); err != nil {
			t.Fatal(err)
		}
	}
	if err := rootfs.WriteHeader(&tar.Header{Name: "bin/busybox", Mode: 0555, Size: int64(len(binary)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := rootfs.Write(binary); err != nil {
		t.Fatal(err)
	}
	for _, applet := range []string{"sh", "id", "touch", "head", "sleep"} {
		if err := rootfs.WriteHeader(&tar.Header{Name: "bin/" + applet, Linkname: "busybox", Mode: 0777, Typeflag: tar.TypeSymlink}); err != nil {
			t.Fatal(err)
		}
	}
	if err := rootfs.Close(); err != nil {
		t.Fatal(err)
	}
	encode := func(value any) []byte {
		t.Helper()
		wire, err := json.Marshal(value, json.Deterministic(true))
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	descriptor := func(wire []byte, mediaType string) imagespec.Descriptor {
		return imagespec.Descriptor{MediaType: mediaType, Digest: digest.FromBytes(wire), Size: int64(len(wire))}
	}
	layerDesc := descriptor(layer.Bytes(), imagespec.MediaTypeImageLayer)
	config := encode(imagespec.Image{Architecture: "amd64", OS: "linux",
		Config: imagespec.ImageConfig{Env: []string{"PATH=/bin"}, Cmd: []string{"/bin/sh"}},
		RootFS: imagespec.RootFS{Type: "layers", DiffIDs: []digest.Digest{layerDesc.Digest}}})
	configDesc := descriptor(config, imagespec.MediaTypeImageConfig)
	manifest := encode(imagespec.Manifest{SchemaVersion: 2, MediaType: imagespec.MediaTypeImageManifest, Config: configDesc, Layers: []imagespec.Descriptor{layerDesc}})
	target := descriptor(manifest, imagespec.MediaTypeImageManifest)
	index := encode(imagespec.Index{SchemaVersion: 2, MediaType: imagespec.MediaTypeImageIndex, Manifests: []imagespec.Descriptor{target}})
	archivePath := filepath.Join(t.TempDir(), "smoke.oci.tar")
	file, err := os.OpenFile(archivePath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	archiveHash := sha256.New()
	archive := tar.NewWriter(io.MultiWriter(file, archiveHash))
	for _, entry := range []struct {
		name string
		wire []byte
	}{
		{"oci-layout", encode(imagespec.ImageLayout{Version: imagespec.ImageLayoutVersion})},
		{"index.json", index},
		{"blobs/sha256/" + target.Digest.Encoded(), manifest},
		{"blobs/sha256/" + configDesc.Digest.Encoded(), config},
		{"blobs/sha256/" + layerDesc.Digest.Encoded(), layer.Bytes()},
	} {
		if err := archive.WriteHeader(&tar.Header{Name: entry.name, Mode: 0444, Size: int64(len(entry.wire)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := archive.Write(entry.wire); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	ref := "registry.invalid/offline-smoke@" + target.Digest.String()
	if _, err := client.Import(ctx, file, containerd.WithDigestRef(func(digest.Digest) string { return ref })); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(runtimeContext(context.Background()), 10*time.Second)
		defer cancel()
		if err := client.ImageService().Delete(cleanup, ref); err != nil {
			t.Error("remove exact offline smoke image", err)
		}
	})
	image, err := client.GetImage(ctx, ref)
	if err != nil || image.Target().Digest != target.Digest {
		t.Fatal("imported offline smoke manifest differs from exact local archive", err)
	}
	if unpacked, err := image.IsUnpacked(ctx, "native"); err != nil || unpacked {
		t.Fatalf("fresh offline image unexpectedly unpacked before Prepare: %t, %v", unpacked, err)
	}
	t.Logf("actual offline smoke asset SHA256=%s; generated OCI archive=%s SHA256=%x manifest=%s", offlineSmokeBusyboxSHA256, archivePath, archiveHash.Sum(nil), target.Digest)
	return image
}
