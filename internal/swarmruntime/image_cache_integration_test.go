package swarmruntime

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/images/archive"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/errdefs"
	"github.com/moby/swarmkit/v2/api"
	"github.com/opencontainers/go-digest"
	imagespec "github.com/opencontainers/image-spec/specs-go/v1"
)

type deniedCacheRegistry struct{ requests atomic.Int32 }

func (r *deniedCacheRegistry) Resolve(context.Context, string) (string, imagespec.Descriptor, error) {
	r.requests.Add(1)
	return "", imagespec.Descriptor{}, errors.New("registry egress denied")
}
func (r *deniedCacheRegistry) Fetcher(context.Context, string) (remotes.Fetcher, error) {
	r.requests.Add(1)
	return nil, errors.New("registry egress denied")
}
func (r *deniedCacheRegistry) Pusher(context.Context, string) (remotes.Pusher, error) {
	r.requests.Add(1)
	return nil, errors.New("registry egress denied")
}

func TestContainerdImportedImageWithoutRegistryEgress(t *testing.T) {
	if *integrationSocket == "" {
		t.Fatal("provide -containerd-socket for a disposable real runtime")
	}
	ctx, cancel := context.WithTimeout(runtimeContext(t.Context()), 2*time.Minute)
	defer cancel()
	e, err := newIntegrationExecutor(*integrationSocket, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	image, marker := importCacheFixture(t, ctx, e.client)
	unpacked, err := image.IsUnpacked(ctx, "native")
	if err != nil || unpacked {
		t.Fatalf("import must leave unique native rootfs unpacked=false: %t, %v", unpacked, err)
	}
	registry := new(deniedCacheRegistry)
	admitted, admissions := true, 0
	denied := errors.New("current image admission denied")
	if err := e.SetRegistryResolver(func(_ context.Context, task *api.Task, _ *api.Node) (remotes.Resolver, error) {
		admissions++
		if _, err := DecodeContainer(task); err != nil {
			return nil, err
		}
		if !admitted {
			return nil, denied
		}
		return registry, nil
	}); err != nil {
		t.Fatal(err)
	}
	controllerFor := func(imageRef string) *controller {
		t.Helper()
		runtime, err := ContainerRuntime(&api.ContainerSpec{Image: imageRef, User: "65532:65532", Command: []string{"/bin/sh", "-c", "test -f /" + marker}})
		if err != nil {
			t.Fatal(err)
		}
		task := &api.Task{ID: fmt.Sprintf("cache%d", time.Now().UnixNano()), ServiceID: "cacheintegration", Spec: api.TaskSpec{Runtime: runtime, Resources: containerTestResources(250_000_000, 64<<20)}}
		c, err := integrationContainerController(e, task)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
			defer stop()
			if err := c.Remove(cleanup); err != nil {
				t.Error(err)
			}
		})
		return c.(*controller)
	}
	c := controllerFor(image.Name())
	if err := c.Prepare(ctx); err != nil {
		t.Fatal(err)
	}
	if unpacked, err := image.IsUnpacked(ctx, "native"); err != nil || !unpacked {
		t.Fatalf("Prepare did not unpack imported local content: %t, %v", unpacked, err)
	}
	if err := c.Prepare(ctx); err != nil {
		t.Fatalf("cached container reattach: %v", err)
	}
	admitted = false
	if err := c.Prepare(ctx); !errors.Is(err, denied) {
		t.Fatalf("existing container bypassed current admission: %v", err)
	}
	freshDenied := controllerFor(image.Name())
	if err := freshDenied.Prepare(ctx); !errors.Is(err, denied) {
		t.Fatalf("cached image bypassed current admission: %v", err)
	}
	admitted = true
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Wait(ctx); err != nil {
		t.Fatalf("imported image marker workload: %v", err)
	}
	wrongRef := "registry.invalid/cache@sha256:" + strings.Repeat("0", 64)
	if _, err := e.client.ImageService().Create(ctx, images.Image{Name: wrongRef, Target: image.Target()}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.client.ImageService().Delete(runtimeContext(context.Background()), wrongRef) })
	wrong := controllerFor(wrongRef)
	if err := wrong.Prepare(ctx); err == nil || !strings.Contains(err.Error(), "target differs from pinned digest") {
		t.Fatalf("wrong target metadata accepted: %v", err)
	}
	if _, err := e.client.LoadContainer(ctx, wrong.id); !errdefs.IsNotFound(err) {
		t.Fatalf("wrong-target image created a container: %v", err)
	}
	corruptData := []byte("{")
	corruptTarget := imagespec.Descriptor{MediaType: imagespec.MediaTypeImageManifest, Digest: digest.FromBytes(corruptData), Size: int64(len(corruptData))}
	corruptRef := "registry.invalid/cache@" + corruptTarget.Digest.String()
	if err := content.WriteBlob(ctx, e.client.ContentStore(), "corrupt-cache-fixture", bytes.NewReader(corruptData), corruptTarget); err != nil {
		t.Fatal(err)
	}
	if _, err := e.client.ImageService().Create(ctx, images.Image{Name: corruptRef, Target: corruptTarget}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.client.ImageService().Delete(runtimeContext(context.Background()), corruptRef) })
	corrupt := controllerFor(corruptRef)
	if err := corrupt.Prepare(ctx); err == nil {
		t.Fatal("corrupt local manifest accepted")
	}
	if _, err := e.client.LoadContainer(ctx, corrupt.id); !errdefs.IsNotFound(err) {
		t.Fatalf("corrupt image created a container: %v", err)
	}
	if admissions != 6 || registry.requests.Load() != 0 {
		t.Fatalf("admission calls=%d (want 6), registry requests=%d (want 0)", admissions, registry.requests.Load())
	}
	t.Log("imported exact child image unpacked and executed locally; cached and reattached admission enforced; wrong target and corrupt manifest rejected; registry requests=0")
}

// Add a unique real layer so the imported image must exercise local native unpack.
func importCacheFixture(t *testing.T, ctx context.Context, client *containerd.Client) (containerd.Image, string) {
	t.Helper()
	ctx, release, err := client.WithLease(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release(ctx)
	base, err := client.Pull(ctx, integrationImage)
	if err != nil {
		t.Fatal(err)
	}
	store := client.ContentStore()
	manifestData, err := content.ReadBlob(ctx, store, base.Target())
	if err != nil {
		t.Fatal(err)
	}
	var manifest imagespec.Manifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		t.Fatal(err)
	}
	config, err := base.Spec(ctx)
	if err != nil {
		t.Fatal(err)
	}
	marker := fmt.Sprintf("cache-fixture-%d", time.Now().UnixNano())
	var layer bytes.Buffer
	writer := tar.NewWriter(&layer)
	if err := writer.WriteHeader(&tar.Header{Name: marker, Mode: 0444, Size: 0}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	writeBlob := func(data []byte, mediaType string) imagespec.Descriptor {
		t.Helper()
		desc := imagespec.Descriptor{MediaType: mediaType, Digest: digest.FromBytes(data), Size: int64(len(data))}
		if err := content.WriteBlob(ctx, store, marker+desc.Digest.String(), bytes.NewReader(data), desc); err != nil {
			t.Fatal(err)
		}
		return desc
	}
	layerDesc := writeBlob(layer.Bytes(), imagespec.MediaTypeImageLayer)
	config.RootFS.DiffIDs = append(config.RootFS.DiffIDs, layerDesc.Digest)
	configData, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Config = writeBlob(configData, imagespec.MediaTypeImageConfig)
	manifest.Layers = append(manifest.Layers, layerDesc)
	manifest.MediaType = imagespec.MediaTypeImageManifest
	manifestData, err = json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	target := writeBlob(manifestData, imagespec.MediaTypeImageManifest)
	var archiveData bytes.Buffer
	if err := client.Export(ctx, &archiveData, archive.WithManifest(target), archive.WithSkipDockerManifest()); err != nil {
		t.Fatal(err)
	}
	ref := "registry.invalid/cache@" + target.Digest.String()
	if _, err := client.Import(ctx, &archiveData, containerd.WithDigestRef(func(digest.Digest) string { return ref })); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.ImageService().Delete(runtimeContext(context.Background()), ref) })
	image, err := client.GetImage(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	return image, marker
}
