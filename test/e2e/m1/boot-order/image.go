package main

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"runtime"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/opencontainers/go-digest"
	imagespec "github.com/opencontainers/image-spec/specs-go/v1"
)

func image(ctx context.Context, client *containerd.Client) (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", err
	}
	binary, err := os.ReadFile(executable)
	if err != nil {
		return "", err
	}
	var layer bytes.Buffer
	archive := tar.NewWriter(&layer)
	if err := archive.WriteHeader(&tar.Header{Name: ".", Mode: 0755, Typeflag: tar.TypeDir}); err != nil {
		return "", err
	}
	if err := archive.WriteHeader(&tar.Header{Name: "probe", Mode: 0755, Size: int64(len(binary))}); err != nil {
		return "", err
	}
	if _, err := archive.Write(binary); err != nil {
		return "", err
	}
	if err := archive.Close(); err != nil {
		return "", err
	}
	blob := func(media string, data []byte, labels map[string]string) (imagespec.Descriptor, error) {
		desc := imagespec.Descriptor{MediaType: media, Digest: digest.FromBytes(data), Size: int64(len(data))}
		return desc, content.WriteBlob(ctx, client.ContentStore(), desc.Digest.String(), bytes.NewReader(data), desc, content.WithLabels(labels))
	}
	root, err := blob(imagespec.MediaTypeImageLayer, layer.Bytes(), nil)
	if err != nil {
		return "", err
	}
	config := imagespec.Image{Platform: imagespec.Platform{Architecture: runtime.GOARCH, OS: "linux"},
		Config: imagespec.ImageConfig{Entrypoint: []string{"/probe", "workload"}}, RootFS: imagespec.RootFS{Type: "layers", DiffIDs: []digest.Digest{root.Digest}}}
	data, err := json.Marshal(config)
	if err != nil {
		return "", err
	}
	cfg, err := blob(imagespec.MediaTypeImageConfig, data, nil)
	if err != nil {
		return "", err
	}
	manifest := imagespec.Manifest{MediaType: imagespec.MediaTypeImageManifest, Config: cfg, Layers: []imagespec.Descriptor{root}}
	manifest.SchemaVersion = 2
	data, err = json.Marshal(manifest)
	if err != nil {
		return "", err
	}
	target, err := blob(imagespec.MediaTypeImageManifest, data, map[string]string{"containerd.io/gc.ref.content.config": cfg.Digest.String(), "containerd.io/gc.ref.content.l.0": root.Digest.String()})
	if err != nil {
		return "", err
	}
	name := "docker.io/library/boot-probe@" + target.Digest.String()
	_, err = client.ImageService().Create(ctx, images.Image{Name: name, Target: target})
	return name, err
}
