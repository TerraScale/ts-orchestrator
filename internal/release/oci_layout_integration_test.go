package release

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// These scenarios cross the retained OCI layout, digest, JSON and filesystem boundaries.
func TestInspectContainerImageLayout(t *testing.T) {
	for _, architecture := range []string{"arm64", "amd64"} {
		for _, indexed := range []bool{false, true} {
			t.Run(architecture+map[bool]string{false: "/manifest", true: "/index"}[indexed], func(t *testing.T) {
				fixture := newContainerLayoutFixture(t, architecture)
				pin, child, index := fixture.publish(t, indexed)
				inspected, err := InspectContainerImageLayout(t.Context(), fixture.directory, pin, architecture)
				if err != nil {
					t.Fatal(err)
				}
				if inspected.Image != "registry.example/terrascale/service@"+child.Digest.String() || inspected.ManifestSHA256 != child.Digest.Encoded() || inspected.Architecture != architecture || inspected.IndexSHA256 != index {
					t.Fatalf("wrong child identity: %+v", inspected)
				}
			})
		}
	}
	for _, failure := range []string{"config architecture", "config OS", "config media", "manifest media", "layer media", "external layer", "inline layer", "layer size", "layer digest", "malformed digest", "missing layer", "ambiguous child", "missing architecture", "variant", "diff ids", "manifest schema", "layout version", "tampered layer", "root missing", "tag", "tar archive", "escape", "metadata bound", "canceled"} {
		t.Run(failure, func(t *testing.T) {
			fixture := newContainerLayoutFixture(t, "arm64")
			switch failure {
			case "config architecture":
				fixture.config.Architecture = "amd64"
			case "config OS":
				fixture.config.OS = "windows"
			case "config media":
				fixture.manifest.Config.MediaType = "application/octet-stream"
			case "manifest media":
				fixture.manifest.MediaType = ocispec.MediaTypeImageIndex
			case "layer media":
				fixture.manifest.Layers[0].MediaType = "application/octet-stream"
			case "external layer":
				fixture.manifest.Layers[0].URLs = []string{"http://169.254.169.254/latest/credentials"}
			case "inline layer":
				fixture.manifest.Layers[0].Data = []byte("inline bytes")
			case "layer size":
				fixture.manifest.Layers[0].Size++
			case "layer digest", "missing layer":
				fixture.manifest.Layers[0].Digest = digest.Digest("sha256:" + strings.Repeat("0", 64))
			case "malformed digest":
				fixture.manifest.Layers[0].Digest = "../../outside"
			case "ambiguous child":
				fixture.duplicate = true
			case "missing architecture":
				fixture.platform.Architecture = "amd64"
			case "variant":
				fixture.platform.Variant = "v9"
			case "diff ids":
				fixture.config.RootFS.DiffIDs = nil
			case "manifest schema":
				fixture.manifest.SchemaVersion = 1
			}
			pin, _, _ := fixture.publish(t, true)
			ctx := t.Context()
			switch failure {
			case "layout version":
				fixture.write(t, "oci-layout", []byte(`{"imageLayoutVersion":"0.0.0"}`))
			case "tampered layer":
				fixture.write(t, "blobs/sha256/"+fixture.layer.Digest.Encoded(), []byte("changed"))
			case "layer digest":
				fixture.write(t, "blobs/sha256/"+strings.Repeat("0", 64), fixture.layerBytes)
			case "root missing":
				pin = "registry.example/terrascale/service@sha256:" + strings.Repeat("0", 64)
			case "tag":
				pin = "registry.example/terrascale/service:latest"
			case "tar archive":
				fixture.write(t, "image.tar", fixture.layerBytes)
				fixture.directory = filepath.Join(fixture.directory, "image.tar")
			case "escape":
				outside := filepath.Join(t.TempDir(), "layer")
				if err := os.WriteFile(outside, fixture.layerBytes, 0o600); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(fixture.directory, "blobs/sha256/"+fixture.layer.Digest.Encoded())
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, path); err != nil {
					t.Fatal(err)
				}
			case "metadata bound":
				if err := os.Truncate(filepath.Join(fixture.directory, "index.json"), maxContainerMetadataBytes+1); err != nil {
					t.Fatal(err)
				}
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if _, err := InspectContainerImageLayout(ctx, fixture.directory, pin, "arm64"); err == nil {
				t.Fatalf("accepted %s", failure)
			} else if failure == "canceled" && !errors.Is(err, context.Canceled) {
				t.Fatalf("lost cancellation: %v", err)
			}
		})
	}
}

func TestInspectContainerImageLayoutStandardRootIndex(t *testing.T) {
	arm := newContainerLayoutFixture(t, "arm64")
	amd := newContainerLayoutFixture(t, "amd64")
	_, armChild, _ := arm.publish(t, false)
	_, amdChild, _ := amd.publish(t, false)
	files, err := os.ReadDir(filepath.Join(amd.directory, "blobs/sha256"))
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		wire, err := os.ReadFile(filepath.Join(amd.directory, "blobs/sha256", file.Name()))
		if err != nil {
			t.Fatal(err)
		}
		arm.write(t, "blobs/sha256/"+file.Name(), wire)
	}
	index, err := json.Marshal(ocispec.Index{SchemaVersion: 2, MediaType: ocispec.MediaTypeImageIndex,
		Manifests: []ocispec.Descriptor{armChild, amdChild}})
	if err != nil {
		t.Fatal(err)
	}
	arm.write(t, "index.json", index)
	root := digest.FromBytes(index)
	if _, err := os.Stat(filepath.Join(arm.directory, "blobs/sha256", root.Encoded())); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("fixture unexpectedly has a duplicate root blob: %v", err)
	}
	for _, child := range []ocispec.Descriptor{armChild, amdChild} {
		t.Run(child.Platform.Architecture, func(t *testing.T) {
			result, err := InspectContainerImageLayout(t.Context(), arm.directory,
				"registry.example/terrascale/service@"+root.String(), child.Platform.Architecture)
			if err != nil {
				t.Fatal(err)
			}
			if result.ManifestSHA256 != child.Digest.Encoded() || result.IndexSHA256 != root.Encoded() || result.Image != "registry.example/terrascale/service@"+child.Digest.String() {
				t.Fatalf("standard root index selected the wrong child: %+v", result)
			}
		})
	}
	arm.write(t, "index.json", append(index, '\n'))
	if _, err := InspectContainerImageLayout(t.Context(), arm.directory,
		"registry.example/terrascale/service@"+root.String(), "arm64"); err == nil {
		t.Fatal("changed root index bytes retained the pinned digest")
	}
}

type containerLayoutFixture struct {
	directory  string
	config     ocispec.Image
	manifest   ocispec.Manifest
	platform   ocispec.Platform
	layer      ocispec.Descriptor
	layerBytes []byte
	duplicate  bool
}

func newContainerLayoutFixture(t *testing.T, architecture string) *containerLayoutFixture {
	t.Helper()
	var layer bytes.Buffer
	archive := tar.NewWriter(&layer)
	contents := []byte("#!/bin/sh\nexit 0\n")
	if err := archive.WriteHeader(&tar.Header{Name: "service", Mode: 0o755, Size: int64(len(contents))}); err != nil {
		t.Fatal(err)
	}
	if _, err := archive.Write(contents); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	f := &containerLayoutFixture{directory: t.TempDir(), platform: ocispec.Platform{OS: "linux", Architecture: architecture}, layerBytes: layer.Bytes()}
	f.layer = f.blob(t, f.layerBytes, ocispec.MediaTypeImageLayer)
	f.config = ocispec.Image{Platform: f.platform, RootFS: ocispec.RootFS{Type: "layers", DiffIDs: []digest.Digest{f.layer.Digest}}}
	f.manifest = ocispec.Manifest{SchemaVersion: 2, MediaType: ocispec.MediaTypeImageManifest,
		Config: ocispec.Descriptor{MediaType: ocispec.MediaTypeImageConfig}, Layers: []ocispec.Descriptor{f.layer}}
	f.write(t, "oci-layout", []byte(`{"imageLayoutVersion":"1.0.0"}`))
	return f
}

func (f *containerLayoutFixture) publish(t *testing.T, indexed bool) (string, ocispec.Descriptor, string) {
	t.Helper()
	encode := func(value any) []byte {
		t.Helper()
		wire, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	f.manifest.Config = f.blob(t, encode(f.config), f.manifest.Config.MediaType)
	child := f.blob(t, encode(f.manifest), ocispec.MediaTypeImageManifest)
	child.Platform = &f.platform
	root, indexDigest := child, ""
	if indexed {
		children := []ocispec.Descriptor{child}
		if f.duplicate {
			children = append(children, child)
		}
		index := ocispec.Index{SchemaVersion: 2, MediaType: ocispec.MediaTypeImageIndex, Manifests: children}
		root = f.blob(t, encode(index), ocispec.MediaTypeImageIndex)
		indexDigest = root.Digest.Encoded()
	}
	f.write(t, "index.json", encode(ocispec.Index{SchemaVersion: 2, Manifests: []ocispec.Descriptor{root}}))
	return "registry.example/terrascale/service@" + root.Digest.String(), child, indexDigest
}

func (f *containerLayoutFixture) blob(t *testing.T, wire []byte, media string) ocispec.Descriptor {
	t.Helper()
	value := digest.FromBytes(wire)
	f.write(t, "blobs/sha256/"+value.Encoded(), wire)
	return ocispec.Descriptor{Digest: value, Size: int64(len(wire)), MediaType: media}
}

func (f *containerLayoutFixture) write(t *testing.T, name string, wire []byte) {
	t.Helper()
	path := filepath.Join(f.directory, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, wire, 0o600); err != nil {
		t.Fatal(err)
	}
}
