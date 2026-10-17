package release

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/distribution/reference"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	maxContainerMetadataBytes = 8 << 20
	maxContainerLayerBytes    = 8 << 30
	maxContainerLayoutBytes   = 32 << 30
	maxContainerLayers        = 512
)

// ContainerImage retains the producer's immutable index and selected child.
// Image always names the executable child, never a platform index or a tag.
type ContainerImage struct {
	Image          string
	Index          []byte
	IndexSHA256    string
	ManifestSHA256 string
	Architecture   string
}

// InspectContainerImageLayout verifies a retained OCI Image Layout before its
// selected Linux child can be signed. It performs no network access or extraction.
func InspectContainerImageLayout(ctx context.Context, directory, pinnedImage, architecture string) (ContainerImage, error) {
	if architecture != "arm64" && architecture != "amd64" {
		return ContainerImage{}, errors.New("container image architecture must be arm64 or amd64")
	}
	ref, err := reference.ParseNormalizedNamed(pinnedImage)
	if err != nil {
		return ContainerImage{}, errors.New("container image requires a canonical digest reference")
	}
	canonical, ok := ref.(reference.Canonical)
	_, tagged := ref.(reference.Tagged)
	if !ok || tagged || canonical.String() != pinnedImage || canonical.Digest().Validate() != nil || canonical.Digest().Algorithm().String() != "sha256" {
		return ContainerImage{}, errors.New("container image requires a canonical sha256 reference without a tag")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return ContainerImage{}, fmt.Errorf("open OCI image layout: %w", err)
	}
	defer root.Close()
	layout := containerLayout{root: root, ctx: ctx}
	wire, err := layout.read("oci-layout", maxContainerMetadataBytes)
	if err != nil {
		return ContainerImage{}, err
	}
	var version ocispec.ImageLayout
	if err := json.Unmarshal(wire, &version); err != nil || version.Version != ocispec.ImageLayoutVersion {
		return ContainerImage{}, errors.New("unsupported OCI image layout version")
	}
	wire, err = layout.read("index.json", maxContainerMetadataBytes)
	if err != nil {
		return ContainerImage{}, err
	}
	var index ocispec.Index
	if err := json.Unmarshal(wire, &index); err != nil || index.SchemaVersion != 2 || index.MediaType != "" && index.MediaType != ocispec.MediaTypeImageIndex || len(index.Manifests) == 0 || len(index.Manifests) > maxContainerLayers {
		return ContainerImage{}, errors.New("invalid OCI image layout index")
	}
	var descriptor ocispec.Descriptor
	rootIsIndex := fmt.Sprintf("%x", sha256.Sum256(wire)) == canonical.Digest().Encoded()
	if rootIsIndex {
		descriptor = ocispec.Descriptor{MediaType: ocispec.MediaTypeImageIndex, Digest: canonical.Digest(), Size: int64(len(wire))}
	} else {
		for _, candidate := range index.Manifests {
			if candidate.Digest == canonical.Digest() {
				if descriptor.Digest != "" {
					return ContainerImage{}, errors.New("OCI layout repeats the pinned image")
				}
				descriptor = candidate
			}
		}
	}
	if descriptor.Digest == "" {
		return ContainerImage{}, errors.New("pinned image is absent from OCI layout index")
	}
	result := ContainerImage{Architecture: architecture}
	if descriptor.MediaType == ocispec.MediaTypeImageIndex || descriptor.MediaType == "application/vnd.docker.distribution.manifest.list.v2+json" {
		if !rootIsIndex {
			wire, err = layout.blob(descriptor, maxContainerMetadataBytes, true)
			if err != nil {
				return ContainerImage{}, err
			}
		}
		var platforms ocispec.Index
		if err := json.Unmarshal(wire, &platforms); err != nil || platforms.SchemaVersion != 2 || platforms.MediaType != "" && platforms.MediaType != descriptor.MediaType || len(platforms.Manifests) == 0 || len(platforms.Manifests) > maxContainerLayers || platforms.ArtifactType != "" || platforms.Subject != nil {
			return ContainerImage{}, errors.New("invalid pinned OCI platform index")
		}
		result.IndexSHA256 = descriptor.Digest.Encoded()
		result.Index = wire
		descriptor = ocispec.Descriptor{}
		for _, child := range platforms.Manifests {
			if child.Platform != nil && child.Platform.OS == "linux" && child.Platform.Architecture == architecture {
				if descriptor.Digest != "" {
					return ContainerImage{}, errors.New("OCI index has multiple matching platform children")
				}
				descriptor = child
			}
		}
		if descriptor.Digest == "" {
			return ContainerImage{}, errors.New("OCI index lacks the required Linux architecture")
		}
	}
	if descriptor.MediaType != ocispec.MediaTypeImageManifest && descriptor.MediaType != "application/vnd.docker.distribution.manifest.v2+json" {
		return ContainerImage{}, errors.New("container child must be an OCI or Docker v2 image manifest")
	}
	if p := descriptor.Platform; p != nil && (p.OS != "linux" || p.Architecture != architecture || p.Variant != "" && !(architecture == "arm64" && p.Variant == "v8") || p.OSVersion != "" || len(p.OSFeatures) != 0) {
		return ContainerImage{}, errors.New("container platform requires unsupported OS or CPU features")
	}
	wire, err = layout.blob(descriptor, maxContainerMetadataBytes, true)
	if err != nil {
		return ContainerImage{}, err
	}
	var manifest ocispec.Manifest
	if err := json.Unmarshal(wire, &manifest); err != nil || manifest.SchemaVersion != 2 || manifest.MediaType != "" && manifest.MediaType != descriptor.MediaType || manifest.ArtifactType != "" || manifest.Subject != nil || len(manifest.Layers) > maxContainerLayers {
		return ContainerImage{}, errors.New("invalid OCI container child manifest")
	}
	if manifest.Config.MediaType != ocispec.MediaTypeImageConfig && manifest.Config.MediaType != "application/vnd.docker.container.image.v1+json" {
		return ContainerImage{}, errors.New("container manifest has an unsupported image config")
	}
	wire, err = layout.blob(manifest.Config, maxContainerMetadataBytes, true)
	if err != nil {
		return ContainerImage{}, err
	}
	var config ocispec.Image
	if err := json.Unmarshal(wire, &config); err != nil || config.OS != "linux" || config.Architecture != architecture || config.Variant != "" && !(architecture == "arm64" && config.Variant == "v8") || config.OSVersion != "" || len(config.OSFeatures) != 0 || config.RootFS.Type != "layers" || len(config.RootFS.DiffIDs) != len(manifest.Layers) {
		return ContainerImage{}, errors.New("container config differs from the required Linux architecture or layers")
	}
	// shortcut: containerd checks uncompressed DiffIDs; add unpack checks if producer qualification must prove them.
	for index, layer := range manifest.Layers {
		switch layer.MediaType {
		case ocispec.MediaTypeImageLayer, ocispec.MediaTypeImageLayerGzip, ocispec.MediaTypeImageLayerZstd, "application/vnd.docker.image.rootfs.diff.tar.gzip":
		default:
			return ContainerImage{}, errors.New("container manifest has an unsupported layer media type")
		}
		if diff := config.RootFS.DiffIDs[index]; diff.Validate() != nil || diff.Algorithm().String() != "sha256" {
			return ContainerImage{}, errors.New("container config contains an invalid layer diff digest")
		}
		if _, err := layout.blob(layer, maxContainerLayerBytes, false); err != nil {
			return ContainerImage{}, err
		}
	}
	result.ManifestSHA256 = descriptor.Digest.Encoded()
	result.Image = reference.TrimNamed(ref).String() + "@" + descriptor.Digest.String()
	return result, ctx.Err()
}

type containerLayout struct {
	root  *os.Root
	ctx   context.Context
	bytes int64
}

func (layout *containerLayout) read(name string, limit int64) ([]byte, error) {
	file, err := layout.open(name, limit)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var wire bytes.Buffer
	if _, err := layout.copy(&wire, file, limit); err != nil {
		return nil, err
	}
	return wire.Bytes(), nil
}

func (layout *containerLayout) open(name string, limit int64) (*os.File, error) {
	if err := layout.ctx.Err(); err != nil {
		return nil, err
	}
	// Nonblocking open rejects a FIFO without waiting for an untrusted writer.
	file, err := layout.root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("read retained OCI layout file: %w", err)
	}
	stat, err := file.Stat()
	if err != nil || !stat.Mode().IsRegular() || stat.Size() < 0 || stat.Size() > limit {
		file.Close()
		return nil, errors.New("OCI layout file must be a bounded regular file")
	}
	return file, nil
}

func (layout *containerLayout) copy(dst io.Writer, src io.Reader, limit int64) (int64, error) {
	buffer := make([]byte, 128<<10)
	var total int64
	for total <= limit {
		if err := layout.ctx.Err(); err != nil {
			return total, err
		}
		n, err := src.Read(buffer[:min(int64(len(buffer)), limit-total+1)])
		total += int64(n)
		layout.bytes += int64(n)
		if total > limit || layout.bytes > maxContainerLayoutBytes {
			return total, errors.New("retained OCI image exceeds byte limit")
		}
		if _, writeErr := dst.Write(buffer[:n]); writeErr != nil {
			return total, writeErr
		}
		if errors.Is(err, io.EOF) {
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
	return total, errors.New("retained OCI image exceeds byte limit")
}

func (layout *containerLayout) blob(descriptor ocispec.Descriptor, limit int64, retain bool) ([]byte, error) {
	if descriptor.Digest.Validate() != nil || descriptor.Digest.Algorithm().String() != "sha256" || descriptor.Size <= 0 || descriptor.Size > limit || len(descriptor.URLs) != 0 || len(descriptor.Data) != 0 || descriptor.ArtifactType != "" {
		return nil, errors.New("OCI descriptor requires a bounded local sha256 blob")
	}
	file, err := layout.open("blobs/sha256/"+descriptor.Digest.Encoded(), limit)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	hash := sha256.New()
	var wire bytes.Buffer
	var dst io.Writer = hash
	if retain {
		dst = io.MultiWriter(hash, &wire)
	}
	n, err := layout.copy(dst, file, descriptor.Size)
	if err != nil {
		return nil, err
	}
	if n != descriptor.Size || fmt.Sprintf("%x", hash.Sum(nil)) != descriptor.Digest.Encoded() {
		return nil, errors.New("retained OCI blob differs from its descriptor digest or size")
	}
	return wire.Bytes(), nil
}
