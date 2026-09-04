package vmqual

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/vmimage"
)

type ImageResult struct {
	Manifest  vmimage.GuestImageManifest
	Installed vmimage.InstalledImage
}

type ArtifactResult struct {
	Config    Config
	Pins      Pins
	Toolchain vmimage.InstalledToolchain
	Image     ImageResult
}

// MaterializeArtifacts installs the architecture-specific Firecracker tools
// and guest boot pair from their checked-in immutable source manifests.
func MaterializeArtifacts(ctx context.Context, config Config) (ArtifactResult, error) {
	pins, err := LoadPins(config.PinsPath)
	if err != nil {
		return ArtifactResult{}, err
	}
	if string(pins.Architecture) != runtime.GOARCH {
		return ArtifactResult{}, fmt.Errorf("vmqual: toolchain architecture %s does not match native %s", pins.Architecture, runtime.GOARCH)
	}
	config = config.ApplyPins(pins)
	installer := vmimage.ToolchainInstaller{Root: config.Root}
	toolchain, err := installer.Install(ctx, pins)
	if err != nil {
		return ArtifactResult{}, err
	}
	config.FirecrackerPath = toolchain.Firecracker
	config.JailerPath = toolchain.Jailer
	image, err := MaterializeImage(ctx, config)
	if err != nil {
		return ArtifactResult{}, err
	}
	config.KernelPath = image.Installed.Kernel
	config.RootFSPath = image.Installed.RootFS
	config.ExpectedKernelSHA256 = image.Manifest.Kernel.SHA256
	config.ExpectedRootFSSHA256 = image.Manifest.RootFS.SHA256
	return ArtifactResult{Config: config, Pins: pins, Toolchain: toolchain, Image: image}, nil
}

// MaterializeImage verifies and atomically installs the pinned kernel/rootfs
// pair into the digest-keyed cache. It never downloads an unpinned asset.
func MaterializeImage(ctx context.Context, config Config) (ImageResult, error) {
	if ctx == nil {
		return ImageResult{}, errors.New("vmqual: image context is nil")
	}
	if config.ImageManifestPath == "" || !filepath.IsAbs(config.ImageManifestPath) {
		return ImageResult{}, errors.New("vmqual: image manifest path must be absolute")
	}
	if config.ImageCacheRoot == "" || !filepath.IsAbs(config.ImageCacheRoot) {
		return ImageResult{}, errors.New("vmqual: image cache root must be absolute")
	}
	b, err := os.ReadFile(config.ImageManifestPath)
	if err != nil {
		return ImageResult{}, fmt.Errorf("vmqual: read image manifest: %w", err)
	}
	manifest, err := vmimage.DecodeManifest(b)
	if err != nil {
		return ImageResult{}, fmt.Errorf("vmqual: decode image manifest: %w", err)
	}
	manifest, err = resolveManifestSources(manifest, filepath.Dir(config.ImageManifestPath))
	if err != nil {
		return ImageResult{}, err
	}
	if string(manifest.Architecture) != runtime.GOARCH {
		return ImageResult{}, fmt.Errorf("vmqual: image architecture %s does not match native %s", manifest.Architecture, runtime.GOARCH)
	}
	if config.ExpectedKernelSHA256 != "" && !strings.EqualFold(config.ExpectedKernelSHA256, manifest.Kernel.SHA256) {
		return ImageResult{}, errors.New("vmqual: configured kernel checksum differs from the committed image manifest")
	}
	if config.ExpectedRootFSSHA256 != "" && !strings.EqualFold(config.ExpectedRootFSSHA256, manifest.RootFS.SHA256) {
		return ImageResult{}, errors.New("vmqual: configured rootfs checksum differs from the committed image manifest")
	}
	if err := vmimage.ValidateManifest(manifest); err != nil {
		return ImageResult{}, err
	}
	cache, err := vmimage.NewCache(config.ImageCacheRoot)
	if err != nil {
		return ImageResult{}, err
	}
	installed, err := cache.Install(ctx, manifest)
	if err != nil {
		return ImageResult{}, err
	}
	if err := cache.VerifyInstalled(installed); err != nil {
		return ImageResult{}, fmt.Errorf("vmqual: verify installed image: %w", err)
	}
	return ImageResult{Manifest: installed.Manifest, Installed: installed}, nil
}

func resolveManifestSources(manifest vmimage.GuestImageManifest, base string) (vmimage.GuestImageManifest, error) {
	resolve := func(source string) (string, error) {
		if source == "" || filepath.IsAbs(source) {
			return source, nil
		}
		// Only local relative sources are resolved here. URL sources remain
		// untouched and are still bounded and digest-verified by vmimage.Cache.
		if strings.Contains(source, "://") {
			return source, nil
		}
		resolved, err := filepath.Abs(filepath.Join(base, source))
		if err != nil {
			return "", fmt.Errorf("vmqual: resolve image source: %w", err)
		}
		return resolved, nil
	}
	var err error
	if manifest.Kernel.Source, err = resolve(manifest.Kernel.Source); err != nil {
		return vmimage.GuestImageManifest{}, err
	}
	if manifest.RootFS.Source, err = resolve(manifest.RootFS.Source); err != nil {
		return vmimage.GuestImageManifest{}, err
	}
	return manifest, nil
}

func LoadImageManifest(path string) (vmimage.GuestImageManifest, error) {
	if path == "" || !filepath.IsAbs(path) {
		return vmimage.GuestImageManifest{}, errors.New("vmqual: image manifest path must be absolute")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return vmimage.GuestImageManifest{}, err
	}
	return vmimage.DecodeManifest(b)
}

// WriteImageResult emits bounded canonical JSON for CI evidence. It never
// includes credentials or host command output.
func WriteImageResult(w io.Writer, result ImageResult) error {
	if w == nil {
		return errors.New("vmqual: nil image result writer")
	}
	b, err := json.Marshal(struct {
		Manifest  vmimage.GuestImageManifest `json:"manifest"`
		Directory string                     `json:"directory"`
	}{result.Manifest, result.Installed.Dir})
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}
