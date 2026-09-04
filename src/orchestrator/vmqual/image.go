package vmqual

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/vmimage"
)

type ImageResult struct {
	Manifest  vmimage.GuestImageManifest
	Installed vmimage.InstalledImage
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
	b, err := os.ReadFile(config.ImageManifestPath)
	if err != nil {
		return ImageResult{}, fmt.Errorf("vmqual: read image manifest: %w", err)
	}
	manifest, err := vmimage.DecodeManifest(b)
	if err != nil {
		return ImageResult{}, fmt.Errorf("vmqual: decode image manifest: %w", err)
	}
	if config.KernelPath != "" {
		manifest.Kernel.Source = config.KernelPath
	}
	if config.RootFSPath != "" {
		manifest.RootFS.Source = config.RootFSPath
	}
	if config.ExpectedKernelSHA256 != "" {
		manifest.Kernel.SHA256 = strings.ToLower(config.ExpectedKernelSHA256)
	}
	if config.ExpectedRootFSSHA256 != "" {
		manifest.RootFS.SHA256 = strings.ToLower(config.ExpectedRootFSSHA256)
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
