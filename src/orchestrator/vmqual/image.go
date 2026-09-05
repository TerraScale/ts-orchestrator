package vmqual

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
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
	Pins      vmimage.ToolchainManifest
	Toolchain vmimage.InstalledToolchain
	Image     ImageResult
}

// MaterializeArtifacts installs the architecture-specific Firecracker tools
// and guest boot pair from their checked-in immutable source manifests.
func MaterializeArtifacts(ctx context.Context, config Config) (ArtifactResult, error) {
	if ctx == nil {
		return ArtifactResult{}, errors.New("vmqual: artifact context is nil")
	}
	if err := config.Validate(); err != nil {
		return ArtifactResult{}, err
	}
	pins, err := LoadPins(config.PinsPath)
	if err != nil {
		return ArtifactResult{}, err
	}
	if string(pins.Architecture) != runtime.GOARCH {
		return ArtifactResult{}, fmt.Errorf("vmqual: toolchain architecture %s does not match native %s", pins.Architecture, runtime.GOARCH)
	}
	if err := validateToolchainOverrides(config, pins); err != nil {
		return ArtifactResult{}, err
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
	if err := materializeGuestControl(ctx, config); err != nil {
		return ArtifactResult{}, err
	}
	return ArtifactResult{Config: config, Pins: pins, Toolchain: toolchain, Image: image}, nil
}

func validateToolchainOverrides(config Config, pins vmimage.ToolchainManifest) error {
	for name, configured := range map[string]string{
		"Firecracker version":  config.ExpectedVersion,
		"Firecracker checksum": config.ExpectedFirecrackerSHA256,
		"jailer checksum":      config.ExpectedJailerSHA256,
		"SDK module":           config.SDKModule,
		"SDK version":          config.SDKVersion,
	} {
		if configured == "" {
			continue
		}
		var pinned string
		switch name {
		case "Firecracker version":
			pinned = pins.FirecrackerVersion
		case "Firecracker checksum":
			pinned = pins.Firecracker.SHA256
		case "jailer checksum":
			pinned = pins.Jailer.SHA256
		case "SDK module":
			pinned = pins.SDKModule
		case "SDK version":
			pinned = pins.SDKVersion
		}
		if configured != pinned {
			return fmt.Errorf("vmqual: configured %s differs from the committed native pin", name)
		}
	}
	return nil
}

// materializeGuestControl builds the tiny, test-only forced SSH command from
// this checkout. It is deliberately built into the private qualification
// root, never installed on the host or copied from an unpinned URL.
func materializeGuestControl(ctx context.Context, config Config) error {
	if ctx == nil {
		return errors.New("vmqual: guest control context is nil")
	}
	if config.GuestControlPath == "" || !filepath.IsAbs(config.GuestControlPath) {
		return errors.New("vmqual: guest control path must be absolute")
	}
	directory := filepath.Dir(config.GuestControlPath)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return fmt.Errorf("vmqual: create guest control directory: %w", err)
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("vmqual: guest control directory must be a non-symlink directory")
	}
	if err := os.Chmod(directory, 0700); err != nil {
		return fmt.Errorf("vmqual: secure guest control directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".vm-guest-control-*")
	if err != nil {
		return fmt.Errorf("vmqual: create guest control staging file: %w", err)
	}
	tmp := temporary.Name()
	if err := temporary.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("vmqual: close guest control staging file: %w", err)
	}
	defer os.Remove(tmp)
	command := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", tmp, "./cmd/vm-guest-control")
	command.Dir = repositoryRoot()
	command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("vmqual: build guest control: %w: %s", err, strings.TrimSpace(string(output)))
	}
	info, err = os.Lstat(tmp)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("vmqual: built guest control is not a regular file")
	}
	if err := os.Chmod(tmp, 0500); err != nil {
		return err
	}
	if err := SyncPath(tmp); err != nil {
		return fmt.Errorf("vmqual: sync guest control: %w", err)
	}
	if err := os.Rename(tmp, config.GuestControlPath); err != nil {
		return fmt.Errorf("vmqual: install guest control: %w", err)
	}
	return SyncPath(directory)
}

func SyncPath(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	return errors.Join(syncErr, closeErr)
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
