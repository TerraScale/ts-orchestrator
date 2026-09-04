// Package vmqual contains the test-only Firecracker qualification coordinator.
//
// Nothing in this package is used by the production orchestrator.  The
// command path deliberately has no fake backend: callers must provide the
// pinned artifacts, Linux/KVM capabilities, and a real guest readiness channel.
package vmqual

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	OwnershipMarker   = "terrascale-vmqual-v1"
	DefaultMemoryMiB  = int64(512)
	MaxGuestMemoryMiB = int64(512)
	MaxIdleRSSBytes   = int64(4 << 30)
	MaxIdleCPU        = 1.0
)

// ArtifactPin is an immutable, repository-declared host artifact.
type ArtifactPin struct {
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	Version string `json:"version"`
}

// Pins is the small machine-readable pin set consumed by vm-doctor.  It is
// intentionally separate from the guest image manifest: the former includes
// host executables and the latter describes the kernel/rootfs boot pair.
type Pins struct {
	SchemaVersion int         `json:"schemaVersion"`
	Firecracker   ArtifactPin `json:"firecracker"`
	Jailer        ArtifactPin `json:"jailer"`
	Kernel        ArtifactPin `json:"kernel"`
	RootFS        ArtifactPin `json:"rootfs"`
	SDKModule     string      `json:"sdkModule"`
	SDKVersion    string      `json:"sdkVersion"`
}

// Config is shared by all qualification commands. Empty values are filled
// from the documented TS_VM_* environment variables; no ambient production
// credentials are read.
type Config struct {
	Root                      string
	StateRoot                 string
	JournalPath               string
	PinsPath                  string
	ImageManifestPath         string
	ImageCacheRoot            string
	ReadinessRoot             string
	FirecrackerPath           string
	JailerPath                string
	KernelPath                string
	RootFSPath                string
	ExpectedVersion           string
	ExpectedKernelSHA256      string
	ExpectedRootFSSHA256      string
	ExpectedFirecrackerSHA256 string
	ExpectedJailerSHA256      string
	SDKModule                 string
	SDKVersion                string
	MemoryMiB                 int64
	ReadinessTimeout          time.Duration
	StopTimeout               time.Duration
	MaxDiskBytes              int64
}

// DefaultConfig resolves paths but does not create directories or inspect the
// host.  Requiring an explicit pins file is what makes missing artifacts fail
// closed instead of silently selecting a host installation.
func DefaultConfig() Config {
	root := strings.TrimSpace(os.Getenv("TS_VM_ROOT"))
	if root == "" {
		root = filepath.Join(".terrascale", "vmqual")
	}
	c := Config{
		Root:                      root,
		StateRoot:                 filepath.Join(root, "state"),
		JournalPath:               filepath.Join(root, "cleanup-journal.json"),
		PinsPath:                  os.Getenv("TS_VM_PINS"),
		ImageManifestPath:         os.Getenv("TS_VM_IMAGE_MANIFEST"),
		ImageCacheRoot:            filepath.Join(root, "images"),
		ReadinessRoot:             filepath.Join(root, "readiness"),
		FirecrackerPath:           os.Getenv("TS_VM_FIRECRACKER"),
		JailerPath:                os.Getenv("TS_VM_JAILER"),
		KernelPath:                os.Getenv("TS_VM_KERNEL"),
		RootFSPath:                os.Getenv("TS_VM_ROOTFS"),
		ExpectedVersion:           os.Getenv("TS_VM_FIRECRACKER_VERSION"),
		ExpectedKernelSHA256:      os.Getenv("TS_VM_KERNEL_SHA256"),
		ExpectedRootFSSHA256:      os.Getenv("TS_VM_ROOTFS_SHA256"),
		ExpectedFirecrackerSHA256: os.Getenv("TS_VM_FIRECRACKER_SHA256"),
		ExpectedJailerSHA256:      os.Getenv("TS_VM_JAILER_SHA256"),
		SDKModule:                 os.Getenv("TS_VM_SDK_MODULE"),
		SDKVersion:                os.Getenv("TS_VM_SDK_VERSION"),
		MemoryMiB:                 DefaultMemoryMiB,
		ReadinessTimeout:          2 * time.Minute,
		StopTimeout:               30 * time.Second,
		MaxDiskBytes:              4 << 30,
	}
	if v := os.Getenv("TS_VM_MEMORY_MIB"); v != "" {
		_, _ = fmt.Sscan(v, &c.MemoryMiB)
	}
	if v := os.Getenv("TS_VM_IMAGE_CACHE"); v != "" {
		c.ImageCacheRoot = v
	}
	if v := os.Getenv("TS_VM_READINESS_ROOT"); v != "" {
		c.ReadinessRoot = v
	}
	if v := os.Getenv("TS_VM_STATE_ROOT"); v != "" {
		c.StateRoot = v
	}
	if v := os.Getenv("TS_VM_JOURNAL"); v != "" {
		c.JournalPath = v
	}
	return c
}

func (c Config) Validate() error {
	if c.Root == "" || !filepath.IsAbs(c.Root) {
		return errors.New("vmqual: root must be an absolute path")
	}
	for name, value := range map[string]string{"state root": c.StateRoot, "journal": c.JournalPath, "pins": c.PinsPath, "image manifest": c.ImageManifestPath, "image cache": c.ImageCacheRoot, "readiness root": c.ReadinessRoot} {
		if value == "" || !filepath.IsAbs(value) {
			return fmt.Errorf("vmqual: %s must be an absolute path", name)
		}
	}
	if c.MemoryMiB < 256 || c.MemoryMiB > MaxGuestMemoryMiB {
		return fmt.Errorf("vmqual: guest memory must be 256-512 MiB: %d", c.MemoryMiB)
	}
	if c.ReadinessTimeout <= 0 || c.StopTimeout <= 0 {
		return errors.New("vmqual: readiness and stop timeouts must be positive")
	}
	if c.MaxDiskBytes <= 0 {
		return errors.New("vmqual: disk budget must be positive")
	}
	return nil
}

func LoadPins(path string) (Pins, error) {
	if path == "" || !filepath.IsAbs(path) {
		return Pins{}, errors.New("vmqual: pins path must be absolute")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return Pins{}, fmt.Errorf("vmqual: read pins: %w", err)
	}
	var pins Pins
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&pins); err != nil {
		return Pins{}, fmt.Errorf("vmqual: decode pins: %w", err)
	}
	if pins.SchemaVersion != 1 {
		return Pins{}, fmt.Errorf("vmqual: unsupported pins schema %d", pins.SchemaVersion)
	}
	for name, pin := range map[string]ArtifactPin{"firecracker": pins.Firecracker, "jailer": pins.Jailer, "kernel": pins.Kernel, "rootfs": pins.RootFS} {
		if pin.Path == "" || !filepath.IsAbs(pin.Path) || len(pin.SHA256) != 64 || strings.ToLower(pin.SHA256) != pin.SHA256 {
			return Pins{}, fmt.Errorf("vmqual: invalid %s pin", name)
		}
	}
	if pins.SDKModule == "" || pins.SDKVersion == "" {
		return Pins{}, errors.New("vmqual: pinned Firecracker Go SDK module and version are required")
	}
	return pins, nil
}

func (c Config) applyPins(p Pins) Config {
	if c.FirecrackerPath == "" {
		c.FirecrackerPath = p.Firecracker.Path
	}
	if c.JailerPath == "" {
		c.JailerPath = p.Jailer.Path
	}
	if c.KernelPath == "" {
		c.KernelPath = p.Kernel.Path
	}
	if c.RootFSPath == "" {
		c.RootFSPath = p.RootFS.Path
	}
	if c.ExpectedVersion == "" {
		c.ExpectedVersion = p.Firecracker.Version
	}
	if c.ExpectedFirecrackerSHA256 == "" {
		c.ExpectedFirecrackerSHA256 = p.Firecracker.SHA256
	}
	if c.ExpectedJailerSHA256 == "" {
		c.ExpectedJailerSHA256 = p.Jailer.SHA256
	}
	if c.ExpectedKernelSHA256 == "" {
		c.ExpectedKernelSHA256 = p.Kernel.SHA256
	}
	if c.ExpectedRootFSSHA256 == "" {
		c.ExpectedRootFSSHA256 = p.RootFS.SHA256
	}
	if c.SDKModule == "" {
		c.SDKModule = p.SDKModule
	}
	if c.SDKVersion == "" {
		c.SDKVersion = p.SDKVersion
	}
	return c
}

// ApplyPins returns a command-ready configuration using only values from the
// declared pin file for fields the caller did not explicitly provide.
func (c Config) ApplyPins(p Pins) Config { return c.applyPins(p) }

// HostPlatform reports whether the current process can qualify Firecracker.
// It is deliberately a fact, not a fallback selector.
func HostPlatform() string { return runtime.GOOS + "/" + runtime.GOARCH }
