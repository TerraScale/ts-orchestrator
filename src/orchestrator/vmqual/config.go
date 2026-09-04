// Package vmqual contains the test-only Firecracker qualification coordinator.
//
// Nothing in this package is used by the production orchestrator.  The
// command path deliberately has no fake backend: callers must provide the
// pinned artifacts, Linux/KVM capabilities, and a real guest readiness channel.
package vmqual

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/vmimage"
	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
)

const (
	OwnershipMarker   = "terrascale-vmqual-v1"
	DefaultMemoryMiB  = int64(512)
	MaxGuestMemoryMiB = int64(512)
	MaxIdleRSSBytes   = int64(4 << 30)
	MaxIdleCPU        = 1.0
)

// Pins is the architecture-specific, source-backed Firecracker toolchain
// manifest. Keep the alias here for the command package's public API.
type Pins = vmimage.ToolchainManifest

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
	GuestControlPath          string
	NetworkPlan               vmnet.NetworkPlan
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
	configurationError        string
}

// DefaultConfig resolves paths but does not create directories or inspect the
// host. The default artifact root is deliberately inside the checkout's
// tmp/ directory: qualification never writes into a user's home directory or
// a system path. TS_VM_ROOT may still select an isolated absolute root in CI.
func DefaultConfig() Config {
	repoRoot := repositoryRoot()
	root := strings.TrimSpace(os.Getenv("TS_VM_ROOT"))
	if root == "" {
		root = filepath.Join(repoRoot, "tmp", "vmqual")
	} else {
		root = absolutePath(root, repoRoot)
	}
	architecture := runtime.GOARCH
	c := Config{
		Root:                      root,
		StateRoot:                 filepath.Join(root, "state"),
		JournalPath:               filepath.Join(root, "cleanup-journal.json"),
		PinsPath:                  absolutePath(defaultOrEnv("TS_VM_PINS", filepath.Join(repoRoot, "src", "orchestrator", "vmimage", "pins-"+architecture+".json")), repoRoot),
		ImageManifestPath:         absolutePath(defaultOrEnv("TS_VM_IMAGE_MANIFEST", filepath.Join(repoRoot, "src", "orchestrator", "vmimage", "ubuntu-24.04.3-"+architecture+".json")), repoRoot),
		ImageCacheRoot:            filepath.Join(root, "images"),
		ReadinessRoot:             filepath.Join(root, "readiness"),
		GuestControlPath:          filepath.Join(root, "bin", "vm-guest-control"),
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
		MaxDiskBytes:              8 << 30,
	}
	if v := os.Getenv("TS_VM_MEMORY_MIB"); v != "" {
		memory, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			c.configurationError = "TS_VM_MEMORY_MIB must be a base-10 integer"
		} else {
			c.MemoryMiB = memory
		}
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
	// Environment variables are accepted as convenient relative paths, but
	// the command contract remains absolute and unambiguous.
	c.StateRoot = absolutePath(c.StateRoot, repoRoot)
	c.JournalPath = absolutePath(c.JournalPath, repoRoot)
	c.ImageCacheRoot = absolutePath(c.ImageCacheRoot, repoRoot)
	c.ReadinessRoot = absolutePath(c.ReadinessRoot, repoRoot)
	c.GuestControlPath = absoluteIfSet(c.GuestControlPath, repoRoot)
	c.FirecrackerPath = absoluteIfSet(c.FirecrackerPath, repoRoot)
	c.JailerPath = absoluteIfSet(c.JailerPath, repoRoot)
	c.KernelPath = absoluteIfSet(c.KernelPath, repoRoot)
	c.RootFSPath = absoluteIfSet(c.RootFSPath, repoRoot)
	return c
}

func defaultOrEnv(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func absolutePath(value, base string) string {
	if filepath.IsAbs(value) {
		return filepath.Clean(value)
	}
	absolute, err := filepath.Abs(filepath.Join(base, value))
	if err != nil {
		return filepath.Clean(filepath.Join(base, value))
	}
	return absolute
}

func absoluteIfSet(value, base string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	return absolutePath(value, base)
}

// repositoryRoot finds the checkout containing go.mod. It keeps defaults
// stable when make is invoked from a subdirectory while retaining a useful
// absolute fallback for an installed/test binary.
func repositoryRoot() string {
	working, err := os.Getwd()
	if err != nil {
		working = "."
	}
	if root := findGoModuleRoot(working); root != "" {
		return root
	}
	if _, source, _, ok := runtime.Caller(0); ok {
		if root := findGoModuleRoot(filepath.Dir(source)); root != "" {
			return root
		}
	}
	absolute, err := filepath.Abs(working)
	if err != nil {
		return filepath.Clean(working)
	}
	return absolute
}

func findGoModuleRoot(start string) string {
	current, err := filepath.Abs(start)
	if err != nil {
		return ""
	}
	for {
		if info, statErr := os.Stat(filepath.Join(current, "go.mod")); statErr == nil && !info.IsDir() {
			return current
		}
		parent := filepath.Dir(current)
		if parent == current {
			return ""
		}
		current = parent
	}
}

func (c Config) Validate() error {
	if c.configurationError != "" {
		return errors.New("vmqual: " + c.configurationError)
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return fmt.Errorf("vmqual: native architecture %s is unsupported by Firecracker qualification", runtime.GOARCH)
	}
	if c.Root == "" || !filepath.IsAbs(c.Root) {
		return errors.New("vmqual: root must be an absolute path")
	}
	for name, value := range map[string]string{"state root": c.StateRoot, "journal": c.JournalPath, "pins": c.PinsPath, "image manifest": c.ImageManifestPath, "image cache": c.ImageCacheRoot, "readiness root": c.ReadinessRoot, "guest control": c.GuestControlPath} {
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
	pins, err := vmimage.DecodeToolchainManifest(b)
	if err != nil {
		return Pins{}, fmt.Errorf("vmqual: decode pins: %w", err)
	}
	return pins, nil
}

func (c Config) applyPins(p Pins) Config {
	installer := vmimage.ToolchainInstaller{Root: c.Root}
	location, locationErr := installer.Location(p)
	if c.FirecrackerPath == "" {
		c.FirecrackerPath = location.Firecracker
	}
	if c.JailerPath == "" {
		c.JailerPath = location.Jailer
	}
	if c.ExpectedVersion == "" {
		c.ExpectedVersion = p.FirecrackerVersion
	}
	if c.ExpectedFirecrackerSHA256 == "" {
		c.ExpectedFirecrackerSHA256 = p.Firecracker.SHA256
	}
	if c.ExpectedJailerSHA256 == "" {
		c.ExpectedJailerSHA256 = p.Jailer.SHA256
	}
	if c.SDKModule == "" {
		c.SDKModule = p.SDKModule
	}
	if c.SDKVersion == "" {
		c.SDKVersion = p.SDKVersion
	}
	if locationErr != nil && c.configurationError == "" {
		c.configurationError = locationErr.Error()
	}
	if manifest, err := LoadImageManifest(c.ImageManifestPath); err == nil {
		if plan, err := vmimage.NewBuildPlan(manifest, c.ImageCacheRoot); err == nil {
			if c.KernelPath == "" {
				c.KernelPath = filepath.Join(plan.CacheEntry, manifest.Kernel.Name)
			}
			if c.RootFSPath == "" {
				c.RootFSPath = filepath.Join(plan.CacheEntry, manifest.RootFS.Name)
			}
			if c.ExpectedKernelSHA256 == "" {
				c.ExpectedKernelSHA256 = manifest.Kernel.SHA256
			}
			if c.ExpectedRootFSSHA256 == "" {
				c.ExpectedRootFSSHA256 = manifest.RootFS.SHA256
			}
		}
	}
	return c
}

// ApplyPins returns a command-ready configuration using only values from the
// declared pin file for fields the caller did not explicitly provide.
func (c Config) ApplyPins(p Pins) Config { return c.applyPins(p) }

// HostPlatform reports whether the current process can qualify Firecracker.
// It is deliberately a fact, not a fallback selector.
func HostPlatform() string { return runtime.GOOS + "/" + runtime.GOARCH }
