// Package vmqual contains the test-only Firecracker qualification coordinator.
//
// Nothing in this package is used by the production orchestrator.  The
// command path deliberately has no fake backend: callers must provide the
// pinned artifacts, Linux/KVM capabilities, and a real guest readiness channel.
package vmqual

import (
	"crypto/sha256"
	"encoding/hex"
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

// ProductionArtifactInput names one exact signed binary used by the real
// guest bootstrap. Versions are explicit so qualification cannot relabel an
// arbitrary local build as a release.
type ProductionArtifactInput struct {
	Path          string
	SignaturePath string
	Version       string
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
	GuestControlPath          string
	ReleasePublicKeyPath      string
	TSNode                    ProductionArtifactInput
	Orchestrator              ProductionArtifactInput
	TerraBase                 ProductionArtifactInput
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
	JailerUID                 int
	JailerGID                 int
	MemoryMiB                 int64
	ReadinessTimeout          time.Duration
	StopTimeout               time.Duration
	MaxDiskBytes              int64
	RequiredPorts             []int
	configurationError        string
}

// DefaultConfig resolves paths but does not create directories or inspect the
// host. The default artifact root is deliberately inside the checkout's
// tmp/ directory: qualification never writes into a user's home directory or
// a system path. TS_VM_ROOT may still select an isolated absolute root in CI.
func DefaultConfig() Config {
	return defaultConfigForArchitecture(runtime.GOARCH)
}

func defaultConfigForArchitecture(architecture string) Config {
	repoRoot := repositoryRoot()
	root := strings.TrimSpace(os.Getenv("TS_VM_ROOT"))
	if root == "" {
		root = filepath.Join(repoRoot, "tmp", "vmqual")
	} else {
		root = absolutePath(root, repoRoot)
	}
	c := Config{
		Root:                      root,
		StateRoot:                 filepath.Join(root, "state"),
		JournalPath:               filepath.Join(root, "cleanup-journal.json"),
		PinsPath:                  absolutePath(defaultOrEnv("TS_VM_PINS", filepath.Join(repoRoot, "src", "orchestrator", "vmimage", "pins-"+architecture+".json")), repoRoot),
		ImageManifestPath:         absolutePath(defaultOrEnv("TS_VM_IMAGE_MANIFEST", filepath.Join(repoRoot, "src", "orchestrator", "vmimage", "ubuntu-24.04.3-"+architecture+".json")), repoRoot),
		ImageCacheRoot:            filepath.Join(root, "images"),
		ReadinessRoot:             filepath.Join(root, "readiness"),
		GuestControlPath:          filepath.Join(root, "bin", "vm-guest-control"),
		ReleasePublicKeyPath:      os.Getenv("TS_VM_RELEASE_PUBLIC_KEY"),
		TSNode:                    productionArtifactFromEnvironment("TS_VM_TS_NODE"),
		Orchestrator:              productionArtifactFromEnvironment("TS_VM_ORCHESTRATOR"),
		TerraBase:                 productionArtifactFromEnvironment("TS_VM_TERRABASE"),
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
	uidText, uidSet := os.LookupEnv("TS_VM_JAILER_UID")
	gidText, gidSet := os.LookupEnv("TS_VM_JAILER_GID")
	if uidSet != gidSet {
		c.setConfigurationError("TS_VM_JAILER_UID and TS_VM_JAILER_GID must be configured together")
	} else if uidSet {
		uid, uidErr := parseStrictDecimal(uidText, 32)
		gid, gidErr := parseStrictDecimal(gidText, 32)
		if uidErr != nil || gidErr != nil || uid <= 0 || gid <= 0 {
			c.setConfigurationError("TS_VM_JAILER_UID and TS_VM_JAILER_GID must be nonzero unsigned base-10 integers")
		} else {
			c.JailerUID, c.JailerGID = int(uid), int(gid)
		}
	}
	if architecture != string(vmimage.ArchitectureAMD64) && architecture != string(vmimage.ArchitectureARM64) {
		c.setConfigurationError("native architecture " + architecture + " is unsupported by Firecracker qualification")
	}
	if v := os.Getenv("TS_VM_MEMORY_MIB"); v != "" {
		memory, err := parseStrictDecimal(v, 64)
		if err != nil {
			c.setConfigurationError("TS_VM_MEMORY_MIB must be an unsigned base-10 integer")
		} else {
			c.MemoryMiB = memory
		}
	}
	if v := os.Getenv("TS_VM_REQUIRED_PORTS"); v != "" {
		ports, err := parseRequiredPorts(v)
		if err != nil {
			c.setConfigurationError("TS_VM_REQUIRED_PORTS " + err.Error())
		} else {
			c.RequiredPorts = ports
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
	c.ReleasePublicKeyPath = absoluteIfSet(c.ReleasePublicKeyPath, repoRoot)
	c.TSNode = absoluteProductionArtifact(c.TSNode, repoRoot)
	c.Orchestrator = absoluteProductionArtifact(c.Orchestrator, repoRoot)
	c.TerraBase = absoluteProductionArtifact(c.TerraBase, repoRoot)
	c.FirecrackerPath = absoluteIfSet(c.FirecrackerPath, repoRoot)
	c.JailerPath = absoluteIfSet(c.JailerPath, repoRoot)
	c.KernelPath = absoluteIfSet(c.KernelPath, repoRoot)
	c.RootFSPath = absoluteIfSet(c.RootFSPath, repoRoot)
	return c
}

func productionArtifactFromEnvironment(prefix string) ProductionArtifactInput {
	return ProductionArtifactInput{
		Path:          os.Getenv(prefix),
		SignaturePath: os.Getenv(prefix + "_SIGNATURE"),
		Version:       os.Getenv(prefix + "_VERSION"),
	}
}

func absoluteProductionArtifact(input ProductionArtifactInput, base string) ProductionArtifactInput {
	input.Path = absoluteIfSet(input.Path, base)
	input.SignaturePath = absoluteIfSet(input.SignaturePath, base)
	input.Version = strings.TrimSpace(input.Version)
	return input
}

func (c *Config) setConfigurationError(message string) {
	if c.configurationError == "" {
		c.configurationError = message
	}
}

func parseStrictDecimal(value string, bitSize int) (int64, error) {
	if value == "" {
		return 0, errors.New("value is empty")
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return 0, errors.New("value contains a non-decimal character")
		}
	}
	return strconv.ParseInt(value, 10, bitSize)
}

func parseRequiredPorts(value string) ([]int, error) {
	parts := strings.Split(value, ",")
	ports := make([]int, 0, len(parts))
	seen := make(map[int]struct{}, len(parts))
	for _, part := range parts {
		parsed, err := parseStrictDecimal(part, 32)
		if err != nil || parsed == 0 || parsed > 65535 {
			return nil, errors.New("must be a comma-separated list of unique ports in the range 1-65535 without whitespace")
		}
		port := int(parsed)
		if _, duplicate := seen[port]; duplicate {
			return nil, fmt.Errorf("contains duplicate port %d", port)
		}
		seen[port] = struct{}{}
		ports = append(ports, port)
	}
	return ports, nil
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
	for _, required := range []struct{ name, value string }{
		{"state root", c.StateRoot},
		{"journal", c.JournalPath},
		{"pins", c.PinsPath},
		{"image manifest", c.ImageManifestPath},
		{"image cache", c.ImageCacheRoot},
		{"readiness root", c.ReadinessRoot},
		{"guest control", c.GuestControlPath},
	} {
		name, value := required.name, required.value
		if value == "" || !filepath.IsAbs(value) {
			return fmt.Errorf("vmqual: %s must be an absolute path", name)
		}
	}
	for _, optional := range []struct{ name, value string }{
		{"Firecracker", c.FirecrackerPath},
		{"jailer", c.JailerPath},
		{"kernel", c.KernelPath},
		{"rootfs", c.RootFSPath},
		{"release public key", c.ReleasePublicKeyPath},
		{"ts-node artifact", c.TSNode.Path},
		{"ts-node signature", c.TSNode.SignaturePath},
		{"orchestrator artifact", c.Orchestrator.Path},
		{"orchestrator signature", c.Orchestrator.SignaturePath},
		{"TerraBase artifact", c.TerraBase.Path},
		{"TerraBase signature", c.TerraBase.SignaturePath},
	} {
		if optional.value != "" && !filepath.IsAbs(optional.value) {
			return fmt.Errorf("vmqual: %s path must be absolute when configured", optional.name)
		}
	}
	for _, digest := range []struct{ name, value string }{
		{"kernel", c.ExpectedKernelSHA256},
		{"rootfs", c.ExpectedRootFSSHA256},
		{"Firecracker", c.ExpectedFirecrackerSHA256},
		{"jailer", c.ExpectedJailerSHA256},
	} {
		if digest.value != "" && !ValidPinnedSHA256(digest.value) {
			return fmt.Errorf("vmqual: %s checksum must be a non-zero lowercase SHA-256 digest", digest.name)
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
	if (c.JailerUID == 0) != (c.JailerGID == 0) || c.JailerUID < 0 || c.JailerGID < 0 || uint64(c.JailerUID) > 1<<32-1 || uint64(c.JailerGID) > 1<<32-1 {
		return errors.New("vmqual: jailer UID and GID must be configured together as nonnegative uint32 values")
	}
	if err := validateRequiredPorts(c.RequiredPorts); err != nil {
		return fmt.Errorf("vmqual: required ports: %w", err)
	}
	return nil
}

// ResolveRuntimeIdentity binds the jailer and every planned TAP to one
// explicit non-root operating-system identity. A sudo invocation may supply
// the same pair through SUDO_UID and SUDO_GID.
func ResolveRuntimeIdentity(config Config) (Config, error) {
	uid, gid := config.JailerUID, config.JailerGID
	if uid == 0 && gid == 0 {
		uidText, uidSet := os.LookupEnv("SUDO_UID")
		gidText, gidSet := os.LookupEnv("SUDO_GID")
		if !uidSet || !gidSet {
			return Config{}, errors.New("vmqual: a nonzero jailer UID/GID is required through TS_VM_JAILER_UID/TS_VM_JAILER_GID or SUDO_UID/SUDO_GID")
		}
		parsedUID, uidErr := parseStrictDecimal(uidText, 32)
		parsedGID, gidErr := parseStrictDecimal(gidText, 32)
		if uidErr != nil || gidErr != nil || parsedUID <= 0 || parsedGID <= 0 {
			return Config{}, errors.New("vmqual: SUDO_UID and SUDO_GID must be nonzero unsigned base-10 integers")
		}
		uid, gid = int(parsedUID), int(parsedGID)
	}
	if uid <= 0 || gid <= 0 || uint64(uid) > 1<<32-1 || uint64(gid) > 1<<32-1 {
		return Config{}, errors.New("vmqual: jailer UID and GID must be nonzero uint32 values")
	}
	config.JailerUID, config.JailerGID = uid, gid
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func ValidPinnedSHA256(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) || value == strings.Repeat("0", sha256.Size*2) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func validateRequiredPorts(ports []int) error {
	seen := make(map[int]struct{}, len(ports))
	for _, port := range ports {
		if port < 1 || port > 65535 {
			return fmt.Errorf("port %d is outside 1-65535", port)
		}
		if _, duplicate := seen[port]; duplicate {
			return fmt.Errorf("port %d is duplicated", port)
		}
		seen[port] = struct{}{}
	}
	return nil
}

func LoadPins(path string) (vmimage.ToolchainManifest, error) {
	if path == "" || !filepath.IsAbs(path) {
		return vmimage.ToolchainManifest{}, errors.New("vmqual: pins path must be absolute")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return vmimage.ToolchainManifest{}, fmt.Errorf("vmqual: read pins: %w", err)
	}
	pins, err := vmimage.DecodeToolchainManifest(b)
	if err != nil {
		return vmimage.ToolchainManifest{}, fmt.Errorf("vmqual: decode pins: %w", err)
	}
	return pins, nil
}

// ApplyPins fills unspecified configuration from the declared toolchain manifest.
func (c Config) ApplyPins(p vmimage.ToolchainManifest) Config {
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

// HostPlatform reports whether the current process can qualify Firecracker.
// It is deliberately a fact, not a fallback selector.
func HostPlatform() string { return runtime.GOOS + "/" + runtime.GOARCH }
