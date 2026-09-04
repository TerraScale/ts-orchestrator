package vmqual

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDefaultConfigRejectsUnsupportedArchitectureWithoutFallback(t *testing.T) {
	clearVMManifestEnvironment(t)
	config := defaultConfigForArchitecture("riscv64")
	if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "riscv64") {
		t.Fatalf("Validate() error = %v, want unsupported architecture", err)
	}
	if strings.Contains(config.PinsPath, "amd64") || strings.Contains(config.ImageManifestPath, "amd64") {
		t.Fatalf("unsupported architecture silently selected amd64: pins=%q image=%q", config.PinsPath, config.ImageManifestPath)
	}
}

func TestDefaultConfigParsesNumericEnvironmentStrictly(t *testing.T) {
	clearVMManifestEnvironment(t)
	for _, value := range []string{"+512", "-512", " 512", "512 ", "0x200", "5e2", "512MiB", "9223372036854775808"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("TS_VM_MEMORY_MIB", value)
			config := defaultConfigForArchitecture(runtime.GOARCH)
			if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "TS_VM_MEMORY_MIB") {
				t.Fatalf("Validate() error = %v, want strict TS_VM_MEMORY_MIB failure", err)
			}
		})
	}
	t.Run("decimal", func(t *testing.T) {
		t.Setenv("TS_VM_MEMORY_MIB", "512")
		config := defaultConfigForArchitecture(runtime.GOARCH)
		if err := config.Validate(); err != nil {
			t.Fatal(err)
		}
		if config.MemoryMiB != 512 {
			t.Fatalf("MemoryMiB = %d, want 512", config.MemoryMiB)
		}
	})
}

func TestRequiredPortsParsingAndValidation(t *testing.T) {
	ports, err := parseRequiredPorts("2200,4222,8443")
	if err != nil {
		t.Fatal(err)
	}
	if got := len(ports); got != 3 || ports[0] != 2200 || ports[1] != 4222 || ports[2] != 8443 {
		t.Fatalf("parseRequiredPorts() = %v", ports)
	}
	for _, value := range []string{"", "0", "65536", "2200,", ",2200", "2200,,4222", "2200, 4222", "2200,2200", "+2200", "-1"} {
		if _, err := parseRequiredPorts(value); err == nil {
			t.Fatalf("parseRequiredPorts(%q) succeeded", value)
		}
	}
	for _, ports := range [][]int{{0}, {65536}, {2200, 2200}} {
		if err := validateRequiredPorts(ports); err == nil {
			t.Fatalf("validateRequiredPorts(%v) succeeded", ports)
		}
	}

	clearVMManifestEnvironment(t)
	t.Setenv("TS_VM_REQUIRED_PORTS", "2200,4222")
	config := defaultConfigForArchitecture(runtime.GOARCH)
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(config.RequiredPorts) != 2 || config.RequiredPorts[0] != 2200 || config.RequiredPorts[1] != 4222 {
		t.Fatalf("RequiredPorts = %v", config.RequiredPorts)
	}
}

func TestConfigRejectsPlaceholderAndMalformedExpectedDigests(t *testing.T) {
	clearVMManifestEnvironment(t)
	for _, digest := range []string{
		strings.Repeat("0", 64),
		strings.Repeat("A", 64),
		strings.Repeat("a", 63),
		strings.Repeat("g", 64),
	} {
		config := defaultConfigForArchitecture(runtime.GOARCH)
		config.ExpectedKernelSHA256 = digest
		if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "non-zero lowercase SHA-256") {
			t.Fatalf("Validate() error = %v for digest %q", err, digest)
		}
	}
	config := defaultConfigForArchitecture(runtime.GOARCH)
	config.ExpectedKernelSHA256 = strings.Repeat("a", 64)
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestLoadPinsRejectsAllZeroPlaceholderDigest(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "vmimage", "pins-amd64.json"))
	if err != nil {
		t.Fatal(err)
	}
	var pins Pins
	if err := json.Unmarshal(data, &pins); err != nil {
		t.Fatal(err)
	}
	pins.Archive.SHA256 = strings.Repeat("0", 64)
	data, err = json.Marshal(pins)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "pins.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPins(path); err == nil || !strings.Contains(err.Error(), "non-zero") {
		t.Fatalf("LoadPins() error = %v, want zero digest rejection", err)
	}
}

func clearVMManifestEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"TS_VM_ROOT",
		"TS_VM_PINS",
		"TS_VM_IMAGE_MANIFEST",
		"TS_VM_MEMORY_MIB",
		"TS_VM_REQUIRED_PORTS",
		"TS_VM_IMAGE_CACHE",
		"TS_VM_READINESS_ROOT",
		"TS_VM_STATE_ROOT",
		"TS_VM_JOURNAL",
		"TS_VM_FIRECRACKER",
		"TS_VM_JAILER",
		"TS_VM_KERNEL",
		"TS_VM_ROOTFS",
		"TS_VM_FIRECRACKER_VERSION",
		"TS_VM_KERNEL_SHA256",
		"TS_VM_ROOTFS_SHA256",
		"TS_VM_FIRECRACKER_SHA256",
		"TS_VM_JAILER_SHA256",
		"TS_VM_SDK_MODULE",
		"TS_VM_SDK_VERSION",
	} {
		t.Setenv(name, "")
	}
}
