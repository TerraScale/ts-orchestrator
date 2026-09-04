package vmqual

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/vmimage"
)

func TestValidateToolchainOverridesRejectsPinDrift(t *testing.T) {
	t.Parallel()
	pins := Pins{
		FirecrackerVersion: "1.15.1",
		Firecracker:        vmimage.ArchiveMember{SHA256: strings.Repeat("1", 64)},
		Jailer:             vmimage.ArchiveMember{SHA256: strings.Repeat("2", 64)},
		SDKModule:          "github.com/firecracker-microvm/firecracker-go-sdk",
		SDKVersion:         "v1.0.0",
	}
	valid := Config{
		ExpectedVersion:           pins.FirecrackerVersion,
		ExpectedFirecrackerSHA256: pins.Firecracker.SHA256,
		ExpectedJailerSHA256:      pins.Jailer.SHA256,
		SDKModule:                 pins.SDKModule,
		SDKVersion:                pins.SDKVersion,
	}
	if err := validateToolchainOverrides(valid, pins); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Config){
		"version":          func(config *Config) { config.ExpectedVersion = "1.14.0" },
		"firecracker hash": func(config *Config) { config.ExpectedFirecrackerSHA256 = strings.Repeat("a", 64) },
		"jailer hash":      func(config *Config) { config.ExpectedJailerSHA256 = strings.Repeat("b", 64) },
		"SDK module":       func(config *Config) { config.SDKModule += "/fork" },
		"SDK version":      func(config *Config) { config.SDKVersion = "v0.24.0" },
	} {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			config := valid
			mutate(&config)
			if err := validateToolchainOverrides(config, pins); err == nil {
				t.Fatal("toolchain override drift was accepted")
			}
		})
	}
}

func TestMaterializeGuestControlRejectsNilContextAndSymlinkDirectory(t *testing.T) {
	t.Parallel()
	if err := materializeGuestControl(nil, Config{}); err == nil {
		t.Fatal("nil context was accepted")
	}
	root := t.TempDir()
	realDirectory := filepath.Join(root, "real")
	if err := os.Mkdir(realDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	linkedDirectory := filepath.Join(root, "linked")
	if err := os.Symlink(realDirectory, linkedDirectory); err != nil {
		t.Fatal(err)
	}
	config := Config{GuestControlPath: filepath.Join(linkedDirectory, "vm-guest-control")}
	if err := materializeGuestControl(context.Background(), config); err == nil {
		t.Fatal("symlink guest control directory was accepted")
	}
}
