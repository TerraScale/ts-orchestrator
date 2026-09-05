package hostagent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
)

func TestComponentLaunchConfigurationArgumentResolvesConfig(t *testing.T) {
	spec := testComponentSpec()
	spec.Arguments = "--config @config"
	spec.Configuration = "mode = \"production\"\n"
	unit, err := RenderSystemdUnit("/opt/terrascale", spec)
	if err != nil || !strings.Contains(unit, " --config "+filepath.Join(VersionDir("/opt/terrascale", spec.Name, spec.Version), spec.Name+".config")+"\n") {
		t.Fatalf("config launch: %v %s", err, unit)
	}
}

func TestComponentLaunchImmutableInstallAndRollback(t *testing.T) {
	h := newTestHarness(t)
	ctx := context.Background()
	first := h.publish(t, "terrabase", "1.0.0")
	first.Arguments, first.Configuration = "--config @config", "revision = 1\n"
	second := h.publish(t, "terrabase", "2.0.0")
	second.Arguments, second.Configuration = "--config-file @config", "revision = 2\n"
	h.applyDesired(t, first)
	if err := h.lifecycle.BeginDrain(ctx); err != nil {
		t.Fatal(err)
	}
	if err := h.lifecycle.Deploy(ctx, first.Name, first.Version); err != nil {
		t.Fatal(err)
	}
	h.applyDesired(t, second)
	wanted := filepath.Join(VersionDir(h.lifecycle.installRoot, first.Name, first.Version), first.Name+".config")
	if raw, err := initialgrant.ReadConfiguration(wanted); err != nil || string(raw) != first.Configuration {
		t.Fatalf("immutable configuration cannot pass safe admission: %v", err)
	}
	if _, err := initialgrant.ReadConfiguration(filepath.Join(InstallDir(h.lifecycle.installRoot, first.Name), "current", first.Name+".config")); err == nil {
		t.Fatal("configuration admission followed a mutable current symlink")
	}
	before, err := os.ReadFile(filepath.Join(h.lifecycle.unitDir, UnitName(first.Name)))
	if err != nil || !strings.Contains(string(before), " --config "+wanted+"\n") {
		t.Fatalf("staged config prematurely changed running args: %v %s", err, before)
	}
	if err := h.lifecycle.BeginDrain(ctx); err != nil {
		t.Fatal(err)
	}
	if err := h.lifecycle.Deploy(ctx, second.Name, second.Version); err != nil {
		t.Fatal(err)
	}
	if err := h.lifecycle.Rollback(ctx, first.Name); err != nil {
		t.Fatal(err)
	}
	config, err := os.ReadFile(filepath.Join(InstallDir(h.lifecycle.installRoot, first.Name), "current", first.Name+".config"))
	if err != nil || string(config) != first.Configuration {
		t.Fatalf("rollback configuration: %v %q", err, config)
	}
	unit, err := os.ReadFile(filepath.Join(h.lifecycle.unitDir, UnitName(first.Name)))
	if err != nil || !strings.Contains(string(unit), " --config "+wanted+"\n") || strings.Contains(string(unit), "--config-file") {
		t.Fatalf("rollback arguments: %v %s", err, unit)
	}
	first.Configuration = "revision = 3\n"
	if _, err := h.lifecycle.installer.Install(first); err == nil {
		t.Fatal("same version configuration mutation accepted")
	}
	first.Configuration = "revision = 1\n"
	configPath := filepath.Join(VersionDir(h.lifecycle.installRoot, first.Name, first.Version), first.Name+".config")
	if err := os.Chmod(configPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("tampered"), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := h.lifecycle.BeginDrain(ctx); err != nil {
		t.Fatal(err)
	}
	if err := h.lifecycle.ReleaseDrain(ctx); err == nil {
		t.Fatal("start accepted corrupt current configuration")
	}
}

func TestInstalledLaunchMetadataCannotBeBackfilled(t *testing.T) {
	h := newTestHarness(t)
	spec := h.publish(t, "terrabase", "1.0.0")
	h.applyDesired(t, spec)
	path := filepath.Join(VersionDir(h.lifecycle.installRoot, spec.Name, spec.Version), spec.Name+".launch.json")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := h.lifecycle.installer.Install(spec); err == nil {
		t.Fatal("missing admitted launch metadata was silently recreated")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("missing metadata changed: %v", err)
	}
}
