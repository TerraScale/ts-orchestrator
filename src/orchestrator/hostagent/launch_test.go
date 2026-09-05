package hostagent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestComponentLaunchRejectsInterpolationAndSecretKey(t *testing.T) {
	for _, arguments := range []string{"--config $PATH", "--config %i", "--config `whoami`", "--config \"file\"", "--config /tmp/a\nb", "--config  /tmp/a", "@config", "@config @config"} {
		spec := testComponentSpec()
		spec.Arguments = arguments
		if _, err := NewComponentSpec(spec); err == nil {
			t.Errorf("unsafe arguments accepted: %q", arguments)
		}
	}
	spec := testComponentSpec()
	spec.Arguments, spec.Configuration = "--config @config", "-----BEGIN PRIVATE KEY-----"
	if _, err := NewComponentSpec(spec); err == nil {
		t.Fatal("embedded key accepted")
	}
	spec.Configuration = "mode = \"production\"\n"
	unit, err := RenderSystemdUnit("/opt/terrascale", spec)
	if err != nil || !strings.Contains(unit, " --config /opt/terrascale/terrabase/current/terrabase.config\n") {
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
	before, err := os.ReadFile(filepath.Join(h.lifecycle.unitDir, UnitName(first.Name)))
	if err != nil || !strings.Contains(string(before), " --config ") {
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
	if err != nil || !strings.Contains(string(unit), " --config ") || strings.Contains(string(unit), "--config-file") {
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
