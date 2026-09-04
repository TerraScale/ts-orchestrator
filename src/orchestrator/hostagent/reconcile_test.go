package hostagent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestManifestReconciliationInstallsUnitsAndStarts asserts one manifest
// pass: release installed, dedicated user provisioned, data volume owned,
// unit file rendered, unit enabled and started — and no symlink flip.
func TestManifestReconciliationInstallsUnitsAndStarts(t *testing.T) {
	harness := newTestHarness(t)
	spec := harness.publish(t, "terrabase", "1.0.0")
	manifest := `{"components":[` + componentJSON(t, spec) + `]}`
	manifestPath := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	watcher, err := NewManifestWatcher(ManifestWatcherConfig{
		ManifestPath: manifestPath,
		Interval:     time.Minute,
		Lifecycle:    harness.lifecycle,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := watcher.ReconcileOnce(context.Background()); err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if !InstalledVersion(harness.root, "terrabase", "1.0.0") {
		t.Fatal("release not installed")
	}
	if harness.users.ensured["terrascale-terrabase"] != 1 {
		t.Fatalf("user ensured %d times", harness.users.ensured["terrascale-terrabase"])
	}
	if harness.users.owned["terrascale-terrabase"] != spec.DataVolume {
		t.Fatalf("data volume ownership is %q", harness.users.owned["terrascale-terrabase"])
	}
	if info, err := os.Stat(spec.DataVolume); err != nil || !info.IsDir() {
		t.Fatalf("data volume not created: %v", err)
	}
	unit, err := os.ReadFile(filepath.Join(harness.unitDir, UnitName("terrabase")))
	if err != nil || len(unit) == 0 {
		t.Fatalf("unit file not written: %v", err)
	}
	if !harness.systemd.isActive(UnitName("terrabase")) {
		t.Fatal("unit not started")
	}
	if current, _ := CurrentVersion(harness.root, "terrabase"); current != "" {
		t.Fatalf("reconciliation flipped current to %q", current)
	}
}

func componentJSON(t *testing.T, spec ComponentSpec) string {
	t.Helper()
	encoded, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

// TestManifestReconciliationIsIdempotent asserts a second identical pass
// installs nothing new, writes nothing, and daemon-reloads nothing.
func TestManifestReconciliationIsIdempotent(t *testing.T) {
	harness := newTestHarness(t)
	spec := harness.publish(t, "terrabase", "1.0.0")
	harness.applyDesired(t, spec)
	operations := len(harness.systemd.ops())
	harness.applyDesired(t, spec)
	if replayed := harness.systemd.ops(); len(replayed) != operations {
		t.Fatalf("second pass replayed operations: %v", replayed[operations:])
	}
}

// TestManifestVersionBumpDoesNotFlip asserts a new desired version installs
// beside the current one and leaves the running symlink untouched: the flip
// belongs to the orchestrator-coordinated deploy.
func TestManifestVersionBumpDoesNotFlip(t *testing.T) {
	harness := newTestHarness(t)
	v1 := harness.publish(t, "terrabase", "1.0.0")
	harness.applyDesired(t, v1)
	if err := FlipCurrent(harness.root, "terrabase", "1.0.0"); err != nil {
		t.Fatal(err)
	}
	v2 := harness.publish(t, "terrabase", "1.1.0")
	harness.applyDesired(t, v2)
	if !InstalledVersion(harness.root, "terrabase", "1.1.0") {
		t.Fatal("new release not installed")
	}
	if current, _ := CurrentVersion(harness.root, "terrabase"); current != "1.0.0" {
		t.Fatalf("reconciliation flipped current to %q", current)
	}
}

// TestManifestRetirementRemovesUnitsKeepsData asserts a component that left
// the manifest is stopped, disabled, its unit file and versions removed —
// and its data volume kept: deleting a database is a human decision.
func TestManifestRetirementRemovesUnitsKeepsData(t *testing.T) {
	harness := newTestHarness(t)
	spec := harness.publish(t, "terrabase", "1.0.0")
	harness.applyDesired(t, spec)
	harness.applyDesired(t)
	if _, err := os.Stat(filepath.Join(harness.unitDir, UnitName("terrabase"))); !os.IsNotExist(err) {
		t.Fatal("unit file not removed on retirement")
	}
	if _, err := os.Stat(InstallDir(harness.root, "terrabase")); !os.IsNotExist(err) {
		t.Fatal("component directory not removed on retirement")
	}
	if harness.systemd.isActive(UnitName("terrabase")) {
		t.Fatal("unit still active after retirement")
	}
	if info, err := os.Stat(spec.DataVolume); err != nil || !info.IsDir() {
		t.Fatalf("data volume not preserved: %v", err)
	}
}

// TestManifestInvalidOrMissingChangesNothing asserts a truncated or missing
// manifest never retires the serving state: the last valid desired set
// stays applied.
func TestManifestInvalidOrMissingChangesNothing(t *testing.T) {
	harness := newTestHarness(t)
	spec := harness.publish(t, "terrabase", "1.0.0")
	harness.applyDesired(t, spec)
	manifestPath := filepath.Join(t.TempDir(), "manifest.json")
	watcher, err := NewManifestWatcher(ManifestWatcherConfig{
		ManifestPath: manifestPath,
		Interval:     time.Minute,
		Lifecycle:    harness.lifecycle,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := watcher.ReconcileOnce(context.Background()); err == nil {
		t.Fatal("missing manifest reported success")
	}
	if err := os.WriteFile(manifestPath, []byte(`{"components":[{"name":"terrabase"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := watcher.ReconcileOnce(context.Background()); err == nil {
		t.Fatal("invalid manifest reported success")
	}
	if !InstalledVersion(harness.root, "terrabase", "1.0.0") {
		t.Fatal("invalid manifest retired the release")
	}
	if len(harness.lifecycle.Desired()) != 1 {
		t.Fatal("invalid manifest changed the desired set")
	}
}

// TestManifestTsNodeSelfComponentInstallsWithoutUnit asserts the reserved
// self-component installs and flips nothing, writes no unit, and creates no
// account: its unit is cloud-init's, exactly one.
func TestManifestTsNodeSelfComponentInstallsWithoutUnit(t *testing.T) {
	harness := newTestHarness(t)
	spec := harness.publish(t, TsNodeComponentName, "2.0.0")
	spec.User = "ignored-user"
	harness.applyDesired(t, spec)
	if !InstalledVersion(harness.root, TsNodeComponentName, "2.0.0") {
		t.Fatal("ts-node release not installed")
	}
	if _, err := os.Stat(filepath.Join(harness.unitDir, UnitName(TsNodeComponentName))); !os.IsNotExist(err) {
		t.Fatal("ts-node unit file written")
	}
	if len(harness.users.ensured) != 0 {
		t.Fatal("ts-node component provisioned an account")
	}
}
