package hostagent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
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
	wantOperations := []string{
		"daemon-reload:",
		"enable:" + UnitName("terrabase"),
		"start:" + UnitName("terrabase"),
	}
	if got := harness.systemd.ops(); !slices.Equal(got, wantOperations) {
		t.Fatalf("systemd operations = %v, want %v", got, wantOperations)
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

func TestParseHostManifestRejectsNonCanonicalJSON(t *testing.T) {
	harness := newTestHarness(t)
	component := componentJSON(t, harness.publish(t, "terrabase", "1.0.0"))
	valid := `{"components":[` + component + `]}`
	cases := map[string]string{
		"top-level null":      `null`,
		"components null":     `{"components":null}`,
		"component null":      `{"components":[null]}`,
		"top-level duplicate": `{"components":[],"components":[]}`,
		"top-level case":      strings.Replace(valid, `"components"`, `"Components"`, 1),
		"top-level unknown":   strings.Replace(valid, `{`, `{"unknown":true,`, 1),
		"trailing document":   valid + `{}`,
		"component duplicate": strings.Replace(valid, `"name":"terrabase"`, `"name":"terrabase","name":"terrabase"`, 1),
		"component case":      strings.Replace(valid, `"artifactUrl"`, `"ArtifactUrl"`, 1),
		"component unknown":   strings.Replace(valid, `"name":"terrabase"`, `"name":"terrabase","unknown":true`, 1),
		"component null field": strings.Replace(valid,
			`"dataVolume":"`+harness.dataVolume+`/terrabase"`, `"dataVolume":null`, 1),
		"component missing field": strings.Replace(valid, `,"needsNetlink":false`, ``, 1),
	}
	for name, document := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseHostManifest([]byte(document)); err == nil {
				t.Fatal("non-canonical manifest accepted")
			}
		})
	}
	if _, err := ParseHostManifest([]byte(valid)); err != nil {
		t.Fatalf("canonical manifest rejected: %v", err)
	}
	oversized := append([]byte(valid), []byte(strings.Repeat(" ", hostAgentMaximumManifestBytes-len(valid)+1))...)
	if _, err := ParseHostManifest(oversized); err == nil {
		t.Fatal("oversized manifest accepted")
	}
}

func TestManifestRejectsDataVolumesOutsideRootBeforeMutation(t *testing.T) {
	harness := newTestHarness(t)
	spec := harness.publish(t, "terrabase", "1.0.0")
	spec.DataVolume = filepath.Join(t.TempDir(), "outside")
	if err := harness.lifecycle.ApplyDesired(context.Background(), []ComponentSpec{spec}); err == nil {
		t.Fatal("data volume outside configured root accepted")
	}
	if InstalledVersion(harness.root, spec.Name, spec.Version) {
		t.Fatal("artifact installed before data volume admission")
	}
	if len(harness.users.ensured) != 0 || len(harness.systemd.ops()) != 0 {
		t.Fatal("host mutated before data volume admission")
	}
}

func TestManifestRejectsDataVolumeSymlinkBeforeMutation(t *testing.T) {
	harness := newTestHarness(t)
	if err := os.MkdirAll(harness.dataVolume, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	link := filepath.Join(harness.dataVolume, "linked")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	spec := harness.publish(t, "terrabase", "1.0.0")
	spec.DataVolume = filepath.Join(link, "terrabase")
	if err := harness.lifecycle.ApplyDesired(context.Background(), []ComponentSpec{spec}); err == nil {
		t.Fatal("symlinked data volume accepted")
	}
	if InstalledVersion(harness.root, spec.Name, spec.Version) {
		t.Fatal("artifact installed before symlink admission")
	}
	if _, err := os.Stat(filepath.Join(outside, "terrabase")); !os.IsNotExist(err) {
		t.Fatalf("directory created through symlink: %v", err)
	}
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

func TestManifestRetirementPreservesPossiblyServingVersionWhenStopFails(t *testing.T) {
	harness := newTestHarness(t)
	spec := harness.publish(t, "terrabase", "1.0.0")
	harness.applyDesired(t, spec)
	harness.systemd.failOn["stop"] = UnitName(spec.Name)
	if err := harness.lifecycle.ApplyDesired(context.Background(), nil); err == nil {
		t.Fatal("failed stop reported successful retirement")
	}
	if !InstalledVersion(harness.root, spec.Name, spec.Version) {
		t.Fatal("possibly serving immutable version was removed")
	}
	if _, err := os.Stat(filepath.Join(harness.unitDir, UnitName(spec.Name))); err != nil {
		t.Fatalf("possibly serving unit was removed: %v", err)
	}
	if len(harness.lifecycle.Desired()) != 0 {
		t.Fatal("retired component remains eligible for deployment or restart")
	}
	delete(harness.systemd.failOn, "stop")
	harness.applyDesired(t)
	if InstalledVersion(harness.root, spec.Name, spec.Version) {
		t.Fatal("failed retirement was not retried")
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
	if err := os.WriteFile(manifestPath, []byte(strings.Repeat(" ", hostAgentMaximumManifestBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := watcher.ReconcileOnce(context.Background()); err == nil {
		t.Fatal("oversized manifest reported success")
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
// account: its unit is the shared bootstrap unit, exactly one.
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

func TestManifestReadmissionCancelsFailedRetirement(t *testing.T) {
	harness := newTestHarness(t)
	spec := harness.publish(t, "terrabase", "1.0.0")
	harness.applyDesired(t, spec)
	harness.systemd.failOn["stop"] = UnitName(spec.Name)
	if err := harness.lifecycle.ApplyDesired(context.Background(), nil); err == nil {
		t.Fatal("expected failed retirement")
	}
	delete(harness.systemd.failOn, "stop")
	harness.applyDesired(t, spec)
	if !InstalledVersion(harness.root, spec.Name, spec.Version) || !harness.systemd.isActive(UnitName(spec.Name)) {
		t.Fatal("readmitted component retired")
	}
}

func TestManifestRetirementResumesAfterRestart(t *testing.T) {
	for _, removed := range []bool{false, true} {
		t.Run(fmt.Sprint("artifactsRemoved=", removed), func(t *testing.T) {
			harness := newTestHarness(t)
			spec := harness.publish(t, "terrabase", "1.0.0")
			harness.applyDesired(t, spec)
			harness.systemd.failOn["daemon-reload"] = ""
			if err := harness.lifecycle.ApplyDesired(context.Background(), nil); err == nil {
				t.Fatal("expected failed retirement")
			}
			if removed {
				if err := os.RemoveAll(InstallDir(harness.root, spec.Name)); err != nil {
					t.Fatal(err)
				}
			}
			delete(harness.systemd.failOn, "daemon-reload")
			// Real systemd rejects stop/disable after the unit has vanished.
			harness.systemd.failOn["stop"] = UnitName(spec.Name)
			harness.systemd.failOn["disable"] = UnitName(spec.Name)
			lifecycle, err := NewLifecycle(LifecycleConfig{
				InstallRoot: harness.root, UnitDir: harness.unitDir, DataVolumeRoot: harness.dataVolume,
				Installer: harness.lifecycle.installer, Systemd: harness.systemd, Users: harness.users,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := lifecycle.HydrateDesired(nil); err != nil {
				t.Fatal(err)
			}
			if err := lifecycle.BeginDrain(context.Background()); err != nil {
				t.Fatal(err)
			}
			if !lifecycle.Quiesced(context.Background()) {
				t.Fatal("retirement marker blocks drain recovery")
			}
			if err := lifecycle.ApplyDesired(context.Background(), nil); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(InstallDir(harness.root, spec.Name)); !os.IsNotExist(err) {
				t.Fatalf("artifact cleanup incomplete: %v", err)
			}
			if _, err := os.Stat(filepath.Join(harness.unitDir, UnitName(spec.Name)+".retiring")); !os.IsNotExist(err) {
				t.Fatalf("marker cleanup incomplete: %v", err)
			}
		})
	}
}
