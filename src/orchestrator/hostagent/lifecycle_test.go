package hostagent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testHarness builds one lifecycle over temp directories with a signed
// release server, a recording fake systemd, and fake users.
type testHarness struct {
	root       string
	unitDir    string
	dataVolume string
	lifecycle  *Lifecycle
	systemd    *fakeSystemd
	users      *fakeUsers
	privateKey ed25519.PrivateKey
	releases   map[string][]byte
}

func newTestHarness(t *testing.T) *testHarness {
	t.Helper()
	root := t.TempDir()
	unitDir := t.TempDir()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	harness := &testHarness{
		root:       root,
		unitDir:    unitDir,
		dataVolume: filepath.Join(t.TempDir(), "data"),
		systemd:    newFakeSystemd(),
		users:      newFakeUsers(),
		privateKey: privateKey,
		releases:   map[string][]byte{},
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	installer, err := NewInstaller(InstallerConfig{
		InstallRoot:  root,
		PublicKeyHex: hex.EncodeToString(publicKey),
		Downloader:   memoryDownloader{files: harness.releases},
	})
	if err != nil {
		t.Fatal(err)
	}
	harness.lifecycle, err = NewLifecycle(LifecycleConfig{
		InstallRoot: root,
		UnitDir:     unitDir,
		Installer:   installer,
		Systemd:     harness.systemd,
		Users:       harness.users,
	})
	if err != nil {
		t.Fatal(err)
	}
	return harness
}

// publish signs and serves one component release and returns its spec.
func (h *testHarness) publish(t *testing.T, name, version string) ComponentSpec {
	t.Helper()
	spec := testComponentSpec()
	spec.Name = name
	spec.Version = version
	spec.User = "terrascale-" + name
	spec.DataVolume = filepath.Join(h.dataVolume, name)
	spec.CPUWeight, spec.MemoryMaxBytes, spec.IOWeight = 100, 4<<30, 100
	base := "https://releases.terrascale.tech/" + name + "/" + version
	spec.ArtifactURL = base + "/" + name
	spec.SignatureURL = base + "/" + name + ".sig"
	artifact, signature, sha256Hex := signedRelease(t, name+"-"+version, h.privateKey)
	h.releases[spec.ArtifactURL] = artifact
	h.releases[spec.SignatureURL] = []byte(signature)
	spec.Sha256 = sha256Hex
	return spec
}

func (h *testHarness) applyDesired(t *testing.T, specs ...ComponentSpec) {
	t.Helper()
	if err := h.lifecycle.ApplyDesired(context.Background(), specs); err != nil {
		t.Fatalf("apply desired failed: %v", err)
	}
}

// TestDrainLifecycleIsQuiescedRestartReady walks the full D-69 restart
// choreography: reconcile to desired, drain, quiesce, deploy the next
// version under the drain, release back to serving.
func TestDrainLifecycleIsQuiescedRestartReady(t *testing.T) {
	harness := newTestHarness(t)
	ctx := context.Background()
	v1 := harness.publish(t, "terrabase", "1.0.0")
	v2 := harness.publish(t, "terrabase", "1.1.0")
	harness.applyDesired(t, v1)

	// Reconciliation installed v1, rendered the unit, enabled and started it.
	if !harness.systemd.active[UnitName("terrabase")] {
		t.Fatal("unit not started by reconciliation")
	}
	if current, _ := CurrentVersion(harness.root, "terrabase"); current != "" {
		t.Fatalf("reconciliation flipped current to %q; installs never flip", current)
	}
	if err := FlipCurrent(harness.root, "terrabase", "1.0.0"); err != nil {
		t.Fatal(err)
	}

	// Drain: state draining, unit stopped, quiesced true.
	if err := harness.lifecycle.BeginDrain(ctx); err != nil {
		t.Fatalf("drain failed: %v", err)
	}
	if state := harness.lifecycle.State(); state != NodeStateDraining {
		t.Fatalf("state is %q", state)
	}
	if harness.systemd.active[UnitName("terrabase")] {
		t.Fatal("unit still active after drain")
	}
	if !harness.lifecycle.Quiesced(ctx) {
		t.Fatal("node not quiesced after drain")
	}

	// Install the next release through reconciliation while drained: the
	// unit must not be restarted by the reconciler mid-drain.
	harness.applyDesired(t, v2)
	if harness.systemd.active[UnitName("terrabase")] {
		t.Fatal("reconciler started the unit during drain")
	}
	if !InstalledVersion(harness.root, "terrabase", "1.1.0") {
		t.Fatal("next release not installed during drain")
	}

	// Deploy under the drain: symlink flip, unit started on the new version.
	if err := harness.lifecycle.Deploy(ctx, "terrabase", "1.1.0"); err != nil {
		t.Fatalf("deploy failed: %v", err)
	}
	if current, _ := CurrentVersion(harness.root, "terrabase"); current != "1.1.0" {
		t.Fatalf("current is %q after deploy", current)
	}
	if !harness.systemd.active[UnitName("terrabase")] {
		t.Fatal("unit not started by deploy")
	}
	unit, err := os.ReadFile(filepath.Join(harness.unitDir, UnitName("terrabase")))
	if err != nil || !strings.Contains(string(unit), "Description=TerraScale terrabase 1.1.0") {
		t.Fatalf("unit file not re-rendered for the deployed version: %v", err)
	}

	// Release: serving again.
	if err := harness.lifecycle.ReleaseDrain(ctx); err != nil {
		t.Fatalf("release failed: %v", err)
	}
	if state := harness.lifecycle.State(); state != NodeStateServing {
		t.Fatalf("state is %q after release", state)
	}
}

// TestDeployRefusesWithoutDrain asserts the fail-closed gate: no deploy
// while serving.
func TestDeployRefusesWithoutDrain(t *testing.T) {
	harness := newTestHarness(t)
	v1 := harness.publish(t, "terrabase", "1.0.0")
	harness.applyDesired(t, v1)
	if err := FlipCurrent(harness.root, "terrabase", "1.0.0"); err != nil {
		t.Fatal(err)
	}
	if err := harness.lifecycle.Deploy(context.Background(), "terrabase", "1.0.0"); err == nil {
		t.Fatal("deploy accepted without drain")
	}
}

// TestDeployRefusesUninstalledVersion asserts the deploy gate on the
// version directory.
func TestDeployRefusesUninstalledVersion(t *testing.T) {
	harness := newTestHarness(t)
	ctx := context.Background()
	v1 := harness.publish(t, "terrabase", "1.0.0")
	harness.applyDesired(t, v1)
	if err := harness.lifecycle.BeginDrain(ctx); err != nil {
		t.Fatal(err)
	}
	if err := harness.lifecycle.Deploy(ctx, "terrabase", "9.9.9"); err == nil {
		t.Fatal("deploy accepted for uninstalled version")
	}
}

// TestRollbackWorksWithoutDrain asserts the emergency path: rollback is the
// symlink back plus restart, available from serving.
func TestRollbackWorksWithoutDrain(t *testing.T) {
	harness := newTestHarness(t)
	ctx := context.Background()
	v1 := harness.publish(t, "terrabase", "1.0.0")
	v2 := harness.publish(t, "terrabase", "1.1.0")
	harness.applyDesired(t, v1, v2)
	if err := FlipCurrent(harness.root, "terrabase", "1.0.0"); err != nil {
		t.Fatal(err)
	}
	if err := FlipCurrent(harness.root, "terrabase", "1.1.0"); err != nil {
		t.Fatal(err)
	}
	if err := harness.lifecycle.Rollback(ctx, "terrabase"); err != nil {
		t.Fatalf("rollback failed: %v", err)
	}
	if current, _ := CurrentVersion(harness.root, "terrabase"); current != "1.0.0" {
		t.Fatalf("current is %q after rollback", current)
	}
	if !harness.systemd.active[UnitName("terrabase")] {
		t.Fatal("unit not restarted by rollback")
	}
}

// TestDrainIsIdempotentAndReleasable asserts drain twice and release from
// serving are safe.
func TestDrainIsIdempotentAndReleasable(t *testing.T) {
	harness := newTestHarness(t)
	ctx := context.Background()
	harness.applyDesired(t, harness.publish(t, "terrabase", "1.0.0"))
	if err := harness.lifecycle.ReleaseDrain(ctx); err != nil {
		t.Fatalf("release from serving failed: %v", err)
	}
	if err := harness.lifecycle.BeginDrain(ctx); err != nil {
		t.Fatal(err)
	}
	if err := harness.lifecycle.BeginDrain(ctx); err != nil {
		t.Fatalf("second drain failed: %v", err)
	}
	if !harness.lifecycle.Quiesced(ctx) {
		t.Fatal("not quiesced after second drain")
	}
}
