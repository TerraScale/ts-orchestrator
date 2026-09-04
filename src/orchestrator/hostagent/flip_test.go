package hostagent

import (
	"os"
	"path/filepath"
	"testing"
)

// installFakeVersion creates one version directory with its binary inside.
func installFakeVersion(t *testing.T, root, component, version string) {
	t.Helper()
	dir := filepath.Join(root, component, version)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, component), []byte("v"+version), 0o755); err != nil {
		t.Fatal(err)
	}
}

// TestFlipCurrentAndRollback covers the D-69 version switch: flip current to
// a new version, roll it back through previous, and observe that the
// rollback target of a rollback is the rolled-forward version.
func TestFlipCurrentAndRollback(t *testing.T) {
	root := t.TempDir()
	installFakeVersion(t, root, "terrabase", "1.0.0")
	installFakeVersion(t, root, "terrabase", "1.1.0")
	installFakeVersion(t, root, "terrabase", "1.2.0")

	if err := FlipCurrent(root, "terrabase", "1.0.0"); err != nil {
		t.Fatalf("initial flip failed: %v", err)
	}
	if current, _ := CurrentVersion(root, "terrabase"); current != "1.0.0" {
		t.Fatalf("current is %q", current)
	}

	if err := FlipCurrent(root, "terrabase", "1.1.0"); err != nil {
		t.Fatalf("flip forward failed: %v", err)
	}
	if current, _ := CurrentVersion(root, "terrabase"); current != "1.1.0" {
		t.Fatalf("current is %q", current)
	}
	if previous, _ := PreviousVersion(root, "terrabase"); previous != "1.0.0" {
		t.Fatalf("previous is %q", previous)
	}

	// Rollback: current back to 1.0.0, previous now 1.1.0.
	if err := RollbackCurrent(root, "terrabase"); err != nil {
		t.Fatalf("rollback failed: %v", err)
	}
	if current, _ := CurrentVersion(root, "terrabase"); current != "1.0.0" {
		t.Fatalf("current after rollback is %q", current)
	}
	if previous, _ := PreviousVersion(root, "terrabase"); previous != "1.1.0" {
		t.Fatalf("previous after rollback is %q", previous)
	}

	// Rollback of the rollback returns to 1.1.0.
	if err := RollbackCurrent(root, "terrabase"); err != nil {
		t.Fatalf("rollback of rollback failed: %v", err)
	}
	if current, _ := CurrentVersion(root, "terrabase"); current != "1.1.0" {
		t.Fatalf("current after rollback-of-rollback is %q", current)
	}
}

// TestFlipCurrentRefusesUninstalledVersion asserts the symlink never points
// at a directory that does not hold the release binary.
func TestFlipCurrentRefusesUninstalledVersion(t *testing.T) {
	root := t.TempDir()
	installFakeVersion(t, root, "terrabase", "1.0.0")
	if err := FlipCurrent(root, "terrabase", "9.9.9"); err == nil {
		t.Fatal("flip to uninstalled version accepted")
	}
}

// TestFlipCurrentSameVersionIsNoOp asserts flipping to the running version
// keeps the previous target intact.
func TestFlipCurrentSameVersionIsNoOp(t *testing.T) {
	root := t.TempDir()
	installFakeVersion(t, root, "terrabase", "1.0.0")
	installFakeVersion(t, root, "terrabase", "1.1.0")
	if err := FlipCurrent(root, "terrabase", "1.0.0"); err != nil {
		t.Fatal(err)
	}
	if err := FlipCurrent(root, "terrabase", "1.1.0"); err != nil {
		t.Fatal(err)
	}
	if err := FlipCurrent(root, "terrabase", "1.1.0"); err != nil {
		t.Fatal(err)
	}
	if previous, _ := PreviousVersion(root, "terrabase"); previous != "1.0.0" {
		t.Fatalf("no-op flip clobbered previous: %q", previous)
	}
}

// TestRollbackWithoutPreviousFailsClosed asserts rollback needs a previous
// target.
func TestRollbackWithoutPreviousFailsClosed(t *testing.T) {
	root := t.TempDir()
	installFakeVersion(t, root, "terrabase", "1.0.0")
	if err := RollbackCurrent(root, "terrabase"); err == nil {
		t.Fatal("rollback without previous accepted")
	}
}
