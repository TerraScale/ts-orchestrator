package bootstrapstart

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testFounderFloor(t *testing.T) *FounderSelectionFloorStore {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "controller")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return &FounderSelectionFloorStore{directory: directory, ownerUID: uint32(os.Geteuid()), allowUnsafeAncestors: true}
}

func TestFounderSelectionFloorRequiresProvisioningAndRejectsRollback(t *testing.T) {
	store := testFounderFloor(t)
	a := strings.Repeat("a", 64)
	b := strings.Repeat("b", 64)
	if err := store.Check(1, a); !errors.Is(err, ErrFounderSelectionFloor) {
		t.Fatalf("missing floor: %v", err)
	}
	if err := store.Initialize(1, a); err != nil {
		t.Fatal(err)
	}
	if err := store.Initialize(1, a); err == nil {
		t.Fatal("replaced provisioned floor")
	}
	if err := store.Observe(2, b); err != nil {
		t.Fatal(err)
	}
	restarted := *store
	if err := restarted.Check(1, a); !errors.Is(err, ErrFounderSelectionFloor) {
		t.Fatalf("rollback across restart: %v", err)
	}
	if err := restarted.Check(2, a); !errors.Is(err, ErrFounderSelectionFloor) {
		t.Fatalf("same-generation equivocation: %v", err)
	}
	if err := restarted.Check(2, b); err != nil {
		t.Fatalf("current generation: %v", err)
	}
}

func TestFounderSelectionFloorRejectsTamperedFileAndDirectory(t *testing.T) {
	store := testFounderFloor(t)
	digest := strings.Repeat("a", 64)
	if err := store.Initialize(1, digest); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(store.directory, founderSelectionFloorName)
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := store.Check(1, digest); !errors.Is(err, ErrFounderSelectionFloor) {
		t.Fatalf("writable floor: %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"schemaVersion":1,"generation":1,"selectionSha256":"bad"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Check(1, digest); !errors.Is(err, ErrFounderSelectionFloor) {
		t.Fatalf("invalid floor content: %v", err)
	}
	if err := os.Chmod(store.directory, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := store.Check(1, digest); !errors.Is(err, ErrFounderSelectionFloor) {
		t.Fatalf("writable directory: %v", err)
	}
}
