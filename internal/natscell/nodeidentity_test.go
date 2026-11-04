package natscell

import (
	"encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestNodeIdentityPinsCellSlotAndRaftID(t *testing.T) {
	dir := t.TempDir()
	if err := pinNodeIdentity(dir, "gru", "controller-a", "abc123XY"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ cell, slot, id string }{
		{"sjc", "controller-a", "abc123XY"},
	} {
		if err := pinNodeIdentity(dir, tc.cell, tc.slot, tc.id); !errors.Is(err, ErrStoreIdentity) {
			t.Fatalf("another identity claimed this store: %+v, %v", tc, err)
		}
	}
	if err := pinNodeIdentity(dir, "gru", "controller-a", "abc123XY"); err != nil {
		t.Fatalf("the original identity no longer opens its store: %v", err)
	}
}

func readNodeIdentity(t *testing.T, dir string) nodeIdentity {
	t.Helper()
	wire, err := os.ReadFile(filepath.Join(dir, nodeIdentityFile))
	if err != nil {
		t.Fatal(err)
	}
	var identity nodeIdentity
	if err := json.Unmarshal(wire, &identity); err != nil {
		t.Fatal(err)
	}
	return identity
}

func TestStartRejectsConflictingNodeIdentityBeforeListening(t *testing.T) {
	dir := t.TempDir()
	if err := pinNodeIdentity(dir, "sjc", "controller-a", "abc123XY"); err != nil {
		t.Fatal(err)
	}
	runtime, err := Start(t.Context(), labController(t, "controller-a", dir))
	if runtime != nil || !errors.Is(err, ErrStoreIdentity) {
		t.Fatalf("broker started with another controller's pin: %v, %v", runtime, err)
	}
}
