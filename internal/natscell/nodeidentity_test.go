package natscell

import (
	"encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestNodeIdentityPinsCellSlotAndRaftID(t *testing.T) {
	dir := t.TempDir()
	if err := pinNodeIdentity(dir, "gru", "controller-a", "abc123XY"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ cell, slot, id string }{
		{"sjc", "controller-a", "abc123XY"},
		{"gru", "controller-b", "abc123XY"},
		{"gru", "controller-a", "xyz456AB"},
		{"gru", "controller-a", "bad/id!!"},
	} {
		if err := pinNodeIdentity(dir, tc.cell, tc.slot, tc.id); !errors.Is(err, ErrStoreIdentity) {
			t.Fatalf("another identity claimed this store: %+v, %v", tc, err)
		}
	}
	if err := pinNodeIdentity(dir, "gru", "controller-a", "abc123XY"); err != nil {
		t.Fatalf("the original identity no longer opens its store: %v", err)
	}
}

func TestNodeIdentityConcurrentPinsCannotReplaceAnOwner(t *testing.T) {
	dir := t.TempDir()
	var workers sync.WaitGroup
	errs := make(chan error, 16)
	for range 16 {
		workers.Go(func() { errs <- pinNodeIdentity(dir, "gru", "controller-a", "abc123XY") })
	}
	workers.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := pinNodeIdentity(dir, "gru", "controller-b", "xyz456AB"); !errors.Is(err, ErrStoreIdentity) {
		t.Fatalf("another starter replaced the owner: %v", err)
	}
}

func TestNodeIdentityExistingPinCannotBypassConcurrentDirectorySync(t *testing.T) {
	dir := t.TempDir()
	linked, release := make(chan struct{}), make(chan struct{}, 1)
	first := make(chan error, 1)
	go func() {
		first <- pinNodeIdentityWithSync(dir, "gru", "controller-a", "abc123XY", func(dir string) error {
			close(linked)
			<-release
			return syncIdentityDirectory(dir)
		})
	}()
	<-linked
	syncFailed := errors.New("directory sync failed")
	second := pinNodeIdentityWithSync(dir, "gru", "controller-a", "abc123XY", func(string) error { return syncFailed })
	release <- struct{}{}
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if !errors.Is(second, syncFailed) {
		t.Fatalf("existing pin started without syncing its directory: %v", second)
	}
}

func TestNodeIdentityRejectsCorruptOrIndirectPins(t *testing.T) {
	for _, kind := range []string{"partial", "unknown-field", "unversioned", "wrong-version", "permissions", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			if err := pinNodeIdentity(dir, "gru", "controller-a", "abc123XY"); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, nodeIdentityFile)
			switch kind {
			case "partial":
				if err := os.WriteFile(path, []byte(`{"cell":`), 0o600); err != nil {
					t.Fatal(err)
				}
			case "unknown-field":
				if err := os.WriteFile(path, []byte(`{"version":1,"cell":"gru","instance":"controller-a","node_id":"abc123XY","extra":true}`), 0o600); err != nil {
					t.Fatal(err)
				}
			case "unversioned", "wrong-version":
				wire := `{"cell":"gru","instance":"controller-a","node_id":"abc123XY"}`
				if kind == "wrong-version" {
					wire = `{"version":2,"cell":"gru","instance":"controller-a","node_id":"abc123XY"}`
				}
				if err := os.WriteFile(path, []byte(wire), 0o600); err != nil {
					t.Fatal(err)
				}
			case "permissions":
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(path, path+".other"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".other", path); err != nil {
					t.Fatal(err)
				}
			}
			if err := pinNodeIdentity(dir, "gru", "controller-a", "abc123XY"); !errors.Is(err, ErrStoreIdentity) {
				t.Fatalf("unsafe pin accepted: %v", err)
			}
		})
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
