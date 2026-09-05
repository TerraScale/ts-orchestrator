package vmqual

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
)

func TestFixtureStoreCleanupReplaysDurableStackJournal(t *testing.T) {
	root := t.TempDir()
	config := StackConfig{VMFactory: &smokeFakeFactory{}, Network: &smokeFakeNetwork{}, ResourceRoot: root, StateRoot: filepath.Join(root, "state"), JournalPath: filepath.Join(root, "journal.json")}
	stack, err := NewStack(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := stack.WriteJournal(config.JournalPath, vmnet.Journal{}); err != nil {
		t.Fatal(err)
	}
	ctx := stack.fixtureStoreContext(context.WithValue(context.Background(), qualificationRunIDKey{}, stack.RunID()))
	path, err := PrepareNATSFixtureStore(ctx, config.StateRoot, stack.RunID())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "stored-message"), []byte("persisted"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := stack.verifyFixtureStoreRemoved(); err == nil {
		t.Fatal("live journal overlooked remaining store")
	}
	// Simulate a dead controller releasing its OS journal lock. Cleanup must
	// reconstruct ownership entirely from persisted records.
	stack.releaseJournalLock()
	if err := CleanJournal(context.Background(), config.JournalPath, nil); err != nil {
		t.Fatal(err)
	}
	for _, removed := range []string{path, config.JournalPath} {
		if _, err := os.Lstat(removed); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("cleanup left %s", removed)
		}
	}
}

func TestFixtureStoreRegistersBeforeCreationAndRecovers(t *testing.T) {
	root := t.TempDir()
	runID := "11111111-1111-4111-8111-111111111111"
	ctx := context.WithValue(context.Background(), qualificationRunIDKey{}, runID)
	var claimed string
	ctx = context.WithValue(ctx, fixtureStoreRegistrarKey{}, fixtureStoreRegistrar(func(path string) error {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("store created before registration")
		}
		claimed = path
		return nil
	}))
	path, err := PrepareNATSFixtureStore(ctx, root, runID)
	if err != nil {
		t.Fatal(err)
	}
	if claimed != path {
		t.Fatal("cleanup path differs")
	}
	if err := os.WriteFile(filepath.Join(path, "jetstream.bin"), []byte("durable data"), 0600); err != nil {
		t.Fatal(err)
	}
	journal := Journal{StateRoot: root, RunID: runID, NATSFixtureStore: path}
	if err := cleanupNATSFixtureStore(journal); err != nil {
		t.Fatal(err)
	}
	if err := cleanupNATSFixtureStore(journal); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("store remains")
	}
}

func TestFixtureStoreRegistrationFailureCreatesNothing(t *testing.T) {
	root := t.TempDir()
	runID := "11111111-1111-4111-8111-111111111111"
	ctx := context.WithValue(context.Background(), qualificationRunIDKey{}, runID)
	if _, err := PrepareNATSFixtureStore(ctx, root, runID); err == nil {
		t.Fatal("missing journal accepted")
	}
	ctx = context.WithValue(ctx, fixtureStoreRegistrarKey{}, fixtureStoreRegistrar(func(string) error { return errors.New("disk full") }))
	if _, err := PrepareNATSFixtureStore(ctx, root, runID); err == nil {
		t.Fatal("failed journal accepted")
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed registration created resources: %v", err)
	}
}

func TestFixtureStoreCleanupRejectsUnownedDataAndSymlinks(t *testing.T) {
	for _, kind := range []string{"unmarked", "wrong-owner", "symlink", "outside"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			runID := "11111111-1111-4111-8111-111111111111"
			path := filepath.Join(root, "nats-fixture-"+runID)
			outside := t.TempDir()
			if kind == "symlink" {
				if err := os.Symlink(outside, path); err != nil {
					t.Fatal(err)
				}
			} else {
				if kind == "outside" {
					path = outside
				} else if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(path, "keep"), []byte("unrelated"), 0600); err != nil {
					t.Fatal(err)
				}
				if kind == "wrong-owner" {
					if err := writeExclusiveJSON(filepath.Join(path, ".vmqual-owner.json"), fixtureStoreOwnership{"different", path}); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := cleanupNATSFixtureStore(Journal{StateRoot: root, RunID: runID, NATSFixtureStore: path}); err == nil {
				t.Fatal("unowned store deleted")
			}
			if _, err := os.Lstat(path); err != nil {
				t.Fatal("unowned path removed")
			}
		})
	}
}

func TestFixtureStoreCleanupRecoversBeforeOwnershipPublication(t *testing.T) {
	for _, partial := range []bool{false, true} {
		root := t.TempDir()
		runID := "11111111-1111-4111-8111-111111111111"
		path := filepath.Join(root, "nats-fixture-"+runID)
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		if partial {
			if err := os.WriteFile(filepath.Join(path, ".vmqual-new-interrupted.tmp"), []byte("{\"runId\":"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		if err := cleanupNATSFixtureStore(Journal{StateRoot: root, RunID: runID, NATSFixtureStore: path}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFixtureStoreFailedRemovalPreservesMarkerForRetry(t *testing.T) {
	root := t.TempDir()
	runID := "11111111-1111-4111-8111-111111111111"
	path, err := PrepareNATSFixtureStore(context.Background(), root, runID)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a", "b"} {
		if err := os.WriteFile(filepath.Join(path, name), []byte("data"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	failure := errors.New("interrupted child removal")
	err = removeMarkedFixtureStore(path, func(root *os.Root, name string) error {
		if err := root.RemoveAll(name); err != nil {
			return err
		}
		return failure
	})
	if !errors.Is(err, failure) {
		t.Fatalf("missing failure: %v", err)
	}
	if _, err := os.Stat(filepath.Join(path, ".vmqual-owner.json")); err != nil {
		t.Fatal("failed deletion lost ownership marker", err)
	}
	if err := RemoveNATSFixtureStore(root, runID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("retry left fixture store")
	}
}
