package client

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestManagedRollbackDeletionSyncFailureKeepsPendingAndRetries(t *testing.T) {
	for _, path := range []string{managedBinary, managedStatePaths[0]} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			f := newManagedFixture(t)
			if err := os.Remove(f.m.path(managedBinary)); err != nil {
				t.Fatal(err)
			}
			if _, err := f.m.install(t.Context(), f.pin, f.cfg, f.options); err != nil {
				t.Fatal(err)
			}
			// procfs allows opening the directory but rejects fsync. The target
			// is already absent, modeling a retry after an interrupted deletion.
			if _, err := os.Lstat(filepath.Join("/proc", filepath.Base(path))); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("fault fixture target is not absent: %v", err)
			}
			parent := filepath.Dir(f.m.path(path))
			if err := os.Rename(parent, parent+".saved"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/proc", parent); err != nil {
				t.Fatal(err)
			}
			if err := f.m.finish(t.Context(), f.options.TransactionID, true); !errors.Is(err, syscall.EINVAL) {
				t.Fatalf("rollback ignored deletion directory sync failure: %v", err)
			}
			transaction, err := f.m.readTransaction()
			if err != nil || !transaction.Pending || transaction.RolledBack {
				t.Fatalf("unsynced deletion completed its journal: %+v %v", transaction, err)
			}
			if err := os.Remove(parent); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(parent+".saved", parent); err != nil {
				t.Fatal(err)
			}
			if err := f.m.finish(t.Context(), f.options.TransactionID, true); err != nil {
				t.Fatalf("rollback did not recover after directory sync was repaired: %v", err)
			}
			transaction, err = f.m.readTransaction()
			if err != nil || transaction.Pending || !transaction.RolledBack {
				t.Fatalf("synced rollback did not complete: %+v %v", transaction, err)
			}
			if _, err := os.Lstat(f.m.path(path)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("rollback did not restore first-install absence: %v", err)
			}
		})
	}
}

func TestManagedRollbackBeforeConfigurationToleratesMissingStateParents(t *testing.T) {
	f := newManagedFixture(t)
	if err := os.Remove(f.m.path(managedBinary)); err != nil {
		t.Fatal(err)
	}
	transaction := managedTransaction{ManagedResult: ManagedResult{TransactionID: f.options.TransactionID,
		Version: f.pin.Version, Pending: true, RollbackDeadline: time.Now().Add(time.Minute)},
		BinarySHA256: f.pin.Archives.AMD64.BinarySHA256, Architecture: "amd64", StateBackup: true}
	if err := f.m.backupState(t.Context(), transaction); err != nil {
		t.Fatal(err)
	}
	if err := f.m.writeTransaction(transaction); err != nil {
		t.Fatal(err)
	}
	if err := f.m.finish(t.Context(), transaction.TransactionID, true); err != nil {
		t.Fatalf("missing pre-configuration parent blocked bootstrap rollback: %v", err)
	}
	current, err := f.m.readTransaction()
	if err != nil || current.Pending || !current.RolledBack {
		t.Fatalf("pre-configuration rollback did not complete: %+v %v", current, err)
	}
	if _, err := os.Stat(f.m.path("/etc")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rollback recreated absent state parents: %v", err)
	}
}
