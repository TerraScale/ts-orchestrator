package client

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/netbird"
)

func TestManagedRetainedExecutableRunsRollbackAfterReleasePruning(t *testing.T) {
	f := newManagedFixture(t)
	if runtime.GOARCH != f.m.architecture {
		t.Skip("native executable smoke test needs the fixture's amd64 architecture")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	release := t.TempDir()
	f.m.executable = filepath.Join(release, "ts-orch")
	copy, err := os.Create(f.m.executable)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(copy, source)
	if err := errors.Join(err, copy.Chmod(0755), copy.Close()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.install(t.Context(), f.pin, f.cfg, f.options); err != nil {
		t.Fatal(err)
	}
	transaction, err := f.m.readTransaction()
	if err != nil {
		t.Fatal(err)
	}
	retained := f.m.rollbackExecutable(transaction)
	unit, err := os.ReadFile(f.m.path("/etc/systemd/system/" + rollbackUnit + ".service"))
	if err != nil || !strings.Contains(string(unit), "ExecStart=\""+retained+"\" netbird agent rollback") {
		t.Fatalf("watchdog references a prunable release: %v", err)
	}
	if err := os.RemoveAll(release); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(f.m.path("/etc/systemd/system/" + rollbackUnit + ".timer")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.recover(t.Context()); err != nil {
		t.Fatalf("watchdog could not rearm after release pruning: %v", err)
	}
	transaction.RollbackDeadline = time.Now().Add(-time.Second)
	if err := f.m.writeTransaction(transaction); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(t.Context(), retained, "-test.run=^TestManagedRollbackExecutableHelper$")
	command.Env = append(os.Environ(), "TS_NETBIRD_ROLLBACK_HELPER_ROOT="+f.m.root)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("retained executable could not perform rollback: %s %v", output, err)
	}
	actual, err := f.m.readTransaction()
	if err != nil || actual.Pending || !actual.RolledBack {
		t.Fatalf("retained watchdog did not finish its journal: %+v %v", actual, err)
	}
	assertManagedFile(t, f.m.path(managedBinary), f.old)
}

func TestManagedRollbackExecutableHelper(t *testing.T) {
	root := os.Getenv("TS_NETBIRD_ROLLBACK_HELPER_ROOT")
	if root == "" {
		return
	}
	m := managedClient{root: root, architecture: "amd64",
		systemctl: func(context.Context, ...string) error { return nil }}
	if err := m.finishMode(t.Context(), "test-transaction", true, true); err != nil {
		t.Fatal(err)
	}
}

func TestManagedSnapshotRetentionWaitsForDurableSuccessor(t *testing.T) {
	f := newManagedFixture(t)
	if _, err := f.m.install(t.Context(), f.pin, f.cfg, f.options); err != nil {
		t.Fatal(err)
	}
	if err := f.m.finish(t.Context(), f.options.TransactionID, false); err != nil {
		t.Fatal(err)
	}
	first, err := f.m.readTransaction()
	if err != nil {
		t.Fatal(err)
	}
	control := f.m.systemctl
	f.options.TransactionID = "interrupted-successor"
	f.m.systemctl = func(ctx context.Context, args ...string) error {
		if slices.Equal(args, []string{"restart", rollbackUnit + ".timer"}) {
			current, err := f.m.readTransaction()
			if err != nil || current.TransactionID != first.TransactionID {
				t.Fatalf("successor committed before watchdog admission: %+v %v", current, err)
			}
			assertManagedFile(t, f.m.previousBinary(first), f.old)
			if err := f.m.rollbackExecutableReady(first); err != nil {
				t.Fatal("preparation revoked current watchdog executable")
			}
			return errors.New("watchdog admission failed before successor journal commit")
		}
		return control(ctx, args...)
	}
	if _, err := f.m.install(t.Context(), f.pin, f.cfg, f.options); err == nil {
		t.Fatal("interrupted preparation was accepted")
	}
	assertManagedFile(t, f.m.previousBinary(first), f.old)
	f.m.systemctl = control
	f.options.TransactionID = "durable-successor"
	f.m.enroll = func(context.Context, netbird.Config) error {
		current, err := f.m.readTransaction()
		entries, listErr := os.ReadDir(f.m.path(managedDirectory + "/transactions"))
		if err != nil || current.TransactionID != f.options.TransactionID || !current.Pending || listErr != nil ||
			len(entries) != 1 || entries[0].Name() != current.TransactionID {
			t.Fatalf("history was not reclaimed after durable successor: %+v entries=%v errors=%v/%v", current, entries, err, listErr)
		}
		assertManagedFile(t, f.m.previousBinary(current), f.next)
		return nil
	}
	if _, err := f.m.install(t.Context(), f.pin, f.cfg, f.options); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(f.m.backupDirectory(first)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("obsolete rollback snapshot was retained: %v", err)
	}
}

func TestManagedSnapshotCleanupRejectsUnsafeParent(t *testing.T) {
	for _, kind := range []string{"symlink", "writable", "foreign-owner"} {
		t.Run(kind, func(t *testing.T) {
			if kind == "foreign-owner" && os.Geteuid() != 0 {
				t.Skip("changing directory ownership requires root")
			}
			f := newManagedFixture(t)
			lock, err := f.m.lock()
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Close()
			directory := f.m.path(managedDirectory + "/transactions")
			outside := t.TempDir()
			if kind == "symlink" {
				err = os.Symlink(outside, directory)
			} else {
				err = os.Mkdir(directory, 0700)
				outside = directory
			}
			if err != nil {
				t.Fatal(err)
			}
			sentinel := filepath.Join(outside, "unrelated-data")
			if err := os.WriteFile(sentinel, []byte("preserve"), 0600); err != nil {
				t.Fatal(err)
			}
			if kind == "writable" {
				err = os.Chmod(directory, 0777)
			} else if kind == "foreign-owner" {
				err = os.Chown(directory, 1, -1)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := f.m.pruneTransactions(managedTransaction{}); err == nil {
				t.Fatal("cleanup traversed an unsafe snapshot parent")
			}
			assertManagedFile(t, sentinel, []byte("preserve"))
		})
	}
}

func TestManagedPendingRecoveryDoesNotDependOnSnapshotCleanup(t *testing.T) {
	f := newManagedFixture(t)
	if _, err := f.m.install(t.Context(), f.pin, f.cfg, f.options); err != nil {
		t.Fatal(err)
	}
	transaction, err := f.m.readTransaction()
	if err != nil {
		t.Fatal(err)
	}
	directory := f.m.path(managedDirectory + "/transactions")
	orphan := filepath.Join(directory, "interrupted-preparation")
	if err := os.Mkdir(orphan, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(directory, 0700) })
	transaction.RollbackDeadline = time.Now().Add(-time.Second)
	if err := f.m.writeTransaction(transaction); err != nil {
		t.Fatal(err)
	}
	if current, err := f.m.recover(t.Context()); err != nil || current.Pending || !current.RolledBack {
		t.Fatalf("snapshot cleanup gated pending recovery: %+v %v", current, err)
	}
	if _, err := os.Stat(orphan); err != nil {
		t.Fatal("pending recovery attempted unrelated snapshot cleanup")
	}
	assertManagedFile(t, f.m.path(managedBinary), f.old)
}
