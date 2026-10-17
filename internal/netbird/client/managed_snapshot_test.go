package client

import (
	"context"
	"encoding/json/v2"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestManagedSnapshotAndWatchdogRejectFIFOWithoutHoldingLock(t *testing.T) {
	for _, operation := range []string{"snapshot", "watchdog"} {
		t.Run(operation, func(t *testing.T) {
			f := newManagedFixture(t)
			path := f.m.path(managedStatePaths[0])
			want := f.old
			if operation == "watchdog" {
				if _, err := f.m.install(t.Context(), f.pin, f.cfg, f.options); err != nil {
					t.Fatal(err)
				}
				path, want = f.m.path("/etc/systemd/system/"+rollbackUnit+".timer"), f.next
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			} else if _, err := directDirectory(f.m.root, filepath.Dir(managedStatePaths[0]), 0755, false); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mkfifo(path, 0600); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				var err error
				if operation == "snapshot" {
					_, err = f.m.install(t.Context(), f.pin, f.cfg, f.options)
				} else {
					_, err = f.m.recover(t.Context())
				}
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("FIFO was accepted as managed state")
				}
			case <-time.After(2 * time.Second):
				// Unblock a regressed read before failing the test.
				fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_NONBLOCK, 0)
				if err == nil {
					_ = syscall.Close(fd)
				}
				<-done
				t.Fatal("FIFO blocked managed recovery while holding its lock")
			}
			assertManagedFile(t, f.m.path(managedBinary), want)
			lock, err := f.m.lock()
			if err != nil {
				t.Fatalf("FIFO rejection did not release the operation lock: %v", err)
			}
			_ = lock.Close()
		})
	}
}

func TestManagedSnapshotPersistsOnlyConfirmedServiceStateFromProcess(t *testing.T) {
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		state string
		code  int
		want  string
	}{
		{"enabled\n", 0, "enabled"}, {"enabled-runtime\n", 0, "enabled"}, {"static\n", 0, "enabled"},
		{"transient\n", 0, "error"}, {"transient\n", 1, "error"},
		{"disabled\n", 1, "disabled"}, {"masked\n", 1, "disabled"}, {"linked\n", 1, "disabled"},
		{"not-found\n", 4, "disabled"}, {"", 1, "error"}, {"disabled\n", 0, "error"},
		{"enabled\n", 1, "error"}, {"not-found\n", 1, "error"}, {"unknown-secret-state", 1, "error"},
	} {
		t.Run(strings.TrimSpace(test.state)+"-"+strconv.Itoa(test.code), func(t *testing.T) {
			f := newManagedFixture(t)
			f.m.systemctl = func(ctx context.Context, args ...string) error {
				if !slices.Equal(args, []string{"is-enabled", "netbird.service"}) {
					t.Fatalf("unexpected command %v", args)
				}
				command := exec.CommandContext(ctx, shell, "-c", `printf '%s' "$1"; exit "$2"`, "--", test.state, strconv.Itoa(test.code))
				output, err := command.Output()
				return managedUnitEnabledResult(string(output), err)
			}
			transaction := managedTransaction{ManagedResult: ManagedResult{TransactionID: f.options.TransactionID}, StateBackup: true}
			err := f.m.backupState(t.Context(), transaction)
			manifest := filepath.Join(f.m.backupDirectory(transaction), "state.json")
			if test.want == "error" {
				if err == nil || strings.Contains(err.Error(), "unknown-secret-state") {
					t.Fatalf("uncertain process result persisted: %v", err)
				}
				if _, err := os.Stat(manifest); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("unsafe snapshot published: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			wire, err := os.ReadFile(manifest)
			var saved managedSavedState
			if err != nil || json.Unmarshal(wire, &saved) != nil || saved.Enabled != (test.want == "enabled") {
				t.Fatalf("wrong persisted service state: %+v %v", saved, err)
			}
		})
	}
}

func TestManagedSnapshotRecordsConfirmedEnableState(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		t.Run(map[bool]string{true: "enabled", false: "disabled-or-missing"}[enabled], func(t *testing.T) {
			f := newManagedFixture(t)
			if !enabled {
				f.m.systemctl = func(context.Context, ...string) error { return errManagedUnitNotEnabled }
			}
			transaction := managedTransaction{ManagedResult: ManagedResult{TransactionID: f.options.TransactionID}, StateBackup: true}
			if err := f.m.backupState(t.Context(), transaction); err != nil {
				t.Fatal(err)
			}
			body, err := os.ReadFile(filepath.Join(f.m.backupDirectory(transaction), "state.json"))
			var state managedSavedState
			if err != nil || json.Unmarshal(body, &state) != nil || state.Enabled != enabled {
				t.Fatalf("confirmed enabled state was not retained: enabled=%t error=%v", state.Enabled, err)
			}
		})
	}
}

func TestManagedFailedEnableQueryPreservesPriorRollbackBeforeMutation(t *testing.T) {
	for _, failure := range []error{context.DeadlineExceeded, context.Canceled, errors.New("systemd bus unavailable")} {
		t.Run(failure.Error(), func(t *testing.T) {
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
			journal, err := os.ReadFile(f.m.path(managedDirectory + "/pending.json"))
			if err != nil {
				t.Fatal(err)
			}
			options := f.options
			options.TransactionID = "4W9FSTA8N5DH64STS19C0G95GK"
			control, before := f.m.systemctl, len(f.calls)
			f.m.systemctl = func(ctx context.Context, args ...string) error {
				if err := control(ctx, args...); err != nil {
					return err
				}
				if slices.Equal(args, []string{"is-enabled", "netbird.service"}) {
					return failure
				}
				return nil
			}
			if _, err := f.m.install(t.Context(), f.pin, f.cfg, options); !errors.Is(err, failure) {
				t.Fatalf("uncertain enable state allowed preparation: %v", err)
			}
			assertManagedFile(t, f.m.path(managedBinary), f.next)
			assertManagedFile(t, f.m.previousBinary(first), f.old)
			assertManagedFile(t, f.m.path(managedDirectory+"/pending.json"), journal)
			if !slices.Equal(f.calls[before:], []string{"is-enabled netbird.service"}) {
				t.Fatalf("failed snapshot query allowed service changes: %v", f.calls[before:])
			}
			if _, err := os.Stat(filepath.Join(f.m.backupDirectory(managedTransaction{ManagedResult: ManagedResult{TransactionID: options.TransactionID}}), "state.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("failed query wrote an incorrect durable snapshot: %v", err)
			}
		})
	}
}
