package client

import (
	"context"
	"encoding/json/v2"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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

func TestManagedUnitEnabledResultRequiresStateAndExitStatus(t *testing.T) {
	exit1 := exec.Command("sh", "-c", "exit 1").Run()
	exit4 := exec.Command("sh", "-c", "exit 4").Run()
	for _, test := range []struct {
		state string
		err   error
		want  string
	}{
		{state: "enabled\n", want: "enabled"},
		{state: "enabled-runtime\n", want: "enabled"},
		{state: "static\n", want: "enabled"},
		{state: "transient\n", want: "error"},
		{state: "transient\n", err: exit1, want: "error"},
		{state: "disabled\n", err: exit1, want: "disabled"},
		{state: "masked\n", err: exit1, want: "disabled"},
		{state: "linked\n", err: exit1, want: "disabled"},
		{state: "not-found\n", err: exit4, want: "disabled"},
		{err: exit1, want: "error"},
		{state: "disabled\n", want: "error"},
		{state: "enabled\n", err: exit1, want: "error"},
		{state: "not-found\n", err: exit1, want: "error"},
		{state: "disabled\n", err: context.DeadlineExceeded, want: "error"},
		{state: "disabled\n", err: context.Canceled, want: "error"},
		{state: "disabled\n", err: errors.New("systemd communication failed"), want: "error"},
		{state: "unknown-secret-state", err: exit1, want: "error"},
	} {
		err := managedUnitEnabledResult(test.state, test.err)
		actual := "error"
		if err == nil {
			actual = "enabled"
		} else if errors.Is(err, errManagedUnitNotEnabled) {
			actual = "disabled"
		}
		if actual != test.want || err != nil && strings.Contains(err.Error(), "unknown-secret-state") {
			t.Errorf("state %q / %v: result=%s error=%v, want=%s", test.state, test.err, actual, err, test.want)
		}
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
