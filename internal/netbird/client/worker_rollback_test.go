package client

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/netbird"
)

func TestManagedWorkerAcknowledgesPreJournalFailure(t *testing.T) {
	for _, previous := range []string{"absent", "confirmed"} {
		for _, failure := range []string{"checksum", "snapshot", "watchdog"} {
			t.Run(previous+"/"+failure, func(t *testing.T) {
				f := newManagedFixture(t)
				if previous == "confirmed" {
					if _, err := f.m.install(t.Context(), f.pin, f.cfg, f.options); err != nil {
						t.Fatal(err)
					}
					if err := f.m.finish(t.Context(), f.options.TransactionID, false); err != nil {
						t.Fatal(err)
					}
				}
				before, err := f.m.readTransaction()
				if err != nil {
					t.Fatal(err)
				}
				live, err := os.ReadFile(f.m.path(managedBinary))
				if err != nil {
					t.Fatal(err)
				}
				f.options.TransactionID = "22FE8CPAW11ZMZF376BD8RV1DK"
				var proof ManagedRollbackProof
				f.options.Prepare = func(previous ManagedResult) error {
					if lock, err := f.m.lock(); err == nil {
						lock.Close()
						t.Fatal("worker preparation proof was recorded outside managed.lock")
					}
					proof = ManagedRollbackProof{InstallStarted: true, PreviousTransactionID: previous.TransactionID}
					return nil
				}
				switch failure {
				case "checksum":
					f.pin.Archives.AMD64.BinarySHA256 = strings.Repeat("0", 64)
				case "snapshot":
					path := f.m.path(netbird.PublicConfigPath)
					if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, []byte("unsafe configuration"), 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.Chmod(path, 0666); err != nil {
						t.Fatal(err)
					}
				case "watchdog":
					control := f.m.systemctl
					f.m.systemctl = func(ctx context.Context, args ...string) error {
						if slices.Equal(args, []string{"restart", rollbackUnit + ".timer"}) {
							return errors.New("watchdog preparation failed")
						}
						return control(ctx, args...)
					}
				}
				result, err := f.m.install(t.Context(), f.pin, f.cfg, f.options)
				if err == nil || result.TransactionID != "" || !proof.InstallStarted {
					t.Fatalf("pre-journal failure lost its preparation proof: %+v %+v %v", result, proof, err)
				}
				if err := f.m.finish(t.Context(), f.options.TransactionID, true); err == nil {
					t.Fatal("strict rollback accepted an absent or different journal")
				}
				calls := len(f.calls)
				if err := f.m.finishModeWithProof(t.Context(), f.options.TransactionID, true, false, &proof); err != nil {
					t.Fatalf("worker could not acknowledge unchanged preparation: %v", err)
				}
				if !slices.Equal(f.calls[calls:], []string{"stop " + rollbackUnit + ".timer " + rollbackUnit + ".service"}) {
					t.Fatalf("no-op rollback changed more than its orphaned watchdog: %v", f.calls[calls:])
				}
				assertManagedFile(t, f.m.path(managedBinary), live)
				after, err := f.m.readTransaction()
				if err != nil || after != before {
					t.Fatalf("no-op rollback replaced another journal: %+v %v", after, err)
				}
			})
		}
	}
}

func TestManagedWorkerNoopRejectsUnprovenOrPendingTransactions(t *testing.T) {
	for _, test := range []struct {
		name, current, baseline string
		pending, committed      bool
		started, accepted       bool
	}{
		{"unstarted absent", "", "", false, false, false, true},
		{"prepared absent", "", "", false, false, true, true},
		{"unstarted completed", "0VWD7JSS84Y3FHDZ5Y8RJWJJMA", "", false, false, false, true},
		{"prepared completed", "0VWD7JSS84Y3FHDZ5Y8RJWJJMA", "0VWD7JSS84Y3FHDZ5Y8RJWJJMA", false, false, true, true},
		{"unrelated completed", "2VP7F78J0ZNFE8BE3RYC7BNX9T", "0VWD7JSS84Y3FHDZ5Y8RJWJJMA", false, false, true, false},
		{"baseline disappeared", "", "0VWD7JSS84Y3FHDZ5Y8RJWJJMA", false, false, true, false},
		{"known mutation absent", "", "", false, true, true, false},
		{"known mutation completed", "0VWD7JSS84Y3FHDZ5Y8RJWJJMA", "0VWD7JSS84Y3FHDZ5Y8RJWJJMA", false, true, true, false},
		{"other pending unstarted", "2VP7F78J0ZNFE8BE3RYC7BNX9T", "", true, false, false, false},
		{"other pending prepared", "0VWD7JSS84Y3FHDZ5Y8RJWJJMA", "0VWD7JSS84Y3FHDZ5Y8RJWJJMA", true, false, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newManagedFixture(t)
			lock, err := f.m.lock()
			if err != nil {
				t.Fatal(err)
			}
			lock.Close()
			if test.current != "" {
				transaction := managedTransaction{ManagedResult: ManagedResult{TransactionID: test.current, Pending: test.pending,
					Version: f.pin.Version, RollbackDeadline: time.Now().Add(time.Minute)},
					BinarySHA256: f.pin.Archives.AMD64.BinarySHA256, Architecture: "amd64"}
				if err := f.m.writeTransaction(transaction); err != nil {
					t.Fatal(err)
				}
			}
			before, err := f.m.readTransaction()
			if err != nil {
				t.Fatal(err)
			}
			proof := ManagedRollbackProof{InstallStarted: test.started, InstallCommitted: test.committed, PreviousTransactionID: test.baseline}
			err = f.m.finishModeWithProof(t.Context(), "6RM8HAK91JYKCX4FCY5QDEW0CY", true, false, &proof)
			if (err == nil) != test.accepted {
				t.Fatalf("rollback error=%v, want accepted=%v", err, test.accepted)
			}
			after, err := f.m.readTransaction()
			if err != nil || after != before {
				t.Fatalf("proof changed unrelated state: %+v %v %v", after, f.calls, err)
			}
			var wantCalls []string
			if test.accepted {
				wantCalls = []string{"stop " + rollbackUnit + ".timer " + rollbackUnit + ".service"}
			}
			if !slices.Equal(f.calls, wantCalls) {
				t.Fatalf("proof changed units without a valid no-op: %v", f.calls)
			}
			assertManagedFile(t, f.m.path(managedBinary), f.old)
		})
	}
}

func TestManagedWorkerMatchingJournalAlwaysRollsBack(t *testing.T) {
	for _, confirmed := range []bool{false, true} {
		t.Run(map[bool]string{false: "pending", true: "confirmed"}[confirmed], func(t *testing.T) {
			f := newManagedFixture(t)
			if _, err := f.m.install(t.Context(), f.pin, f.cfg, f.options); err != nil {
				t.Fatal(err)
			}
			if confirmed {
				if err := f.m.finish(t.Context(), f.options.TransactionID, false); err != nil {
					t.Fatal(err)
				}
			}
			// Even a worker crash before recording mutation cannot waive a
			// matching managed journal or its real binary/state restoration.
			if err := f.m.finishModeWithProof(t.Context(), f.options.TransactionID, true, false, &ManagedRollbackProof{}); err != nil {
				t.Fatal(err)
			}
			transaction, err := f.m.readTransaction()
			if err != nil || transaction.Pending || !transaction.RolledBack {
				t.Fatalf("matching journal was not rolled back: %+v %v", transaction, err)
			}
			assertManagedFile(t, f.m.path(managedBinary), f.old)
		})
	}
}

func TestManagedWorkerProofDoesNotBypassLockValidationOrCancellation(t *testing.T) {
	f := newManagedFixture(t)
	proof := &ManagedRollbackProof{}
	lock, err := f.m.lock()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.m.finishModeWithProof(t.Context(), f.options.TransactionID, true, false, proof); err == nil {
		t.Fatal("no-op rollback bypassed another operation's lock")
	}
	lock.Close()
	for _, id := range []string{"", "../transaction"} {
		if err := f.m.finishModeWithProof(t.Context(), id, true, false, proof); err == nil {
			t.Fatal("no-op rollback accepted an invalid identity")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := f.m.finishModeWithProof(ctx, f.options.TransactionID, true, false, proof); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled rollback was acknowledged: %v", err)
	}
	f.options.Prepare = func(ManagedResult) error { return errors.New("private proof could not be saved") }
	if _, err := f.m.install(t.Context(), f.pin, f.cfg, f.options); err == nil || len(f.calls) != 0 {
		t.Fatalf("failed worker proof allowed effects: %v %v", f.calls, err)
	}
	assertManagedFile(t, f.m.path(managedBinary), f.old)
}

func TestManagedWorkerWatchdogCleanupCannotRevokeNoopAcknowledgment(t *testing.T) {
	for _, failure := range []string{"systemd-error", "cleanup-cancellation"} {
		t.Run(failure, func(t *testing.T) {
			f := newManagedFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			called := false
			f.m.systemctl = func(ctx context.Context, args ...string) error {
				called = true
				if !slices.Equal(args, []string{"stop", rollbackUnit + ".timer", rollbackUnit + ".service"}) {
					t.Fatalf("cleanup touched the live NetBird service: %v", args)
				}
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > 5*time.Second {
					t.Fatal("watchdog cleanup lacks a bounded deadline")
				}
				if failure == "cleanup-cancellation" {
					cancel()
					<-ctx.Done()
					return ctx.Err()
				}
				return errors.New("systemd unavailable")
			}
			proof := &ManagedRollbackProof{}
			if err := f.m.finishModeWithProof(ctx, "59WHTJBB9ED5H7ACSPQAHVZXXK", true, false, proof); err != nil || !called {
				t.Fatalf("watchdog cleanup revoked the proven no-op: %v called=%v", err, called)
			}
			transaction, err := f.m.readTransaction()
			if err != nil || transaction.TransactionID != "" {
				t.Fatalf("watchdog cleanup wrote a journal: %+v %v", transaction, err)
			}
			assertManagedFile(t, f.m.path(managedBinary), f.old)
		})
	}
}
