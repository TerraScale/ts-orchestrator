package client

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/netbird"
)

func TestManagedRollbackCalendarNeverPrecedesFractionalDeadline(t *testing.T) {
	f := newManagedFixture(t)
	for _, nanoseconds := range []int64{0, 1, 999999999} {
		deadline := time.Unix(1800000000, nanoseconds)
		unit := f.m.rollbackFiles(managedTransaction{ManagedResult: ManagedResult{RollbackDeadline: deadline}})[".timer"]
		_, calendar, ok := strings.Cut(unit, "OnCalendar=")
		if !ok {
			t.Fatal("rollback timer has no calendar trigger")
		}
		calendar, _, _ = strings.Cut(calendar, "\n")
		trigger, err := time.Parse("2006-01-02 15:04:05 MST", calendar)
		if err != nil || trigger.Before(deadline) || trigger.Sub(deadline) >= time.Second {
			t.Fatalf("watchdog can fire prematurely or too late: deadline=%s trigger=%s error=%v", deadline, trigger, err)
		}
	}
}

func TestManagedInstallResumesWithinPersistedDeadlineAndReleasesRecoveryLock(t *testing.T) {
	for _, operation := range []string{"timer", "status", "enable", "restart", "enroll"} {
		t.Run(operation, func(t *testing.T) {
			f := newManagedFixture(t)
			if _, err := f.m.install(t.Context(), f.pin, f.cfg, f.options); err != nil {
				t.Fatal(err)
			}
			transaction, err := f.m.readTransaction()
			if err != nil {
				t.Fatal(err)
			}
			// Allow protected-file fsyncs to reach the selected blocking boundary.
			transaction.RollbackDeadline = time.Now().Add(2 * time.Second)
			transaction.RestartRequired = operation == "restart"
			if err := f.m.writeTransaction(transaction); err != nil {
				t.Fatal(err)
			}
			control, status, enroll := f.m.systemctl, f.m.status, f.m.enroll
			blocked, bound := false, false
			block := func(ctx context.Context) error {
				blocked = true
				deadline, ok := ctx.Deadline()
				bound = ok && deadline.Equal(transaction.RollbackDeadline)
				if !bound {
					return errors.New("installer did not preserve the transaction deadline")
				}
				<-ctx.Done()
				return ctx.Err()
			}
			f.m.systemctl = func(ctx context.Context, args ...string) error {
				if operation == "timer" && slices.Equal(args, []string{"restart", rollbackUnit + ".timer"}) ||
					operation == "enable" && slices.Equal(args, []string{"enable", "netbird.service"}) ||
					operation == "restart" && slices.Equal(args, []string{"restart", "netbird.service"}) {
					return block(ctx)
				}
				return control(ctx, args...)
			}
			f.m.status = func(ctx context.Context) (netbird.LocalStatus, error) {
				if operation == "status" {
					return netbird.LocalStatus{}, block(ctx)
				}
				return status(ctx)
			}
			f.m.enroll = func(ctx context.Context, cfg netbird.Config) error {
				if operation == "enroll" {
					return block(ctx)
				}
				return enroll(ctx, cfg)
			}
			if _, err := f.m.install(t.Context(), f.pin, f.cfg, f.options); err == nil || !blocked || !bound {
				t.Fatalf("blocking %s escaped the persisted window: blocked=%t bound=%t error=%v", operation, blocked, bound, err)
			}
			f.m.systemctl, f.m.status, f.m.enroll = control, status, enroll
			current, err := f.m.readTransaction()
			if err != nil || !current.Pending || !current.RollbackDeadline.Equal(transaction.RollbackDeadline) {
				t.Fatalf("canceled retry renewed or completed its journal: %+v %v", current, err)
			}
			if recovered, err := f.m.recover(t.Context()); err != nil || recovered.Pending || !recovered.RolledBack {
				t.Fatalf("deadline did not release the lock for recovery: %+v %v", recovered, err)
			}
			assertManagedFile(t, f.m.path(managedBinary), f.old)
		})
	}
}

func TestManagedNewInstallPropagatesItsDeadlineAndPreservesEarlierCallerDeadline(t *testing.T) {
	t.Run("transaction", func(t *testing.T) {
		f := newManagedFixture(t)
		control, status, enroll := f.m.systemctl, f.m.status, f.m.enroll
		var deadlines []time.Time
		observe := func(ctx context.Context) {
			deadline, ok := ctx.Deadline()
			if !ok {
				t.Fatal("new installer operation had no deadline")
			}
			deadlines = append(deadlines, deadline)
		}
		f.m.systemctl = func(ctx context.Context, args ...string) error { observe(ctx); return control(ctx, args...) }
		f.m.status = func(ctx context.Context) (netbird.LocalStatus, error) { observe(ctx); return status(ctx) }
		f.m.enroll = func(ctx context.Context, cfg netbird.Config) error { observe(ctx); return enroll(ctx, cfg) }
		result, err := f.m.install(t.Context(), f.pin, f.cfg, f.options)
		if err != nil {
			t.Fatal(err)
		}
		for _, deadline := range deadlines {
			if !deadline.Equal(result.RollbackDeadline) {
				t.Fatalf("new installer operation changed its window: got=%s want=%s", deadline, result.RollbackDeadline)
			}
		}
	})
	t.Run("caller", func(t *testing.T) {
		f := newManagedFixture(t)
		ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
		defer cancel()
		f.m.systemctl = func(callCtx context.Context, args ...string) error {
			<-callCtx.Done()
			return callCtx.Err()
		}
		if result, err := f.m.install(ctx, f.pin, f.cfg, f.options); err == nil || result.Pending {
			t.Fatalf("new install ignored caller cancellation or claimed an uncommitted journal: %+v %v", result, err)
		}
		if transaction, err := f.m.readTransaction(); err != nil || transaction.TransactionID != "" {
			t.Fatalf("canceled preparation committed a journal: %+v %v", transaction, err)
		}
		lock, err := f.m.lock()
		if err != nil {
			t.Fatalf("canceled preparation did not release its lock: %v", err)
		}
		lock.Close()
	})
}
