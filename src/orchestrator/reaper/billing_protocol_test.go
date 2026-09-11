package reaper

import (
	"context"
	"testing"
	"time"
)

// validatingReaperStore runs every save through the exact durable protocol
// the production NATSStateStore enforces, so reconciler tests exercise the
// billing lifecycle under the real transition rules instead of the
// permissive in-memory store.
type validatingReaperStore struct {
	MemoryStore
	before *State
}

func (s *validatingReaperStore) Save(ctx context.Context, state State) error {
	if _, err := reaperStateBytes(&state); err != nil {
		return err
	}
	if s.before != nil {
		if err := reaperIntentTransition(s.before, &state); err != nil {
			return err
		}
	}
	if err := s.MemoryStore.Save(ctx, state); err != nil {
		return err
	}
	stored := s.MemoryStore.Snapshot()
	s.before = &stored
	return nil
}

func billingDatabase(deadline time.Time) Database {
	return Database{ID: "billing-db", OwnerEmail: "owner@example.test", Plan: PlanFree, LastRequest: deadline.Add(-90 * 24 * time.Hour), BillingGraceDeadline: &deadline, BillingDeletionEligible: true}
}

// The billing deletion enters deleting without the idle notice ladder; the
// durable protocol must represent that transition and the deletion ladder it
// runs, or the production store rejects every save after the irreversible
// admission committed.
func TestBillingDeletionSatisfiesDurableProtocol(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	due := base.Add(30 * 24 * time.Hour)
	deadline := due.Add(-24 * time.Hour)
	catalog := &testCatalog{databases: []Database{billingDatabase(deadline)}}
	store := &validatingReaperStore{}
	reaper := makeReaper(t, &testClock{now: deadline}, catalog, &testExecutor{observed: true}, &testMailer{}, store, &testAudit{})
	if result, err := reaper.Run(context.Background()); err != nil || result.Paused != 1 {
		t.Fatalf("billing pause: result=%+v err=%v", result, err)
	}
	entry := store.Snapshot().Entries["billing-db"]
	if !entry.BillingGrace || entry.Phase != PhasePaused {
		t.Fatalf("billing pause state: %+v", entry)
	}
	executor := &testExecutor{observed: true}
	reaper = makeReaper(t, &testClock{now: due}, catalog, executor, &testMailer{}, store, &testAudit{})
	if result, err := reaper.Run(context.Background()); err != nil || result.Deleted != 1 {
		t.Fatalf("billing deletion under durable protocol: result=%+v err=%v", result, err)
	}
	if state := store.Snapshot().Entries["billing-db"]; state.Phase != PhaseDeleted {
		t.Fatalf("billing deletion did not complete: %+v", state)
	}
}

// Cancelling a billing deletion — before any irreversible work, both from the
// pause state and after the deletion entered — must satisfy the durable
// protocol and return the database to active.
func TestBillingCancellationSatisfiesDurableProtocol(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	pausedAt := base.Add(24 * time.Hour)
	restored := base.Add(48 * time.Hour)
	for _, stage := range []string{"paused", "deleting"} {
		t.Run(stage, func(t *testing.T) {
			deadline := base // grace covered again before it comes due
			catalog := &testCatalog{databases: []Database{billingDatabase(deadline)}}
			store := &validatingReaperStore{}
			reaper := makeReaper(t, &testClock{now: base}, catalog, &testExecutor{}, &testMailer{}, store, &testAudit{})
			if _, err := reaper.Run(context.Background()); err != nil {
				t.Fatalf("billing pause: %v", err)
			}
			if stage == "deleting" {
				// Enter deletion once under a due deadline, with the shred
				// failing before any irreversible operation is recorded.
				executor := &testExecutor{fail: map[string]int{"shred": 1}}
				reaper = makeReaper(t, &testClock{now: base.Add(2 * time.Hour)}, catalog, executor, &testMailer{}, store, &testAudit{})
				if _, err := reaper.Run(context.Background()); err != nil {
					t.Fatalf("billing deletion entry: %v", err)
				}
				if entry := store.Snapshot().Entries["billing-db"]; entry.Phase != PhaseDeleting {
					t.Fatalf("deleting stage fixture: %+v", entry)
				}
			}
			covered := billingDatabase(restored.Add(72 * time.Hour))
			covered.BillingGraceDeadline = nil
			catalog.databases = []Database{covered}
			reaper = makeReaper(t, &testClock{now: restored}, catalog, &testExecutor{}, &testMailer{}, store, &testAudit{})
			if result, err := reaper.Run(context.Background()); err != nil || result.Reactivated != 1 {
				t.Fatalf("billing cancellation under durable protocol: result=%+v err=%v", result, err)
			}
			if entry := store.Snapshot().Entries["billing-db"]; entry.Phase != PhaseActive || entry.BillingGrace {
				t.Fatalf("cancellation did not reactivate: %+v", entry)
			}
		})
	}
}
