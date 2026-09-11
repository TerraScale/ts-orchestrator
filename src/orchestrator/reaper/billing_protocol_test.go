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
	*MemoryStore
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
	store := &validatingReaperStore{MemoryStore: &MemoryStore{}}
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
	// The next scan compacts the terminal entry after its audit is durable:
	// the store's entry ceiling must not wedge the reaper at the cap.
	covered := billingDatabase(due)
	covered.BillingGraceDeadline = nil
	catalog.databases = []Database{covered}
	reaper = makeReaper(t, &testClock{now: due.Add(time.Hour)}, catalog, &testExecutor{observed: true}, &testMailer{}, store, &testAudit{})
	if _, err := reaper.Run(context.Background()); err != nil {
		t.Fatalf("terminal compaction: %v", err)
	}
	if _, present := store.Snapshot().Entries["billing-db"]; present {
		t.Fatal("terminal entry was not compacted after its completion audit")
	}
}

// Cancelling a billing deletion — before any irreversible work, both from the
// pause state and after the deletion entered — must satisfy the durable
// protocol and return the database to active.
func TestBillingCancellationSatisfiesDurableProtocol(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	restored := base.Add(48 * time.Hour)
	for _, stage := range []string{"paused", "deleting"} {
		t.Run(stage, func(t *testing.T) {
			deadline := base // grace covered again before it comes due
			catalog := &testCatalog{databases: []Database{billingDatabase(deadline)}}
			memory := &MemoryStore{}
			store := &validatingReaperStore{MemoryStore: memory}
			reaper := makeReaper(t, &testClock{now: base}, catalog, &testExecutor{}, &testMailer{}, store, &testAudit{})
			if _, err := reaper.Run(context.Background()); err != nil {
				t.Fatalf("billing pause: %v", err)
			}
			if stage == "deleting" {
				// Enter deletion once under a due deadline, failing at the
				// edge purge: no shred or data operation may exist, so the
				// cancellation stays valid. (A failed shred request would
				// already be past the irreversible edge and must hold.)
				executor := &testExecutor{fail: map[string]int{"purge": 1}}
				reaper = makeReaper(t, &testClock{now: base.Add(2 * time.Hour)}, catalog, executor, &testMailer{}, store, &testAudit{})
				// The failing shred surfaces as an error; the durable entry
				// must still have landed in deleting.
				_, _ = reaper.Run(context.Background())
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

// Two billing episodes with no customer request in between freeze LastRequest:
// the second reactivation must still run the executor call instead of
// skipping on the stale done key of the first episode.
func TestRepeatedBillingEpisodesReactivateTheProviderEveryTime(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	withDeadline := billingDatabase(base)
	covered := withDeadline
	covered.BillingGraceDeadline = nil
	executor := &testExecutor{observed: true}
	catalog := &testCatalog{databases: []Database{withDeadline}}
	store := &validatingReaperStore{MemoryStore: &MemoryStore{}}
	run := func(now time.Time) Result {
		t.Helper()
		reaper := makeReaper(t, &testClock{now: now}, catalog, executor, &testMailer{}, store, &testAudit{})
		result, err := reaper.Run(context.Background())
		if err != nil {
			t.Fatalf("run at %s: %v", now, err)
		}
		return result
	}
	if result := run(base); result.Paused != 1 {
		t.Fatalf("episode one pause: %+v", result)
	}
	catalog.databases = []Database{covered}
	if result := run(base.Add(time.Hour)); result.Reactivated != 1 {
		t.Fatalf("episode one reactivation: %+v", result)
	}
	catalog.databases = []Database{withDeadline}
	if result := run(base.Add(2 * time.Hour)); result.Paused != 1 {
		t.Fatalf("episode two pause: %+v", result)
	}
	catalog.databases = []Database{covered}
	if result := run(base.Add(3 * time.Hour)); result.Reactivated != 1 {
		t.Fatalf("second episode reactivation: %+v", result)
	}
	reactivates := 0
	for _, call := range executor.calls {
		if call == "reactivate/billing-db" {
			reactivates++
		}
	}
	if reactivates != 2 {
		t.Fatalf("executor reactivations = %d, want one per episode", reactivates)
	}
}
