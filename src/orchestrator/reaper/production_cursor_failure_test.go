package reaper

import (
	"context"
	"errors"
	"testing"
	"time"
)

type cursorProductionDatabase struct {
	rows  []Database
	fail  map[string]int
	calls []string
}

func (d *cursorProductionDatabase) List(_ context.Context, cursor string, _ int) (Page, error) {
	start := 0
	for start < len(d.rows) && d.rows[start].ID <= cursor {
		start++
	}
	return Page{Databases: append([]Database(nil), d.rows[start:]...)}, nil
}
func (d *cursorProductionDatabase) call(name, id string) error {
	d.calls = append(d.calls, name+"/"+id)
	if d.fail[name] > 0 {
		d.fail[name]--
		return errors.New("temporary")
	}
	return nil
}
func (d *cursorProductionDatabase) EnsureSnapshot(_ context.Context, id, _ string) error {
	return d.call("snapshot", id)
}
func (d *cursorProductionDatabase) VerifySnapshotPlacement(context.Context, string) error { return nil }
func (d *cursorProductionDatabase) CloseDatabase(_ context.Context, id, _ string) error {
	return d.call("close", id)
}
func (d *cursorProductionDatabase) StopNativeBackup(_ context.Context, id, _ string) error {
	return d.call("backup", id)
}
func (d *cursorProductionDatabase) Reactivate(_ context.Context, id, _ string) error {
	return d.call("reactivate", id)
}
func (d *cursorProductionDatabase) PurgeCDN(_ context.Context, id, _ string) error {
	return d.call("purge", id)
}
func (d *cursorProductionDatabase) DeleteOwnedData(_ context.Context, id, _ string) error {
	return d.call("delete", id)
}

type cursorProductionKey struct {
	fail     int
	observed bool
	calls    int
}

func (k *cursorProductionKey) DestroyDEK(context.Context, string, string) error {
	k.calls++
	if k.fail > 0 {
		k.fail--
		return errors.New("temporary")
	}
	return nil
}
func (k *cursorProductionKey) ObserveDEKDestruction(context.Context, string, string) (bool, error) {
	return k.observed, nil
}

func TestProductionExecutorCursorRetryPreservesLaterPage(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	deadline := base.Add(DefaultPauseAfter)
	rows := []Database{{ID: "db-1", OwnerEmail: "one@example.test", Plan: PlanPaid, BillingGraceDeadline: &deadline, BillingDeletionEligible: true}, {ID: "db-2", OwnerEmail: "two@example.test", Plan: PlanPaid, BillingGraceDeadline: &deadline, BillingDeletionEligible: true}}
	db := &cursorProductionDatabase{rows: rows, fail: map[string]int{"purge": 1}}
	key := &cursorProductionKey{}
	store := &MemoryStore{}
	r, err := NewReconciler(Config{Catalog: db, Executor: productionExecutor{database: db, key: key, check: func(context.Context) error { return nil }}, Mailer: &testMailer{}, Audit: &testAudit{}, Store: store, Clock: ClockFunc(func() time.Time { return deadline }), PageSize: 10})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Run(context.Background()); err == nil {
		t.Fatal("expected first page failure")
	}
	if store.Snapshot().Cursor != "" {
		t.Fatalf("cursor advanced across failure: %q", store.Snapshot().Cursor)
	}
	// The first failed purge is consumed by the first delete attempt; the next
	// scan must finish db-1 and then reach db-2 rather than skip the page.
	if result, err := r.Run(context.Background()); err != nil || result.Deleted != 2 {
		t.Fatalf("retry pages: result=%+v err=%v", result, err)
	}
}
