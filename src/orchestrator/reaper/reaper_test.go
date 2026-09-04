package reaper

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time    { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *testClock) Set(now time.Time) { c.mu.Lock(); c.now = now; c.mu.Unlock() }

type testCatalog struct{ databases []Database }

func (c *testCatalog) List(ctx context.Context, cursor string, limit int) (Page, error) {
	if err := ctx.Err(); err != nil {
		return Page{}, err
	}
	if cursor != "" {
		return Page{}, nil
	}
	return Page{Databases: append([]Database(nil), c.databases...), NextCursor: ""}, nil
}

type testExecutor struct {
	mu    sync.Mutex
	calls []string
	fail  map[string]int
}

func (e *testExecutor) call(name, id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls = append(e.calls, name+"/"+id)
	if e.fail[name] > 0 {
		e.fail[name]--
		return errors.New("temporary failure")
	}
	return nil
}
func (e *testExecutor) EnsureSnapshot(_ context.Context, id, _ string) error {
	return e.call("snapshot", id)
}
func (e *testExecutor) CloseDatabase(_ context.Context, id, _ string) error {
	return e.call("close", id)
}
func (e *testExecutor) StopLitestream(_ context.Context, id, _ string) error {
	return e.call("litestream", id)
}
func (e *testExecutor) Reactivate(_ context.Context, id, _ string) error {
	return e.call("reactivate", id)
}
func (e *testExecutor) PurgeCDN(_ context.Context, id, _ string) error   { return e.call("purge", id) }
func (e *testExecutor) DestroyDEK(_ context.Context, id, _ string) error { return e.call("shred", id) }
func (e *testExecutor) DeleteOwnedData(_ context.Context, id, _ string) error {
	return e.call("delete", id)
}

type testMailer struct {
	mu     sync.Mutex
	emails []Email
	fail   int
}

func (m *testMailer) Send(_ context.Context, email Email) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail > 0 {
		m.fail--
		return errors.New("mail unavailable")
	}
	m.emails = append(m.emails, email)
	return nil
}

type testAudit struct {
	mu     sync.Mutex
	events []AuditEvent
}

func (a *testAudit) Record(_ context.Context, event AuditEvent) error {
	a.mu.Lock()
	a.events = append(a.events, event)
	a.mu.Unlock()
	return nil
}

func makeReaper(t *testing.T, clock *testClock, catalog *testCatalog, executor *testExecutor, mailer *testMailer, store *MemoryStore, audit *testAudit) *Reconciler {
	t.Helper()
	reaper, err := NewReconciler(Config{Catalog: catalog, Executor: executor, Mailer: mailer, Audit: audit, Store: store, Clock: clock, PageSize: 10})
	if err != nil {
		t.Fatal(err)
	}
	return reaper
}

func freeDatabase(at time.Time) Database {
	return Database{ID: "db-1", OwnerEmail: "owner@example.test", Plan: PlanFree, LastRequest: at}
}

func TestLifecyclePauseNoticesAndDelete(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := &testClock{now: base.Add(30 * 24 * time.Hour)}
	catalog := &testCatalog{databases: []Database{freeDatabase(base)}}
	executor, mailer, audit, store := &testExecutor{}, &testMailer{}, &testAudit{}, &MemoryStore{}
	reaper := makeReaper(t, clock, catalog, executor, mailer, store, audit)
	if result, err := reaper.Run(context.Background()); err != nil || result.Paused != 1 {
		t.Fatalf("pause: result=%+v err=%v", result, err)
	}
	clock.Set(base.Add(60 * 24 * time.Hour))
	if result, err := reaper.Run(context.Background()); err != nil || result.Notices != 1 {
		t.Fatalf("first reminder: result=%+v err=%v", result, err)
	}
	clock.Set(base.Add(80 * 24 * time.Hour))
	if result, err := reaper.Run(context.Background()); err != nil || result.Notices != 1 {
		t.Fatalf("second reminder: result=%+v err=%v", result, err)
	}
	clock.Set(base.Add(90 * 24 * time.Hour))
	if result, err := reaper.Run(context.Background()); err != nil || result.Deleted != 1 {
		t.Fatalf("delete: result=%+v err=%v", result, err)
	}
	state := store.Snapshot().Entries["db-1"]
	if state.Phase != PhaseDeleted || len(mailer.emails) != 3 {
		t.Fatalf("state=%+v emails=%d", state, len(mailer.emails))
	}
	if got := executor.calls; len(got) != 6 || got[3][:5] != "purge" || got[4][:5] != "shred" || got[5][:6] != "delete" {
		t.Fatalf("calls=%v", got)
	}
	if len(audit.events) < 6 {
		t.Fatalf("expected audit outcomes, got %d", len(audit.events))
	}
}

func TestPaidAndExemptNeverInvokeExecutor(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := &testClock{now: base.Add(100 * 24 * time.Hour)}
	catalog := &testCatalog{databases: []Database{
		{ID: "paid", OwnerEmail: "paid@example.test", Plan: PlanPaid, LastRequest: base},
		{ID: "hold", OwnerEmail: "hold@example.test", Plan: PlanFree, LastRequest: base, Exemption: Exemption{Active: true, Reason: "legal hold"}},
	}}
	executor, mailer, audit, store := &testExecutor{}, &testMailer{}, &testAudit{}, &MemoryStore{}
	reaper := makeReaper(t, clock, catalog, executor, mailer, store, audit)
	if _, err := reaper.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(executor.calls) != 0 || len(mailer.emails) != 0 {
		t.Fatalf("effects on ineligible databases: calls=%v emails=%v", executor.calls, mailer.emails)
	}
}

func TestPartialFailureRetriesSameOperationAndPauseEmail(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := &testClock{now: base.Add(30 * 24 * time.Hour)}
	catalog := &testCatalog{databases: []Database{freeDatabase(base)}}
	executor := &testExecutor{fail: map[string]int{"litestream": 1}}
	mailer := &testMailer{fail: 1}
	audit, store := &testAudit{}, &MemoryStore{}
	reaper := makeReaper(t, clock, catalog, executor, mailer, store, audit)
	if _, err := reaper.Run(context.Background()); err == nil {
		t.Fatal("expected first run failure")
	}
	if _, err := reaper.Run(context.Background()); err == nil {
		t.Fatal("expected mail failure")
	}
	if _, err := reaper.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(executor.calls) != 4 {
		t.Fatalf("expected snapshot, close, failed+retry litestream, got %v", executor.calls)
	}
	state := store.Snapshot().Entries["db-1"]
	if state.Phase != PhasePaused || state.Operations["notice/pause/db-1"].Status != operationDone {
		t.Fatalf("state=%+v", state)
	}
}

func TestReactivationIsIdempotentAndConcurrentSafe(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := &testClock{now: base.Add(30 * 24 * time.Hour)}
	catalog := &testCatalog{databases: []Database{freeDatabase(base)}}
	executor, mailer, audit, store := &testExecutor{}, &testMailer{}, &testAudit{}, &MemoryStore{}
	reaper := makeReaper(t, clock, catalog, executor, mailer, store, audit)
	if _, err := reaper.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	clock.Set(base.Add(31 * 24 * time.Hour))
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = reaper.Reactivate(context.Background(), "db-1") }()
	}
	wg.Wait()
	state := store.Snapshot().Entries["db-1"]
	if state.Phase != PhaseActive {
		t.Fatalf("state=%+v", state)
	}
	count := 0
	for _, call := range executor.calls {
		if call[:10] == "reactivate" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("reactivation calls=%v", executor.calls)
	}
}

func TestFileStoreRoundTrip(t *testing.T) {
	path := t.TempDir() + "/reaper/state.json"
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	when := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	want := State{Version: 7, Cursor: "page-2", Entries: map[string]Entry{"db": {DatabaseID: "db", Phase: PhasePaused, PausedAt: when, Operations: map[string]Operation{"pause/close": {Status: operationDone}}, Audits: map[string]bool{"audit": true}}}}
	if err := store.Save(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != want.Version || got.Cursor != want.Cursor || got.Entries["db"].Operations["pause/close"].Status != operationDone || !got.Entries["db"].PausedAt.Equal(when) {
		t.Fatalf("round trip: got=%+v", got)
	}
}
