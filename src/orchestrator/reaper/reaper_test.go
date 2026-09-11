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
	mu               sync.Mutex
	calls            []string
	purgeKeys        []string
	fail             map[string]int
	observed         bool
	cancelAfterPurge context.CancelFunc
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
func (e *testExecutor) StopNativeBackup(_ context.Context, id, _ string) error {
	return e.call("backup", id)
}
func (e *testExecutor) Reactivate(_ context.Context, id, _ string) error {
	return e.call("reactivate", id)
}
func (e *testExecutor) PurgeCDN(_ context.Context, id, key string) error {
	e.mu.Lock()
	e.purgeKeys = append(e.purgeKeys, key)
	cancel := e.cancelAfterPurge
	e.mu.Unlock()
	err := e.call("purge", id)
	if err == nil && cancel != nil {
		cancel()
	}
	return err
}
func (e *testExecutor) DestroyDEK(_ context.Context, id, _ string) error { return e.call("shred", id) }
func (e *testExecutor) ObserveDEKDestruction(_ context.Context, _, _ string) (bool, error) {
	return e.observed, nil
}
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

type testAdmission struct{}

func (testAdmission) AdmitDeletion(context.Context, Database, string) error { return nil }

func (testAdmission) CancelDeletion(context.Context, Database) error { return nil }

func (a *testAudit) Record(_ context.Context, event AuditEvent) error {
	a.mu.Lock()
	a.events = append(a.events, event)
	a.mu.Unlock()
	return nil
}

func makeReaper(t *testing.T, clock *testClock, catalog *testCatalog, executor *testExecutor, mailer *testMailer, store StateStore, audit *testAudit) *Reconciler {
	t.Helper()
	reaper, err := NewReconciler(Config{Catalog: catalog, Executor: executor, Admission: testAdmission{}, Mailer: mailer, Audit: audit, Store: store, Clock: clock, PageSize: 10})
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
	clock.Set(base.Add(90 * 24 * time.Hour))
	if result, err := reaper.Run(context.Background()); err != nil || result.Deleted != 1 {
		t.Fatalf("delete: result=%+v err=%v", result, err)
	}
	state := store.Snapshot().Entries["db-1"]
	if state.Phase != PhaseDeleted || len(mailer.emails) != 3 || mailer.emails[2].Template != "free-tier-final" {
		t.Fatalf("state=%+v emails=%d", state, len(mailer.emails))
	}
	if got := executor.calls; len(got) != 6 || got[3][:5] != "purge" || got[4][:5] != "shred" || got[5][:6] != "delete" {
		t.Fatalf("calls=%v", got)
	}
	if len(audit.events) < 6 {
		t.Fatalf("expected audit outcomes, got %d", len(audit.events))
	}
}

func TestCryptoShredPrecedesOwnedDataDeletion(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := &testClock{now: base.Add(DefaultPauseAfter)}
	catalog := &testCatalog{databases: []Database{freeDatabase(base)}}
	executor, mailer, audit, store := &testExecutor{}, &testMailer{}, &testAudit{}, &MemoryStore{}
	reaper := makeReaper(t, clock, catalog, executor, mailer, store, audit)

	if _, err := reaper.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	clock.Set(base.Add(DefaultFirstReminder))
	if _, err := reaper.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	clock.Set(base.Add(DefaultDeleteAfter))
	if _, err := reaper.Run(context.Background()); err != nil {
		t.Fatal(err)
	}

	var shredAt, deleteAt int
	for index, call := range executor.calls {
		switch call {
		case "shred/db-1":
			shredAt = index
		case "delete/db-1":
			deleteAt = index
		}
	}
	if shredAt == 0 || deleteAt == 0 || shredAt >= deleteAt {
		t.Fatalf("crypto-shred must precede owned data deletion: calls=%v", executor.calls)
	}
}

func TestOwnedDataFailureAfterCryptoShredRetriesData(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := &testClock{now: base.Add(DefaultPauseAfter)}
	catalog := &testCatalog{databases: []Database{freeDatabase(base)}}
	executor := &testExecutor{fail: map[string]int{"delete": 1}}
	store := &MemoryStore{}
	reaper := makeReaper(t, clock, catalog, executor, &testMailer{}, store, &testAudit{})
	if _, err := reaper.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	clock.Set(base.Add(DefaultFirstReminder))
	if _, err := reaper.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	clock.Set(base.Add(DefaultDeleteAfter))
	if _, err := reaper.Run(context.Background()); err == nil {
		t.Fatal("expected owned data deletion failure")
	}
	if len(executor.calls) < 5 || executor.calls[len(executor.calls)-2][:5] != "shred" || executor.calls[len(executor.calls)-1][:6] != "delete" {
		t.Fatalf("crypto-shred did not precede owned data failure: %v", executor.calls)
	}
	result, err := reaper.Run(context.Background())
	if err != nil || result.Deleted != 1 {
		t.Fatalf("retry did not complete deletion: result=%+v err=%v", result, err)
	}
	if len(executor.calls) < 7 || executor.calls[len(executor.calls)-2][:6] != "delete" || executor.calls[len(executor.calls)-1][:6] != "delete" {
		t.Fatalf("retry order=%v", executor.calls)
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

func TestDueBillingGraceDeletesPaidDatabaseDespiteIdleExemption(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	deadline := base.Add(30 * 24 * time.Hour)
	clock := &testClock{now: deadline}
	catalog := &testCatalog{databases: []Database{{
		ID: "billing-db", OwnerEmail: "owner@example.test", Plan: PlanPaid,
		Exemption:            Exemption{Active: true, Reason: "deletion protection"},
		BillingGraceDeadline: &deadline, BillingDeletionEligible: true,
	}}}
	executor, mailer, audit, store := &testExecutor{}, &testMailer{}, &testAudit{}, &MemoryStore{}
	reaper := makeReaper(t, clock, catalog, executor, mailer, store, audit)
	if result, err := reaper.Run(context.Background()); err != nil || result.Paused != 1 {
		t.Fatalf("billing pause: result=%+v err=%v", result, err)
	}
	if result, err := reaper.Run(context.Background()); err != nil || result.Deleted != 1 {
		t.Fatalf("billing delete: result=%+v err=%v", result, err)
	}
	if len(executor.calls) != 6 || store.Snapshot().Entries["billing-db"].Phase != PhaseDeleted {
		t.Fatalf("billing effects/state: calls=%v state=%+v", executor.calls, store.Snapshot().Entries["billing-db"])
	}
}

func TestDueBillingGraceFromPausedStateResumesAfterDeletionFailure(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	deadline := base.Add(30 * 24 * time.Hour)
	clock := &testClock{now: deadline}
	database := Database{ID: "billing-db", OwnerEmail: "owner@example.test", Plan: PlanPaid, BillingGraceDeadline: &deadline, BillingDeletionEligible: true}
	executor, mailer, audit, store := &testExecutor{fail: map[string]int{"purge": 1}}, &testMailer{}, &testAudit{}, &MemoryStore{}
	if err := store.Save(t.Context(), State{Version: 1, Entries: map[string]Entry{
		"billing-db": {
			DatabaseID: "billing-db", Plan: PlanPaid, Phase: PhasePaused,
			Operations: map[string]Operation{}, Audits: map[string]bool{},
		},
	}}); err != nil {
		t.Fatal(err)
	}
	reaper := makeReaper(t, clock, &testCatalog{databases: []Database{database}}, executor, mailer, store, audit)
	if _, err := reaper.Run(context.Background()); err == nil {
		t.Fatal("expected deletion failure")
	}
	state := store.Snapshot().Entries["billing-db"]
	if state.Phase != PhaseDeleting || !state.BillingGrace {
		t.Fatalf("failed billing deletion lost fence: %+v", state)
	}
	if result, err := reaper.Run(context.Background()); err != nil || result.Deleted != 1 {
		t.Fatalf("billing deletion retry: result=%+v err=%v", result, err)
	}
}

func TestRestoredBillingCoverageReactivatesBeforeIdleReaper(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	deadline := base.Add(30 * 24 * time.Hour)
	clock := &testClock{now: deadline}
	database := Database{ID: "billing-db", OwnerEmail: "owner@example.test", Plan: PlanFree, BillingGraceDeadline: &deadline, BillingDeletionEligible: true}
	catalog := &testCatalog{databases: []Database{database}}
	executor, mailer, audit, store := &testExecutor{}, &testMailer{}, &testAudit{}, &MemoryStore{}
	reaper := makeReaper(t, clock, catalog, executor, mailer, store, audit)
	if _, err := reaper.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	database.BillingGraceDeadline, database.BillingDeletionEligible = nil, false
	catalog.databases[0] = database
	if result, err := reaper.Run(context.Background()); err != nil || result.Reactivated != 1 {
		t.Fatalf("restored coverage: result=%+v err=%v", result, err)
	}
	if store.Snapshot().Entries["billing-db"].Phase != PhaseActive {
		t.Fatalf("restored billing state=%+v", store.Snapshot().Entries["billing-db"])
	}
}

func TestResolvedExpiredReasonDoesNotRemainPausedForFutureGrace(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	deadline := base.Add(30 * 24 * time.Hour)
	future := base.Add(60 * 24 * time.Hour)
	clock := &testClock{now: deadline}
	database := Database{ID: "billing-db", OwnerEmail: "owner@example.test", Plan: PlanFree, BillingGraceDeadline: &deadline, BillingDeletionEligible: true}
	catalog := &testCatalog{databases: []Database{database}}
	executor, mailer, audit, store := &testExecutor{}, &testMailer{}, &testAudit{}, &MemoryStore{}
	reaper := makeReaper(t, clock, catalog, executor, mailer, store, audit)
	if _, err := reaper.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	database.BillingGraceDeadline, database.BillingDeletionEligible = &future, false
	catalog.databases[0] = database
	if result, err := reaper.Run(context.Background()); err != nil || result.Reactivated != 1 {
		t.Fatalf("future grace: result=%+v err=%v", result, err)
	}
}

func TestBillingDeletionResumesAfterEachIrreversibleStepFailure(t *testing.T) {
	for _, failedStep := range []string{"purge", "shred", "delete"} {
		t.Run(failedStep, func(t *testing.T) {
			base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			deadline := base.Add(30 * 24 * time.Hour)
			clock := &testClock{now: deadline}
			catalog := &testCatalog{databases: []Database{{ID: "billing-db", OwnerEmail: "owner@example.test", Plan: PlanPaid, BillingGraceDeadline: &deadline, BillingDeletionEligible: true}}}
			executor, mailer, audit, store := &testExecutor{fail: map[string]int{failedStep: 1}, observed: failedStep != "purge"}, &testMailer{}, &testAudit{}, &MemoryStore{}
			reaper := makeReaper(t, clock, catalog, executor, mailer, store, audit)
			if _, err := reaper.Run(context.Background()); err != nil {
				t.Fatal(err)
			}
			if _, err := reaper.Run(context.Background()); err == nil {
				t.Fatal("expected deletion step failure")
			}
			if state := store.Snapshot().Entries["billing-db"]; state.Phase != PhaseDeleting {
				t.Fatalf("failed deletion lost its fence: %+v", state)
			}
			if result, err := reaper.Run(context.Background()); err != nil || result.Deleted != 1 {
				t.Fatalf("resume: result=%+v err=%v", result, err)
			}
			if state := store.Snapshot().Entries["billing-db"]; state.Phase != PhaseDeleted {
				t.Fatalf("resume state=%+v", state)
			}
		})
	}
}

func TestRestoredCoverageCancelsBeforeCryptoShred(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	deadline := base.Add(30 * 24 * time.Hour)
	clock := &testClock{now: deadline}
	database := Database{ID: "billing-db", OwnerEmail: "owner@example.test", Plan: PlanFree, BillingGraceDeadline: &deadline, BillingDeletionEligible: true}
	executor := &testExecutor{fail: map[string]int{"purge": 1}}
	catalog := &testCatalog{databases: []Database{database}}
	audit, store := &testAudit{}, &MemoryStore{}
	reaper := makeReaper(t, clock, catalog, executor, &testMailer{}, store, audit)
	if _, err := reaper.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := reaper.Run(context.Background()); err == nil {
		t.Fatal("expected purge failure")
	}
	database.BillingGraceDeadline, database.BillingDeletionEligible = nil, false
	catalog.databases[0] = database
	if result, err := reaper.Run(context.Background()); err != nil || result.Reactivated != 1 {
		t.Fatalf("cancel: result=%+v err=%v", result, err)
	}
	for _, call := range executor.calls {
		if len(call) >= 5 && call[:5] == "shred" {
			t.Fatalf("crypto shred after restored coverage: %v", executor.calls)
		}
	}
}

func TestRestoredCoverageCannotUndoCryptoShredFence(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	deadline := base.Add(30 * 24 * time.Hour)
	clock := &testClock{now: deadline}
	database := Database{ID: "billing-db", OwnerEmail: "owner@example.test", Plan: PlanFree, BillingGraceDeadline: &deadline, BillingDeletionEligible: true}
	executor := &testExecutor{fail: map[string]int{"shred": 1}, observed: true}
	catalog := &testCatalog{databases: []Database{database}}
	audit, store := &testAudit{}, &MemoryStore{}
	reaper := makeReaper(t, clock, catalog, executor, &testMailer{}, store, audit)
	if _, err := reaper.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := reaper.Run(context.Background()); err == nil {
		t.Fatal("expected crypto shred failure")
	}
	database.BillingGraceDeadline, database.BillingDeletionEligible = nil, false
	catalog.databases[0] = database
	if result, err := reaper.Run(context.Background()); err != nil || result.Deleted != 1 {
		t.Fatalf("fenced resume: result=%+v err=%v", result, err)
	}
	if store.Snapshot().Entries["billing-db"].Phase != PhaseDeleted {
		t.Fatalf("state=%+v", store.Snapshot().Entries["billing-db"])
	}
}

func TestNoEffectObservationRetriesWhileBillingStillDue(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	deadline := base.Add(30 * 24 * time.Hour)
	clock := &testClock{now: deadline}
	catalog := &testCatalog{databases: []Database{{ID: "billing-db", OwnerEmail: "owner@example.test", Plan: PlanFree, BillingGraceDeadline: &deadline, BillingDeletionEligible: true}}}
	executor := &testExecutor{fail: map[string]int{"shred": 1}}
	audit, store := &testAudit{}, &MemoryStore{}
	reaper := makeReaper(t, clock, catalog, executor, &testMailer{}, store, audit)
	if _, err := reaper.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := reaper.Run(context.Background()); err == nil {
		t.Fatal("expected crypto shred failure")
	}
	if result, err := reaper.Run(context.Background()); err != nil || result.Deleted != 1 {
		t.Fatalf("retry due deletion: result=%+v err=%v", result, err)
	}
}

func TestDoneCryptoShredRequiresObservationAcrossRestart(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	deadline := base.Add(30 * 24 * time.Hour)
	clock := &testClock{now: deadline}
	catalog := &testCatalog{databases: []Database{{ID: "billing-db", OwnerEmail: "owner@example.test", Plan: PlanFree, BillingGraceDeadline: &deadline, BillingDeletionEligible: true}}}
	executor := &testExecutor{}
	store := &MemoryStore{}
	now := deadline
	if err := store.Save(context.Background(), State{Version: 1, Entries: map[string]Entry{
		"billing-db": {
			DatabaseID: "billing-db", Plan: PlanFree, Phase: PhaseDeleting, BillingGrace: true,
			SecondNoticeAt: now, Operations: map[string]Operation{
				"delete/cdn-purge":    {Status: operationDone, CompletedAt: now},
				"delete/crypto-shred": {Status: operationDone, CompletedAt: now},
			}, Audits: map[string]bool{},
		},
	}}); err != nil {
		t.Fatal(err)
	}
	first := makeReaper(t, clock, catalog, executor, &testMailer{}, store, &testAudit{})
	if _, err := first.Run(context.Background()); !errors.Is(err, ErrKeyDestructionUnconfirmed) {
		t.Fatalf("unobserved completion error = %v", err)
	}
	if state := store.Snapshot().Entries["billing-db"]; state.Phase != PhaseDeleting {
		t.Fatalf("unobserved completion changed phase: %+v", state)
	}
	for _, call := range executor.calls {
		if call == "delete/billing-db" {
			t.Fatalf("deleted data before DEK observation: %v", executor.calls)
		}
	}

	executor.observed = true
	second := makeReaper(t, clock, catalog, executor, &testMailer{}, store, &testAudit{})
	result, err := second.Run(context.Background())
	if err != nil || result.Deleted != 1 {
		t.Fatalf("observed completion after restart: result=%+v err=%v", result, err)
	}
	if state := store.Snapshot().Entries["billing-db"]; state.Phase != PhaseDeleted {
		t.Fatalf("observed completion did not finish deletion: %+v", state)
	}
}

func TestDeletionPurgeUsesCycleKeyAndCommitsAfterCancellation(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	deadline := now
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	executor := &testExecutor{cancelAfterPurge: cancel}
	store := &MemoryStore{}
	if err := store.Save(t.Context(), State{Version: 1, Entries: map[string]Entry{
		"db-1": {
			DatabaseID: "db-1", Plan: PlanFree, Phase: PhaseDeleting, Cycle: 1,
			PausedAt: now, FirstNoticeAt: now, SecondNoticeAt: now, BillingGrace: true,
			Operations: map[string]Operation{
				"pause/snapshot/cycle-1":      {Status: operationDone, Attempts: 1, StartedAt: now, CompletedAt: now},
				"pause/close/cycle-1":         {Status: operationDone, Attempts: 1, StartedAt: now, CompletedAt: now},
				"pause/native-backup/cycle-1": {Status: operationDone, Attempts: 1, StartedAt: now, CompletedAt: now},
			},
		},
	}}); err != nil {
		t.Fatal(err)
	}
	clock := &testClock{now: now}
	catalog := &testCatalog{databases: []Database{{ID: "db-1", OwnerEmail: "owner@example.test", Plan: PlanFree, LastRequest: now, BillingGraceDeadline: &deadline, BillingDeletionEligible: true}}}
	reaper := makeReaper(t, clock, catalog, executor, &testMailer{}, store, &testAudit{})
	if _, err := reaper.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled purge run error = %v, want context cancellation", err)
	}
	state := store.Snapshot().Entries["db-1"]
	purge := state.Operations["delete/cdn-purge/cycle-1"]
	if purge.Status != operationDone {
		t.Fatalf("successful canceled purge status = %q, want done: %+v", purge.Status, state.Operations)
	}
	if len(executor.purgeKeys) != 1 || executor.purgeKeys[0] != "delete/cdn-purge/cycle-1/db-1" {
		t.Fatalf("purge operation keys = %v, want cycle-scoped key", executor.purgeKeys)
	}
}

func TestPartialFailureRetriesSameOperationAndPauseEmail(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := &testClock{now: base.Add(30 * 24 * time.Hour)}
	catalog := &testCatalog{databases: []Database{freeDatabase(base)}}
	executor := &testExecutor{fail: map[string]int{"backup": 1}}
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
		t.Fatalf("expected snapshot, close, failed+retry backup, got %v", executor.calls)
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

func TestReactivationStartsFreshPauseOperationCycle(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := &testClock{now: base.Add(30 * 24 * time.Hour)}
	catalog := &testCatalog{databases: []Database{freeDatabase(base)}}
	executor, mailer, audit, store := &testExecutor{}, &testMailer{}, &testAudit{}, &MemoryStore{}
	reaper := makeReaper(t, clock, catalog, executor, mailer, store, audit)
	if _, err := reaper.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	clock.Set(base.Add(31 * 24 * time.Hour))
	if err := reaper.Reactivate(context.Background(), "db-1"); err != nil {
		t.Fatal(err)
	}
	clock.Set(base.Add(61 * 24 * time.Hour))
	if _, err := reaper.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	state := store.Snapshot().Entries["db-1"]
	if state.Phase != PhasePaused || state.Cycle != 1 {
		t.Fatalf("state=%+v", state)
	}
	if len(executor.calls) != 7 {
		t.Fatalf("expected two complete pause cycles and one reactivation, calls=%v", executor.calls)
	}
}

func TestRequestAfterDeletionFenceSkipsEntryWithoutWedgingTheScan(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := &testClock{now: base}
	fenced := Database{ID: "a-fenced", OwnerEmail: "owner@example.test", Plan: PlanFree, LastRequest: base}
	active := freeDatabase(base.Add(-100 * 24 * time.Hour))
	active.ID = "b-active"
	catalog := &testCatalog{databases: []Database{fenced, active}}
	store := &MemoryStore{}
	if err := store.Save(context.Background(), State{Version: 1, Entries: map[string]Entry{
		"a-fenced": {
			DatabaseID: "a-fenced", Plan: PlanFree, Phase: PhaseDeleting,
			LastRequest: base.Add(-24 * time.Hour), PausedAt: base.Add(-48 * time.Hour),
			Operations: map[string]Operation{}, Audits: map[string]bool{},
		},
	}}); err != nil {
		t.Fatal(err)
	}
	reaper := makeReaper(t, clock, catalog, &testExecutor{}, &testMailer{}, store, &testAudit{})
	result, err := reaper.Run(context.Background())
	if err != nil {
		t.Fatalf("a fenced database must not abort the scan: %v", err)
	}
	if result.Processed != 2 || result.Paused != 1 {
		t.Fatalf("the scan must advance past the fenced entry: %+v", result)
	}
	state := store.Snapshot().Entries["a-fenced"]
	if state.Phase != PhaseDeleting {
		t.Fatalf("the fenced entry must stay contained in deleting: %+v", state)
	}
}
