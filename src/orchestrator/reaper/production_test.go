package reaper

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type productionDatabase struct {
	mu       sync.Mutex
	database Database
	calls    []string
	verify   error
}

func (d *productionDatabase) List(ctx context.Context, cursor string, limit int) (Page, error) {
	if err := ctx.Err(); err != nil {
		return Page{}, err
	}
	if cursor != "" {
		return Page{}, nil
	}
	d.mu.Lock()
	database := d.database
	d.mu.Unlock()
	return Page{Databases: []Database{database}}, nil
}

func (d *productionDatabase) record(call string) {
	d.mu.Lock()
	d.calls = append(d.calls, call)
	d.mu.Unlock()
}

func (d *productionDatabase) EnsureSnapshot(_ context.Context, id, _ string) error {
	d.record("snapshot/" + id)
	return nil
}

func (d *productionDatabase) VerifySnapshotPlacement(_ context.Context, id string) error {
	d.record("placement/" + id)
	return d.verify
}

func (d *productionDatabase) CloseDatabase(_ context.Context, id, _ string) error {
	d.record("close/" + id)
	return nil
}

func (d *productionDatabase) StopNativeBackup(_ context.Context, id, _ string) error {
	d.record("backup/" + id)
	return nil
}

func (d *productionDatabase) Reactivate(_ context.Context, id, _ string) error {
	d.record("reactivate/" + id)
	return nil
}

func (d *productionDatabase) PurgeCDN(_ context.Context, id, _ string) error {
	d.record("purge/" + id)
	return nil
}

func (d *productionDatabase) DeleteOwnedData(_ context.Context, id, _ string) error {
	d.record("delete/" + id)
	return nil
}

type productionKey struct{ calls []string }

func (k *productionKey) DestroyDEK(_ context.Context, id, _ string) error {
	k.calls = append(k.calls, id)
	return nil
}
func (k *productionKey) ObserveDEKDestruction(_ context.Context, _, _ string) (bool, error) {
	return false, nil
}

func productionConfig(database *productionDatabase, key *productionKey, clock Clock, store *NATSStateStoreConfig) ProductionConfig {
	return ProductionConfig{
		Database:             database,
		Key:                  key,
		Admission:            testAdmission{},
		Mail:                 &testMailer{},
		Store:                store,
		Audit:                &testAudit{},
		Clock:                clock,
		PageSize:             10,
		CheckEffectAuthority: func(ctx context.Context) error { return ctx.Err() },
	}
}

func TestNewProductionReconcilerFailsClosedOnMissingAuthority(t *testing.T) {
	database := &productionDatabase{database: freeDatabase(time.Unix(1, 0))}
	key := &productionKey{}
	base := productionConfig(database, key, ClockFunc(func() time.Time { return time.Unix(2, 0) }), &NATSStateStoreConfig{})
	tests := []struct {
		name string
		edit func(*ProductionConfig)
	}{
		{"database", func(c *ProductionConfig) { c.Database = nil }},
		{"key", func(c *ProductionConfig) { c.Key = nil }},
		{"admission", func(c *ProductionConfig) { c.Admission = nil }},
		{"mail", func(c *ProductionConfig) { c.Mail = nil }},
		{"store", func(c *ProductionConfig) { c.Store = nil }},
		{"audit", func(c *ProductionConfig) { c.Audit = nil }},
		{"effect authority", func(c *ProductionConfig) { c.CheckEffectAuthority = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := base
			test.edit(&config)
			if _, err := NewProductionReconciler(config); !errors.Is(err, ErrMissingDependency) {
				t.Fatalf("constructor error = %v; want ErrMissingDependency", err)
			}
		})
	}
}

func TestProductionPauseVerifiesPlacementBeforeBackup(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := &testClock{now: base.Add(DefaultPauseAfter)}
	database := &productionDatabase{database: freeDatabase(base), verify: errors.New("placement lock unavailable")}
	reaper, err := NewProductionReconciler(productionConfig(database, &productionKey{}, clock, newProductionStateConfig(t)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reaper.Run(context.Background()); err == nil {
		t.Fatal("placement failure was accepted")
	}
	database.mu.Lock()
	calls := append([]string(nil), database.calls...)
	database.mu.Unlock()
	if len(calls) != 1 || calls[0] != "placement/db-1" {
		t.Fatalf("calls = %v; expected placement check before backup", calls)
	}
}

func TestProductionPolicyDeletesAtNinetyAfterTwoAdditionalNotices(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := &testClock{now: base.Add(DefaultPauseAfter)}
	database := &productionDatabase{database: freeDatabase(base)}
	key := &productionKey{}
	mail := &testMailer{}
	config := productionConfig(database, key, clock, newProductionStateConfig(t))
	config.Mail = mail
	reaper, err := NewProductionReconciler(config)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := reaper.Run(context.Background()); err != nil || result.Paused != 1 {
		t.Fatalf("pause: result=%+v err=%v", result, err)
	}
	clock.Set(base.Add(DefaultFirstReminder))
	if result, err := reaper.Run(context.Background()); err != nil || result.Notices != 1 {
		t.Fatalf("first reminder: result=%+v err=%v", result, err)
	}
	clock.Set(base.Add(DefaultDeleteAfter))
	if result, err := reaper.Run(context.Background()); err != nil || result.Deleted != 1 {
		t.Fatalf("delete: result=%+v err=%v", result, err)
	}
	if len(mail.emails) != 3 || mail.emails[1].Template != "free-tier-reminder-1" || mail.emails[2].Template != "free-tier-final" {
		t.Fatalf("notice sequence = %+v", mail.emails)
	}
	if len(key.calls) != 1 || key.calls[0] != "db-1" {
		t.Fatalf("key calls = %v", key.calls)
	}
}

func TestProductionHookClockDrivenRequestRaceReactivatesOnce(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := &testClock{now: base.Add(DefaultPauseAfter)}
	database := &productionDatabase{database: freeDatabase(base)}
	key := &productionKey{}
	wiring, err := NewProductionWiring(productionConfig(database, key, clock, newProductionStateConfig(t)))
	if err != nil {
		t.Fatal(err)
	}
	hook := wiring.ParentHook()
	if hook.Run == nil || hook.Reconcile == nil || hook.Reactivate == nil {
		t.Fatal("production parent hook is incomplete")
	}
	if _, err := hook.Run(context.Background()); err != nil {
		t.Fatal(err)
	}

	// A request arriving at the pause boundary is observed by the immediate
	// hook before the next periodic scan. The shared durable operation key
	// makes repeated notifications harmless.
	requestAt := base.Add(DefaultPauseAfter + time.Second)
	clock.Set(requestAt)
	database.mu.Lock()
	database.database.LastRequest = requestAt
	database.mu.Unlock()
	if err := hook.Reconcile(context.Background(), database.database); err != nil {
		t.Fatal(err)
	}
	if err := hook.Reconcile(context.Background(), database.database); err != nil {
		t.Fatal(err)
	}
	if len(key.calls) != 0 {
		t.Fatalf("key destruction occurred after reactivation: %v", key.calls)
	}
	database.mu.Lock()
	defer database.mu.Unlock()
	reactivations := 0
	for _, call := range database.calls {
		if call == "reactivate/db-1" {
			reactivations++
		}
	}
	if reactivations != 1 {
		t.Fatalf("reactivations = %d; calls = %v", reactivations, database.calls)
	}
}

func newProductionStateConfig(t *testing.T) *NATSStateStoreConfig {
	t.Helper()
	cluster := newReaperStateCluster(t)
	connection := cluster.connect(t)
	kv := openReaperTestLeaseStore(t, context.Background(), connection, true)
	lease := reaperTestLease(1, "global-controller-gru-a")
	putReaperTestLease(t, context.Background(), kv, lease)
	return &NATSStateStoreConfig{Connection: connection, CandidateID: lease.CandidateId, AuthorityEpoch: uint64(lease.Epoch), LeaseID: lease.LeaseId}
}

func TestProductionEffectAdmissionCoversAllCallsAndDetachedFailureAudit(t *testing.T) {
	database := &productionDatabase{}
	key := &productionKey{}
	mail := &testMailer{}
	audit := &testAudit{}
	fenced := func(context.Context) error { return ErrStateFenced }
	executor := productionExecutor{database: database, key: key, check: fenced}
	for _, call := range []func(context.Context, string, string) error{executor.EnsureSnapshot, executor.CloseDatabase, executor.StopNativeBackup, executor.Reactivate, executor.PurgeCDN, executor.DestroyDEK, executor.DeleteOwnedData} {
		if err := call(t.Context(), "db-1", "op"); !errors.Is(err, ErrStateFenced) {
			t.Fatalf("fenced method: %v", err)
		}
	}
	if err := (guardedReaperMail{mail, fenced}).Send(t.Context(), Email{}); !errors.Is(err, ErrStateFenced) {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := (guardedReaperAudit{audit, fenced}).Record(context.WithoutCancel(canceled), AuditEvent{}); !errors.Is(err, ErrStateFenced) {
		t.Fatal(err)
	}
	executor.check = func(context.Context) error { return nil }
	if err := executor.EnsureSnapshot(canceled, "db-1", "op"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if len(database.calls) != 0 || len(key.calls) != 0 || len(mail.emails) != 0 || len(audit.events) != 0 {
		t.Fatal("fenced/canceled effect reached adapter")
	}
	checks := 0
	executor.check = func(context.Context) error {
		checks++
		if checks > 1 {
			return ErrStateFenced
		}
		return nil
	}
	if err := executor.EnsureSnapshot(t.Context(), "db-1", "op"); !errors.Is(err, ErrStateFenced) {
		t.Fatal(err)
	}
	if len(database.calls) != 1 || database.calls[0] != "placement/db-1" {
		t.Fatalf("snapshot was not rechecked after placement: %v", database.calls)
	}
}
