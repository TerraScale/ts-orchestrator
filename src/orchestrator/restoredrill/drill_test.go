package restoredrill

import (
	"context"
	"errors"
	"sort"
	"sync"
	"testing"
	"time"
)

type fakeBackup struct {
	mu          sync.Mutex
	list        []Database
	stats       map[string]RestoreStats
	restores    []RestoreRequest
	restoreErr  error
	restoreErrs []error
	onRestore   func(context.Context)
}

func (f *fakeBackup) ListDatabases(context.Context) ([]Database, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Database(nil), f.list...), nil
}
func (f *fakeBackup) Restore(ctx context.Context, request RestoreRequest) error {
	f.mu.Lock()
	f.restores = append(f.restores, request)
	err := f.restoreErr
	if len(f.restoreErrs) > 0 {
		err = f.restoreErrs[0]
		f.restoreErrs = f.restoreErrs[1:]
	}
	hook := f.onRestore
	f.mu.Unlock()
	if hook != nil {
		hook(ctx)
	}
	if err == nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

type fakeBranches struct {
	mu       sync.Mutex
	created  []ScratchBranchRequest
	deleted  []string
	stats    map[string]RestoreStats
	onCreate func(context.Context)
}

func (f *fakeBranches) CreateScratch(ctx context.Context, request ScratchBranchRequest) (ScratchBranch, error) {
	f.mu.Lock()
	f.created = append(f.created, request)
	hook := f.onCreate
	f.mu.Unlock()
	if hook != nil {
		hook(ctx)
	}
	return ScratchBranch{ID: "scratch-" + request.SourceDatabaseID}, nil
}
func (f *fakeBranches) Stats(_ context.Context, branch ScratchBranch) (RestoreStats, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stats[branch.ID], nil
}
func (f *fakeBranches) Delete(_ context.Context, branch ScratchBranch) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleted = append(f.deleted, branch.ID)
	return nil
}

type fakeJournal struct {
	mu     sync.Mutex
	facts  map[string]JournalFacts
	runs   map[string]RunRecord
	items  map[string]ItemRecord
	epochs map[string]uint64
	claims map[string]uint64
	fenced map[string]bool
}

func newFakeJournal() *fakeJournal {
	return &fakeJournal{facts: make(map[string]JournalFacts), runs: make(map[string]RunRecord), items: make(map[string]ItemRecord), epochs: make(map[string]uint64), claims: make(map[string]uint64), fenced: make(map[string]bool)}
}
func (f *fakeJournal) Facts(_ context.Context, id, _ string) (JournalFacts, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.facts[id], nil
}
func (f *fakeJournal) LoadRun(_ context.Context, id string) (RunRecord, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	run, ok := f.runs[id]
	return copyRun(run), ok, nil
}
func (f *fakeJournal) ActiveRuns(_ context.Context) ([]RunRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	runs := make([]RunRecord, 0)
	for _, run := range f.runs {
		if run.Status == RunRunning {
			runs = append(runs, copyRun(run))
		}
	}
	sort.Slice(runs, func(i, j int) bool { return runs[i].ScheduledAt.Before(runs[j].ScheduledAt) })
	return runs, nil
}
func (f *fakeJournal) SaveRun(_ context.Context, run RunRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.runs[run.ID] = copyRun(run)
	return nil
}
func (f *fakeJournal) LoadItem(_ context.Context, id string) (ItemRecord, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	item, ok := f.items[id]
	return item, ok, nil
}
func (f *fakeJournal) SaveItem(_ context.Context, item ItemRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if item.RestoreEpoch > 0 && f.fenced[item.DatabaseID] {
		return ErrRestoreEpochFenced
	}
	f.items[item.Key] = item
	return nil
}
func (f *fakeJournal) ClaimRestoreEpoch(_ context.Context, databaseID, key string) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if epoch := f.claims[key]; epoch != 0 {
		return epoch, nil
	}
	f.epochs[databaseID]++
	f.claims[key] = f.epochs[databaseID]
	return f.claims[key], nil
}
func (f *fakeJournal) RestoreEpochCurrent(_ context.Context, databaseID string, epoch uint64) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return !f.fenced[databaseID] && f.epochs[databaseID] == epoch, nil
}

type fakeScheduler struct {
	interval time.Duration
	callback func(context.Context, time.Time) error
}

func (f *fakeScheduler) Every(_ context.Context, interval time.Duration, callback func(context.Context, time.Time) error) error {
	f.interval, f.callback = interval, callback
	return nil
}

type fakePager struct {
	mu    sync.Mutex
	pages []Page
}

type fakeTelemetry struct {
	mu    sync.Mutex
	facts []RunTelemetry
}

func (f *fakeTelemetry) Record(_ context.Context, facts RunTelemetry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.facts = append(f.facts, facts)
	return nil
}

func (f *fakePager) Page(_ context.Context, page Page) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pages = append(f.pages, page)
	return nil
}

func drillFixture() (*Drill, *fakeBackup, *fakeBranches, *fakeJournal, *fakePager) {
	backup := &fakeBackup{list: []Database{{ID: "control", ControlPlane: true}, {ID: "a"}, {ID: "b"}, {ID: "c"}}, stats: map[string]RestoreStats{
		"scratch-control": {Checksum: "cp", RowCount: 2}, "scratch-a": {Checksum: "a", RowCount: 3}, "scratch-b": {Checksum: "b", RowCount: 4}, "scratch-c": {Checksum: "c", RowCount: 5},
	}}
	journal := newFakeJournal()
	journal.facts["control"] = JournalFacts{JournalCut: "10", Checksum: "cp", RowCount: 2}
	journal.facts["a"] = JournalFacts{JournalCut: "11", Checksum: "a", RowCount: 3}
	journal.facts["b"] = JournalFacts{JournalCut: "12", Checksum: "b", RowCount: 4}
	journal.facts["c"] = JournalFacts{JournalCut: "13", Checksum: "c", RowCount: 5}
	branches := &fakeBranches{stats: backup.stats}
	pager := &fakePager{}
	drill, err := New(backup, branches, journal, &fakeScheduler{}, pager, Config{ControlPlaneID: "control", SampleSize: 2, Seed: 7, Now: func() time.Time { return time.Date(2026, 9, 4, 1, 0, 0, 0, time.UTC) }})
	if err != nil {
		panic(err)
	}
	return drill, backup, branches, journal, pager
}

func TestRunIncludesControlPlaneAndCleansEveryScratchBranch(t *testing.T) {
	drill, backup, branches, _, pager := drillFixture()
	run, err := drill.Run(context.Background())
	if err != nil || run.Status != RunSucceeded {
		t.Fatalf("Run = status %s, err %v", run.Status, err)
	}
	if len(run.DatabaseIDs) != 3 || run.DatabaseIDs[0] != "control" {
		t.Fatalf("database selection = %v", run.DatabaseIDs)
	}
	if len(backup.restores) != 3 || len(branches.deleted) != 3 {
		t.Fatalf("restores=%d deleted=%d", len(backup.restores), len(branches.deleted))
	}
	if len(pager.pages) != 0 {
		t.Fatalf("unexpected pages: %d", len(pager.pages))
	}
	for _, request := range backup.restores {
		if request.IdempotencyKey == "" || request.RestoreEpoch == 0 || request.JournalCut == "" {
			t.Fatalf("incomplete restore request: %+v", request)
		}
	}
}

func TestRunRecordsBoundedAggregateTelemetry(t *testing.T) {
	drill, _, _, _, _ := drillFixture()
	telemetry := &fakeTelemetry{}
	drill.config.Telemetry = telemetry

	run, err := drill.Run(t.Context())
	if err != nil || run.Status != RunSucceeded {
		t.Fatalf("Run = status %s, err %v", run.Status, err)
	}
	if len(telemetry.facts) != 1 {
		t.Fatalf("telemetry records = %d, want 1", len(telemetry.facts))
	}
	facts := telemetry.facts[0]
	if facts != (RunTelemetry{Status: RunSucceeded, DatabaseCount: 3, SucceededItems: 3}) {
		t.Fatalf("telemetry facts = %+v", facts)
	}
}

func TestMismatchPersistsFailureAndPages(t *testing.T) {
	drill, _, branches, _, pager := drillFixture()
	drill.config.SampleSize = 3
	branches.stats["scratch-a"] = RestoreStats{Checksum: "corrupt", RowCount: 3}
	run, err := drill.Run(context.Background())
	if !errors.Is(err, ErrChecksumMismatch) || run.Status != RunFailed {
		t.Fatalf("Run = status %s, err %v", run.Status, err)
	}
	if len(pager.pages) != 1 || len(branches.deleted) != 4 {
		t.Fatalf("pages=%d deleted=%d", len(pager.pages), len(branches.deleted))
	}
}

func TestEpochFencePreventsRestoreAndCleanupSurvivesCancellation(t *testing.T) {
	drill, backup, branches, journal, pager := drillFixture()
	journal.fenced["control"] = true
	run, err := drill.Run(context.Background())
	if !errors.Is(err, ErrRestoreEpochFenced) || run.Status != RunFailed {
		t.Fatalf("fenced Run = status %s, err %v", run.Status, err)
	}
	if len(backup.restores) != 2 || len(branches.deleted) != 2 || len(pager.pages) != 1 {
		t.Fatalf("restores=%d deleted=%d pages=%d", len(backup.restores), len(branches.deleted), len(pager.pages))
	}
}

func TestRestartResumesDurableSelectionAndSuccessfulItems(t *testing.T) {
	drill, backup, branches, journal, _ := drillFixture()
	ctx, cancel := context.WithCancel(context.Background())
	backup.onRestore = func(context.Context) { cancel() }
	first, firstErr := drill.Run(ctx)
	if firstErr == nil || first.Status != RunCanceled {
		t.Fatalf("first Run = status %s, err %v", first.Status, firstErr)
	}
	count := len(backup.restores)
	backup.onRestore = nil
	second, secondErr := drill.Run(context.Background())
	if secondErr != nil || second.Status != RunSucceeded {
		t.Fatalf("second Run = status %s, err %v", second.Status, secondErr)
	}
	if len(backup.restores) != count+3 {
		t.Fatalf("restart did not resume expected items: first=%d total=%d", count, len(backup.restores))
	}
	if len(branches.deleted) != 4 {
		t.Fatalf("cleanup count = %d", len(branches.deleted))
	}
	if len(journal.items) != 3 {
		t.Fatalf("durable item count = %d", len(journal.items))
	}
}

func TestPendingRestoreKeepsRunRunningAndResumesSameBranch(t *testing.T) {
	drill, backup, branches, journal, _ := drillFixture()
	backup.restoreErrs = []error{ErrPending}

	first, err := drill.Run(context.Background())
	if err != nil || first.Status != RunRunning {
		t.Fatalf("pending Run = status %s, err %v", first.Status, err)
	}
	if got, found, _ := journal.LoadRun(context.Background(), first.ID); !found || got.Status != RunRunning {
		t.Fatalf("durable pending run = %+v, found=%v", got, found)
	}
	history, err := drill.SuccessHistory(context.Background(), first.ScheduledAt)
	if err != nil {
		t.Fatal(err)
	}
	if history.SuccessfulDays != 0 || history.Ready {
		t.Fatalf("pending run entered success history: %+v", history)
	}
	if len(branches.deleted) != 2 || len(branches.created) != 3 {
		t.Fatalf("pending branch ownership = created %d, deleted %d", len(branches.created), len(branches.deleted))
	}

	second, err := drill.Run(context.Background())
	if err != nil || second.Status != RunSucceeded {
		t.Fatalf("resumed Run = status %s, err %v", second.Status, err)
	}
	if len(backup.restores) != 4 {
		t.Fatalf("restore calls = %d, want initial items plus one pending retry", len(backup.restores))
	}
	if len(branches.created) != 3 || len(branches.deleted) != 3 {
		t.Fatalf("resumed branch identity = created %d, deleted %d", len(branches.created), len(branches.deleted))
	}
}

func TestDayRolloverReconcilesPendingPriorRunBeforeNewSample(t *testing.T) {
	drill, backup, branches, journal, _ := drillFixture()
	backup.restoreErrs = []error{ErrPending}
	firstDay := time.Date(2026, 9, 4, 1, 0, 0, 0, time.UTC)
	secondDay := firstDay.AddDate(0, 0, 16)

	first, err := drill.RunAt(context.Background(), firstDay)
	if err != nil || first.Status != RunRunning {
		t.Fatalf("first day = status %s, err %v", first.Status, err)
	}
	second, err := drill.RunAt(context.Background(), secondDay)
	if err != nil || second.Status != RunSucceeded {
		t.Fatalf("rollover = status %s, err %v", second.Status, err)
	}
	prior, found, err := journal.LoadRun(context.Background(), first.ID)
	if err != nil || !found || prior.Status != RunSucceeded {
		t.Fatalf("prior run after rollover = %+v, found=%v, err=%v", prior, found, err)
	}
	if len(backup.restores) != 7 {
		t.Fatalf("restore calls = %d, want pending retry plus both daily samples", len(backup.restores))
	}
	if len(branches.created) != 6 || len(branches.deleted) != 6 {
		t.Fatalf("rollover branch ownership = created %d, deleted %d", len(branches.created), len(branches.deleted))
	}
}

func TestConcurrentRunAtIsRaceSafeAndIdempotent(t *testing.T) {
	drill, backup, _, _, _ := drillFixture()
	const callers = 8
	errs := make(chan error, callers)
	for i := 0; i < callers; i++ {
		go func() {
			_, err := drill.RunAt(context.Background(), time.Date(2026, 9, 4, 1, 0, 0, 0, time.UTC))
			errs <- err
		}()
	}
	for i := 0; i < callers; i++ {
		if err := <-errs; err != nil {
			t.Errorf("concurrent RunAt: %v", err)
		}
	}
	if len(backup.restores) != 3 {
		t.Fatalf("duplicate restores = %d", len(backup.restores))
	}
}

func TestStartUsesDailyInterval(t *testing.T) {
	drill, _, _, _, _ := drillFixture()
	scheduler := &fakeScheduler{}
	drill.scheduler = scheduler
	if err := drill.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if scheduler.interval != 24*time.Hour || scheduler.callback == nil {
		t.Fatalf("scheduler interval=%s callback=%v", scheduler.interval, scheduler.callback != nil)
	}
}

type fakeSnapshot struct {
	mu       sync.Mutex
	requests []SnapshotRequest
	regions  []string
	err      error
}

func (f *fakeSnapshot) Snapshot(_ context.Context, request SnapshotRequest) (ControlStateSnapshot, error) {
	f.mu.Lock()
	f.requests = append(f.requests, request)
	f.mu.Unlock()
	if f.err != nil {
		return ControlStateSnapshot{}, f.err
	}
	return ControlStateSnapshot{ID: "snapshot-1", ObjectKey: request.ObjectKey, Checksum: "sha", Size: 12, ControlEpoch: request.ControlEpoch}, nil
}

func (f *fakeSnapshot) Mirror(_ context.Context, snapshot ControlStateSnapshot, region string) error {
	if snapshot.ID == "" {
		return errors.New("empty snapshot")
	}
	f.mu.Lock()
	f.regions = append(f.regions, region)
	f.mu.Unlock()
	return nil
}

func TestSnapshotIsMirroredToEveryRegionWithStableIdentity(t *testing.T) {
	drill, _, _, _, _ := drillFixture()
	snapshot := &fakeSnapshot{}
	drill.config.Snapshotter = snapshot
	drill.config.SnapshotMirror = snapshot
	drill.config.SnapshotRegions = []string{"gru", "sfo", "fra"}
	drill.config.ControlEpoch = func() uint64 { return 9 }
	run, err := drill.Run(context.Background())
	if err != nil || run.Status != RunSucceeded {
		t.Fatalf("Run = status %s, err %v", run.Status, err)
	}
	if len(snapshot.requests) != 1 || snapshot.requests[0].IdempotencyKey != run.ID || snapshot.requests[0].ControlEpoch != 9 {
		t.Fatalf("snapshot requests = %+v", snapshot.requests)
	}
	if got := len(snapshot.regions); got != 3 {
		t.Fatalf("mirrors = %d, want 3", got)
	}
	if run.Snapshot.ID == "" || len(run.SnapshotRegions) != 3 {
		t.Fatalf("run snapshot state = %+v regions=%v", run.Snapshot, run.SnapshotRegions)
	}
}

func TestSnapshotFailurePagesAndRetryUsesSameKey(t *testing.T) {
	drill, _, _, journal, pager := drillFixture()
	snapshot := &fakeSnapshot{err: errors.New("snapshot unavailable")}
	drill.config.Snapshotter = snapshot
	drill.config.SnapshotMirror = snapshot
	drill.config.SnapshotRegions = []string{"gru"}
	drill.config.ControlEpoch = func() uint64 { return 2 }
	first, err := drill.Run(context.Background())
	if err == nil || first.Status != RunFailed || len(pager.pages) != 1 {
		t.Fatalf("first = status %s, err %v, pages=%d", first.Status, err, len(pager.pages))
	}
	snapshot.err = nil
	second, err := drill.Run(context.Background())
	if err != nil || second.Status != RunSucceeded {
		t.Fatalf("second = status %s, err %v", second.Status, err)
	}
	if len(snapshot.requests) != 2 || snapshot.requests[0].IdempotencyKey != snapshot.requests[1].IdempotencyKey {
		t.Fatalf("snapshot retry keys = %+v", snapshot.requests)
	}
	if got, ok, _ := journal.LoadRun(context.Background(), first.ID); !ok || got.Status != RunSucceeded {
		t.Fatalf("durable retry run = %+v, found=%v", got, ok)
	}
}

func TestSuccessHistoryCountsOnlyActualConsecutiveDays(t *testing.T) {
	drill, _, _, journal, _ := drillFixture()
	end := time.Date(2026, 9, 14, 1, 0, 0, 0, time.UTC)
	for offset := 0; offset < 14; offset++ {
		day := end.AddDate(0, 0, -offset)
		if offset == 5 { // a real missing day must break the streak
			continue
		}
		if err := journal.SaveRun(context.Background(), RunRecord{ID: runIDFor(day), ScheduledAt: day, Status: RunSucceeded}); err != nil {
			t.Fatal(err)
		}
	}
	history, err := drill.SuccessHistory(context.Background(), end)
	if err != nil {
		t.Fatal(err)
	}
	if history.Ready || history.SuccessfulDays != 13 || history.ConsecutiveDays != 8 {
		t.Fatalf("history = %+v", history)
	}
	if len(history.Days) != 13 {
		t.Fatalf("history days = %d", len(history.Days))
	}
}
