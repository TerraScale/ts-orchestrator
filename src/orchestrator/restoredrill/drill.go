package restoredrill

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"time"
)

// Drill coordinates one daily restore proof. A Drill is safe for concurrent
// calls; calls for the same instance are serialized, while durable state in
// JournalPort makes a new Drill instance resume the same run.
type Drill struct {
	backup    BackupPort
	branches  BranchPort
	journal   JournalPort
	scheduler SchedulerPort
	pager     PagerPort
	config    Config
	runMu     sync.Mutex
}

func New(backup BackupPort, branches BranchPort, journal JournalPort, scheduler SchedulerPort, pager PagerPort, config Config) (*Drill, error) {
	if backup == nil || branches == nil || journal == nil || scheduler == nil || pager == nil {
		return nil, ErrInvalidConfig
	}
	c := config.withDefaults()
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &Drill{backup: backup, branches: branches, journal: journal, scheduler: scheduler, pager: pager, config: c}, nil
}

// Start installs the daily callback. The callback uses its scheduled instant,
// so a retry or controller restart cannot select a different sample for a
// date whose run was already durably started.
func (d *Drill) Start(ctx context.Context) error {
	return d.scheduler.Every(ctx, d.config.DailyInterval, func(runCtx context.Context, scheduledAt time.Time) error {
		_, err := d.RunAt(runCtx, scheduledAt)
		return err
	})
}

// Run executes today's drill according to the injected clock.
func (d *Drill) Run(ctx context.Context) (RunRecord, error) {
	return d.RunAt(ctx, d.config.Now())
}

// RunAt executes the deterministic run identified by the UTC calendar date
// of scheduledAt. Existing durable records are resumed, not recreated.
func (d *Drill) RunAt(ctx context.Context, scheduledAt time.Time) (RunRecord, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	d.runMu.Lock()
	defer d.runMu.Unlock()

	if scheduledAt.IsZero() {
		scheduledAt = d.config.Now()
	}
	runID := runIDFor(scheduledAt)
	run, found, err := d.journal.LoadRun(ctx, runID)
	if err != nil {
		return RunRecord{ID: runID, Status: RunFailed}, err
	}
	if found && run.Status == RunSucceeded {
		return copyRun(run), nil
	}
	if !found {
		ids, selectionErr := d.selectDatabases(ctx, scheduledAt)
		if selectionErr != nil {
			run = RunRecord{ID: runID, ScheduledAt: scheduledAt.UTC(), StartedAt: d.config.Now().UTC(), CompletedAt: d.config.Now().UTC(), Status: RunFailed, Error: selectionErr.Error()}
			durableCtx := durableContext(ctx)
			persistErr := d.journal.SaveRun(durableCtx, copyRun(run))
			pageErr := d.pager.Page(durableCtx, Page{RunID: runID, Reason: selectionErr.Error(), Outcome: copyRun(run)})
			return run, errors.Join(selectionErr, persistErr, pageErr)
		}
		now := d.config.Now().UTC()
		run = RunRecord{ID: runID, ScheduledAt: scheduledAt.UTC(), StartedAt: now, Status: RunRunning, DatabaseIDs: ids}
		if err := d.journal.SaveRun(durableContext(ctx), copyRun(run)); err != nil {
			return run, err
		}
	} else {
		// An interrupted run is resumed with its original sample. Do not erase
		// item records: successful items must remain idempotently skipped.
		run.Status = RunRunning
		run.Error = ""
		if run.StartedAt.IsZero() {
			run.StartedAt = d.config.Now().UTC()
		}
		if err := d.journal.SaveRun(durableContext(ctx), copyRun(run)); err != nil {
			return run, err
		}
	}

	var runErr error
	for _, databaseID := range run.DatabaseIDs {
		item, itemErr := d.runItem(ctx, run, databaseID)
		if itemErr != nil {
			runErr = errors.Join(runErr, itemErr)
		}
		run.Items = upsertItem(run.Items, item)
		if ctx.Err() != nil {
			break
		}
	}
	if runErr == nil || d.config.Snapshotter != nil {
		// A control-state snapshot is a separate durability proof. It is run
		// even when a database item failed, so an item failure cannot suppress
		// the daily JetStream snapshot obligation.
		snapshot, mirrored, snapshotErr := d.snapshotControlState(ctx, run)
		if snapshot.ID != "" {
			run.Snapshot = snapshot
			run.SnapshotRegions = mirrored
		}
		if snapshotErr != nil {
			runErr = errors.Join(runErr, snapshotErr)
		}
	}

	if runErr == nil && ctx.Err() != nil {
		run.Status = RunCanceled
		run.Error = ctx.Err().Error()
		runErr = ctx.Err()
	} else if runErr != nil {
		if errors.Is(runErr, context.Canceled) || errors.Is(runErr, context.DeadlineExceeded) {
			run.Status = RunCanceled
		} else {
			run.Status = RunFailed
		}
		run.Error = runErr.Error()
	} else {
		run.Status = RunSucceeded
		run.Error = ""
	}
	run.CompletedAt = d.config.Now().UTC()
	storeErr := d.journal.SaveRun(durableContext(ctx), copyRun(run))
	if storeErr != nil {
		runErr = errors.Join(runErr, storeErr)
	}
	if run.Status != RunSucceeded {
		pageErr := d.pager.Page(durableContext(ctx), Page{RunID: run.ID, Reason: run.Error, Outcome: copyRun(run)})
		if pageErr != nil {
			runErr = errors.Join(runErr, pageErr)
		}
	}
	return copyRun(run), runErr
}

func (d *Drill) selectDatabases(ctx context.Context, scheduledAt time.Time) ([]string, error) {
	databases, err := d.backup.ListDatabases(ctx)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(databases))
	customers := make([]Database, 0, len(databases))
	controlFound := false
	for _, database := range databases {
		if database.ID == "" {
			return nil, fmt.Errorf("%w: database has empty id", ErrInvalidConfig)
		}
		if _, duplicate := seen[database.ID]; duplicate {
			return nil, fmt.Errorf("%w: duplicate database %q", ErrInvalidConfig, database.ID)
		}
		seen[database.ID] = struct{}{}
		if database.ID == d.config.ControlPlaneID || database.ControlPlane {
			if database.ID == d.config.ControlPlaneID {
				controlFound = true
			}
			continue
		}
		customers = append(customers, database)
	}
	if !controlFound {
		return nil, ErrMissingControlPlane
	}
	sort.Slice(customers, func(i, j int) bool { return customers[i].ID < customers[j].ID })
	seed := d.config.Seed ^ scheduledAt.UTC().Truncate(24*time.Hour).Unix()
	rng := rand.New(rand.NewSource(seed))
	rng.Shuffle(len(customers), func(i, j int) { customers[i], customers[j] = customers[j], customers[i] })
	if d.config.SampleSize < len(customers) {
		customers = customers[:d.config.SampleSize]
	}
	ids := make([]string, 0, len(customers)+1)
	ids = append(ids, d.config.ControlPlaneID)
	for _, database := range customers {
		ids = append(ids, database.ID)
	}
	return ids, nil
}

func (d *Drill) runItem(ctx context.Context, run RunRecord, databaseID string) (ItemRecord, error) {
	key := run.ID + "/" + databaseID
	item, found, err := d.journal.LoadItem(ctx, key)
	if err != nil {
		return ItemRecord{Key: key, RunID: run.ID, DatabaseID: databaseID, Status: ItemFailed, Error: err.Error()}, err
	}
	if found && item.Status == ItemSucceeded {
		return item, nil
	}
	item = ItemRecord{Key: key, RunID: run.ID, DatabaseID: databaseID, Status: ItemRunning, StartedAt: d.config.Now().UTC()}
	itemCtx := ctx
	durableCtx := durableContext(ctx)
	facts, err := d.journal.Facts(itemCtx, databaseID)
	if err != nil {
		return d.finishItem(durableCtx, item, err)
	}
	item.Expected = facts
	if facts.Checksum == "" || facts.RowCount < 0 {
		return d.finishItem(durableCtx, item, fmt.Errorf("%w: invalid journal facts", ErrInvalidConfig))
	}
	epoch, err := d.journal.ClaimRestoreEpoch(durableCtx, databaseID, key)
	if err != nil {
		return d.finishItem(durableCtx, item, err)
	}
	if epoch == 0 {
		return d.finishItem(durableCtx, item, fmt.Errorf("%w: zero epoch", ErrInvalidConfig))
	}
	item.RestoreEpoch = epoch
	if err := d.journal.SaveItem(durableCtx, copyItem(item)); err != nil {
		return item, err
	}
	branch, err := d.branches.CreateScratch(itemCtx, ScratchBranchRequest{
		SourceDatabaseID: databaseID,
		Name:             "restore-drill/" + run.ID + "/" + databaseID,
		IdempotencyKey:   key,
		RestoreEpoch:     epoch,
	})
	if err != nil {
		if branch.ID != "" {
			// Providers may return an indeterminate error after creating a
			// branch. Best-effort cleanup is still mandatory for that case.
			if cleanupErr := d.deleteScratch(branch); cleanupErr != nil {
				err = errors.Join(err, cleanupErr)
				item.CleanupError = cleanupErr.Error()
			}
		}
		return d.finishItem(durableCtx, item, err)
	}
	if branch.ID == "" {
		return d.finishItem(durableCtx, item, fmt.Errorf("%w: branch provider returned empty id", ErrInvalidConfig))
	}
	item.BranchID = branch.ID
	// The cleanup-and-finish closure is used on every path after ownership is
	// established. It uses a context independent of cancellation, ensuring a
	// cancelled drill cannot leak an owned branch.
	cleanupAndFinish := func(operationErr error) (ItemRecord, error) {
		if cleanupErr := d.deleteScratch(branch); cleanupErr != nil {
			item.CleanupError = cleanupErr.Error()
			operationErr = errors.Join(operationErr, cleanupErr)
		}
		return d.finishItem(durableCtx, item, operationErr)
	}
	current, operationErr := d.journal.RestoreEpochCurrent(itemCtx, databaseID, epoch)
	if operationErr != nil {
		return cleanupAndFinish(operationErr)
	}
	if !current {
		return cleanupAndFinish(ErrRestoreEpochFenced)
	}
	operationErr = d.backup.Restore(itemCtx, RestoreRequest{SourceDatabaseID: databaseID, BranchID: branch.ID, JournalCut: facts.JournalCut, RestoreEpoch: epoch, IdempotencyKey: key})
	if operationErr == nil {
		current, operationErr = d.journal.RestoreEpochCurrent(itemCtx, databaseID, epoch)
		if operationErr == nil && !current {
			operationErr = ErrRestoreEpochFenced
		}
	}
	if operationErr == nil {
		item.Observed, operationErr = d.branches.Stats(itemCtx, branch)
	}
	if operationErr == nil {
		var current bool
		current, operationErr = d.journal.RestoreEpochCurrent(itemCtx, databaseID, epoch)
		if operationErr == nil && !current {
			operationErr = ErrRestoreEpochFenced
		}
	}
	if operationErr == nil {
		if item.Observed.Checksum != facts.Checksum {
			operationErr = fmt.Errorf("%w: database %s", ErrChecksumMismatch, databaseID)
		} else if item.Observed.RowCount != facts.RowCount {
			operationErr = fmt.Errorf("%w: database %s", ErrRowCountMismatch, databaseID)
		}
	}
	return cleanupAndFinish(operationErr)
}

func (d *Drill) finishItem(ctx context.Context, item ItemRecord, operationErr error) (ItemRecord, error) {
	if operationErr == nil {
		item.Status = ItemSucceeded
	} else if errors.Is(operationErr, context.Canceled) || errors.Is(operationErr, context.DeadlineExceeded) {
		item.Status = ItemCanceled
	} else {
		item.Status = ItemFailed
	}
	if operationErr != nil {
		item.Error = operationErr.Error()
	}
	item.CompletedAt = d.config.Now().UTC()
	if err := d.journal.SaveItem(ctx, copyItem(item)); err != nil {
		return item, errors.Join(operationErr, err)
	}
	return item, operationErr
}

func (d *Drill) deleteScratch(branch ScratchBranch) error {
	ctx, cancel := context.WithTimeout(context.Background(), d.config.CleanupTimeout)
	defer cancel()
	return d.branches.Delete(ctx, branch)
}

func (d *Drill) snapshotControlState(ctx context.Context, run RunRecord) (ControlStateSnapshot, []string, error) {
	if d.config.Snapshotter == nil {
		return ControlStateSnapshot{}, nil, nil
	}
	epoch := uint64(0)
	if d.config.ControlEpoch != nil {
		epoch = d.config.ControlEpoch()
	} else if d.config.RestoreEpoch != nil {
		epoch = d.config.RestoreEpoch()
	} else {
		epoch = d.config.AcceptedControlEpoch
	}
	if epoch == 0 {
		return ControlStateSnapshot{}, nil, fmt.Errorf("%w: control-state snapshot has zero restore epoch", ErrRestoreEpochFenced)
	}
	prefix := d.config.SnapshotPrefix
	if prefix == "" {
		prefix = "jetstream/control/"
	}
	prefix = strings.TrimSuffix(prefix, "/") + "/"
	key := prefix + run.ID + ".snapshot"
	request := SnapshotRequest{RunID: run.ID, ObjectKey: key, IdempotencyKey: run.ID, ControlEpoch: epoch, RestoreEpoch: epoch}
	snapshot, err := d.config.Snapshotter.Snapshot(ctx, request)
	if err != nil {
		return ControlStateSnapshot{}, nil, err
	}
	if snapshot.ID == "" || snapshot.ObjectKey != key || snapshot.Checksum == "" || snapshot.Size < 0 || (snapshot.ControlEpoch == 0 && snapshot.RestoreEpoch == 0) {
		return snapshot, nil, fmt.Errorf("%w: invalid JetStream snapshot identity", ErrInvalidConfig)
	}
	if snapshot.ControlEpoch != 0 && snapshot.ControlEpoch != epoch {
		return snapshot, nil, ErrRestoreEpochFenced
	}
	if snapshot.RestoreEpoch != 0 && snapshot.RestoreEpoch != epoch {
		return snapshot, nil, ErrRestoreEpochFenced
	}
	var mirrorErr error
	mirrored := make([]string, 0, len(d.config.SnapshotRegions))
	for _, region := range d.config.SnapshotRegions {
		if err := d.config.SnapshotMirror.Mirror(ctx, snapshot, region); err != nil {
			mirrorErr = errors.Join(mirrorErr, fmt.Errorf("snapshot mirror %s: %w", region, err))
			continue
		}
		mirrored = append(mirrored, region)
	}
	return snapshot, mirrored, mirrorErr
}

// SuccessHistory reports the actual successful runs in the 14-day calendar
// window ending at at. It reads each canonical daily run record, so a missing
// record is a missing day and never a synthetic success. The method works
// with every JournalPort implementation; no process-local history is used.
func (d *Drill) SuccessHistory(ctx context.Context, at time.Time) (RestoreHistory, error) {
	if d == nil || d.journal == nil {
		return RestoreHistory{}, ErrInvalidConfig
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if at.IsZero() {
		at = d.config.Now()
	}
	const required = 14
	end := at.UTC().Truncate(24 * time.Hour)
	history := RestoreHistory{RequiredDays: required, Days: make([]time.Time, 0, required)}
	daySet := make(map[int64]struct{}, required)
	for offset := 0; offset < required; offset++ {
		day := end.AddDate(0, 0, -offset)
		run, found, err := d.journal.LoadRun(ctx, runIDFor(day))
		if err != nil {
			return RestoreHistory{}, err
		}
		if !found || run.Status != RunSucceeded {
			continue
		}
		// The ID is canonical, but also check the persisted date so a corrupt
		// journal record cannot count for an unrelated day.
		if !run.ScheduledAt.IsZero() && !sameUTCDate(run.ScheduledAt, day) {
			continue
		}
		date := day.UTC()
		history.Days = append(history.Days, date)
		daySet[date.Unix()] = struct{}{}
	}
	sort.Slice(history.Days, func(i, j int) bool { return history.Days[i].Before(history.Days[j]) })
	history.SuccessfulDays = len(history.Days)
	// Find the longest actual consecutive streak in the observed window. This
	// intentionally does not require the current day to have completed, which
	// lets operators inspect yesterday's 14th proof without inventing today.
	for _, date := range history.Days {
		streak := 1
		for next := date.AddDate(0, 0, 1); ; next = next.AddDate(0, 0, 1) {
			if _, ok := daySet[next.Unix()]; !ok {
				break
			}
			streak++
		}
		if streak > history.ConsecutiveDays {
			history.ConsecutiveDays = streak
		}
	}
	history.Ready = history.ConsecutiveDays >= required
	return history, nil
}

// History is the concise alias used by status/reporting callers.
func (d *Drill) History(ctx context.Context, at time.Time) (RestoreHistory, error) {
	return d.SuccessHistory(ctx, at)
}

func sameUTCDate(a, b time.Time) bool {
	a, b = a.UTC(), b.UTC()
	return a.Year() == b.Year() && a.YearDay() == b.YearDay()
}

func durableContext(ctx context.Context) context.Context {
	return context.WithoutCancel(ctx)
}

func runIDFor(at time.Time) string { return "restore-drill-" + at.UTC().Format("2006-01-02") }

func upsertItem(items []ItemRecord, item ItemRecord) []ItemRecord {
	for i := range items {
		if items[i].Key == item.Key {
			items[i] = copyItem(item)
			return items
		}
	}
	return append(items, copyItem(item))
}

func copyItem(item ItemRecord) ItemRecord { return item }

func copyRun(run RunRecord) RunRecord {
	run.DatabaseIDs = append([]string(nil), run.DatabaseIDs...)
	run.Items = append([]ItemRecord(nil), run.Items...)
	run.SnapshotRegions = append([]string(nil), run.SnapshotRegions...)
	return run
}
