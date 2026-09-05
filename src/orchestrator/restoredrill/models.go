// Package restoredrill implements the daily, out-of-band backup restore proof.
//
// The package deliberately contains no cloud or database client.  Those
// concerns are supplied by the five small ports below, which also makes the
// drill safe to run against deterministic local fixtures.
package restoredrill

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"time"
)

var (
	ErrInvalidConfig       = errors.New("restore drill: invalid config")
	ErrMissingControlPlane = errors.New("restore drill: control-plane database is not available")
	ErrRestoreEpochFenced  = errors.New("restore drill: restore epoch was fenced")
	ErrChecksumMismatch    = errors.New("restore drill: checksum mismatch")
	ErrRowCountMismatch    = errors.New("restore drill: row count mismatch")
)

// Database is a database eligible for a restore drill. ControlPlane marks the
// control-plane database; ControlPlaneID in Config is authoritative when both
// are supplied.
type Database struct {
	ID           string
	Region       string
	ControlPlane bool
}

// JournalFacts are the immutable facts at a journal cut. A restore is proved
// against these facts rather than against a live, changing source database.
type JournalFacts struct {
	JournalCut string
	Checksum   string
	RowCount   int64
}

// RestoreStats are facts observed from a restored scratch branch.
type RestoreStats struct {
	Checksum string
	RowCount int64
}

type RestoreRequest struct {
	SourceDatabaseID string
	BranchID         string
	JournalCut       string
	RestoreEpoch     uint64
	IdempotencyKey   string
}

type ScratchBranchRequest struct {
	SourceDatabaseID string
	Name             string
	IdempotencyKey   string
	RestoreEpoch     uint64
}

type ScratchBranch struct {
	ID string
}

// BackupPort lists source databases and restores a Litestream backup into an
// already-created isolated branch. Restore must honor IdempotencyKey.
type BackupPort interface {
	ListDatabases(context.Context) ([]Database, error)
	Restore(context.Context, RestoreRequest) error
}

// BranchPort owns scratch branches. CreateScratch must be idempotent for an
// identical idempotency key. Delete is expected to be safe if the branch is
// already absent.
type BranchPort interface {
	CreateScratch(context.Context, ScratchBranchRequest) (ScratchBranch, error)
	Stats(context.Context, ScratchBranch) (RestoreStats, error)
	Delete(context.Context, ScratchBranch) error
}

// JournalPort is the durable control-plane store for drill state and facts.
// ClaimRestoreEpoch is an idempotent claim for (database, item key): after a
// process restart it returns the existing epoch. Implementations must reject
// writes for an item whose epoch is no longer current.
type JournalPort interface {
	Facts(context.Context, string) (JournalFacts, error)
	LoadRun(context.Context, string) (RunRecord, bool, error)
	SaveRun(context.Context, RunRecord) error
	LoadItem(context.Context, string) (ItemRecord, bool, error)
	SaveItem(context.Context, ItemRecord) error
	ClaimRestoreEpoch(context.Context, string, string) (uint64, error)
	RestoreEpochCurrent(context.Context, string, uint64) (bool, error)
}

// SchedulerPort is the only timing dependency. Every must invoke f at the
// daily schedule and return callback failures or context cancellation.
type SchedulerPort interface {
	Every(context.Context, time.Duration, func(context.Context, time.Time) error) error
}

// PagerPort receives the one explicit durability page. A failed page delivery
// is returned by Run but does not hide the durable failed outcome.
type PagerPort interface {
	Page(context.Context, Page) error
}

// JetStreamSnapshotter creates one immutable snapshot of the orchestrator's
// control state.  The snapshotter is deliberately a port: the drill package
// must not know how a JetStream stream is encoded or how Object Storage is
// reached. Implementations must treat IdempotencyKey as the identity of the
// daily snapshot and must never silently replace a snapshot at another
// control epoch.
type JetStreamSnapshotter interface {
	Snapshot(context.Context, SnapshotRequest) (ControlStateSnapshot, error)
}

// JetStreamSnapshotMirror copies a verified control-state snapshot to one
// Region's Object Storage bucket. Mirror must be idempotent for the same
// snapshot and Region. The Region is passed separately so implementations can
// bind it to the declared per-Region bucket rather than accepting an arbitrary
// destination from the caller.
type JetStreamSnapshotMirror interface {
	Mirror(context.Context, ControlStateSnapshot, string) error
}

// SnapshotterFunc and SnapshotMirrorFunc make the ports convenient to wire in
// tests and in small provider adapters without introducing another type.
type SnapshotterFunc func(context.Context, SnapshotRequest) (ControlStateSnapshot, error)

func (f SnapshotterFunc) Snapshot(ctx context.Context, request SnapshotRequest) (ControlStateSnapshot, error) {
	return f(ctx, request)
}

type SnapshotMirrorFunc func(context.Context, ControlStateSnapshot, string) error

func (f SnapshotMirrorFunc) Mirror(ctx context.Context, snapshot ControlStateSnapshot, region string) error {
	return f(ctx, snapshot, region)
}

// SnapshotRequest identifies the one daily control-state snapshot. ObjectKey
// is deterministic and ControlEpoch is a fence: a stale snapshot may be
// retained for evidence but must not become the active control state.
type SnapshotRequest struct {
	RunID          string
	ObjectKey      string
	IdempotencyKey string
	// ControlEpoch is the accepted JetStream control epoch.
	ControlEpoch uint64
}

// ControlStateSnapshot is the verified identity of a JetStream snapshot.
// Payload is intentionally absent; snapshot bytes remain in the provider's
// Object Storage and never cross the restore-drill state journal.
type ControlStateSnapshot struct {
	ID           string
	ObjectKey    string
	Checksum     string
	Size         int64
	ControlEpoch uint64
	CreatedAt    time.Time
}

type Page struct {
	RunID   string
	Reason  string
	Outcome RunRecord
}

type RunStatus string

const (
	RunRunning   RunStatus = "running"
	RunSucceeded RunStatus = "succeeded"
	RunFailed    RunStatus = "failed"
	RunCanceled  RunStatus = "canceled"
)

type ItemStatus string

const (
	ItemRunning   ItemStatus = "running"
	ItemSucceeded ItemStatus = "succeeded"
	ItemFailed    ItemStatus = "failed"
	ItemCanceled  ItemStatus = "canceled"
)

type ItemRecord struct {
	Key          string
	RunID        string
	DatabaseID   string
	BranchID     string
	RestoreEpoch uint64
	Expected     JournalFacts
	Observed     RestoreStats
	Status       ItemStatus
	Error        string
	CleanupError string
	StartedAt    time.Time
	CompletedAt  time.Time
}

type RunRecord struct {
	ID          string
	ScheduledAt time.Time
	StartedAt   time.Time
	CompletedAt time.Time
	Status      RunStatus
	DatabaseIDs []string
	Items       []ItemRecord
	Error       string
	Snapshot    ControlStateSnapshot
	// SnapshotRegions records the Regions that acknowledged this run's
	// snapshot. A partial list makes an incomplete mirror visible after restart.
	SnapshotRegions []string
}

// RestoreHistory is calculated solely from durable RunRecords. Missing days
// are left missing; in particular, callers cannot manufacture a passing
// 14-day soak by advancing a clock or by filling in synthetic records.
type RestoreHistory struct {
	RequiredDays    int
	SuccessfulDays  int
	ConsecutiveDays int
	Ready           bool
	Days            []time.Time
}

// Config controls one daily drill. SampleSize is the number of customer
// databases sampled; the control-plane database is always added. The seed is
// mixed with the UTC schedule date, producing stable selection on restart.
type Config struct {
	ControlPlaneID string
	SampleSize     int
	Seed           int64
	CleanupTimeout time.Duration
	DailyInterval  time.Duration
	Now            func() time.Time
	// Snapshotter and SnapshotMirror are optional together. When configured,
	// every run snapshots once and mirrors the resulting object to every Region
	// in SnapshotRegions before the run can be marked successful.
	Snapshotter     JetStreamSnapshotter
	SnapshotMirror  JetStreamSnapshotMirror
	SnapshotRegions []string
	SnapshotPrefix  string
	// AcceptedControlEpoch is a static alternative for controllers whose
	// accepted epoch is already captured at composition time. A callback is
	// preferred when fencing can advance while a run is in progress.
	AcceptedControlEpoch uint64
	ControlEpoch         func() uint64
}

func (c Config) withDefaults() Config {
	if c.SampleSize == 0 {
		c.SampleSize = 1
	}
	if c.CleanupTimeout == 0 {
		c.CleanupTimeout = 30 * time.Second
	}
	if c.DailyInterval == 0 {
		c.DailyInterval = 24 * time.Hour
	}
	if isNil(c.Now) {
		c.Now = time.Now
	}
	return c
}

func (c Config) validate() error {
	if c.ControlPlaneID == "" || c.SampleSize < 0 || c.CleanupTimeout <= 0 || c.DailyInterval <= 0 || isNil(c.Now) {
		return ErrInvalidConfig
	}
	if isNil(c.Snapshotter) != isNil(c.SnapshotMirror) {
		return ErrInvalidConfig
	}
	if !isNil(c.Snapshotter) {
		if len(c.SnapshotRegions) == 0 || (isNil(c.ControlEpoch) && c.AcceptedControlEpoch == 0) {
			return ErrInvalidConfig
		}
		seen := make(map[string]struct{}, len(c.SnapshotRegions))
		for _, region := range c.SnapshotRegions {
			if strings.TrimSpace(region) != region || region == "" || len(region) > 64 {
				return ErrInvalidConfig
			}
			if _, ok := seen[region]; ok {
				return ErrInvalidConfig
			}
			seen[region] = struct{}{}
		}
	}
	return nil
}

func isNil(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}
