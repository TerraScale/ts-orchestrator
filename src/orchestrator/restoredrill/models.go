// Package restoredrill implements the daily, out-of-band backup restore proof.
//
// The package deliberately contains no cloud or database client.  Those
// concerns are supplied by the five small ports below, which also makes the
// drill safe to run against deterministic local fixtures.
package restoredrill

import (
	"context"
	"errors"
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
// daily schedule (and may return when ctx is cancelled).
type SchedulerPort interface {
	Every(context.Context, time.Duration, func(context.Context, time.Time) error) error
}

// PagerPort receives the one explicit durability page. A failed page delivery
// is returned by Run but does not hide the durable failed outcome.
type PagerPort interface {
	Page(context.Context, Page) error
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
	if c.Now == nil {
		c.Now = time.Now
	}
	return c
}

func (c Config) validate() error {
	if c.ControlPlaneID == "" || c.SampleSize < 0 || c.CleanupTimeout <= 0 || c.DailyInterval <= 0 || c.Now == nil {
		return ErrInvalidConfig
	}
	return nil
}
