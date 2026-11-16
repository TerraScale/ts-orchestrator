// Package rollout owns the staged rollout state machine shared by TerraBase
// seat updates, generic workload delivery and orchestrator self-update. Its
// transition core is pure: callers feed observed events and durably store the
// returned record before acting on the actions it implies.
//
// The package also holds the pure per-seat decisions TerraBase seat updates
// use: release compatibility, known-bad candidates, soak gates and the
// transient/terminal classification that decides whether a driver may retry.
// Callers own transport, signing and durable state.
package rollout

import (
	"errors"
	"time"
)

const (
	SchemaVersion = 1
	// MaxUnits bounds one rollout record so it stays well under the KV value
	// limit while covering every controller and managed host in a cell.
	MaxUnits = 512
	// MaxKnownBad bounds the cell's durable known-bad digest list.
	MaxKnownBad = 256
	maxReason   = 512
)

var (
	ErrInvalid = errors.New("rollout input is invalid")

	ErrTerminal          = errors.New("rollout is in a terminal phase")
	ErrKnownBad          = errors.New("rollout target digest is known bad")
	ErrAttemptsExhausted = errors.New("rollout target digest has no attempts left")
	ErrActiveRollout     = errors.New("another rollout is active in this cell")
	ErrFenced            = errors.New("rollout record belongs to a different authority epoch")
	ErrConflict          = errors.New("rollout record changed concurrently")
)

// Kind names the executor family that applies a rollout's unit steps.
type Kind string

const (
	KindTerraBase  Kind = "terrabase"
	KindWorkload   Kind = "workload"
	KindController Kind = "controller"
	KindHost       Kind = "host"
)

// Phase is the rollout-level state. Complete, Aborted and RolledBack are
// terminal; Frozen admits only an explicit operator resume.
type Phase string

const (
	PhasePending     Phase = "pending"
	PhasePreflight   Phase = "preflight"
	PhaseCanary      Phase = "canary"
	PhaseCanarySoak  Phase = "canary-soak"
	PhaseBatch       Phase = "batch"
	PhaseBatchSoak   Phase = "batch-soak"
	PhaseComplete    Phase = "complete"
	PhaseRollingBack Phase = "rolling-back"
	PhaseFrozen      Phase = "frozen"
	PhaseAborted     Phase = "aborted"
	PhaseRolledBack  Phase = "rolled-back"
)

// UnitState is the per-unit progress recorded in the rollout.
type UnitState string

const (
	UnitPending     UnitState = "pending"
	UnitPreparing   UnitState = "preparing"
	UnitSoaking     UnitState = "soaking"
	UnitPromoted    UnitState = "promoted"
	UnitRollingBack UnitState = "rolling-back"
	UnitRolledBack  UnitState = "rolled-back"
	UnitHeld        UnitState = "held"
)

// Unit is one independently replaceable target. Units sharing a Group are
// replicas of one quorum (the controllers, or the seats of a TerraBase
// partition); a wave never takes more than one unit of a group. Seed marks
// the founding controller, which is always replaced last and alone.
type Unit struct {
	ID    string `json:"id"`
	Group string `json:"group"`
	Seed  bool   `json:"seed,omitzero"`
}

// Health is one observed serving report for a unit. ProcessID and StartNonce
// identify the process incarnation, so a restart during soak is detected.
type Health struct {
	Digest     string    `json:"digest"`
	ProcessID  int64     `json:"process_id"`
	StartNonce string    `json:"start_nonce"`
	ObservedAt time.Time `json:"observed_at"`
}

// UnitProgress is the durable per-unit record.
type UnitProgress struct {
	State          UnitState `json:"state"`
	Group          string    `json:"group"`
	Seed           bool      `json:"seed,omitzero"`
	Wave           int       `json:"wave"`
	HealthyReports int       `json:"healthy_reports,omitzero"`
	FirstHealthyAt time.Time `json:"first_healthy_at,omitzero"`
	// LastHealthyAt is the newest counted healthy observation. The soak
	// completes only when the observations themselves span the window.
	LastHealthyAt time.Time `json:"last_healthy_at,omitzero"`
	ProcessID     int64     `json:"process_id,omitzero"`
	StartNonce    string    `json:"start_nonce,omitempty"`
	Attempts      int       `json:"attempts,omitzero"`
}

// Policy is the rollout policy pinned into the record by digest. Durations
// are whole seconds so the canonical encoding is stable across releases.
type Policy struct {
	CanaryUnits             int   `json:"canary_units"`
	BatchSize               int   `json:"batch_size"`
	CanarySoakSeconds       int64 `json:"canary_soak_seconds"`
	BatchSoakSeconds        int64 `json:"batch_soak_seconds"`
	MinHealthyReports       int   `json:"min_healthy_reports"`
	ProofDeadlineSeconds    int64 `json:"proof_deadline_seconds"`
	RollbackDeadlineSeconds int64 `json:"rollback_deadline_seconds"`
	PreflightSeconds        int64 `json:"preflight_seconds"`
	MaxAttempts             int   `json:"max_attempts"`
	MaxRollbackRetries      int   `json:"max_rollback_retries"`
}

// QualificationBudget and ObservationBudget share the fixed release window.
// Rollback has its own recovery deadline and never consumes this budget.
const (
	QualificationBudget = 10 * time.Minute
	ObservationBudget   = 20 * time.Minute
)

// Record is the durable rollout state. It is written by CAS on its KV
// revision and fenced by AuthorityEpoch.
type Record struct {
	SchemaVersion  int                     `json:"schema_version"`
	RolloutID      string                  `json:"rollout_id"`
	Kind           Kind                    `json:"kind"`
	Cell           string                  `json:"cell"`
	FromDigest     string                  `json:"from_digest"`
	ToDigest       string                  `json:"to_digest"`
	Policy         Policy                  `json:"policy"`
	PolicyDigest   string                  `json:"policy_digest"`
	Phase          Phase                   `json:"phase"`
	WaveIndex      int                     `json:"wave_index"`
	Waves          [][]string              `json:"waves"`
	Units          map[string]UnitProgress `json:"units"`
	RollbackOrder  []string                `json:"rollback_order,omitempty"`
	KnownBad       []string                `json:"known_bad,omitempty"`
	StartedAt      time.Time               `json:"started_at"`
	PhaseStartedAt time.Time               `json:"phase_started_at"`
	PhaseDeadline  time.Time               `json:"phase_deadline,omitzero"`
	AuthorityEpoch uint64                  `json:"authority_epoch"`
	Reason         string                  `json:"reason,omitempty"`
}
