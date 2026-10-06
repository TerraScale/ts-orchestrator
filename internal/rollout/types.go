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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
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
	ErrInvalid           = errors.New("rollout input is invalid")
	ErrInvalidTransition = errors.New("rollout event is not valid in the current phase")
	ErrTerminal          = errors.New("rollout is in a terminal phase")
	ErrKnownBad          = errors.New("rollout target digest is known bad")
	ErrAttemptsExhausted = errors.New("rollout target digest has no attempts left")
	ErrActiveRollout     = errors.New("another rollout is active in this cell")
	ErrFenced            = errors.New("rollout record belongs to a different authority epoch")
	ErrConflict          = errors.New("rollout record changed concurrently")

	tokenRE  = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,127}$`)
	digestRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Kind names the executor family that applies a rollout's unit steps.
type Kind string

const (
	KindTerraBase  Kind = "terrabase"
	KindWorkload   Kind = "workload"
	KindController Kind = "controller"
	KindHost       Kind = "host"
)

func (kind Kind) valid() bool {
	return kind == KindTerraBase || kind == KindWorkload || kind == KindController || kind == KindHost
}

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

// Terminal reports whether no further transition can change the record.
func (phase Phase) Terminal() bool {
	return phase == PhaseComplete || phase == PhaseAborted || phase == PhaseRolledBack
}

// Active reports whether the phase holds the cell's single rollout slot.
func (phase Phase) Active() bool { return !phase.Terminal() }

func (phase Phase) preparing() bool { return phase == PhaseCanary || phase == PhaseBatch }
func (phase Phase) soaking() bool   { return phase == PhaseCanarySoak || phase == PhaseBatchSoak }

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

// touched reports whether the unit may run the target digest and therefore
// needs an explicit rollback.
func (state UnitState) touched() bool {
	return state == UnitPreparing || state == UnitSoaking || state == UnitPromoted ||
		state == UnitRollingBack || state == UnitHeld
}

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

// DefaultPolicy is as fast as a binary-only update allows (user decision
// 2026-10-06): one canary soaks five minutes, then every later wave takes as
// many units as PlanWaves lets it (never two of one group, the seed last and
// alone, so three controllers still move one at a time) and soaks two
// minutes. A unit that restarts on another release, or does not prove the
// target within ten minutes, rolls the rollout back.
func DefaultPolicy() Policy {
	return Policy{
		CanaryUnits: 1, BatchSize: MaxUnits,
		CanarySoakSeconds: int64((5 * time.Minute).Seconds()), BatchSoakSeconds: int64((2 * time.Minute).Seconds()),
		MinHealthyReports: 3, ProofDeadlineSeconds: int64((10 * time.Minute).Seconds()),
		RollbackDeadlineSeconds: int64((10 * time.Minute).Seconds()), PreflightSeconds: int64((10 * time.Minute).Seconds()),
		MaxAttempts: 1, MaxRollbackRetries: 3,
	}
}

// Validate rejects policies that could skip the canary, soak or deadlines.
func (policy Policy) Validate() error {
	if policy.CanaryUnits < 1 || policy.CanaryUnits > MaxUnits || policy.BatchSize < 1 || policy.BatchSize > MaxUnits ||
		policy.CanarySoakSeconds < 0 || policy.BatchSoakSeconds < 0 || policy.MinHealthyReports < 1 ||
		policy.ProofDeadlineSeconds < 1 || policy.RollbackDeadlineSeconds < 1 || policy.PreflightSeconds < 1 ||
		policy.MaxAttempts < 1 || policy.MaxRollbackRetries < 0 {
		return fmt.Errorf("%w: policy bounds", ErrInvalid)
	}
	return nil
}

// Digest is SHA-256 of the canonical policy encoding.
func (policy Policy) Digest() (string, error) {
	encoded, err := protocol.EncodeJSON(policy)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func seconds(value int64) time.Duration { return time.Duration(value) * time.Second }

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

// Validate checks the record's structural invariants. It is applied on every
// decode and before every store write.
func (record Record) Validate() error {
	if record.SchemaVersion != SchemaVersion || !tokenRE.MatchString(record.RolloutID) || !record.Kind.valid() ||
		!tokenRE.MatchString(record.Cell) || !digestRE.MatchString(record.FromDigest) || !digestRE.MatchString(record.ToDigest) ||
		record.FromDigest == record.ToDigest || record.AuthorityEpoch == 0 || record.StartedAt.IsZero() ||
		record.PhaseStartedAt.IsZero() || len(record.Reason) > maxReason || len(record.KnownBad) > MaxKnownBad {
		return fmt.Errorf("%w: record identity", ErrInvalid)
	}
	if err := record.Policy.Validate(); err != nil {
		return err
	}
	if digest, err := record.Policy.Digest(); err != nil || digest != record.PolicyDigest {
		return fmt.Errorf("%w: policy digest", ErrInvalid)
	}
	switch record.Phase {
	case PhasePending, PhasePreflight, PhaseCanary, PhaseCanarySoak, PhaseBatch, PhaseBatchSoak,
		PhaseComplete, PhaseRollingBack, PhaseFrozen, PhaseAborted, PhaseRolledBack:
	default:
		return fmt.Errorf("%w: phase", ErrInvalid)
	}
	if len(record.Waves) == 0 || len(record.Units) == 0 || len(record.Units) > MaxUnits ||
		record.WaveIndex < 0 || record.WaveIndex >= len(record.Waves) {
		return fmt.Errorf("%w: waves", ErrInvalid)
	}
	seen := make(map[string]struct{}, len(record.Units))
	for wave, ids := range record.Waves {
		if len(ids) == 0 {
			return fmt.Errorf("%w: empty wave", ErrInvalid)
		}
		for _, id := range ids {
			progress, exists := record.Units[id]
			if _, duplicate := seen[id]; duplicate || !exists || progress.Wave != wave || !tokenRE.MatchString(progress.Group) {
				return fmt.Errorf("%w: wave unit %q", ErrInvalid, id)
			}
			seen[id] = struct{}{}
		}
	}
	if len(seen) != len(record.Units) {
		return fmt.Errorf("%w: unit outside every wave", ErrInvalid)
	}
	for _, id := range record.RollbackOrder {
		if _, exists := record.Units[id]; !exists {
			return fmt.Errorf("%w: rollback unit %q", ErrInvalid, id)
		}
	}
	for _, digest := range record.KnownBad {
		if !digestRE.MatchString(digest) {
			return fmt.Errorf("%w: known-bad digest", ErrInvalid)
		}
	}
	if slices.Contains(record.KnownBad, record.FromDigest) {
		return fmt.Errorf("%w: rollback target is known bad", ErrInvalid)
	}
	return record.validatePhaseUnits()
}

// validatePhaseUnits rejects phase and unit-state contradictions that Apply
// never produces, so a record built outside Apply is refused at the storage
// boundary instead of driving effects.
func (record Record) validatePhaseUnits() error {
	for _, id := range record.Waves[record.WaveIndex] {
		state := record.Units[id].State
		if record.Phase.soaking() && state != UnitSoaking ||
			record.Phase.preparing() && state != UnitPreparing && state != UnitSoaking {
			return fmt.Errorf("%w: phase %s contradicts unit %q in state %s", ErrInvalid, record.Phase, id, state)
		}
	}
	if record.Phase == PhaseRollingBack && record.rollbackHead() == "" {
		return fmt.Errorf("%w: rolling back without a unit to roll back", ErrInvalid)
	}
	return nil
}

// Clone returns a deep copy so transitions never alias a caller's record.
func (record Record) Clone() Record {
	clone := record
	clone.Waves = make([][]string, len(record.Waves))
	for index, wave := range record.Waves {
		clone.Waves[index] = slices.Clone(wave)
	}
	clone.Units = make(map[string]UnitProgress, len(record.Units))
	for id, progress := range record.Units {
		clone.Units[id] = progress
	}
	clone.RollbackOrder = slices.Clone(record.RollbackOrder)
	clone.KnownBad = slices.Clone(record.KnownBad)
	return clone
}

// InFlight returns the units moving forward to ToDigest that have not yet
// been promoted. Invariant (d) bounds them by the wave size and keeps them in
// pairwise distinct groups.
func (record Record) InFlight() []string {
	var units []string
	for id, progress := range record.Units {
		if progress.State == UnitPreparing || progress.State == UnitSoaking {
			units = append(units, id)
		}
	}
	slices.Sort(units)
	return units
}

// OperationID derives the idempotent executor operation identity for one
// unit step, so a retried transition never creates a second operation.
func OperationID(rolloutID, unit string, phase Phase, attempt int) string {
	sum := sha256.Sum256(fmt.Appendf(nil, "rollout\x00%s\x00%s\x00%s\x00%d", rolloutID, unit, phase, attempt))
	return "ro-" + hex.EncodeToString(sum[:16])
}
