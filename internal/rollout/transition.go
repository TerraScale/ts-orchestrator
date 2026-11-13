package rollout

import (
	"fmt"
	"slices"
	"time"
)

// Spec is the caller-supplied rollout definition. KnownBad is the cell's
// durable known-bad list; a target in it can never start.
type Spec struct {
	RolloutID      string
	Kind           Kind
	Cell           string
	FromDigest     string
	ToDigest       string
	Units          []Unit
	Policy         Policy
	KnownBad       []string
	AuthorityEpoch uint64
	StartedAt      time.Time
}

// New plans the waves and returns a pending record. It performs no effect.
func New(spec Spec, now time.Time) (Record, error) {
	if now.IsZero() || spec.StartedAt.After(now) {
		return Record{}, fmt.Errorf("%w: start time", ErrInvalid)
	}
	if slices.Contains(spec.KnownBad, spec.ToDigest) {
		return Record{}, ErrKnownBad
	}
	waves, err := PlanWaves(spec.Units, spec.Policy)
	if err != nil {
		return Record{}, err
	}
	policyDigest, err := spec.Policy.Digest()
	if err != nil {
		return Record{}, err
	}
	units := make(map[string]UnitProgress, len(spec.Units))
	for _, unit := range spec.Units {
		units[unit.ID] = UnitProgress{State: UnitPending, Group: unit.Group, Seed: unit.Seed}
	}
	for wave, ids := range waves {
		for _, id := range ids {
			progress := units[id]
			progress.Wave = wave
			units[id] = progress
		}
	}
	knownBad := slices.Clone(spec.KnownBad)
	slices.Sort(knownBad)
	started := spec.StartedAt
	if started.IsZero() {
		started = now
	}
	record := Record{
		SchemaVersion: SchemaVersion, RolloutID: spec.RolloutID, Kind: spec.Kind, Cell: spec.Cell,
		FromDigest: spec.FromDigest, ToDigest: spec.ToDigest, Policy: spec.Policy, PolicyDigest: policyDigest,
		Phase: PhasePending, Waves: waves, Units: units, KnownBad: slices.Compact(knownBad),
		StartedAt: started.UTC(), PhaseStartedAt: now.UTC(), AuthorityEpoch: spec.AuthorityEpoch,
	}
	if err := record.Validate(); err != nil {
		return Record{}, err
	}
	return record, nil
}

const ()

// rollbackHead returns the next unit to return to FromDigest. Rollback moves
// one unit at a time so the group peer of each step keeps serving.
func (record *Record) rollbackHead() string {
	for _, id := range record.RollbackOrder {
		if record.Units[id].State == UnitRollingBack {
			return id
		}
	}
	return ""
}
