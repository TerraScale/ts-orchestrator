package rollout

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go/jetstream"
)

// Bucket is the replicated JetStream KV bucket holding rollout records and
// the per-cell rollout slot.
const Bucket = "TS_ROLLOUTS"

const (
	cellKey          = "cell"
	maxRecordBytes   = 512 << 10
	cellCASAttempts  = 8
	maxAttemptDigest = 4096
)

// CellState is the cell-level rollout slot. ActiveRolloutID enforces
// invariant (a): at most one non-terminal rollout per cell. KnownBad and
// Attempts survive every rollout, so a rejected digest never restarts.
type CellState struct {
	SchemaVersion   int            `json:"schema_version"`
	Cell            string         `json:"cell"`
	ActiveRolloutID string         `json:"active_rollout_id,omitempty"`
	KnownBad        []string       `json:"known_bad,omitempty"`
	Attempts        map[string]int `json:"attempts,omitempty"`
}

func (state CellState) validate(cell string) error {
	if state.SchemaVersion != SchemaVersion || state.Cell != cell ||
		state.ActiveRolloutID != "" && !tokenRE.MatchString(state.ActiveRolloutID) ||
		len(state.KnownBad) > MaxKnownBad || len(state.Attempts) > maxAttemptDigest {
		return fmt.Errorf("%w: cell rollout state", ErrInvalid)
	}
	for _, digest := range state.KnownBad {
		if !digestRE.MatchString(digest) {
			return fmt.Errorf("%w: known-bad digest", ErrInvalid)
		}
	}
	return nil
}

// Store persists rollout records with CAS on the KV revision. Every write is
// preceded by an authority Guard for the record's epoch (invariant b).
type Store struct {
	kv     jetstream.KeyValue
	fencer authority.Fencer
	cell   string
}

// OpenStore provisions or binds the rollout bucket for one cell.
func OpenStore(ctx context.Context, js jetstream.JetStream, cell string, replicas int, fencer authority.Fencer) (*Store, error) {
	if js == nil || fencer == nil || !tokenRE.MatchString(cell) || replicas != 1 && replicas != 3 && replicas != 5 {
		return nil, fmt.Errorf("%w: rollout store configuration", ErrInvalid)
	}
	kv, err := js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{
		Bucket: Bucket, Storage: jetstream.FileStorage, Replicas: replicas, History: 8, MaxValueSize: maxRecordBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("rollout store: %w", err)
	}
	return &Store{kv: kv, fencer: fencer, cell: cell}, nil
}

func rolloutKey(id string) string { return "rollout." + id }

// Cell returns the cell slot and its revision (zero when absent).
func (s *Store) Cell(ctx context.Context) (CellState, uint64, error) {
	entry, err := s.kv.Get(ctx, cellKey)
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return CellState{SchemaVersion: SchemaVersion, Cell: s.cell}, 0, nil
	}
	if err != nil {
		return CellState{}, 0, err
	}
	var state CellState
	if err := protocol.DecodeStrict(entry.Value(), &state, maxRecordBytes); err != nil {
		return CellState{}, 0, err
	}
	if err := state.validate(s.cell); err != nil {
		return CellState{}, 0, err
	}
	return state, entry.Revision(), nil
}

// Load returns a rollout record and its KV revision.
func (s *Store) Load(ctx context.Context, rolloutID string) (Record, uint64, error) {
	if !tokenRE.MatchString(rolloutID) {
		return Record{}, 0, fmt.Errorf("%w: rollout ID", ErrInvalid)
	}
	entry, err := s.kv.Get(ctx, rolloutKey(rolloutID))
	if err != nil {
		return Record{}, 0, err
	}
	var record Record
	if err := protocol.DecodeStrict(entry.Value(), &record, maxRecordBytes); err != nil {
		return Record{}, 0, err
	}
	if err := record.Validate(); err != nil {
		return Record{}, 0, err
	}
	if record.Cell != s.cell || record.RolloutID != rolloutID {
		return Record{}, 0, fmt.Errorf("%w: stored rollout scope", ErrInvalid)
	}
	return record, entry.Revision(), nil
}

// Begin claims the cell slot for spec and creates its pending record. It is
// idempotent for the same rollout ID and refuses a known-bad digest, a
// digest without attempts left, or a second active rollout.
func (s *Store) Begin(ctx context.Context, spec Spec, now time.Time) (Record, uint64, error) {
	if spec.Cell != s.cell {
		return Record{}, 0, fmt.Errorf("%w: rollout cell", ErrInvalid)
	}
	if err := s.fencer.Guard(ctx, spec.AuthorityEpoch); err != nil {
		return Record{}, 0, err
	}
	for range cellCASAttempts {
		state, revision, err := s.Cell(ctx)
		if err != nil {
			return Record{}, 0, err
		}
		if state.ActiveRolloutID == spec.RolloutID {
			return s.createRecord(ctx, spec, state, now)
		}
		if state.ActiveRolloutID != "" {
			// A terminal commit whose cell release was interrupted is
			// repaired here; a live rollout keeps the slot.
			active, _, err := s.Load(ctx, state.ActiveRolloutID)
			if err != nil || !active.Phase.Terminal() {
				return Record{}, 0, ErrActiveRollout
			}
			if err := s.syncCell(ctx, withEpoch(active, spec.AuthorityEpoch)); err != nil {
				return Record{}, 0, err
			}
			continue
		}
		if slices.Contains(state.KnownBad, spec.ToDigest) {
			return Record{}, 0, ErrKnownBad
		}
		maxAttempts := spec.Policy.MaxAttempts
		if state.Attempts[spec.ToDigest] >= maxAttempts {
			return Record{}, 0, ErrAttemptsExhausted
		}
		if _, err := New(withKnownBad(spec, state.KnownBad), now); err != nil {
			return Record{}, 0, err
		}
		next := state
		next.ActiveRolloutID = spec.RolloutID
		next.Attempts = make(map[string]int, len(state.Attempts)+1)
		for digest, count := range state.Attempts {
			next.Attempts[digest] = count
		}
		next.Attempts[spec.ToDigest]++
		if err := s.writeCell(ctx, spec.AuthorityEpoch, next, revision); errors.Is(err, ErrConflict) {
			continue
		} else if err != nil {
			return Record{}, 0, err
		}
		return s.createRecord(ctx, spec, next, now)
	}
	return Record{}, 0, ErrConflict
}

func withKnownBad(spec Spec, knownBad []string) Spec {
	spec.KnownBad = append(slices.Clone(spec.KnownBad), knownBad...)
	return spec
}

func (s *Store) createRecord(ctx context.Context, spec Spec, state CellState, now time.Time) (Record, uint64, error) {
	if existing, revision, err := s.Load(ctx, spec.RolloutID); err == nil {
		if existing.FromDigest != spec.FromDigest || existing.ToDigest != spec.ToDigest || existing.Kind != spec.Kind {
			return Record{}, 0, fmt.Errorf("%w: rollout ID is bound to a different rollout", ErrConflict)
		}
		return existing, revision, nil
	} else if !errors.Is(err, jetstream.ErrKeyNotFound) {
		return Record{}, 0, err
	}
	record, err := New(withKnownBad(spec, state.KnownBad), now)
	if err != nil {
		return Record{}, 0, err
	}
	encoded, err := protocol.EncodeJSON(record)
	if err != nil {
		return Record{}, 0, err
	}
	if err := s.fencer.Guard(ctx, record.AuthorityEpoch); err != nil {
		return Record{}, 0, err
	}
	revision, err := s.kv.Create(ctx, rolloutKey(record.RolloutID), encoded)
	if errors.Is(err, jetstream.ErrKeyExists) {
		return s.createRecord(ctx, spec, state, now)
	}
	if err != nil {
		return Record{}, 0, err
	}
	recordAdmitted(ctx, record)
	return record, revision, nil
}

// Commit replaces the record stored at revision with next. Identity fields,
// waves and policy are immutable, and the authority epoch may only change
// through Adopt. A terminal record releases the cell slot.
func (s *Store) Commit(ctx context.Context, revision uint64, next Record) (uint64, error) {
	if err := next.Validate(); err != nil {
		return 0, err
	}
	current, storedRevision, err := s.Load(ctx, next.RolloutID)
	if err != nil {
		return 0, err
	}
	if storedRevision != revision {
		return 0, ErrConflict
	}
	if current.AuthorityEpoch != next.AuthorityEpoch {
		return 0, ErrFenced
	}
	if current.Kind != next.Kind || current.Cell != next.Cell || current.FromDigest != next.FromDigest || current.ToDigest != next.ToDigest ||
		current.PolicyDigest != next.PolicyDigest || !slices.EqualFunc(current.Waves, next.Waves, slices.Equal) ||
		!current.StartedAt.Equal(next.StartedAt) {
		return 0, fmt.Errorf("%w: immutable rollout fields changed", ErrInvalid)
	}
	if current.Phase.Terminal() {
		return 0, ErrTerminal
	}
	encoded, err := protocol.EncodeJSON(next)
	if err != nil {
		return 0, err
	}
	if err := s.fencer.Guard(ctx, next.AuthorityEpoch); err != nil {
		return 0, err
	}
	newRevision, err := s.kv.Update(ctx, rolloutKey(next.RolloutID), encoded, revision)
	if errors.Is(err, jetstream.ErrKeyRevisionMismatch) || errors.Is(err, jetstream.ErrKeyExists) {
		return 0, ErrConflict
	}
	if err != nil {
		return 0, err
	}
	recordTransition(ctx, current, next)
	if err := s.syncCell(ctx, next); err != nil {
		return newRevision, fmt.Errorf("record committed; cell slot update pending: %w", err)
	}
	return newRevision, nil
}

// Adopt rebinds an active rollout to a newer authority epoch after a leader
// change. An older epoch can never take a record back.
func (s *Store) Adopt(ctx context.Context, rolloutID string, epoch uint64) (Record, uint64, error) {
	if err := s.fencer.Guard(ctx, epoch); err != nil {
		return Record{}, 0, err
	}
	record, revision, err := s.Load(ctx, rolloutID)
	if err != nil {
		return Record{}, 0, err
	}
	switch {
	case epoch < record.AuthorityEpoch:
		return Record{}, 0, ErrFenced
	case epoch == record.AuthorityEpoch || record.Phase.Terminal():
		return record, revision, nil
	}
	record.AuthorityEpoch = epoch
	encoded, err := protocol.EncodeJSON(record)
	if err != nil {
		return Record{}, 0, err
	}
	newRevision, err := s.kv.Update(ctx, rolloutKey(rolloutID), encoded, revision)
	if errors.Is(err, jetstream.ErrKeyRevisionMismatch) || errors.Is(err, jetstream.ErrKeyExists) {
		return Record{}, 0, ErrConflict
	}
	if err != nil {
		return Record{}, 0, err
	}
	return record, newRevision, nil
}

// syncCell merges the record's known-bad digests into the cell and releases
// the slot once the record is terminal.
func (s *Store) syncCell(ctx context.Context, record Record) error {
	for range cellCASAttempts {
		state, revision, err := s.Cell(ctx)
		if err != nil {
			return err
		}
		next := state
		next.KnownBad = slices.Clone(state.KnownBad)
		for _, digest := range record.KnownBad {
			if !slices.Contains(next.KnownBad, digest) {
				next.KnownBad = append(next.KnownBad, digest)
			}
		}
		// The list keeps insertion order; the oldest entries age out first.
		if len(next.KnownBad) > MaxKnownBad {
			next.KnownBad = next.KnownBad[len(next.KnownBad)-MaxKnownBad:]
		}
		if record.Phase.Terminal() && state.ActiveRolloutID == record.RolloutID {
			next.ActiveRolloutID = ""
		}
		if slices.Equal(next.KnownBad, state.KnownBad) && next.ActiveRolloutID == state.ActiveRolloutID {
			return nil
		}
		if err := s.writeCell(ctx, record.AuthorityEpoch, next, revision); errors.Is(err, ErrConflict) {
			continue
		} else {
			return err
		}
	}
	return ErrConflict
}

func (s *Store) writeCell(ctx context.Context, epoch uint64, state CellState, revision uint64) error {
	if err := state.validate(s.cell); err != nil {
		return err
	}
	encoded, err := protocol.EncodeJSON(state)
	if err != nil {
		return err
	}
	if err := s.fencer.Guard(ctx, epoch); err != nil {
		return err
	}
	if revision == 0 {
		_, err = s.kv.Create(ctx, cellKey, encoded)
	} else {
		_, err = s.kv.Update(ctx, cellKey, encoded, revision)
	}
	if errors.Is(err, jetstream.ErrKeyRevisionMismatch) || errors.Is(err, jetstream.ErrKeyExists) {
		return ErrConflict
	}
	return err
}

// withEpoch fences a cell repair with the caller's current epoch instead of
// the finished record's possibly older one.
func withEpoch(record Record, epoch uint64) Record {
	record.AuthorityEpoch = epoch
	return record
}
