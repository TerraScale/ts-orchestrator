package rollout

import (
	"context"
	"errors"
	"fmt"
	"maps"
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
// Records decode tolerantly, so an older controller reads a newer one's
// records during a self-update; schema_version names breaking changes.
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

// knownBadKey holds one durable known-bad record. The cell's KnownBad list is
// bounded and ages out its oldest entries; these per-digest records do not,
// so a rejected digest never becomes eligible again without a reviewed
// removal of its record.
func knownBadKey(digest string) string { return "knownbad." + digest }

type knownBadEntry struct {
	Digest string `json:"digest"`
}

// recordKnownBad durably records digest. It is idempotent.
func (s *Store) recordKnownBad(ctx context.Context, epoch uint64, digest string) error {
	if !digestRE.MatchString(digest) {
		return fmt.Errorf("%w: known-bad digest", ErrInvalid)
	}
	encoded, err := protocol.EncodeJSON(knownBadEntry{Digest: digest})
	if err != nil {
		return err
	}
	if err := s.fencer.Guard(ctx, epoch); err != nil {
		return err
	}
	if _, err := s.kv.Create(ctx, knownBadKey(digest), encoded); err != nil && !errors.Is(err, jetstream.ErrKeyExists) {
		return fmt.Errorf("record known-bad digest: %w", err)
	}
	return nil
}

// knownBad reports whether digest is known bad in the cell list or in its
// durable per-digest record.
func (s *Store) knownBad(ctx context.Context, state CellState, digest string) (bool, error) {
	if slices.Contains(state.KnownBad, digest) {
		return true, nil
	}
	_, err := s.kv.Get(ctx, knownBadKey(digest))
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read known-bad digest: %w", err)
	}
	return true, nil
}

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
	if err := protocol.DecodeTolerant(entry.Value(), &state, maxRecordBytes); err != nil {
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
	// Records decode tolerantly, so a marker would decode as an empty record:
	// read it first. A record always has a schema version and a marker never
	// does, so a newer binary's members change neither.
	var marker struct {
		AbandonedRollout string `json:"abandoned_rollout"`
		SchemaVersion    int    `json:"schema_version"`
	}
	if protocol.DecodeTolerant(entry.Value(), &marker, maxRecordBytes) == nil &&
		marker.SchemaVersion == 0 && marker.AbandonedRollout == rolloutID {
		return Record{}, 0, errAbandonedRollout
	}
	var record Record
	if err := protocol.DecodeTolerant(entry.Value(), &record, maxRecordBytes); err != nil {
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
	// An ID already bound to another rollout is refused before the cell
	// slot is reserved or the target's attempt is counted.
	if existing, _, err := s.Load(ctx, spec.RolloutID); err == nil {
		if err := sameRollout(existing, spec); err != nil {
			return Record{}, 0, err
		}
	} else if !errors.Is(err, jetstream.ErrKeyNotFound) {
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
			if errors.Is(err, jetstream.ErrKeyNotFound) || errors.Is(err, errAbandonedRollout) {
				// The slot was claimed but its record was never created (a
				// crash or failure between the two writes). Abandon the ID
				// so a late create of it fails, then release the slot.
				if err := s.abandon(ctx, spec.AuthorityEpoch, state.ActiveRolloutID); err != nil {
					return Record{}, 0, err
				}
				if err := s.releaseSlot(ctx, spec.AuthorityEpoch, state.ActiveRolloutID); err != nil {
					return Record{}, 0, err
				}
				continue
			}
			if err != nil {
				return Record{}, 0, fmt.Errorf("load active rollout %q: %w", state.ActiveRolloutID, err)
			}
			if !active.Phase.Terminal() {
				return Record{}, 0, ErrActiveRollout
			}
			if err := s.syncCell(ctx, withEpoch(active, spec.AuthorityEpoch)); err != nil {
				return Record{}, 0, err
			}
			continue
		}
		if bad, err := s.knownBad(ctx, state, spec.ToDigest); err != nil {
			return Record{}, 0, err
		} else if bad {
			return Record{}, 0, ErrKnownBad
		}
		if bad, err := s.knownBad(ctx, state, spec.FromDigest); err != nil {
			return Record{}, 0, err
		} else if bad {
			return Record{}, 0, fmt.Errorf("%w: rollback target digest is known bad", ErrInvalid)
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
		boundAttempts(next.Attempts, next.KnownBad, spec.ToDigest)
		if err := s.writeCell(ctx, spec.AuthorityEpoch, next, revision); errors.Is(err, ErrConflict) {
			continue
		} else if err != nil {
			return Record{}, 0, err
		}
		return s.createRecord(ctx, spec, next, now)
	}
	return Record{}, 0, ErrConflict
}

// sameRollout reports whether an existing record is the rollout spec
// describes. A retry must describe the same plan, not only the same target:
// a changed unit set or policy would otherwise silently run the stored,
// older plan.
func sameRollout(existing Record, spec Spec) error {
	if existing.FromDigest != spec.FromDigest || existing.ToDigest != spec.ToDigest || existing.Kind != spec.Kind {
		return fmt.Errorf("%w: rollout ID is bound to a different rollout", ErrConflict)
	}
	waves, err := PlanWaves(spec.Units, spec.Policy)
	if err != nil {
		return err
	}
	policyDigest, err := spec.Policy.Digest()
	if err != nil {
		return err
	}
	if existing.PolicyDigest != policyDigest || !slices.EqualFunc(existing.Waves, waves, slices.Equal) {
		return fmt.Errorf("%w: rollout ID is bound to a different plan", ErrConflict)
	}
	return nil
}

func withKnownBad(spec Spec, knownBad []string) Spec {
	spec.KnownBad = append(slices.Clone(spec.KnownBad), knownBad...)
	return spec
}

func (s *Store) createRecord(ctx context.Context, spec Spec, state CellState, now time.Time) (Record, uint64, error) {
	if existing, revision, err := s.Load(ctx, spec.RolloutID); err == nil {
		if err := sameRollout(existing, spec); err != nil {
			return Record{}, 0, err
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
				// Durable first: the cell list below is only a bounded
				// cache of the per-digest records.
				if err := s.recordKnownBad(ctx, record.AuthorityEpoch, digest); err != nil {
					return err
				}
				next.KnownBad = append(next.KnownBad, digest)
			}
		}
		// The list keeps insertion order; the oldest entries age out first.
		// Every entry that ages out keeps its durable record, including
		// entries listed before durable records existed.
		if len(next.KnownBad) > MaxKnownBad {
			for _, digest := range next.KnownBad[:len(next.KnownBad)-MaxKnownBad] {
				if err := s.recordKnownBad(ctx, record.AuthorityEpoch, digest); err != nil {
					return err
				}
			}
			next.KnownBad = next.KnownBad[len(next.KnownBad)-MaxKnownBad:]
		}
		next.Attempts = maps.Clone(state.Attempts)
		if record.Phase.Terminal() && state.ActiveRolloutID == record.RolloutID {
			next.ActiveRolloutID = ""
			// The attempt budget limits retries of a rejected digest. A
			// completed rollout proved its digest, so its attempt is
			// refunded once, as the slot is released, and the digest can
			// be targeted again (for example to restore it).
			if record.Phase == PhaseComplete && state.Attempts[record.ToDigest] > 0 {
				if next.Attempts[record.ToDigest]--; next.Attempts[record.ToDigest] == 0 {
					delete(next.Attempts, record.ToDigest)
				}
			}
		}
		boundAttempts(next.Attempts, next.KnownBad, "")
		if slices.Equal(next.KnownBad, state.KnownBad) && next.ActiveRolloutID == state.ActiveRolloutID &&
			maps.Equal(next.Attempts, state.Attempts) {
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

// boundAttempts keeps the per-digest attempt map within maxAttemptDigest so
// the cell state never grows into one validate rejects. Counts of digests the
// cell refuses as known bad go first, since the known-bad check already
// refuses them; then the remaining entries in digest order. keep is never
// evicted.
func boundAttempts(attempts map[string]int, knownBad []string, keep string) {
	if len(attempts) <= maxAttemptDigest {
		return
	}
	digests := slices.Sorted(maps.Keys(attempts))
	for _, refused := range []bool{true, false} {
		for _, digest := range digests {
			if len(attempts) <= maxAttemptDigest {
				return
			}
			if digest != keep && slices.Contains(knownBad, digest) == refused {
				delete(attempts, digest)
			}
		}
	}
}

// errAbandonedRollout marks a rollout ID whose cell claim was reclaimed
// before its record existed.
var errAbandonedRollout = errors.New("rollout ID was abandoned before its record was created")

// abandonedMarker occupies the record key of an abandoned rollout ID. It
// does not decode as a Record, so a late createRecord of that ID fails
// instead of creating a live record after its slot was released.
type abandonedMarker struct {
	AbandonedRollout string `json:"abandoned_rollout"`
}

// abandon writes the marker for rolloutID unless a record or marker exists.
func (s *Store) abandon(ctx context.Context, epoch uint64, rolloutID string) error {
	encoded, err := protocol.EncodeJSON(abandonedMarker{AbandonedRollout: rolloutID})
	if err != nil {
		return err
	}
	if err := s.fencer.Guard(ctx, epoch); err != nil {
		return err
	}
	_, err = s.kv.Create(ctx, rolloutKey(rolloutID), encoded)
	if errors.Is(err, jetstream.ErrKeyExists) {
		// A concurrent create won or the marker is already in place; the
		// next Load tells which.
		if _, _, loadErr := s.Load(ctx, rolloutID); loadErr == nil {
			return ErrActiveRollout
		} else if !errors.Is(loadErr, errAbandonedRollout) {
			return loadErr
		}
		return nil
	}
	return err
}

// releaseSlot clears the cell slot while it still names rolloutID.
func (s *Store) releaseSlot(ctx context.Context, epoch uint64, rolloutID string) error {
	for range cellCASAttempts {
		state, revision, err := s.Cell(ctx)
		if err != nil {
			return err
		}
		if state.ActiveRolloutID != rolloutID {
			return nil
		}
		next := state
		next.ActiveRolloutID = ""
		if err := s.writeCell(ctx, epoch, next, revision); errors.Is(err, ErrConflict) {
			continue
		} else {
			return err
		}
	}
	return ErrConflict
}

// withEpoch fences a cell repair with the caller's current epoch instead of
// the finished record's possibly older one.
func withEpoch(record Record, epoch uint64) Record {
	record.AuthorityEpoch = epoch
	return record
}
