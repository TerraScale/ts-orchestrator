package rollout

import (
	"context"
	"errors"
	"fmt"

	"github.com/nats-io/nats.go/jetstream"
)

// IsKnownBad reports whether digest is known bad in this cell, either in the
// bounded cell list or in its durable per-digest record. Admission paths
// outside this package (placement, the rollout executor) use it to refuse a
// digest that a rollout already rolled back.
func (s *Store) IsKnownBad(ctx context.Context, digest string) (bool, error) {
	if !digestRE.MatchString(digest) {
		return false, fmt.Errorf("%w: known-bad digest", ErrInvalid)
	}
	state, _, err := s.Cell(ctx)
	if err != nil {
		return false, err
	}
	return s.knownBad(ctx, state, digest)
}

// Active returns the record that holds the cell's rollout slot and its KV
// revision. ok is false when the slot is free or names a claim whose record
// was never created; Begin repairs such a slot.
func (s *Store) Active(ctx context.Context) (record Record, revision uint64, ok bool, err error) {
	state, _, err := s.Cell(ctx)
	if err != nil || state.ActiveRolloutID == "" {
		return Record{}, 0, false, err
	}
	record, revision, err = s.Load(ctx, state.ActiveRolloutID)
	if errors.Is(err, jetstream.ErrKeyNotFound) || errors.Is(err, errAbandonedRollout) {
		return Record{}, 0, false, nil
	}
	if err != nil {
		return Record{}, 0, false, err
	}
	return record, revision, true, nil
}

// Settle releases the cell slot still held by a terminal record whose
// release was interrupted after its commit, fenced by the caller's epoch.
// It is a no-op for an active record.
func (s *Store) Settle(ctx context.Context, record Record, epoch uint64) error {
	if !record.Phase.Terminal() {
		return nil
	}
	if err := s.fencer.Guard(ctx, epoch); err != nil {
		return err
	}
	return s.syncCell(ctx, withEpoch(record, epoch))
}

// Matches reports whether record is the rollout spec describes: the same
// digests, kind, waves and policy. A program uses it before it treats an
// earlier record as its completed prerequisite.
func (record Record) Matches(spec Spec) error {
	if record.RolloutID != spec.RolloutID || record.Cell != spec.Cell {
		return fmt.Errorf("%w: rollout ID is bound to a different rollout", ErrConflict)
	}
	return sameRollout(record, spec)
}
