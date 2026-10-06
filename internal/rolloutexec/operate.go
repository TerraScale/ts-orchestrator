package rolloutexec

import (
	"context"
	"errors"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/rollout"
)

// Abort stops the cell's active rollout for an operator unless it already
// targets digest: one still in preflight ends, one moving units rolls every
// touched unit back. A rollout already rolling back or frozen is left to its
// rollback. It returns the ID of the rollout it stopped, if any.
func Abort(ctx context.Context, store *rollout.Store, epoch uint64, digest, reason string, now time.Time) (string, error) {
	return operate(ctx, store, epoch, func(record rollout.Record) (rollout.Event, bool) {
		return rollout.Event{Kind: rollout.EventAbort, Reason: reason, At: now}, record.ToDigest != digest
	})
}

// Resume retries the rollback of a frozen rollout (rollout.EventResume); it
// never moves a unit towards the rejected target. It returns the ID of the
// rollout it resumed, if any.
func Resume(ctx context.Context, store *rollout.Store, epoch uint64, now time.Time) (string, error) {
	return operate(ctx, store, epoch, func(record rollout.Record) (rollout.Event, bool) {
		return rollout.Event{Kind: rollout.EventResume, At: now}, record.Phase == rollout.PhaseFrozen
	})
}

// operate commits one operator event to the active rollout, adopting it
// under epoch first. The executor commits by CAS too, so a conflict with
// its tick is retried on the fresh record.
func operate(ctx context.Context, store *rollout.Store, epoch uint64,
	event func(rollout.Record) (rollout.Event, bool),
) (string, error) {
	for range 4 {
		record, revision, ok, err := store.Active(ctx)
		if err != nil || !ok || record.Phase.Terminal() {
			return "", err
		}
		if record.AuthorityEpoch != epoch {
			if record, revision, err = store.Adopt(ctx, record.RolloutID, epoch); err != nil {
				if errors.Is(err, rollout.ErrConflict) {
					continue
				}
				return "", err
			}
		}
		next, apply := event(record)
		if !apply {
			return "", nil
		}
		updated, err := rollout.Apply(record, next)
		if errors.Is(err, rollout.ErrInvalidTransition) || errors.Is(err, rollout.ErrTerminal) {
			return "", nil
		}
		if err != nil {
			return "", err
		}
		committed, err := store.Commit(ctx, revision, updated)
		if errors.Is(err, rollout.ErrConflict) {
			continue
		}
		if committed == 0 {
			return "", err
		}
		// A committed record whose cell slot update is pending is settled
		// by the executor's next tick.
		return record.RolloutID, nil
	}
	return "", rollout.ErrConflict
}
