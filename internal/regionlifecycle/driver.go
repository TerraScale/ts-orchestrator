package regionlifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"
)

// Effector performs and observes one step's effect. Execute must be
// idempotent for intent.CreateKey: it is the OCI opc-retry-token and the
// freeform ownership tag of anything the step creates. Observe finds the
// effect by that tag and must never create anything. intent.Epoch is the
// global leader epoch under which the driver claimed the effect; the driver
// guards it against the lease immediately before calling Execute.
type Effector interface {
	Execute(ctx context.Context, record Record, intent StepIntent) (StepResult, error)
	Observe(ctx context.Context, record Record, intent StepIntent) (Observation, error)
}

// Driver advances one region by at most one step per call, under the global
// leader's epoch. It journals the intent before the effect and reconciles a
// pending intent by observation before any retry.
//
// Every Execute is fenced twice: the record carrying the intent stamped with
// the caller's epoch is first written by a compare-and-set under that epoch
// (so of two leaders racing on the same record only one can claim the
// effect), and the lease is guarded again immediately before the effect. A
// recovered intent is re-claimed through Machine.ClaimStep, which re-checks
// admission freshness exactly as a fresh step does.
type Driver struct {
	Machine  Machine
	Store    *Store
	Effector Effector
	Now      func() time.Time
}

func (d Driver) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

// Advance runs the next step of cell, if any. Phases that wait on admission
// or a hold return the record unchanged.
func (d Driver) Advance(ctx context.Context, epoch uint64, cell string) (Record, error) {
	record, revision, err := d.Store.Get(ctx, cell)
	if err != nil {
		return Record{}, err
	}
	if epoch == 0 || record.Pending != nil && record.Pending.Epoch > epoch {
		return record, ErrStaleEpoch
	}
	if record.Phase == RetireApproved && record.Pending != nil {
		// A failed bring-up left an intent behind: settle it by observation
		// before any teardown step begins.
		observation, err := d.Effector.Observe(ctx, record, *record.Pending)
		if err != nil {
			return record, err
		}
		next, err := d.Machine.ReconcileRetirePending(record, observation, d.now())
		if err != nil {
			// Not held: Resume could never return a RetireApproved record
			// that still carries its intent, so the intent stays pending
			// for the next reconciliation pass instead.
			return record, err
		}
		if _, err := d.Store.Update(ctx, epoch, record, next, revision); err != nil {
			return record, err
		}
		return next, nil
	}
	if _, running := stepRunning(record.Phase); running && record.Pending != nil {
		// A previous leader may have crashed after the effect. Observe first;
		// only a confirmed-absent effect is retried, with the same key.
		observation, err := d.Effector.Observe(ctx, record, *record.Pending)
		if err != nil {
			return record, err
		}
		if observation.Step != record.Pending.Step || observation.CreateKey != record.Pending.CreateKey {
			return d.hold(ctx, epoch, record, revision, "observation does not match the pending intent", nil)
		}
		if observation.Found {
			next, err := d.Machine.CompleteStep(record, StepResult{Step: observation.Step, CreateKey: observation.CreateKey,
				ResourceID: observation.ResourceID, EvidenceDigest: observation.EvidenceDigest}, d.now())
			if err != nil {
				return d.hold(ctx, epoch, record, revision, "observed result is invalid", err)
			}
			if _, err := d.Store.Update(ctx, epoch, record, next, revision); err != nil {
				// The observed result is not durable; report the stored record.
				return record, err
			}
			return next, nil
		}
		// Re-claim the intent under this epoch with the guards re-checked;
		// a stale admission parks the step unexecuted.
		claimed, intent, err := d.Machine.ClaimStep(record, epoch, d.now())
		if err != nil {
			return record, err
		}
		claimedRevision, err := d.Store.Update(ctx, epoch, record, claimed, revision)
		if err != nil {
			return record, err
		}
		return d.execute(ctx, epoch, claimed, claimedRevision, intent)
	}
	if _, waiting := stepFrom(record.Phase); !waiting {
		return record, nil
	}
	next, intent, err := d.Machine.BeginStep(record, d.now())
	if err != nil {
		// Stale admission: wait for the admission loop instead of holding.
		return record, err
	}
	intent.Epoch = epoch
	next.Pending.Epoch = epoch
	nextRevision, err := d.Store.Update(ctx, epoch, record, next, revision)
	if err != nil {
		return record, err
	}
	return d.execute(ctx, epoch, next, nextRevision, intent)
}

func (d Driver) execute(ctx context.Context, epoch uint64, record Record, revision uint64, intent StepIntent) (Record, error) {
	// The claim above is durable; re-prove the lease right before the
	// external effect so a leader fenced in between never runs it.
	if err := d.Store.Guard(ctx, epoch); err != nil {
		return record, err
	}
	result, err := d.Effector.Execute(ctx, record, intent)
	if err != nil {
		return d.hold(ctx, epoch, record, revision, "step effect failed", err)
	}
	next, err := d.Machine.CompleteStep(record, result, d.now())
	if err != nil {
		return d.hold(ctx, epoch, record, revision, "step result does not match its intent", err)
	}
	if _, err := d.Store.Update(ctx, epoch, record, next, revision); err != nil {
		// The effect happened but its result is not durable. The pending
		// intent remains, so the next leader reconciles by observation.
		return record, err
	}
	return next, nil
}

func (d Driver) hold(ctx context.Context, epoch uint64, record Record, revision uint64, reason string, cause error) (Record, error) {
	detail := reason
	if cause != nil {
		detail = reason + ": " + cause.Error()
	}
	evidence := sha256.Sum256([]byte(detail))
	next, err := d.Machine.Fail(record, detail, hex.EncodeToString(evidence[:]), d.now())
	if err != nil {
		return record, errors.Join(errors.New(detail), err)
	}
	if _, err := d.Store.Update(ctx, epoch, record, next, revision); err != nil {
		return record, errors.Join(errors.New(detail), err)
	}
	return next, errors.New(detail)
}
