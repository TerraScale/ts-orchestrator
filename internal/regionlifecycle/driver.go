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
// effect by that tag and must never create anything.
type Effector interface {
	Execute(ctx context.Context, record Record, intent StepIntent) (StepResult, error)
	Observe(ctx context.Context, record Record, intent StepIntent) (Observation, error)
}

// Driver advances one region by at most one step per call, under the global
// leader's epoch. It journals the intent before the effect and reconciles a
// pending intent by observation before any retry.
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

// Advance runs the next step of cell, if any. Phases that wait on approval,
// admission or a hold return the record unchanged.
func (d Driver) Advance(ctx context.Context, epoch uint64, cell string) (Record, error) {
	record, revision, err := d.Store.Get(ctx, cell)
	if err != nil {
		return Record{}, err
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
			_, err = d.Store.Update(ctx, epoch, record, next, revision)
			return next, err
		}
		return d.execute(ctx, epoch, record, revision, *record.Pending)
	}
	if _, waiting := stepFrom(record.Phase); !waiting {
		return record, nil
	}
	next, intent, err := d.Machine.BeginStep(record, d.now())
	if err != nil {
		// Missing approval or stale admission: wait for an operator or for
		// the admission loop instead of holding.
		return record, err
	}
	nextRevision, err := d.Store.Update(ctx, epoch, record, next, revision)
	if err != nil {
		return record, err
	}
	return d.execute(ctx, epoch, next, nextRevision, intent)
}

func (d Driver) execute(ctx context.Context, epoch uint64, record Record, revision uint64, intent StepIntent) (Record, error) {
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
