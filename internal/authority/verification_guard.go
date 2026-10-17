package authority

import (
	"context"
	"errors"
	"sync/atomic"
	"time"
)

type verificationGuardKey struct{}

type verificationGuard struct {
	runtime       *Runtime
	epoch         uint64
	owner         string
	leaseSequence uint64
	watermark     uint64
	subject       string
	operation     string
	expires       time.Time
	active        atomic.Bool
}

// verify already holds r.mu and has selected the global CAS watermark. A nested
// Guard must check the actual lease without renewing it or locking r.mu again.
func (r *Runtime) verify(ctx context.Context, epoch, leaseSequence, watermark uint64,
	subject, operation string, expires time.Time, check func(context.Context) error,
) error {
	guard := &verificationGuard{runtime: r, epoch: epoch, owner: r.ownerID, leaseSequence: leaseSequence,
		watermark: watermark, subject: subject, operation: operation, expires: expires}
	ctx, cancel := context.WithDeadline(ctx, expires)
	guard.active.Store(true)
	defer func() {
		guard.active.Store(false)
		cancel()
	}()
	return check(context.WithValue(ctx, verificationGuardKey{}, guard))
}

func (r *Runtime) guardVerification(ctx context.Context, epoch uint64, guard *verificationGuard) error {
	if guard.runtime != r || guard.epoch != epoch || guard.owner != r.ownerID || guard.subject == "" || guard.operation == "" ||
		!guard.active.Load() || !time.Now().Before(guard.expires) {
		return ErrFenced
	}
	if err := r.checkClock(); err != nil {
		return ErrClockUnhealthy
	}
	current := r.Current()
	if !current.CanMutate() || current.Epoch != epoch || current.Scope != r.config.Scope ||
		current.DeploymentID != r.config.DeploymentID || current.CandidateID != r.config.CandidateID || current.OwnerID != r.ownerID {
		return ErrFenced
	}
	info, err := r.stream.Info(ctx)
	if err != nil {
		return err
	}
	if err := verifyControlStreamConfig(info.Config, r.config.Replicas); err != nil {
		return err
	}
	if info.State.LastSeq != guard.watermark {
		return ErrConflict
	}
	entry, err := r.stream.GetLastMsgForSubject(ctx, r.leaseSub)
	if err != nil {
		return err
	}
	if entry.Sequence != guard.leaseSequence {
		return ErrConflict
	}
	lease, err := decodeLease(entry.Data)
	if err != nil {
		return errors.Join(ErrLeaseCorrupt, err)
	}
	if !guard.active.Load() || lease.Scope != r.config.Scope || lease.DeploymentID != r.config.DeploymentID ||
		lease.CandidateID != r.config.CandidateID || lease.OwnerID != r.ownerID || lease.Epoch != epoch ||
		lease.Released || !entry.Time.Add(time.Duration(lease.LeaseDuration)).Equal(guard.expires) || !time.Now().Before(guard.expires) {
		return ErrFenced
	}
	return ctx.Err()
}
