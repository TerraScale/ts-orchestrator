package authority

import (
	"context"
	"time"
)

// VerifyLeaseHolder reports whether the durable regional lease is currently
// held, unreleased and unexpired, by exactly candidateID and ownerID at epoch.
// It is a read-only fence for a controller that executes work on behalf of
// another controller's term (the seed relaunching a slot for a non-seed
// authority leader): it never appends a lease record, so it can never take or
// extend authority. The read goes to the control stream's leader, the same
// path the leader's own Guard uses, so a lease another candidate has already
// replaced is never reported as held.
func (r *Runtime) VerifyLeaseHolder(ctx context.Context, epoch uint64, candidateID, ownerID string) error {
	if r == nil {
		return ErrNotLeader
	}
	if epoch == 0 || candidateID == "" || ownerID == "" {
		return ErrFenced
	}
	if r.checkClock() != nil {
		return ErrClockUnhealthy
	}
	readCtx, cancel := context.WithTimeout(ctx, authorityAPITimeout)
	defer cancel()
	// The same control-stream check as the leader's own Guard: a stream whose
	// configuration drifted (replicas, retention, limits) fails closed.
	info, err := r.stream.Info(readCtx)
	if err != nil {
		return stageFailure("foreign_lease_stream_info", err)
	}
	if err := verifyControlStreamConfig(info.Config, r.config.Replicas); err != nil {
		return stageFailure("foreign_lease_stream_config", err)
	}
	entry, err := r.stream.GetLastMsgForSubject(readCtx, r.leaseSub)
	if err != nil {
		return stageFailure("foreign_lease_msg_get", err)
	}
	lease, err := decodeLease(entry.Data)
	if err != nil {
		return stageFailure("foreign_lease_decode", ErrLeaseCorrupt)
	}
	if lease.Scope != r.config.Scope || lease.DeploymentID != r.config.DeploymentID || lease.CandidateID != candidateID || lease.OwnerID != ownerID ||
		lease.Epoch != epoch || lease.Released ||
		!time.Now().Before(entry.Time.Add(time.Duration(lease.LeaseDuration))) {
		return ErrFenced
	}
	return nil
}
