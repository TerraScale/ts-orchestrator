package authority

import (
	"context"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

// CurrentLease observes the existing ordered lease without becoming a candidate
// or renewing it. The result is descriptive and never implements Fencer.
func (r *Reader) CurrentLease(ctx context.Context) (Snapshot, error) {
	if r == nil || r.stream == nil {
		return Snapshot{}, ErrNotLeader
	}
	info, err := r.stream.Info(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	if err := verifyControlStreamConfig(info.Config, 3); err != nil {
		return Snapshot{}, err
	}
	entry, err := r.stream.GetLastMsgForSubject(ctx, protocol.Control(r.scope, "lease"))
	if err != nil {
		return Snapshot{}, err
	}
	lease, err := decodeLease(entry.Data)
	if err != nil || entry.Sequence > info.State.LastSeq || lease.Scope != r.scope || lease.Released {
		return Snapshot{}, ErrFenced
	}
	now := time.Now().UTC()
	expires := entry.Time.Add(time.Duration(lease.LeaseDuration))
	if entry.Time.After(now) || !now.Before(expires) {
		return Snapshot{}, ErrFenced
	}
	return Snapshot{Scope: lease.Scope, DeploymentID: lease.DeploymentID, CandidateID: lease.CandidateID,
		OwnerID: lease.OwnerID, Epoch: lease.Epoch, Revision: entry.Sequence, ExpiresAt: expires, ObservedAt: now}, nil
}
