package authority

import (
	"context"
	"fmt"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

// LeaseAdmission observes one live candidate's authority without granting writes.
// The owner, epoch and original deadline never follow a successor or renewal.
type LeaseAdmission struct {
	reader   *Reader
	original context.Context
	lease    leaseRecord
	revision uint64
	deadline time.Time
}

func (a *LeaseAdmission) Epoch() uint64       { return a.lease.Epoch }
func (a *LeaseAdmission) Deadline() time.Time { return a.deadline }

// AdmitRuntimeLease derives the epoch from the protected current lease. The
// deployment and candidate must come from root's current accepted installation.
func (r *Reader) AdmitRuntimeLease(ctx context.Context, deploymentID, candidateID string) (*LeaseAdmission, error) {
	if ctx == nil || ctx.Err() != nil || !entityid.Valid(deploymentID) || !entityid.Valid(candidateID) {
		return nil, ErrFenced
	}
	lease, _, _, err := r.currentLease(ctx)
	if err != nil {
		return nil, err
	}
	return r.AdmitCurrentLease(ctx, deploymentID, candidateID, lease.Epoch)
}

// AdmitCurrentLease requires expectations derived from the current signed source
// and retained intent, not authority claimed by a request DTO.
func (r *Reader) AdmitCurrentLease(ctx context.Context, deploymentID, candidateID string, expectedEpoch uint64) (*LeaseAdmission, error) {
	if ctx == nil || ctx.Err() != nil || !entityid.Valid(deploymentID) || !entityid.Valid(candidateID) || expectedEpoch == 0 {
		return nil, ErrFenced
	}
	lease, revision, expiresAt, err := r.currentLease(ctx)
	if err != nil {
		return nil, err
	}
	if lease.DeploymentID != deploymentID || lease.CandidateID != candidateID || lease.Epoch != expectedEpoch {
		return nil, ErrFenced
	}
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(expiresAt) {
		expiresAt = deadline
	}
	admitted := &LeaseAdmission{reader: r, original: ctx, lease: lease, revision: revision, deadline: expiresAt}
	if err := admitted.Guard(ctx); err != nil {
		return nil, err
	}
	return admitted, nil
}

func (a *LeaseAdmission) Guard(ctx context.Context) error {
	if a == nil || a.reader == nil || a.original == nil || ctx == nil || a.original.Err() != nil || ctx.Err() != nil || !time.Now().Before(a.deadline) {
		return ErrFenced
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(a.original, cancel)
	defer cancel()
	defer stop()
	lease, revision, _, err := a.reader.currentLease(ctx)
	if err != nil {
		return err
	}
	if lease.Scope != a.lease.Scope || lease.DeploymentID != a.lease.DeploymentID || lease.CandidateID != a.lease.CandidateID ||
		lease.OwnerID != a.lease.OwnerID || lease.Epoch != a.lease.Epoch || revision < a.revision ||
		!time.Now().Before(a.deadline) || a.original.Err() != nil {
		return ErrFenced
	}
	return ctx.Err()
}

func (r *Reader) currentLease(ctx context.Context) (leaseRecord, uint64, time.Time, error) {
	if r == nil || r.stream == nil {
		return leaseRecord{}, 0, time.Time{}, ErrFenced
	}
	subject := fmt.Sprintf("%s.%s.lease", controlSubjectRoot, r.scope)
	for range 8 {
		info, err := r.stream.Info(ctx)
		if err != nil {
			return leaseRecord{}, 0, time.Time{}, err
		}
		if err := verifyControlStreamConfig(info.Config, info.Config.Replicas); err != nil {
			return leaseRecord{}, 0, time.Time{}, err
		}
		entry, err := r.stream.GetLastMsgForSubject(ctx, subject)
		if err != nil {
			return leaseRecord{}, 0, time.Time{}, err
		}
		if entry.Sequence > info.State.LastSeq {
			continue
		}
		lease, err := decodeLease(entry.Data)
		if err != nil || entry.Subject != subject || entry.Sequence == 0 || entry.Time.IsZero() || lease.Scope != r.scope {
			return leaseRecord{}, 0, time.Time{}, ErrLeaseCorrupt
		}
		expiresAt := entry.Time.Add(time.Duration(lease.LeaseDuration))
		if lease.Released || !time.Now().Before(expiresAt) {
			return leaseRecord{}, 0, time.Time{}, ErrFenced
		}
		return lease, entry.Sequence, expiresAt, nil
	}
	return leaseRecord{}, 0, time.Time{}, ErrConflict
}

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
