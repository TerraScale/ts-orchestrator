package authority

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

const netbirdIntentKey = "account"

// CommitNetBirdIntent orders an independently verified regional proposal with
// lease transitions. Its payload contains public signed source facts only.
func (r *Runtime) CommitNetBirdIntent(ctx context.Context, epoch uint64, operationID string,
	expectedSequence uint64, payload []byte, verify func(context.Context) error,
) (uint64, error) {
	if verify == nil {
		return 0, errors.New("NetBird intent requires a current signed source verifier")
	}
	return r.commitMutationVerified(ctx, epoch, MutationNetBirdIntent, netbirdIntentKey,
		operationID, expectedSequence, payload, verify)
}

func (r *Runtime) ReadNetBirdIntent(ctx context.Context) (LogEntry, error) {
	return r.ReadHostMutation(ctx, MutationNetBirdIntent, netbirdIntentKey)
}

func (r *Reader) ReadNetBirdIntent(ctx context.Context) (LogEntry, error) {
	return r.ReadHostMutation(ctx, MutationNetBirdIntent, netbirdIntentKey)
}

// ObserveLeaseRevision authenticates the original finite lease behind a NET
// proposal. This is a root reader API, never part of manager credentials.
func ObserveLeaseRevision(ctx context.Context, js jetstream.JetStream, scope string, revision uint64) (Snapshot, error) {
	if js == nil || !natsToken.MatchString(scope) || revision == 0 {
		return Snapshot{}, ErrFenced
	}
	stream, err := js.Stream(ctx, ControlStreamName)
	if err != nil {
		return Snapshot{}, err
	}
	info, err := stream.Info(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	if err := verifyControlStreamConfig(info.Config, info.Config.Replicas); err != nil {
		return Snapshot{}, err
	}
	entry, err := stream.GetMsg(ctx, revision)
	if err != nil {
		return Snapshot{}, err
	}
	if entry.Subject != fmt.Sprintf("%s.%s.lease", controlSubjectRoot, scope) || entry.Sequence != revision || entry.Time.IsZero() {
		return Snapshot{}, ErrLeaseCorrupt
	}
	lease, err := decodeLease(entry.Data)
	if err != nil || lease.Scope != scope || lease.Released {
		return Snapshot{}, ErrLeaseCorrupt
	}
	expires := entry.Time.Add(time.Duration(lease.LeaseDuration))
	if !time.Now().Before(expires) {
		return Snapshot{}, ErrFenced
	}
	return Snapshot{Scope: scope, DeploymentID: lease.DeploymentID, CandidateID: lease.CandidateID,
		OwnerID: lease.OwnerID, Epoch: lease.Epoch, Revision: revision, ExpiresAt: expires, Ready: true}, nil
}
