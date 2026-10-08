package authority

import "context"

const netbirdStateKey = "state"

// CommitNetBirdState stores the rollout journal and its worker command in one
// revision, atomically ordered with lease changes. expectedSequence must come
// from the journal read that admitted the transition, rather than a later read.
func (r *Runtime) CommitNetBirdState(ctx context.Context, epoch uint64, operationID string,
	expectedSequence uint64, payload []byte,
) (uint64, error) {
	// The verifier also enables the final lease-expiry check after reading the
	// previous state; the stream CAS fences any concurrent authority handoff.
	return r.commitMutationVerified(ctx, epoch, MutationNetBirdState, netbirdStateKey,
		operationID, expectedSequence, payload, func(context.Context) error { return nil })
}

func (r *Runtime) ReadNetBirdState(ctx context.Context) (LogEntry, error) {
	return r.ReadHostMutation(ctx, MutationNetBirdState, netbirdStateKey)
}

func (r *Reader) ReadNetBirdState(ctx context.Context) (LogEntry, error) {
	return r.ReadHostMutation(ctx, MutationNetBirdState, netbirdStateKey)
}
