package authority

import (
	"context"
	"errors"
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
