package messaging

import (
	"errors"

	"github.com/nats-io/nats.go/jetstream"
)

// NatsPublishConvergence is the publish-side convergence rule for message-id
// deduplicated JetStream publishes. Every Orchestrator message id is derived
// deterministically from the exact content being stored, so a duplicate
// acknowledgement PROVES the same message is already durably stored; a retry
// after a lost acknowledgement must converge on that receipt instead of
// failing. Only a server error is a failure.
var NatsPublishConvergence natsPublishConvergence

type natsPublishConvergence struct{}

// EnsureStored ensures the publish reached durable storage, accepting a
// duplicate message id as the converged receipt of the identical message.
// Returns true when the server reported the duplicate (already stored by an
// earlier attempt inside the window).
func (natsPublishConvergence) EnsureStored(acknowledgement *jetstream.PubAck) (bool, error) {
	if acknowledgement == nil {
		return false, errors.New("Value cannot be null. (Parameter 'acknowledgement')")
	}

	return acknowledgement.Duplicate, nil
}
