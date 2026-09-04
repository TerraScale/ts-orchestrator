package control

import (
	"errors"
	"sync"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/protocol"
)

// NatsMessageIdDeduplicationSnapshot holds the observation counters of one
// message-id duplicate window. They sit next to — never in place of — the
// operation-level idempotency-replay counters so the two layers stay
// distinguishable.
type NatsMessageIdDeduplicationSnapshot struct {
	Admitted     int
	Suppressed   int
	Conflicting  int
	BeyondWindow int
	Resident     int
}

// NatsMessageIdDeduplicationDefaultCapacity is the bounded resident set — the
// memory ceiling of one channel's transport window.
const NatsMessageIdDeduplicationDefaultCapacity = 4096

// NatsMessageIdDeduplication is the transport-level message-id duplicate
// window for one durable work channel, layered BENEATH operation-level
// idempotency. Record is called only after a consumer proved the durable
// effect; Inspect is read-only.
type NatsMessageIdDeduplication struct {
	policy protocol.DuplicateWindowPolicy
	window *protocol.MessageIdDuplicateWindow

	admitted     int
	suppressed   int
	conflicting  int
	beyondWindow int
	mu           sync.Mutex
}

func NewNatsMessageIdDeduplication(
	policy protocol.DuplicateWindowPolicy,
	capacity int,
) (*NatsMessageIdDeduplication, error) {
	if !policy.IsWellFormed() {
		return nil, errors.New(
			"The duplicate-window policy is not well formed. (Parameter 'policy')")
	}

	if capacity == 0 {
		capacity = NatsMessageIdDeduplicationDefaultCapacity
	}

	window, err := protocol.NewMessageIdDuplicateWindow(policy.Window, capacity)
	if err != nil {
		return nil, err
	}

	return &NatsMessageIdDeduplication{policy: policy, window: window}, nil
}

func (d *NatsMessageIdDeduplication) Policy() protocol.DuplicateWindowPolicy {
	if d == nil {
		return protocol.DuplicateWindowPolicy{}
	}
	return d.policy
}

func (d *NatsMessageIdDeduplication) Channel() string {
	if d == nil {
		return ""
	}
	return d.policy.Channel
}

func (d *NatsMessageIdDeduplication) Window() time.Duration {
	if d == nil {
		return 0
	}
	return d.policy.Window
}

func (d *NatsMessageIdDeduplication) Snapshot() NatsMessageIdDeduplicationSnapshot {
	if d == nil || d.window == nil {
		return NatsMessageIdDeduplicationSnapshot{}
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	return NatsMessageIdDeduplicationSnapshot{
		Admitted:     d.admitted,
		Suppressed:   d.suppressed,
		Conflicting:  d.conflicting,
		BeyondWindow: d.beyondWindow,
		Resident:     d.window.Count(),
	}
}

// Inspect returns the read-only pre-dispatch decision; it never records
// anything.
func (d *NatsMessageIdDeduplication) Inspect(messageId, digest string, now time.Time) protocol.DuplicateWindowDecision {
	if d == nil || d.window == nil {
		return protocol.DuplicateWindowDecisionAdmit
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.window.Inspect(messageId, digest, now)
}

// Record records one COMPLETED message identity. Call only after the durable
// effect exists or a terminal disposition was recorded for this exact
// delivery.
func (d *NatsMessageIdDeduplication) Record(messageId, digest string, now time.Time) protocol.DuplicateWindowDecision {
	if d == nil || d.window == nil {
		return protocol.DuplicateWindowDecisionAdmit
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	decision := d.window.Observe(messageId, digest, now)
	switch decision {
	case protocol.DuplicateWindowDecisionAdmit:
		d.admitted++
	case protocol.DuplicateWindowDecisionSuppress:
		d.suppressed++
	case protocol.DuplicateWindowDecisionConflict:
		d.conflicting++
	case protocol.DuplicateWindowDecisionAdmitBeyondWindow:
		d.beyondWindow++
	}

	return decision
}
