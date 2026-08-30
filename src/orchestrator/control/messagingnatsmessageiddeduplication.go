// Port of src/TerraScale.Orchestrator/Messaging/NatsMessageIdDeduplication.cs.
package control

import (
	"errors"
	"sync"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/protocol"
)

// NatsMessageIdDeduplicationSnapshot mirrors the C# record: observation
// counters of one message-id duplicate window. They sit next to — never in
// place of — the operation-level idempotency-replay counters so the two layers
// stay distinguishable.
type NatsMessageIdDeduplicationSnapshot struct {
	Admitted     int
	Suppressed   int
	Conflicting  int
	BeyondWindow int
	Resident     int
}

// NatsMessageIdDeduplicationDefaultCapacity mirrors the C# DefaultCapacity:
// the bounded resident set — the memory ceiling of one channel's transport
// window.
const NatsMessageIdDeduplicationDefaultCapacity = 4096

// NatsMessageIdDeduplication mirrors the C# class: the transport-level
// message-id duplicate window for one durable work channel, layered BENEATH
// operation-level idempotency. Record is called only after a consumer proved
// the durable effect; Inspect is read-only.
type NatsMessageIdDeduplication struct {
	policy protocol.DuplicateWindowPolicy
	window *protocol.MessageIdDuplicateWindow

	admitted     int
	suppressed   int
	conflicting  int
	beyondWindow int
	mu           sync.Mutex
}

// NewNatsMessageIdDeduplication mirrors the C# constructor.
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

// Policy mirrors the C# Policy property.
func (d *NatsMessageIdDeduplication) Policy() protocol.DuplicateWindowPolicy { return d.policy }

// Channel mirrors the C# Channel property.
func (d *NatsMessageIdDeduplication) Channel() string { return d.policy.Channel }

// Window mirrors the C# Window property.
func (d *NatsMessageIdDeduplication) Window() time.Duration { return d.policy.Window }

// Snapshot mirrors the C# Snapshot property.
func (d *NatsMessageIdDeduplication) Snapshot() NatsMessageIdDeduplicationSnapshot {
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

// Inspect mirrors the C# Inspect: read-only pre-dispatch decision; never
// records anything.
func (d *NatsMessageIdDeduplication) Inspect(messageId, digest string, now time.Time) protocol.DuplicateWindowDecision {
	return d.window.Inspect(messageId, digest, now)
}

// Record mirrors the C# Record: records one COMPLETED message identity. Call
// only after the durable effect exists or a terminal disposition was recorded
// for this exact delivery.
func (d *NatsMessageIdDeduplication) Record(messageId, digest string, now time.Time) protocol.DuplicateWindowDecision {
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
