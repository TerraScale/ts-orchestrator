package protocol

import (
	"errors"
	"strings"
	"time"
)

// DurableEffectAcknowledgementPolicy is the acknowledgement policy — a worker
// acknowledges only after the durable effect exists or an idempotent replay of
// the same effect is proven. This pins the landed behaviour — the acceptance
// journal record precedes the double-ack, and authority loss after acceptance
// withholds the ack so the next epoch holder re-derives the outcome.
type DurableEffectAcknowledgementPolicy struct {
	RequiresDoubleAck     bool
	ProgressHeartbeat     *time.Duration
	DurableEffectEvidence string
}

// DurableEffectAcknowledgementPolicyLanded is the landed acknowledgement policy.
var DurableEffectAcknowledgementPolicyLanded = DurableEffectAcknowledgementPolicy{
	RequiresDoubleAck:     true,
	ProgressHeartbeat:     durationPointer(30 * time.Second),
	DurableEffectEvidence: "Journal acceptance or convergence record for the exact operation id",
}

// IsWellFormed reports whether the policy is well formed.
func (p DurableEffectAcknowledgementPolicy) IsWellFormed() bool {
	if !p.RequiresDoubleAck {
		return false
	}

	if strings.TrimSpace(p.DurableEffectEvidence) == "" || len(p.DurableEffectEvidence) > 256 {
		return false
	}

	return p.ProgressHeartbeat == nil || *p.ProgressHeartbeat > 0
}

// BoundedRedeliveryPolicy is the bounded redelivery policy. JetStream derives
// the effective ack wait from the first backoff
// interval, so the declared ack wait must equal it. Exhaustion stops
// redelivery only with terminal evidence — no message may disappear silently.
// The pinned maximum ack-pending is the landed CellSpec consumer profile;
// per-consumer flow control may tighten it further but never loosens the
// redelivery contract.
type BoundedRedeliveryPolicy struct {
	MaximumDeliveries                  int
	BackoffLadder                      []time.Duration
	MaximumAckPending                  int
	ExhaustionRequiresTerminalEvidence bool
}

// BoundedRedeliveryPolicyLanded is the landed bounded redelivery policy.
var BoundedRedeliveryPolicyLanded = BoundedRedeliveryPolicy{
	MaximumDeliveries: 5,
	BackoffLadder: []time.Duration{
		1 * time.Second,
		5 * time.Second,
		15 * time.Second,
		30 * time.Second,
	},
	MaximumAckPending:                  8,
	ExhaustionRequiresTerminalEvidence: true,
}

// AckWait returns the declared ack wait, which must equal the first backoff
// interval.
func (p BoundedRedeliveryPolicy) AckWait() (time.Duration, error) {
	if len(p.BackoffLadder) > 0 {
		return p.BackoffLadder[0], nil
	}

	return 0, errors.New("The backoff ladder is empty.")
}

// IsWellFormed reports whether the policy is well formed.
func (p BoundedRedeliveryPolicy) IsWellFormed() bool {
	if p.MaximumDeliveries < 1 || p.MaximumDeliveries > 100 {
		return false
	}

	if len(p.BackoffLadder) < 1 || len(p.BackoffLadder) > 16 {
		return false
	}

	for _, step := range p.BackoffLadder {
		if step <= 0 {
			return false
		}
	}

	for index := 1; index < len(p.BackoffLadder); index++ {
		if p.BackoffLadder[index] <= p.BackoffLadder[index-1] {
			return false
		}
	}

	return p.MaximumAckPending >= 1 && p.ExhaustionRequiresTerminalEvidence
}

// PoisonDisposition is the disposition of one poison decision.
type PoisonDisposition int

const (
	PoisonDispositionUnspecified PoisonDisposition = 0
	// PoisonDispositionTerminate: a deterministic durable conflict; terminate
	// now with terminal evidence.
	PoisonDispositionTerminate PoisonDisposition = 1
	// PoisonDispositionRetryWithDelay: a transient failure; negative-acknowledge
	// with the next backoff delay.
	PoisonDispositionRetryWithDelay PoisonDisposition = 2
	// PoisonDispositionHoldForOperator: an operational capacity issue; retry
	// with delay, stay loud, and never terminate the healthy message.
	PoisonDispositionHoldForOperator PoisonDisposition = 3
	// PoisonDispositionExhausted: the delivery budget is exhausted; redelivery
	// stops and terminal evidence is mandatory.
	PoisonDispositionExhausted PoisonDisposition = 4
)

// PoisonTerminalReason is why a message was terminated or exhausted; the
// reason must survive in terminal evidence.
type PoisonTerminalReason int

const (
	PoisonTerminalReasonUnspecified                            PoisonTerminalReason = 0
	PoisonTerminalReasonDeterministicIdentityConflict          PoisonTerminalReason = 1
	PoisonTerminalReasonMalformedEnvelope                      PoisonTerminalReason = 2
	PoisonTerminalReasonDuplicateOperationWithDifferentPayload PoisonTerminalReason = 3
	PoisonTerminalReasonDeliveryBudgetExhausted                PoisonTerminalReason = 4
	PoisonTerminalReasonJournalRetentionOverflow               PoisonTerminalReason = 5
)

// PoisonDecision is one poison-message decision.
type PoisonDecision struct {
	Disposition PoisonDisposition
	Reason      PoisonTerminalReason
	Delay       *time.Duration
}

// PoisonDecisionNone is the empty decision returned for out-of-range inputs.
var PoisonDecisionNone = PoisonDecision{
	Disposition: PoisonDispositionUnspecified,
	Reason:      PoisonTerminalReasonUnspecified,
	Delay:       nil,
}

// PoisonMessagePolicy is the poison-message decision core. A deterministic
// conflict (identical inputs, same wrong result every redelivery) terminates
// immediately; a transient failure retries with delay; an operational capacity
// failure holds loudly; exhaustion always produces terminal evidence.
var PoisonMessagePolicy poisonMessagePolicy

type poisonMessagePolicy struct{}

// Decide returns the disposition of one delivery attempt. DeliveryCount is
// 1-based; maximumDeliveries comes from the consumer profile.
func (poisonMessagePolicy) Decide(
	deterministicConflict bool,
	malformedInput bool,
	operationalCapacityFailure bool,
	deliveryCount int,
	maximumDeliveries int,
	backoffLadder []time.Duration,
) PoisonDecision {
	if maximumDeliveries < 1 || deliveryCount < 1 || len(backoffLadder) == 0 {
		return PoisonDecisionNone
	}

	if deterministicConflict {
		return PoisonDecision{
			Disposition: PoisonDispositionTerminate,
			Reason:      PoisonTerminalReasonDeterministicIdentityConflict,
			Delay:       nil,
		}
	}

	if operationalCapacityFailure {
		return PoisonDecision{
			Disposition: PoisonDispositionHoldForOperator,
			Reason:      PoisonTerminalReasonJournalRetentionOverflow,
			Delay:       durationPointer(backoffLadder[len(backoffLadder)-1]),
		}
	}

	if malformedInput && deliveryCount >= maximumDeliveries {
		return PoisonDecision{
			Disposition: PoisonDispositionExhausted,
			Reason:      PoisonTerminalReasonMalformedEnvelope,
			Delay:       nil,
		}
	}

	delayIndex := deliveryCount - 1
	if delayIndex > len(backoffLadder)-1 {
		delayIndex = len(backoffLadder) - 1
	}

	reason := PoisonTerminalReasonUnspecified
	if malformedInput {
		reason = PoisonTerminalReasonMalformedEnvelope
	}

	return PoisonDecision{
		Disposition: PoisonDispositionRetryWithDelay,
		Reason:      reason,
		Delay:       durationPointer(backoffLadder[delayIndex]),
	}
}

// CancellationPolicy is the cancellation policy: cancelling before the durable
// effect means the message is NOT acknowledged (it returns for redelivery);
// cancelling during the effect completes or compensates through the journal;
// there is no partial acknowledgement.
type CancellationPolicy struct {
	AcknowledgeOnlyAfterDurableEffect bool
	PartialAcknowledgementAllowed     bool
}

// CancellationPolicyLanded is the landed cancellation policy.
var CancellationPolicyLanded = CancellationPolicy{
	AcknowledgeOnlyAfterDurableEffect: true,
	PartialAcknowledgementAllowed:     false,
}

// IsWellFormed reports whether the policy is well formed.
func (p CancellationPolicy) IsWellFormed() bool {
	return p.AcknowledgeOnlyAfterDurableEffect && !p.PartialAcknowledgementAllowed
}

// DuplicateWindowPolicy is the transport duplicate-window policy: message-id
// duplicate windows are TRANSPORT suppression layered beneath operation-level
// idempotency. The contract makes no exactly-once claim: outside the window a
// duplicate is admitted and the idempotency key remains the authority.
type DuplicateWindowPolicy struct {
	Window  time.Duration
	Channel string
}

// NoExactlyOnceClaim is the contract's no-exactly-once disclaimer.
const NoExactlyOnceClaim = "Duplicate windows suppress transport-level replays only; correctness is owned by " +
	"operation-level idempotency keys, and no delivery is claimed to be exactly-once."

// DuplicateWindowPolicyCellStreams is the duplicate-window policy of the
// regional cell streams.
var DuplicateWindowPolicyCellStreams = DuplicateWindowPolicy{
	Window:  2 * time.Minute,
	Channel: "regional-cell-streams",
}

// IsWellFormed reports whether the policy is well formed.
func (p DuplicateWindowPolicy) IsWellFormed() bool {
	return p.Window > 0 && p.Window <= 24*time.Hour && strings.TrimSpace(p.Channel) != ""
}

// DuplicateWindowDecision is the pure transport-suppression decision for one
// message id.
type DuplicateWindowDecision int

const (
	DuplicateWindowDecisionUnspecified DuplicateWindowDecision = 0
	// DuplicateWindowDecisionAdmit: first observation inside the window; admit
	// and remember.
	DuplicateWindowDecisionAdmit DuplicateWindowDecision = 1
	// DuplicateWindowDecisionSuppress: same message id with the SAME digest
	// inside the window; suppress.
	DuplicateWindowDecisionSuppress DuplicateWindowDecision = 2
	// DuplicateWindowDecisionConflict: same message id with a DIFFERENT digest
	// inside the window; conflict — surface, never silently drop.
	DuplicateWindowDecisionConflict DuplicateWindowDecision = 3
	// DuplicateWindowDecisionAdmitBeyondWindow: outside the window the
	// transport no longer suppresses; admit (idempotency decides the effect).
	DuplicateWindowDecisionAdmitBeyondWindow DuplicateWindowDecision = 4
)

// duplicateWindowRecord is one resident observation.
type duplicateWindowRecord struct {
	digest     string
	observedAt time.Time
}

// MessageIdDuplicateWindow is the deterministic, bounded message-id
// duplicate-window tracker. It is pure: every observation carries an explicit
// timestamp, and callers must still apply operation-level idempotency. It is
// NOT safe for concurrent use.
type MessageIdDuplicateWindow struct {
	window        time.Duration
	capacity      int
	observed      map[string]duplicateWindowRecord
	evictionOrder []string
}

// NewMessageIdDuplicateWindow creates a tracker with the given window and
// capacity.
func NewMessageIdDuplicateWindow(window time.Duration, capacity int) (*MessageIdDuplicateWindow, error) {
	if window <= 0 {
		return nil, errors.New("Specified argument was out of the range of valid values. (Parameter 'window')")
	}

	if capacity < 1 {
		return nil, errors.New("Specified argument was out of the range of valid values. (Parameter 'capacity')")
	}

	return &MessageIdDuplicateWindow{
		window:   window,
		capacity: capacity,
		observed: make(map[string]duplicateWindowRecord, capacity),
	}, nil
}

// Count returns the number of resident message ids.
func (w *MessageIdDuplicateWindow) Count() int { return len(w.observed) }

// Observe records one observation and decides.
func (w *MessageIdDuplicateWindow) Observe(messageId, digest string, now time.Time) DuplicateWindowDecision {
	if messageId == "" || digest == "" {
		return DuplicateWindowDecisionAdmit
	}

	if prior, present := w.observed[messageId]; present {
		if now.Sub(prior.observedAt) > w.window {
			// The id is still RESIDENT here, so refresh it in place: it must keep its
			// single FIFO eviction slot. Remove + Remember would re-enqueue the id while
			// its old slot stayed queued, giving one id two slots — later evictions then
			// dequeue ids that are no longer tracked, observed.Count can exceed capacity,
			// and the queue grows without bound under beyond-window redelivery churn.
			w.observed[messageId] = duplicateWindowRecord{digest: digest, observedAt: now}
			return DuplicateWindowDecisionAdmitBeyondWindow
		}

		if prior.digest == digest {
			return DuplicateWindowDecisionSuppress
		}

		return DuplicateWindowDecisionConflict
	}

	w.remember(messageId, digest, now)
	return DuplicateWindowDecisionAdmit
}

// Inspect returns the read-only decision for one message id: exactly the
// decision Observe would return, without recording anything. Consumers use it
// before dispatch (the recording happens only after the durable effect is
// proven) so suppression can never skip work.
func (w *MessageIdDuplicateWindow) Inspect(messageId, digest string, now time.Time) DuplicateWindowDecision {
	if messageId == "" || digest == "" {
		return DuplicateWindowDecisionAdmit
	}

	prior, present := w.observed[messageId]
	if !present {
		return DuplicateWindowDecisionAdmit
	}

	if now.Sub(prior.observedAt) > w.window {
		return DuplicateWindowDecisionAdmitBeyondWindow
	}

	if prior.digest == digest {
		return DuplicateWindowDecisionSuppress
	}

	return DuplicateWindowDecisionConflict
}

func (w *MessageIdDuplicateWindow) remember(messageId, digest string, now time.Time) {
	if len(w.observed) >= w.capacity {
		evicted := w.evictionOrder[0]
		w.evictionOrder = w.evictionOrder[1:]
		delete(w.observed, evicted)
	}

	if _, present := w.observed[messageId]; !present {
		w.evictionOrder = append(w.evictionOrder, messageId)
	}

	w.observed[messageId] = duplicateWindowRecord{digest: digest, observedAt: now}
}

// DuplicateWindowDeliveryAction is the delivery action a consumer derives from
// one transport duplicate-window decision.
type DuplicateWindowDeliveryAction int

const (
	DuplicateWindowDeliveryActionUnspecified DuplicateWindowDeliveryAction = 0
	// DuplicateWindowDeliveryActionProcess: first observation or
	// beyond-window observation; run the normal journal/idempotency path.
	DuplicateWindowDeliveryActionProcess DuplicateWindowDeliveryAction = 1
	// DuplicateWindowDeliveryActionAcknowledgeSuppressedReplay: this exact
	// message id and digest were already completed locally; acknowledge the
	// delivery without reprocessing.
	DuplicateWindowDeliveryActionAcknowledgeSuppressedReplay DuplicateWindowDeliveryAction = 2
	// DuplicateWindowDeliveryActionTerminateConflictingIdentity: the same
	// message id arrived with a different digest; a deterministic identity
	// conflict — terminate the delivery with terminal evidence.
	DuplicateWindowDeliveryActionTerminateConflictingIdentity DuplicateWindowDeliveryAction = 3
)

// DuplicateWindowDelivery is the pure mapping from a duplicate-window decision
// to the consumer delivery action.
var DuplicateWindowDelivery duplicateWindowDelivery

type duplicateWindowDelivery struct{}

// Decide maps one duplicate-window decision to its delivery action.
func (duplicateWindowDelivery) Decide(decision DuplicateWindowDecision) DuplicateWindowDeliveryAction {
	switch decision {
	case DuplicateWindowDecisionAdmit, DuplicateWindowDecisionAdmitBeyondWindow:
		return DuplicateWindowDeliveryActionProcess
	case DuplicateWindowDecisionSuppress:
		return DuplicateWindowDeliveryActionAcknowledgeSuppressedReplay
	case DuplicateWindowDecisionConflict:
		return DuplicateWindowDeliveryActionTerminateConflictingIdentity
	default:
		return DuplicateWindowDeliveryActionUnspecified
	}
}

// AuthorityLeaseClaim is the fenced authority claim a handler must hold to own
// work. It matches the landed RegionalAuthorityCoordinator lease document:
// epoch from KV CAS, lease expiry, and the KV revision of the accepted
// authority generation.
type AuthorityLeaseClaim struct {
	Epoch          int64
	KvRevision     int64
	LeaseExpiresAt time.Time
	AuthorityId    string
	CandidateId    string
}

// IsLive reports whether the claim is live at now.
func (c AuthorityLeaseClaim) IsLive(now time.Time) bool {
	return c.Epoch > 0 && c.KvRevision > 0 && c.LeaseExpiresAt.After(now)
}

// IsWellFormed reports whether the claim fields are populated.
func (c AuthorityLeaseClaim) IsWellFormed() bool {
	return c.Epoch > 0 && c.KvRevision > 0 &&
		strings.TrimSpace(c.AuthorityId) != "" && strings.TrimSpace(c.CandidateId) != ""
}

// QueueGroupAdmission is the admission decision for one queue-group delivery.
type QueueGroupAdmission int

const (
	QueueGroupAdmissionUnspecified QueueGroupAdmission = 0
	// QueueGroupAdmissionAdmit: the holder owns this work; epoch and
	// generation match the live claim.
	QueueGroupAdmissionAdmit QueueGroupAdmission = 1
	// QueueGroupAdmissionStaleEpoch: the message names an older epoch than the
	// live claim; fence it — do not act, do not acknowledge.
	QueueGroupAdmissionStaleEpoch QueueGroupAdmission = 2
	// QueueGroupAdmissionLeaseLost: the message names a newer epoch than the
	// live claim; this holder lost the lease; leave the work for the new holder.
	QueueGroupAdmissionLeaseLost QueueGroupAdmission = 3
	// QueueGroupAdmissionNotLeader: this holder is not the leader; a
	// queue-group peer that is equivalent may act, an authoritative writer may not.
	QueueGroupAdmissionNotLeader QueueGroupAdmission = 4
)

// QueueGroupOwnership is the queue-group ownership and handler-fencing
// decision core. Queue groups distribute only
// equivalent-worker work; authoritative writes additionally require the live
// fenced lease, checked BEFORE the effect and again BEFORE the
// acknowledgement, which is what prevents split writers: two holders can
// never both pass a CAS-backed epoch equality check.
var QueueGroupOwnership queueGroupOwnership

type queueGroupOwnership struct{}

// Decide admits or fences one delivery.
func (queueGroupOwnership) Decide(
	liveClaim *AuthorityLeaseClaim,
	isLeader bool,
	messageEpoch int64,
	messageGeneration int64,
	requiresAuthority bool,
) QueueGroupAdmission {
	if !requiresAuthority {
		// Equivalent-worker fanout: any queue-group member may answer; no fenced lease applies.
		return QueueGroupAdmissionAdmit
	}

	if liveClaim == nil || !liveClaim.IsWellFormed() {
		return QueueGroupAdmissionNotLeader
	}

	if !isLeader {
		return QueueGroupAdmissionNotLeader
	}

	if messageEpoch < liveClaim.Epoch {
		return QueueGroupAdmissionStaleEpoch
	}

	if messageEpoch > liveClaim.Epoch {
		return QueueGroupAdmissionLeaseLost
	}

	if messageGeneration == liveClaim.KvRevision {
		return QueueGroupAdmissionAdmit
	}

	return QueueGroupAdmissionStaleEpoch
}

// MayCommitAuthoritativeWrite is the split-writer check for an authoritative
// journal append. The same fenced
// claim must be live immediately before the durable write and immediately
// before the acknowledgement. A loss at either checkpoint abandons or
// withholds — the in-flight write either never happened or is re-derived by
// the next epoch holder.
func (queueGroupOwnership) MayCommitAuthoritativeWrite(
	claimBeforeEffect *AuthorityLeaseClaim,
	claimBeforeAcknowledge *AuthorityLeaseClaim,
	now time.Time,
) bool {
	return claimBeforeEffect != nil && claimBeforeAcknowledge != nil &&
		claimBeforeEffect.Epoch == claimBeforeAcknowledge.Epoch &&
		claimBeforeEffect.KvRevision == claimBeforeAcknowledge.KvRevision &&
		claimBeforeEffect.CandidateId == claimBeforeAcknowledge.CandidateId &&
		claimBeforeEffect.IsLive(now) && claimBeforeAcknowledge.IsLive(now)
}

func durationPointer(value time.Duration) *time.Duration { return &value }
