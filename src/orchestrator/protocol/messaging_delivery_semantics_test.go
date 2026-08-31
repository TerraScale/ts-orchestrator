package protocol

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

var deliveryNow = time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)

var liveClaim = AuthorityLeaseClaim{
	Epoch:          7,
	KvRevision:     42,
	LeaseExpiresAt: deliveryNow.Add(10 * time.Second),
	AuthorityId:    "gru-regional",
	CandidateId:    "gru-controller-controller-1",
}

func TestTheLandedRedeliveryPolicyIsPinned(t *testing.T) {
	policy := BoundedRedeliveryPolicyLanded

	if !policy.IsWellFormed() {
		t.Fatal("landed policy must be well formed")
	}

	if policy.MaximumDeliveries != 5 {
		t.Fatalf("max deliveries = %d", policy.MaximumDeliveries)
	}

	ackWait, err := policy.AckWait()
	if err != nil || ackWait != time.Second {
		t.Fatalf("ack wait = %v", ackWait)
	}

	if policy.MaximumAckPending != 8 {
		t.Fatalf("max ack pending = %d", policy.MaximumAckPending)
	}

	seconds := []string{}
	for _, step := range policy.BackoffLadder {
		seconds = append(seconds, strconv.FormatFloat(step.Seconds(), 'f', -1, 64))
	}

	if strings.Join(seconds, ",") != "1,5,15,30" {
		t.Fatalf("backoff ladder = %v", seconds)
	}

	if !policy.ExhaustionRequiresTerminalEvidence {
		t.Fatal("exhaustion must require terminal evidence")
	}
}

func TestRedeliveryPoliciesMustBeBoundedAndMonotonic(t *testing.T) {
	if (BoundedRedeliveryPolicy{MaximumDeliveries: 0, BackoffLadder: []time.Duration{time.Second},
		MaximumAckPending: 1, ExhaustionRequiresTerminalEvidence: true}).IsWellFormed() {
		t.Fatal("zero deliveries must be invalid")
	}

	if (BoundedRedeliveryPolicy{MaximumDeliveries: 5, BackoffLadder: []time.Duration{},
		MaximumAckPending: 1, ExhaustionRequiresTerminalEvidence: true}).IsWellFormed() {
		t.Fatal("empty ladder must be invalid")
	}

	if (BoundedRedeliveryPolicy{MaximumDeliveries: 5,
		BackoffLadder:     []time.Duration{5 * time.Second, time.Second},
		MaximumAckPending: 1, ExhaustionRequiresTerminalEvidence: true}).IsWellFormed() {
		t.Fatal("decreasing ladder must be invalid")
	}

	if (BoundedRedeliveryPolicy{MaximumDeliveries: 5,
		BackoffLadder:     []time.Duration{time.Second, time.Second},
		MaximumAckPending: 1, ExhaustionRequiresTerminalEvidence: true}).IsWellFormed() {
		t.Fatal("flat ladder must be invalid")
	}

	if (BoundedRedeliveryPolicy{MaximumDeliveries: 5, BackoffLadder: []time.Duration{time.Second},
		MaximumAckPending: 0, ExhaustionRequiresTerminalEvidence: true}).IsWellFormed() {
		t.Fatal("zero ack pending must be invalid")
	}

	if (BoundedRedeliveryPolicy{MaximumDeliveries: 5, BackoffLadder: []time.Duration{time.Second},
		MaximumAckPending: 8, ExhaustionRequiresTerminalEvidence: false}).IsWellFormed() {
		t.Fatal("silent exhaustion must be invalid")
	}
}

func TestAcknowledgementRequiresADurableEffectAndDoubleAck(t *testing.T) {
	if !DurableEffectAcknowledgementPolicyLanded.IsWellFormed() {
		t.Fatal("landed acknowledgement policy must be well formed")
	}

	if !DurableEffectAcknowledgementPolicyLanded.RequiresDoubleAck {
		t.Fatal("landed acknowledgement policy must require double ack")
	}

	if (DurableEffectAcknowledgementPolicy{RequiresDoubleAck: false,
		DurableEffectEvidence: "journal acceptance"}).IsWellFormed() {
		t.Fatal("single ack must be invalid")
	}
}

func TestCancellationNeverAdmitsAPartialAcknowledgement(t *testing.T) {
	if !CancellationPolicyLanded.IsWellFormed() {
		t.Fatal("landed cancellation policy must be well formed")
	}

	if (CancellationPolicy{AcknowledgeOnlyAfterDurableEffect: true, PartialAcknowledgementAllowed: true}).IsWellFormed() {
		t.Fatal("partial acknowledgement must be invalid")
	}
}

func TestDeterministicConflictsTerminateImmediatelyWithTerminalEvidence(t *testing.T) {
	for _, deliveryCount := range []int{1, 3, 5} {
		decision := PoisonMessagePolicy.Decide(true, false, false, deliveryCount, 5,
			BoundedRedeliveryPolicyLanded.BackoffLadder)

		if decision.Disposition != PoisonDispositionTerminate ||
			decision.Reason != PoisonTerminalReasonDeterministicIdentityConflict {
			t.Fatalf("delivery %d: disposition = %v", deliveryCount, decision.Disposition)
		}
	}
}

func TestTransientFailuresRetryOnTheBackoffLadderAndClampBeyondItsEnd(t *testing.T) {
	first := PoisonMessagePolicy.Decide(false, false, false, 1, 5, BoundedRedeliveryPolicyLanded.BackoffLadder)
	if first.Disposition != PoisonDispositionRetryWithDelay || first.Delay == nil || *first.Delay != time.Second {
		t.Fatalf("first retry = %v", first.Disposition)
	}

	reorderedFarBeyondLadder := PoisonMessagePolicy.Decide(false, false, false, 99, 5,
		BoundedRedeliveryPolicyLanded.BackoffLadder)
	if reorderedFarBeyondLadder.Delay == nil || *reorderedFarBeyondLadder.Delay != 30*time.Second {
		t.Fatal("retry delay must clamp to the last ladder step")
	}
}

func TestMalformedInputRetriesUntilTheBudgetIsExhaustedThenRequiresTerminalEvidence(t *testing.T) {
	beforeExhaustion := PoisonMessagePolicy.Decide(false, true, false, 4, 5,
		BoundedRedeliveryPolicyLanded.BackoffLadder)
	if beforeExhaustion.Disposition != PoisonDispositionRetryWithDelay ||
		beforeExhaustion.Reason != PoisonTerminalReasonMalformedEnvelope {
		t.Fatalf("before exhaustion = %v", beforeExhaustion.Disposition)
	}

	exhausted := PoisonMessagePolicy.Decide(false, true, false, 5, 5,
		BoundedRedeliveryPolicyLanded.BackoffLadder)
	if exhausted.Disposition != PoisonDispositionExhausted ||
		exhausted.Reason != PoisonTerminalReasonMalformedEnvelope {
		t.Fatalf("exhausted = %v", exhausted.Disposition)
	}

	stillRetrying := PoisonMessagePolicy.Decide(false, true, false, 2, 5,
		BoundedRedeliveryPolicyLanded.BackoffLadder)
	if stillRetrying.Disposition != PoisonDispositionRetryWithDelay {
		t.Fatal("mid-budget malformed input must keep retrying")
	}
}

func TestOperationalCapacityFailuresHoldLoudlyAndNeverTerminateAHealthyMessage(t *testing.T) {
	decision := PoisonMessagePolicy.Decide(false, false, true, 3, 5,
		BoundedRedeliveryPolicyLanded.BackoffLadder)

	if decision.Disposition != PoisonDispositionHoldForOperator ||
		decision.Reason != PoisonTerminalReasonJournalRetentionOverflow ||
		decision.Delay == nil || *decision.Delay != 30*time.Second {
		t.Fatalf("capacity failure = %v", decision.Disposition)
	}
}

func TestInvalidPoisonInputsDecideNothingRatherThanGuessing(t *testing.T) {
	decision := PoisonMessagePolicy.Decide(false, false, false, 0, 5, []time.Duration{time.Second})
	if decision.Disposition != PoisonDispositionUnspecified {
		t.Fatalf("invalid input disposition = %v", decision.Disposition)
	}
}

func TestDuplicateWindowsAreTransportSuppressionOnlyAndNeverClaimExactlyOnce(t *testing.T) {
	if DuplicateWindowPolicyCellStreams.Window != 2*time.Minute {
		t.Fatal("cell stream window must be two minutes")
	}

	if DuplicateWindowPolicyGlobalCiStream.Window != 24*time.Hour {
		t.Fatal("global CI stream window must be twenty-four hours")
	}

	if !strings.Contains(NoExactlyOnceClaim, "exactly-once") {
		t.Fatal("the no-exactly-once claim must name exactly-once")
	}

	if (DuplicateWindowPolicy{Window: 0, Channel: "channel"}).IsWellFormed() {
		t.Fatal("zero window must be invalid")
	}

	if (DuplicateWindowPolicy{Window: 8 * 24 * time.Hour, Channel: "channel"}).IsWellFormed() {
		t.Fatal("over-max window must be invalid")
	}
}

func TestTheDuplicateWindowSuppressesReplaysFlagsConflictsAndExpires(t *testing.T) {
	window := mustWindow(t, 2*time.Minute, 4)

	if window.Observe("m1", "digest-a", deliveryNow) != DuplicateWindowDecisionAdmit {
		t.Fatal("first observation must be admitted")
	}

	if window.Observe("m1", "digest-a", deliveryNow.Add(30*time.Second)) != DuplicateWindowDecisionSuppress {
		t.Fatal("in-window replay with the same digest must be suppressed")
	}

	// Same message id with a different payload digest is a conflict, never a silent drop.
	if window.Observe("m1", "digest-b", deliveryNow.Add(40*time.Second)) != DuplicateWindowDecisionConflict {
		t.Fatal("in-window replay with a different digest must conflict")
	}

	// Beyond the window the transport no longer suppresses; idempotency decides the effect.
	if window.Observe("m1", "digest-a", deliveryNow.Add(3*time.Minute)) != DuplicateWindowDecisionAdmitBeyondWindow {
		t.Fatal("beyond-window observation must be admitted")
	}

	if window.Observe("", "digest", deliveryNow) != DuplicateWindowDecisionAdmit {
		t.Fatal("empty message ids must be admitted")
	}
}

func mustWindow(t *testing.T, window time.Duration, capacity int) *MessageIdDuplicateWindow {
	t.Helper()
	result, err := NewMessageIdDuplicateWindow(window, capacity)
	if err != nil {
		t.Fatalf("window construction failed: %v", err)
	}

	return result
}

func TestTheDuplicateWindowEvictsOldestEntriesAtCapacity(t *testing.T) {
	window := mustWindow(t, 2*time.Minute, 2)

	window.Observe("m1", "d1", deliveryNow)
	window.Observe("m2", "d2", deliveryNow)
	window.Observe("m3", "d3", deliveryNow)

	if window.Count() != 2 {
		t.Fatalf("count = %d", window.Count())
	}

	if window.Observe("m1", "d1", deliveryNow.Add(time.Second)) != DuplicateWindowDecisionAdmit {
		t.Fatal("the evicted id must be admitted again")
	}
}

func TestBeyondWindowReobservationOfAResidentIdKeepsExactlyOneFifoSlot(t *testing.T) {
	// A beyond-window refresh of a RESIDENT id must not re-enqueue it: Remove +
	// Remember would leave the id's old eviction slot queued, so later evictions
	// dequeue ids that are no longer tracked and observed.Count can exceed capacity.
	window := mustWindow(t, 2*time.Minute, 3)

	window.Observe("a", "da", deliveryNow)
	window.Observe("b", "db", deliveryNow)
	window.Observe("c", "dc", deliveryNow)
	window.Observe("a", "da", deliveryNow.Add(5*time.Minute))
	if window.Count() != 3 {
		t.Fatalf("count = %d", window.Count())
	}

	// Fresh ids push the queue forward until the stale "a" slot would surface
	// while "a" itself is no longer tracked; every insertion must still respect
	// the capacity.
	for _, fresh := range []string{"d", "e", "f", "g"} {
		window.Observe(fresh, "d-"+fresh, deliveryNow.Add(5*time.Minute))
		if window.Count() > 3 {
			t.Fatalf("capacity violated at %s: %d", fresh, window.Count())
		}
	}
}

func TestBeyondWindowReobservationChurnKeepsTheCapacityBoundAndCorrectDecisions(t *testing.T) {
	const capacity = 3
	window := mustWindow(t, 2*time.Minute, capacity)
	churnIds := []string{"redelivery-0", "redelivery-1", "redelivery-2", "redelivery-3"}

	for round := 0; round < 120; round++ {
		now := deliveryNow.Add(5 * time.Minute * time.Duration(round))

		// Re-observe a churn id beyond the window: admitted either because it
		// stayed resident (AdmitBeyondWindow) or because capacity pressure
		// evicted it (Admit).
		decision := window.Observe(churnIds[round%len(churnIds)], "digest-churn", now)
		if decision != DuplicateWindowDecisionAdmit && decision != DuplicateWindowDecisionAdmitBeyondWindow {
			t.Fatalf("round %d: churn decision = %v", round, decision)
		}

		if window.Count() > capacity {
			t.Fatalf("round %d: capacity violated", round)
		}

		// The refresh is resident now: an in-window replay with the same digest suppresses.
		if window.Observe(churnIds[round%len(churnIds)], "digest-churn", now) != DuplicateWindowDecisionSuppress {
			t.Fatalf("round %d: replay must suppress", round)
		}

		if window.Count() > capacity {
			t.Fatalf("round %d: capacity violated after replay", round)
		}

		// Fresh ids keep flowing, forcing evictions across the churn.
		if window.Observe("fresh-"+strconv.Itoa(round), "digest-"+strconv.Itoa(round), now) !=
			DuplicateWindowDecisionAdmit {
			t.Fatalf("round %d: fresh id must be admitted", round)
		}

		if window.Count() > capacity {
			t.Fatalf("round %d: capacity violated after fresh id", round)
		}
	}
}

func TestQueueGroupOwnershipAdmitsOnlyTheLiveFencedLeader(t *testing.T) {
	if QueueGroupOwnership.Decide(&liveClaim, true, 7, 42, true) != QueueGroupAdmissionAdmit {
		t.Fatal("the live fenced leader must be admitted")
	}

	if QueueGroupOwnership.Decide(&liveClaim, false, 7, 42, true) != QueueGroupAdmissionNotLeader {
		t.Fatal("a non-leader must not be admitted")
	}

	if QueueGroupOwnership.Decide(nil, true, 7, 42, true) != QueueGroupAdmissionNotLeader {
		t.Fatal("a missing claim must not be admitted")
	}
}

func TestStaleAndSupersededEpochsAreFencedOrLeftForTheNewHolder(t *testing.T) {
	// A reordered stale delivery from an older epoch: fence it — do not act, do
	// not acknowledge.
	if QueueGroupOwnership.Decide(&liveClaim, true, 6, 41, true) != QueueGroupAdmissionStaleEpoch {
		t.Fatal("stale epoch must be fenced")
	}

	// A message from a newer epoch: this holder lost the lease; leave the work.
	if QueueGroupOwnership.Decide(&liveClaim, true, 8, 43, true) != QueueGroupAdmissionLeaseLost {
		t.Fatal("newer epoch must mean lease lost")
	}

	// Same epoch but a different generation: stale claim, fenced.
	if QueueGroupOwnership.Decide(&liveClaim, true, 7, 43, true) != QueueGroupAdmissionStaleEpoch {
		t.Fatal("stale generation must be fenced")
	}
}

func TestEquivalentWorkerQueueGroupsDoNotRequireTheAuthorityLease(t *testing.T) {
	if QueueGroupOwnership.Decide(&liveClaim, false, 0, 0, false) != QueueGroupAdmissionAdmit {
		t.Fatal("equivalent-worker groups must admit without the lease")
	}
}

func TestAuthoritativeWritesRequireTheSameLiveClaimBeforeEffectAndBeforeAcknowledgement(t *testing.T) {
	if !QueueGroupOwnership.MayCommitAuthoritativeWrite(&liveClaim, &liveClaim, deliveryNow) {
		t.Fatal("the same live claim must authorize the write")
	}

	// Lease expired between effect and acknowledgement: withhold.
	expired := liveClaim
	expired.LeaseExpiresAt = deliveryNow.Add(-time.Second)
	if QueueGroupOwnership.MayCommitAuthoritativeWrite(&expired, &expired, deliveryNow) {
		t.Fatal("an expired claim must not authorize the write")
	}

	// Split writer: a different candidate took over between effect and acknowledgement.
	successor := liveClaim
	successor.Epoch = 8
	successor.KvRevision = 43
	successor.CandidateId = "gru-controller-controller-2"
	if QueueGroupOwnership.MayCommitAuthoritativeWrite(&liveClaim, &successor, deliveryNow) {
		t.Fatal("a split writer must not be authorized")
	}

	if QueueGroupOwnership.MayCommitAuthoritativeWrite(&successor, &liveClaim, deliveryNow) {
		t.Fatal("a split writer must not be authorized (reversed)")
	}

	if QueueGroupOwnership.MayCommitAuthoritativeWrite(nil, &liveClaim, deliveryNow) {
		t.Fatal("a missing pre-effect claim must not authorize")
	}

	if QueueGroupOwnership.MayCommitAuthoritativeWrite(&liveClaim, nil, deliveryNow) {
		t.Fatal("a missing pre-acknowledgement claim must not authorize")
	}
}
