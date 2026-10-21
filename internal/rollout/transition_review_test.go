package rollout

import (
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// Early reports and elapsed tick time never prove a soak: a replayed report
// is not counted, and the observations themselves must span the window
// (#127 12116).

// A completion event after its phase deadline cannot erase the deadline
// (#127 12131).
func TestLateCompletionEventsDoNotBypassDeadlines(t *testing.T) {
	record, at := startedCanary(t, controllers())
	deadline := at.Add(seconds(record.Policy.ProofDeadlineSeconds))
	late := apply(t, record, Event{Kind: EventPrepared, Unit: "ctrl-b", At: deadline.Add(time.Minute)})
	requireRollingBack(t, late, "prepare deadline")

	pending := newRecord(t, controllers(), testPolicy())
	pending = apply(t, pending, Event{Kind: EventStart, At: at})
	expired := at.Add(seconds(pending.Policy.PreflightSeconds))
	if next := apply(t, pending, Event{Kind: EventPreflightPassed, At: expired}); next.Phase != PhaseAborted {
		t.Fatalf("expired preflight advanced: %s", next.Phase)
	}

	// A first healthy report after the serving-proof deadline rolls back.
	soaking := apply(t, record, Event{Kind: EventPrepared, Unit: "ctrl-b", At: at})
	proofDeadline := soaking.PhaseDeadline
	next := apply(t, soaking, Event{Kind: EventHealthy, Unit: "ctrl-b", Health: health(proofDeadline, 10), At: proofDeadline})
	requireRollingBack(t, next, "serving-proof deadline")

	// In time, the same events still advance.
	if next := apply(t, record, Event{Kind: EventPrepared, Unit: "ctrl-b", At: deadline.Add(-time.Second)}); next.Phase != PhaseCanarySoak {
		t.Fatalf("in-time prepare = %s", next.Phase)
	}
}

// A failure reason at the event limit is stored within the record limit, so
// the rollback it triggers is never discarded by validation (#127 12121).
func TestNearLimitFailureReasonStillRollsBack(t *testing.T) {
	record, at := startedCanary(t, controllers())
	record = apply(t, record, Event{Kind: EventPrepared, Unit: "ctrl-b", At: at})
	reason := strings.Repeat("é", maxReason/2)
	for _, kind := range []EventKind{EventUnhealthy, EventHeld} {
		next, err := Apply(record, Event{Kind: kind, Unit: "ctrl-b", Reason: reason, At: at})
		if err != nil {
			t.Fatalf("%s with a %d-byte reason: %v", kind, len(reason), err)
		}
		requireRollingBack(t, next, "unit ctrl-b: ")
		if len(next.Reason) > maxReason || !utf8.ValidString(next.Reason) {
			t.Fatalf("stored reason is %d bytes, valid UTF-8 %t", len(next.Reason), utf8.ValidString(next.Reason))
		}
	}
	if _, err := Apply(record, Event{Kind: EventUnhealthy, Unit: "ctrl-b", Reason: reason + "x", At: at}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("over-limit input reason accepted: %v", err)
	}
}

// A soak cannot start or complete without a positive process identity
// (#127 12122).
func TestSoakRequiresAPositiveProcessIdentity(t *testing.T) {
	start := time.Unix(1_800_000_000, 0)
	digest := strings.Repeat("c", 64)
	sample := func(offset time.Duration, pid int) SoakSample {
		return SoakSample{At: start.Add(offset), ArtifactDigest: digest, OperationID: "0000000000VWA5N990CSNH40S5",
			Phase: "canary-serving", Serving: true, ProcessPID: pid}
	}
	soak := &Soak{Window: time.Minute, Digest: digest, Promoted: "canary-serving"}
	for _, s := range []SoakSample{sample(0, 0), sample(30*time.Second, 0), sample(55*time.Second, 0)} {
		if done, err := soak.Observe(s); done || err != nil {
			t.Fatalf("PID-less sample at %s = %t %v", s.At.Sub(start), done, err)
		}
	}
	if _, err := soak.Observe(sample(70*time.Second, 0)); err == nil || Classify(err) == ClassTerminal {
		t.Fatalf("a soak without any process identity = %v, want a transient gap", err)
	}
	soak = &Soak{Window: time.Minute, Digest: digest, Promoted: "canary-serving"}
	for _, s := range []SoakSample{sample(0, 0), sample(10*time.Second, 77), sample(50*time.Second, 0)} {
		if done, err := soak.Observe(s); done || err != nil {
			t.Fatalf("sample at %s = %t %v", s.At.Sub(start), done, err)
		}
	}
	// The window starts at the first identified sample and only that
	// process completes it.
	if done, err := soak.Observe(sample(65*time.Second, 0)); done || err != nil {
		t.Fatalf("PID-less sample completed the soak: %t %v", done, err)
	}
	if done, err := soak.Observe(sample(70*time.Second, 77)); !done || err != nil {
		t.Fatalf("identified completion = %t %v", done, err)
	}
}
