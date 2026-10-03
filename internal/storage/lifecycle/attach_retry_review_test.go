package lifecycle

import (
	"testing"
	"time"
)

// Repeated stalled attaches through the full force-detach-retry cycle keep
// their same-host retry count and escalate to host replacement; a successful
// attach resets it (#127 12045).
func TestAttachRetriesSurviveTheDetachReattachCycle(t *testing.T) {
	deadlines := DefaultDeadlines()
	state := State{Phase: Attaching, Since: t0}
	at := t0
	for cycle := uint32(0); ; cycle++ {
		at = at.Add(deadlines.For(Attaching) + time.Second)
		stuck, expired := Check(state, at, deadlines)
		if !expired || stuck.Phase != Stuck {
			t.Fatalf("cycle %d: attach did not stall: %+v", cycle, stuck)
		}
		remediation := Remediate(stuck, deadlines)
		if cycle >= deadlines.MaxAttachRetries {
			if remediation != RemediationReplaceHost {
				t.Fatalf("cycle %d: remediation = %s, want host replacement", cycle, remediation)
			}
			break
		}
		if remediation != RemediationForceDetachRetry {
			t.Fatalf("cycle %d: remediation = %s", cycle, remediation)
		}
		state = mustApply(t, stuck, EventRetry, at)
		for _, event := range []Event{EventDetachRequested, EventDetached, EventAttachRequested} {
			state = mustApply(t, state, event, at)
		}
		if state.Phase != Attaching || state.Attempts != cycle+1 {
			t.Fatalf("cycle %d: after reattach = %+v", cycle, state)
		}
	}
	attached := mustApply(t, State{Phase: Attaching, Since: t0, Attempts: 2}, EventAttached, t0)
	if attached.Attempts != 0 {
		t.Fatalf("a successful attach kept the retry count: %+v", attached)
	}
	detached := mustApply(t, mustApply(t, attached, EventDetachRequested, t0), EventDetached, t0)
	if reattach := mustApply(t, detached, EventAttachRequested, t0); reattach.Attempts != 0 {
		t.Fatalf("an ordinary reattach inherited retries: %+v", reattach)
	}
}
