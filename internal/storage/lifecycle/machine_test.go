package lifecycle

import (
	"errors"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

func mustApply(t *testing.T, state State, event Event, at time.Time) State {
	t.Helper()
	next, err := Apply(state, event, at, "")
	if err != nil {
		t.Fatalf("Apply(%s, %s): %v", state.Phase, event, err)
	}
	return next
}

func TestHappyPathReachesMountedAndDeleted(t *testing.T) {
	state := New(t0)
	steps := []struct {
		event Event
		want  Phase
	}{
		{EventCreateRequested, Creating},
		{EventCreated, Available},
		{EventAttachRequested, Attaching},
		{EventAttached, Attached},
		{EventFormatStarted, Formatting},
		{EventMounted, Mounted},
		{EventResizeRequested, Resizing},
		{EventResized, Mounted},
		{EventDetachRequested, Detaching},
		{EventDetached, Detached},
		{EventAttachRequested, Attaching},
		{EventDetached, Detached},
		{EventDeleteRequested, Deleting},
		{EventDeleted, Deleted},
	}
	for index, step := range steps {
		state = mustApply(t, state, step.event, t0.Add(time.Duration(index)*time.Second))
		if state.Phase != step.want {
			t.Fatalf("step %d %s: phase %s, want %s", index, step.event, state.Phase, step.want)
		}
		if !state.Since.Equal(t0.Add(time.Duration(index) * time.Second)) {
			t.Fatalf("step %d: Since was not restarted on progress", index)
		}
	}
	if _, err := Apply(state, EventCreateRequested, t0, ""); !errors.Is(err, ErrTerminal) {
		t.Fatalf("Deleted accepted another event: %v", err)
	}
	if _, err := Apply(state, EventHold, t0, "x"); !errors.Is(err, ErrTerminal) {
		t.Fatalf("Deleted accepted a hold: %v", err)
	}
}

func TestInvalidTransitionsAreRejectedWithoutMutation(t *testing.T) {
	cases := []struct {
		phase Phase
		event Event
	}{
		{Pending, EventAttachRequested},
		{Available, EventFormatStarted},
		{Mounted, EventFormatStarted},
		{Mounted, EventDeleteRequested},
		{Attached, EventDeleteRequested},
		{Attaching, EventMounted},
		{Detaching, EventAttachRequested},
		{Resizing, EventDetachRequested},
		{Available, EventResizeRequested},
		{Phase("bogus"), EventCreated},
	}
	for _, test := range cases {
		state := State{Phase: test.phase, Since: t0}
		got, err := Apply(state, test.event, t0.Add(time.Hour), "")
		if !errors.Is(err, ErrInvalidTransition) {
			t.Fatalf("%s on %s: err %v, want invalid", test.event, test.phase, err)
		}
		if got != state {
			t.Fatalf("%s on %s mutated state: %+v", test.event, test.phase, got)
		}
	}
}

func TestReobservingTransitionalPhaseKeepsDeadline(t *testing.T) {
	state := mustApply(t, State{Phase: Available, Since: t0}, EventAttachRequested, t0)
	again := mustApply(t, state, EventAttachRequested, t0.Add(9*time.Minute))
	if again != state {
		t.Fatalf("re-observing ATTACHING restarted the deadline: %+v", again)
	}
}

func TestAttachingTimesOutIntoStuckAndCannotBeResetByReobservation(t *testing.T) {
	deadlines := DefaultDeadlines()
	state := mustApply(t, State{Phase: Available, Since: t0}, EventAttachRequested, t0)
	if _, stuck := Check(state, t0.Add(9*time.Minute), deadlines); stuck {
		t.Fatal("ATTACHING became stuck before its deadline")
	}
	stuck, changed := Check(state, t0.Add(10*time.Minute), deadlines)
	if !changed || stuck.Phase != Stuck || stuck.StuckFrom != Attaching || stuck.Reason == "" {
		t.Fatalf("ATTACHING did not become stuck: %+v", stuck)
	}
	// The placement loop keeps observing ATTACHING; that must not unstick it.
	if again := mustApply(t, stuck, EventAttachRequested, t0.Add(11*time.Minute)); again != stuck {
		t.Fatalf("re-observed ATTACHING cleared stuck: %+v", again)
	}
	if got := Remediate(stuck, deadlines); got != RemediationForceDetachRetry {
		t.Fatalf("first stall remediation = %q", got)
	}
	// A late positive observation resolves the stall without a retry.
	if resolved := mustApply(t, stuck, EventAttached, t0.Add(12*time.Minute)); resolved.Phase != Attached || resolved.Attempts != 0 {
		t.Fatalf("late ATTACHED did not resolve stall: %+v", resolved)
	}
}

func TestRetryCountsAttemptsAndEscalatesToHostReplacement(t *testing.T) {
	deadlines := Deadlines{MaxAttachRetries: 2}
	state := State{Phase: Attaching, Since: t0}
	now := t0
	for attempt := uint32(0); attempt < 2; attempt++ {
		now = now.Add(deadlines.For(Attaching))
		stuck, changed := Check(state, now, deadlines)
		if !changed || stuck.Attempts != attempt {
			t.Fatalf("attempt %d: stuck=%+v", attempt, stuck)
		}
		if got := Remediate(stuck, deadlines); got != RemediationForceDetachRetry {
			t.Fatalf("attempt %d remediation = %q", attempt, got)
		}
		state = mustApply(t, stuck, EventRetry, now)
		if state.Phase != Attaching || state.Attempts != attempt+1 || !state.Since.Equal(now) {
			t.Fatalf("retry did not restart attaching: %+v", state)
		}
	}
	now = now.Add(deadlines.For(Attaching))
	stuck, _ := Check(state, now, deadlines)
	if got := Remediate(stuck, deadlines); got != RemediationReplaceHost {
		t.Fatalf("exhausted retries remediation = %q", got)
	}
}

func TestRemediationPerStalledPhase(t *testing.T) {
	cases := map[Phase]Remediation{
		Detaching:  RemediationForceDetach,
		Creating:   RemediationOperator,
		Formatting: RemediationOperator,
		Resizing:   RemediationOperator,
		Deleting:   RemediationOperator,
	}
	for phase, want := range cases {
		stuck, changed := Check(State{Phase: phase, Since: t0}, t0.Add(25*time.Hour), Deadlines{})
		if !changed {
			t.Fatalf("%s did not expire", phase)
		}
		if got := Remediate(stuck, Deadlines{}); got != want {
			t.Fatalf("%s remediation = %q, want %q", phase, got, want)
		}
	}
	if got := Remediate(State{Phase: Mounted}, Deadlines{}); got != RemediationNone {
		t.Fatalf("non-stuck remediation = %q", got)
	}
}

func TestStablePhasesNeverExpire(t *testing.T) {
	for _, phase := range []Phase{Pending, Available, Attached, Mounted, Detached, Deleted, Held, Stuck} {
		if _, changed := Check(State{Phase: phase, Since: t0}, t0.Add(1000*time.Hour), Deadlines{}); changed {
			t.Fatalf("%s expired", phase)
		}
	}
}

func TestCorruptOrFutureSinceExpiresImmediately(t *testing.T) {
	if _, changed := Check(State{Phase: Attaching}, t0, Deadlines{}); !changed {
		t.Fatal("zero Since did not expire")
	}
	if _, changed := Check(State{Phase: Attaching, Since: t0.Add(time.Hour)}, t0, Deadlines{}); !changed {
		t.Fatal("future Since did not expire")
	}
	if _, changed := Check(State{Phase: Attaching, Since: t0.Add(30 * time.Second)}, t0, Deadlines{}); changed {
		t.Fatal("small clock skew expired a fresh phase")
	}
}

func TestHoldAndReleaseRoundTrip(t *testing.T) {
	state := State{Phase: Mounted, Since: t0}
	held, err := Apply(state, EventHold, t0.Add(time.Minute), "unknown outcome")
	if err != nil || held.Phase != Held || held.HeldFrom != Mounted || held.Reason != "unknown outcome" {
		t.Fatalf("hold = %+v, %v", held, err)
	}
	if again := mustApply(t, held, EventHold, t0.Add(2*time.Minute)); again != held {
		t.Fatal("second hold changed state")
	}
	if _, err := Apply(held, EventDetachRequested, t0, ""); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("held volume accepted an effect: %v", err)
	}
	released := mustApply(t, held, EventRelease, t0.Add(3*time.Minute))
	if released.Phase != Mounted || released.Reason != "" {
		t.Fatalf("release = %+v", released)
	}
	if _, err := Apply(state, EventRelease, t0, ""); !errors.Is(err, ErrInvalidTransition) {
		t.Fatal("release of a non-held volume succeeded")
	}
}

func TestHoldFromStuckRemembersStalledPhase(t *testing.T) {
	stuck := State{Phase: Stuck, StuckFrom: Attaching, Since: t0, Attempts: 1}
	held := mustApply(t, stuck, EventHold, t0)
	if held.HeldFrom != Attaching || held.Attempts != 1 {
		t.Fatalf("hold from stuck = %+v", held)
	}
	if _, err := Apply(State{Phase: Mounted}, EventRetry, t0, ""); !errors.Is(err, ErrInvalidTransition) {
		t.Fatal("retry of a non-stuck volume succeeded")
	}
}

func TestReleaseKeepsAttemptsSoRetriesStillEscalate(t *testing.T) {
	deadlines := DefaultDeadlines()
	held := mustApply(t, State{Phase: Stuck, StuckFrom: Attaching, Since: t0, Attempts: deadlines.MaxAttachRetries}, EventHold, t0)
	released := mustApply(t, held, EventRelease, t0.Add(time.Minute))
	if released.Phase != Attaching || released.Attempts != deadlines.MaxAttachRetries {
		t.Fatalf("release = %+v, want Attaching with the attempts kept", released)
	}
	stuck, changed := Check(released, released.Since.Add(deadlines.Attaching+time.Second), deadlines)
	if !changed || Remediate(stuck, deadlines) != RemediationReplaceHost {
		t.Fatalf("a stall after hold/release did not escalate: %+v", stuck)
	}
}

func TestOCIAttachmentStateMapping(t *testing.T) {
	for state, want := range map[string]Event{
		"ATTACHING": EventAttachRequested, "ATTACHED": EventAttached,
		"DETACHING": EventDetachRequested, "DETACHED": EventDetached,
	} {
		if got, ok := FromOCIAttachmentState(state); !ok || got != want {
			t.Fatalf("%s -> %s %v", state, got, ok)
		}
	}
	if _, ok := FromOCIAttachmentState("FAULTY"); ok {
		t.Fatal("unknown OCI attachment state mapped to an event")
	}
}

func TestDeadlineValidation(t *testing.T) {
	if err := (Deadlines{}).Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (Deadlines{Attaching: -time.Second}).Validate(); err == nil {
		t.Fatal("negative deadline accepted")
	}
	if err := (Deadlines{Deleting: 48 * time.Hour}).Validate(); err == nil {
		t.Fatal("unbounded deadline accepted")
	}
	if err := (Deadlines{MaxAttachRetries: 11}).Validate(); err == nil {
		t.Fatal("unbounded retries accepted")
	}
	if got := (Deadlines{Attaching: time.Minute}).For(Attaching); got != time.Minute {
		t.Fatalf("custom deadline ignored: %s", got)
	}
}
