package lifecycle

import (
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

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
