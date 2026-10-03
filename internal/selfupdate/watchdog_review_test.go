package selfupdate

import (
	"testing"
	"time"
)

// A proof produced after the activation deadline never confirms, while a
// proof produced in time still confirms at a late check (#127 12038).
func TestProofAfterTheDeadlineNeverConfirms(t *testing.T) {
	f := newFixture(t)
	baked, err := Seed(f.layout, f.baked)
	if err != nil {
		t.Fatal(err)
	}
	target := f.stage([]byte("slow to become ready"))
	activation, err := Activate(f.layout, target, testUnit, f.now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	late := f.proof(activation, activation.Deadline.Add(10*time.Second))
	outcome, _, err := Watch(f.layout, testUnit, late, activation.Deadline.Add(20*time.Second))
	if err != nil || outcome != OutcomeRolledBack {
		t.Fatalf("late proof = %s %v", outcome, err)
	}
	if current, _ := f.layout.Current(); current != baked {
		t.Fatalf("current = %s, want the restored %s", current, baked)
	}

	g := newFixture(t)
	if _, err := Seed(g.layout, g.baked); err != nil {
		t.Fatal(err)
	}
	target = g.stage([]byte("ready in time"))
	activation, err = Activate(g.layout, target, testUnit, g.now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	onTime := g.proof(activation, activation.Deadline.Add(-time.Second))
	if outcome, _, err := Watch(g.layout, testUnit, onTime, activation.Deadline.Add(10*time.Second)); err != nil || outcome != OutcomeConfirmed {
		t.Fatalf("on-time proof checked late = %s %v", outcome, err)
	}
}

// A rollback interrupted after it marked the target known bad and moved the
// link is finished, not confirmed by a proof the rejected process wrote
// afterwards; a target that is not current is never confirmed (#127 12041).
func TestInterruptedRollbackIsFinishedNotConfirmed(t *testing.T) {
	f := newFixture(t)
	baked, err := Seed(f.layout, f.baked)
	if err != nil {
		t.Fatal(err)
	}
	target := f.stage([]byte("rejected build"))
	activation, err := Activate(f.layout, target, testUnit, f.now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	// rollback: known bad, then the link moved, then the process died
	// before removing activation.json.
	if err := f.layout.markKnownBad(target); err != nil {
		t.Fatal(err)
	}
	if err := f.layout.flipCurrent(baked); err != nil {
		t.Fatal(err)
	}
	proof := f.proof(activation, f.now.Add(time.Second))
	outcome, _, err := Watch(f.layout, testUnit, proof, f.now.Add(2*time.Second))
	if err != nil || outcome != OutcomeRolledBack {
		t.Fatalf("interrupted rollback = %s %v", outcome, err)
	}
	if _, pending, _ := f.layout.Pending(); pending {
		t.Fatal("interrupted rollback left the activation pending")
	}
	if current, _ := f.layout.Current(); current != baked {
		t.Fatalf("current = %s", current)
	}

	// Without a committed rollback, a target that is not selected stays
	// pending instead of being confirmed.
	g := newFixture(t)
	gBaked, err := Seed(g.layout, g.baked)
	if err != nil {
		t.Fatal(err)
	}
	target = g.stage([]byte("not yet selected"))
	activation, err = Activate(g.layout, target, testUnit, g.now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.layout.flipCurrent(gBaked); err != nil {
		t.Fatal(err)
	}
	if outcome, _, err := Watch(g.layout, testUnit, g.proof(activation, g.now.Add(time.Second)), g.now.Add(2*time.Second)); err != nil ||
		outcome != OutcomePending {
		t.Fatalf("proof for an unselected target = %s %v", outcome, err)
	}
}

// A rollback leaves a restart obligation for the unit that only the unit's
// next start clears (#127 12039).
func TestRollbackLeavesARestartObligationUntilTheUnitStarts(t *testing.T) {
	f := newFixture(t)
	if _, err := Seed(f.layout, f.baked); err != nil {
		t.Fatal(err)
	}
	target := f.stage([]byte("never proves"))
	activation, err := Activate(f.layout, target, testUnit, f.now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if owed, err := f.layout.RestartPending(testUnit); err != nil || owed {
		t.Fatalf("restart owed before any rollback = %t %v", owed, err)
	}
	if outcome, _, err := Watch(f.layout, testUnit, ProofCheck{}, activation.Deadline); err != nil || outcome != OutcomeRolledBack {
		t.Fatalf("deadline = %s %v", outcome, err)
	}
	for range 2 {
		if outcome, _, err := Watch(f.layout, testUnit, ProofCheck{}, activation.Deadline.Add(time.Minute)); err != nil ||
			outcome != OutcomeIdle {
			t.Fatalf("later watch = %s %v", outcome, err)
		}
		if owed, err := f.layout.RestartPending(testUnit); err != nil || !owed {
			t.Fatalf("restart obligation lost = %t %v", owed, err)
		}
	}
	if _, err := Prepare(f.layout, testUnit, f.baked, ProofCheck{}, activation.Deadline.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if owed, err := f.layout.RestartPending(testUnit); err != nil || owed {
		t.Fatalf("unit start did not clear the obligation = %t %v", owed, err)
	}
}
