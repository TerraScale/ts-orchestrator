package selfupdate

import (
	"bytes"
	"errors"
	"os"
	"slices"
	"testing"
	"time"
)

func TestUnreadableActivationRejectsUnrelatedCurrentBeforeRecoveryEffects(t *testing.T) {
	f := newFixture(t)
	if _, err := Seed(f.layout, f.baked); err != nil {
		t.Fatal(err)
	}
	target := f.stage([]byte("damaged record target"))
	if _, err := Activate(f.layout, target, testUnit, f.now, time.Minute); err != nil {
		t.Fatal(err)
	}
	wire, err := os.ReadFile(f.layout.activationPath())
	if err != nil {
		t.Fatal(err)
	}
	wire = bytes.Replace(wire, []byte(`"schema"`), []byte(`"unknown":true,"schema"`), 1)
	if err := writeFileAtomic(f.layout.activationPath(), wire, 0o644); err != nil {
		t.Fatal(err)
	}
	unrelated := f.stage([]byte("independently selected release"))
	if err := f.layout.flipCurrent(unrelated); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Watch(f.layout, testUnit, ProofCheck{}, f.now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unrelated selection admitted recovery: %v", err)
	}
	if current, _ := f.layout.Current(); current != unrelated {
		t.Fatal("recovery changed unrelated current")
	}
	if owed, err := f.layout.RestartPending(testUnit); err != nil || owed {
		t.Fatalf("unrelated release acquired a restart obligation: %t %v", owed, err)
	}
	if bad, err := f.layout.KnownBad(); err != nil || bad[target] {
		t.Fatalf("inconsistent recovery marked target bad: %v", err)
	}
	if retained, err := os.ReadFile(f.layout.activationPath()); err != nil || !bytes.Equal(retained, wire) {
		t.Fatal("refusal changed unreadable activation evidence")
	}
}

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

// Units on one node share the current link: while one unit's activation is
// pending, the other unit never starts its unconfirmed target, and it starts
// again once the activation is confirmed or rolled back.
func TestPrepareRefusesAnotherUnitsUnconfirmedTarget(t *testing.T) {
	for _, confirm := range []bool{true, false} {
		f := newFixture(t)
		baked, err := Seed(f.layout, f.baked)
		if err != nil {
			t.Fatal(err)
		}
		target := f.stage([]byte("controller build"))
		activation, err := Activate(f.layout, target, ControllerUnit, f.now, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Prepare(f.layout, HostUnit, f.baked, ProofCheck{}, f.now.Add(time.Second)); !errors.Is(err, ErrInvalid) {
			t.Fatalf("host started on the controller's unconfirmed target: %v", err)
		}
		if outcome, err := Prepare(f.layout, ControllerUnit, f.baked, ProofCheck{}, f.now.Add(time.Second)); err != nil || outcome != OutcomePending {
			t.Fatalf("controller prepare = %s %v", outcome, err)
		}
		want, at := target, activation.Deadline
		if confirm {
			if outcome, _, err := Watch(f.layout, ControllerUnit, f.proof(activation, f.now.Add(2*time.Second)), f.now.Add(3*time.Second)); err != nil || outcome != OutcomeConfirmed {
				t.Fatalf("confirm = %s %v", outcome, err)
			}
			at = f.now.Add(4 * time.Second)
		} else {
			if outcome, _, err := Watch(f.layout, ControllerUnit, ProofCheck{}, activation.Deadline); err != nil || outcome != OutcomeRolledBack {
				t.Fatalf("rollback = %s %v", outcome, err)
			}
			want = baked
		}
		if _, err := Prepare(f.layout, HostUnit, f.baked, ProofCheck{}, at); err != nil {
			t.Fatalf("host prepare after the activation resolved (confirmed %v): %v", confirm, err)
		}
		if current, _ := f.layout.Current(); current != want {
			t.Fatalf("current = %s, want %s", current, want)
		}
	}
}

// Only a confirmation moves the known-good link, so the root steps never
// run the code of a release that has not proved itself: not after a
// rollback, a restore or an unreadable record. The image-baked release and
// a release rejected since are never delegates.
func TestKnownGoodMovesOnlyOnConfirmation(t *testing.T) {
	f := newFixture(t)
	baked, err := Seed(f.layout, f.baked)
	if err != nil {
		t.Fatal(err)
	}
	known := func(want string) {
		t.Helper()
		if got, err := f.layout.KnownGood(); err != nil || got != want {
			t.Fatalf("known good = %q %v, want %q", got, err, want)
		}
	}
	known("")
	if delegate, err := f.layout.Delegate(); err != nil || delegate != "" {
		t.Fatalf("delegate without a confirmation = %q %v", delegate, err)
	}
	// A rolled-back target stays out.
	bad := f.stage([]byte("unproven build"))
	activation, err := Activate(f.layout, bad, ControllerUnit, f.now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if outcome, _, err := Watch(f.layout, ControllerUnit, ProofCheck{}, activation.Deadline); err != nil || outcome != OutcomeRolledBack {
		t.Fatalf("rollback = %s %v", outcome, err)
	}
	known("")
	// A confirmed release becomes the delegate and is never pruned.
	good := f.stage([]byte("confirmed build"))
	activation, err = Activate(f.layout, good, ControllerUnit, f.now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if outcome, _, err := Watch(f.layout, ControllerUnit, f.proof(activation, f.now.Add(time.Second)), f.now.Add(2*time.Second)); err != nil || outcome != OutcomeConfirmed {
		t.Fatalf("confirm = %s %v", outcome, err)
	}
	known(good)
	if delegate, err := f.layout.Delegate(); err != nil || delegate != good {
		t.Fatalf("delegate = %q %v, want %s", delegate, err, good)
	}
	if removed, err := f.layout.PruneReleases(f.now.Add(48 * time.Hour)); err != nil || slices.Contains(removed, good) {
		t.Fatalf("pruned the known-good release: %v %v", removed, err)
	}
	// A restore to a release that never proved itself leaves the link, and
	// the rejected known-good release is no longer a delegate.
	never := f.stage([]byte("never run build"))
	if _, err := Restore(f.layout, never, good, ControllerUnit); err != nil {
		t.Fatal(err)
	}
	known(good)
	if delegate, err := f.layout.Delegate(); err != nil || delegate != "" {
		t.Fatalf("delegate after its rejection = %q %v", delegate, err)
	}
	// A record that cannot be resolved is moved aside without moving it.
	next := f.stage([]byte("unreadable record build"))
	if _, err := Activate(f.layout, next, ControllerUnit, f.now, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(f.layout.activationPath(), []byte(`{"target":"`+next+`"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(f.layout, ControllerUnit, f.baked, ProofCheck{}, f.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	known(good)
	if current, _ := f.layout.Current(); current == baked {
		t.Fatal("fixture: expected the unresolvable target to stay current")
	}
	// A known-good release whose bytes changed is refused.
	if err := f.layout.flipLink(knownGoodLink, never); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(f.layout.BinaryPath(never), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.layout.BinaryPath(never), []byte("other bytes"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := f.layout.Delegate(); err == nil {
		t.Fatal("a tampered known-good release was delegated to")
	}
}

// After the known-good release ran a step, the image-baked binary still
// rolls back an activation it left pending well past its deadline, and
// leaves records it cannot read to the release that wrote them.
func TestBackstopEnforcesDeadlinesTheDelegateIgnored(t *testing.T) {
	f := newFixture(t)
	baked, err := Seed(f.layout, f.baked)
	if err != nil {
		t.Fatal(err)
	}
	target := f.stage([]byte("ignored build"))
	activation, err := Activate(f.layout, target, HostUnit, f.now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if outcome, _, err := Backstop(f.layout, activation.Deadline.Add(OrphanedActivationGrace-time.Second)); err != nil || outcome != OutcomePending {
		t.Fatalf("backstop within the grace = %s %v", outcome, err)
	}
	data, err := os.ReadFile(f.layout.activationPath())
	if err != nil {
		t.Fatal(err)
	}
	newer := bytes.Replace(data, []byte(`"schema"`), []byte(`"future_field":true,"schema"`), 1)
	if err := writeFileAtomic(f.layout.activationPath(), newer, 0o644); err != nil {
		t.Fatal(err)
	}
	if outcome, _, err := Backstop(f.layout, activation.Deadline.Add(time.Hour)); err != nil || outcome != OutcomeIdle {
		t.Fatalf("backstop over a newer record = %s %v", outcome, err)
	}
	if err := writeFileAtomic(f.layout.activationPath(), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if outcome, _, err := Backstop(f.layout, activation.Deadline.Add(OrphanedActivationGrace)); err != nil || outcome != OutcomeRolledBack {
		t.Fatalf("backstop after the grace = %s %v", outcome, err)
	}
	if current, _ := f.layout.Current(); current != baked {
		t.Fatalf("current = %s, want %s", current, baked)
	}
	if owed, err := f.layout.RestartPending(HostUnit); err != nil || !owed {
		t.Fatalf("rollback owes no restart: %v %v", owed, err)
	}
}

func TestBackstopRollsBackDamagedTargetBeforeDeadline(t *testing.T) {
	f := newFixture(t)
	previous, err := Seed(f.layout, f.baked)
	if err != nil {
		t.Fatal(err)
	}
	target := f.stage([]byte("target damaged after activation"))
	if _, err := Activate(f.layout, target, HostUnit, f.now, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(f.layout.BinaryPath(target)); err != nil {
		t.Fatal(err)
	}
	outcome, _, err := Backstop(f.layout, f.now.Add(time.Second))
	if err != nil || outcome != OutcomeRolledBack {
		t.Fatalf("damaged target = %s, %v", outcome, err)
	}
	if current, _ := f.layout.Current(); current != previous {
		t.Fatal("trusted predecessor was not restored")
	}
}
