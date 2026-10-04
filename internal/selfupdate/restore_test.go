package selfupdate

import (
	"errors"
	"os"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

// A restore never leaves a pending activation, and one interrupted after
// its intent was recorded (before the link moved) is finished by the next
// Watch, so neither the watchdog's restart nor the unit's start runs the
// rejected release.
func TestRestoreIsNotProofGatedAndAnInterruptedOneIsFinishedByWatch(t *testing.T) {
	f := newFixture(t)
	baked, err := Seed(f.layout, f.baked)
	if err != nil {
		t.Fatal(err)
	}
	rejected := f.stage([]byte("rejected orchestrator"))
	if err := f.layout.flipCurrent(rejected); err != nil {
		t.Fatal(err)
	}
	changed, err := Restore(f.layout, baked, rejected, testUnit)
	if err != nil || !changed {
		t.Fatalf("restore = %v %v", changed, err)
	}
	if _, pending, err := f.layout.Pending(); err != nil || pending {
		t.Fatalf("restore left a pending activation: %v %v", pending, err)
	}
	if again, err := Restore(f.layout, baked, rejected, testUnit); err != nil || again {
		t.Fatalf("repeated restore = %v %v", again, err)
	}
	if _, err := Restore(f.layout, rejected, baked, testUnit); !errors.Is(err, ErrKnownBad) {
		t.Fatalf("restore of the rejected release = %v", err)
	}

	// Interrupt a second restore right after its intent: the link still
	// selects the rejected release and nothing else changed.
	if err := f.layout.ClearRestartPending(testUnit); err != nil {
		t.Fatal(err)
	}
	other := f.stage([]byte("another rejected orchestrator"))
	if err := f.layout.flipCurrent(other); err != nil {
		t.Fatal(err)
	}
	intent, err := protocol.EncodeJSON(restoreIntent{Schema: restoreIntentSchema, Unit: testUnit, Target: baked, Rejected: other})
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(f.layout.restoreIntentPath(testUnit), intent, 0o644); err != nil {
		t.Fatal(err)
	}
	if outcome, _, err := Watch(f.layout, testUnit, ProofCheck{}, f.now); err != nil || outcome != OutcomeIdle {
		t.Fatalf("watch = %s %v", outcome, err)
	}
	if current, err := f.layout.Current(); err != nil || current != baked {
		t.Fatalf("current after watch = %s %v, want the restore target", current, err)
	}
	if bad, err := f.layout.KnownBad(); err != nil || !bad[other] {
		t.Fatalf("interrupted restore did not mark the rejected release: %v %v", bad, err)
	}
	if owed, err := f.layout.RestartPending(testUnit); err != nil || !owed {
		t.Fatalf("interrupted restore left no restart obligation: %v %v", owed, err)
	}
	if _, err := os.Lstat(f.layout.restoreIntentPath(testUnit)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("finished restore kept its intent: %v", err)
	}
}

// An interrupted restore is finished before a later activation changes the
// selection, so its recovery can never overwrite that activation or leave
// it with the rejected release as its predecessor.
func TestActivateFinishesAnInterruptedRestoreFirst(t *testing.T) {
	f := newFixture(t)
	baked, err := Seed(f.layout, f.baked)
	if err != nil {
		t.Fatal(err)
	}
	rejected := f.stage([]byte("rejected orchestrator"))
	next := f.stage([]byte("next orchestrator"))
	if err := f.layout.flipCurrent(rejected); err != nil {
		t.Fatal(err)
	}
	intent, err := protocol.EncodeJSON(restoreIntent{Schema: restoreIntentSchema, Unit: testUnit, Target: baked, Rejected: rejected})
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(f.layout.restoreIntentPath(testUnit), intent, 0o644); err != nil {
		t.Fatal(err)
	}
	activation, err := Activate(f.layout, next, testUnit, f.now, MinProofWindow)
	if err != nil {
		t.Fatal(err)
	}
	if activation.Previous != baked {
		t.Fatalf("activation predecessor = %s, want the restored release %s", activation.Previous, baked)
	}
	if bad, err := f.layout.KnownBad(); err != nil || !bad[rejected] {
		t.Fatalf("the finished restore did not mark the rejected release: %v %v", bad, err)
	}
	// A watchdog run now finds no intent to replay over the activation.
	if outcome, _, err := Watch(f.layout, testUnit, ProofCheck{}, f.now); err != nil || outcome != OutcomePending {
		t.Fatalf("watch = %s %v", outcome, err)
	}
	if current, err := f.layout.Current(); err != nil || current != next {
		t.Fatalf("current = %s %v, want the activated release", current, err)
	}
}

func TestAdmitEpochIsDurableAndMonotonic(t *testing.T) {
	f := newFixture(t)
	if epoch, err := f.layout.AcceptedEpoch(); err != nil || epoch != 0 {
		t.Fatalf("fresh epoch = %d %v", epoch, err)
	}
	for _, epoch := range []uint64{3, 3, 5} {
		if err := f.layout.AdmitEpoch(epoch); err != nil {
			t.Fatalf("admit %d: %v", epoch, err)
		}
	}
	if err := f.layout.AdmitEpoch(4); !errors.Is(err, ErrStaleEpoch) {
		t.Fatalf("older epoch = %v", err)
	}
	if err := f.layout.AdmitEpoch(0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("zero epoch = %v", err)
	}
	if epoch, err := f.layout.AcceptedEpoch(); err != nil || epoch != 5 {
		t.Fatalf("accepted epoch = %d %v", epoch, err)
	}
}
