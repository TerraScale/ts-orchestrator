package bootstrapstart

import (
	"context"
	"errors"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
)

// A replacement whose controller lost its authority term never advances the
// slot or launches, and a term lost between the advance and the launch stops
// before the launch; a later replay resumes the admitted successor.
func TestFencedReplacementStopsBeforeEveryMutation(t *testing.T) {
	fixture, caller, fake, ledger := founderReplacementFixture(t)
	row := fixture.plan.Peers[0]
	retirement := signedSlotRetirement(t, fixture, ledger, row.Slot, fixture.root)
	replacer := &FounderReplacer{caller: *caller}
	launches := fake.launches
	lost := errors.New("authority lease lost")
	err := replacer.ReplaceFenced(t.Context(), row.Slot, retirement, func(context.Context) error { return lost })
	if !errors.Is(err, lost) {
		t.Fatalf("fenced replacement = %v", err)
	}
	if state := readFounderSlot(t, fixture, ledger, row.Slot); state.Head.Attempt != 1 || fake.launches != launches {
		t.Fatalf("a fenced-out replacement mutated: attempt %d, launches %d", state.Head.Attempt, fake.launches-launches)
	}
	checks := 0
	err = replacer.ReplaceFenced(t.Context(), row.Slot, retirement, func(context.Context) error {
		checks++
		if checks > 1 {
			return lost
		}
		return nil
	})
	if !errors.Is(err, lost) {
		t.Fatalf("term lost after the advance = %v", err)
	}
	if state := readFounderSlot(t, fixture, ledger, row.Slot); state.Head.Attempt != 2 || fake.launches != launches {
		t.Fatalf("term lost after the advance: attempt %d, launches %d", state.Head.Attempt, fake.launches-launches)
	}
	if err := replacer.ReplaceFenced(t.Context(), row.Slot, retirement, func(context.Context) error { return nil }); err != nil {
		t.Fatalf("resume admitted successor: %v", err)
	}
	if state := readFounderSlot(t, fixture, ledger, row.Slot); state.Head.Attempt != 2 || state.Result == nil ||
		fake.launches != launches+1 {
		t.Fatalf("resumed successor: attempt %d result %v launches %d", state.Head.Attempt, state.Result,
			fake.launches-launches)
	}
}

// An advance whose successor intent and evidence were stored but whose HEAD
// write failed is finished with those exact bytes on the next Replace,
// instead of blocking the slot behind ErrSlotAdvancePendingHead forever.
func TestReplacementFinishesAStagedAdvanceAfterAHeadWriteFailure(t *testing.T) {
	fixture, caller, objects, fake := newFounderRuntimeFixtureWithSetup(t, func(fixture *founderSignerFixture) {
		founderFixtureWithAdmissibleRelease(t, fixture)
	})
	for _, row := range fixture.plan.Peers {
		if err := caller.runPeer(t.Context(), row.Slot); err != nil {
			t.Fatalf("found %s: %v", row.Slot, err)
		}
	}
	ledger, err := caller.openLedger(t.Context(), fixture.current, fixture.baked.Roots)
	if err != nil {
		t.Fatal(err)
	}
	row := fixture.plan.Peers[0]
	retirement := signedSlotRetirement(t, fixture, ledger, row.Slot, fixture.root)
	launches := fake.launches
	objects.rejectSuffix = "head.json"
	if err := caller.replacePeer(t.Context(), row.Slot, retirement); err == nil {
		t.Fatal("replacement succeeded although its HEAD write failed")
	}
	objects.rejectSuffix = ""
	if _, err := caller.fresh(t.Context(), row.Slot); !errors.Is(err, bootstrap.ErrSlotAdvancePendingHead) {
		t.Fatalf("fault did not leave a staged advance: %v", err)
	}
	if err := caller.replacePeer(t.Context(), row.Slot, retirement); err != nil {
		t.Fatalf("resume staged advance: %v", err)
	}
	state := readFounderSlot(t, fixture, ledger, row.Slot)
	if state.Head.Attempt != 2 || state.Result == nil || state.Head.RetirementDigest != digest(retirement) ||
		fake.launches != launches+1 {
		t.Fatalf("staged advance not finished: attempt %d result %v launches %d", state.Head.Attempt, state.Result,
			fake.launches-launches)
	}
}

// A successor launch runs the founder anti-affinity check, so a replacer
// without the seed's placement source can never relaunch a slot. This is
// why NewAdmittedFounderReplacer wires the IMDS placement source.
func TestReplacementLaunchNeedsTheSeedPlacementSource(t *testing.T) {
	fixture, caller, fake, ledger := founderReplacementFixture(t)
	row := fixture.plan.Peers[0]
	retirement := signedSlotRetirement(t, fixture, ledger, row.Slot, fixture.root)
	withoutPlacement := *caller
	withoutPlacement.placement = nil
	launches := fake.launches
	if err := withoutPlacement.replacePeer(t.Context(), row.Slot, retirement); !errors.Is(err, ErrFounderRuntime) {
		t.Fatalf("replacement without a placement source = %v", err)
	}
	if fake.launches != launches {
		t.Fatal("replacement launched without an anti-affinity check")
	}
}
