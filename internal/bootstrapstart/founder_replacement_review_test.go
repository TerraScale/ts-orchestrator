package bootstrapstart

import (
	"context"
	"errors"
	"testing"
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
