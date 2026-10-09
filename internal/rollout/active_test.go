package rollout

import (
	"errors"
	"testing"
	"time"
)

func TestStoreActiveAndKnownBadFollowTheCellSlot(t *testing.T) {
	store, _ := testStore(t)
	ctx := t.Context()
	if _, _, ok, err := store.Active(ctx); err != nil || ok {
		t.Fatalf("empty cell has an active rollout: %v %v", ok, err)
	}
	if _, err := store.IsKnownBad(ctx, "not-a-digest"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("malformed digest = %v", err)
	}
	record, revision, err := store.Begin(ctx, testSpec("0000000000GBSYKHMNVHNRT6RH"), testStart)
	if err != nil {
		t.Fatal(err)
	}
	active, activeRevision, ok, err := store.Active(ctx)
	if err != nil || !ok || active.RolloutID != "0000000000GBSYKHMNVHNRT6RH" || activeRevision != revision {
		t.Fatalf("active = %s %d %v %v", active.RolloutID, activeRevision, ok, err)
	}
	if err := store.Settle(ctx, active, 7); err != nil {
		t.Fatalf("settling an active rollout: %v", err)
	}
	at := testStart
	for _, event := range []Event{{Kind: EventStart}, {Kind: EventPreflightPassed}, {Kind: EventAbort}} {
		at = at.Add(time.Second)
		event.At = at
		next, err := Apply(record, event)
		if err != nil {
			t.Fatal(err)
		}
		if revision, err = store.Commit(ctx, revision, next); err != nil {
			t.Fatal(err)
		}
		record = next
	}
	if record.Phase != PhaseRollingBack {
		t.Fatalf("phase = %s", record.Phase)
	}
	if bad, err := store.IsKnownBad(ctx, toDigest); err != nil || !bad {
		t.Fatalf("aborted target known bad = %v %v", bad, err)
	}
	if bad, err := store.IsKnownBad(ctx, fromDigest); err != nil || bad {
		t.Fatalf("predecessor known bad = %v %v", bad, err)
	}
}
