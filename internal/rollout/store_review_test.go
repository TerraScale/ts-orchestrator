package rollout

import (
	"errors"
	"fmt"
	"maps"
	"testing"
)

// A known-bad digest that ages out of the bounded cell list keeps its durable
// record, so Begin still refuses it as a target and as a rollback target
// (#127 12119).
func TestStoreKnownBadOutlivesTheBoundedCellList(t *testing.T) {
	store, _ := testStore(t)
	ctx := t.Context()
	// A legacy cell whose list is full and starts with toDigest, which has
	// no durable record yet.
	legacy := CellState{SchemaVersion: SchemaVersion, Cell: "gru"}
	legacy.KnownBad = append(legacy.KnownBad, toDigest)
	for i := 1; len(legacy.KnownBad) < MaxKnownBad; i++ {
		legacy.KnownBad = append(legacy.KnownBad, fmt.Sprintf("%064x", i))
	}
	if err := store.writeCell(ctx, 7, legacy, 0); err != nil {
		t.Fatal(err)
	}
	// One more rejection ages toDigest out of the list.
	newest := fmt.Sprintf("%064x", 1<<40)
	if err := store.syncCell(ctx, Record{AuthorityEpoch: 7, RolloutID: "other", KnownBad: []string{newest}}); err != nil {
		t.Fatal(err)
	}
	cell, _, err := store.Cell(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, digest := range cell.KnownBad {
		if digest == toDigest {
			t.Fatal("fixture did not age toDigest out of the cell list")
		}
	}
	if _, _, err := store.Begin(ctx, testSpec("r1"), testStart); !errors.Is(err, ErrKnownBad) {
		t.Fatalf("aged-out known-bad target admitted: %v", err)
	}
	restore := testSpec("r2")
	restore.FromDigest, restore.ToDigest = toDigest, fromDigest
	if _, _, err := store.Begin(ctx, restore, testStart); !errors.Is(err, ErrInvalid) {
		t.Fatalf("aged-out known-bad rollback target admitted: %v", err)
	}
	if cell, _, _ := store.Cell(ctx); cell.ActiveRolloutID != "" {
		t.Fatalf("a refused Begin reserved the slot: %+v", cell)
	}
}

// Reusing a finished rollout ID for a different target is refused before
// the slot is reserved or the new target's attempt is counted (#127 12118).
func TestStoreBeginChecksAnExistingIDBeforeReserving(t *testing.T) {
	store, _ := testStore(t)
	ctx := t.Context()
	record, revision, err := store.Begin(ctx, testSpec("r1"), testStart)
	if err != nil {
		t.Fatal(err)
	}
	aborted, err := Apply(record, Event{Kind: EventAbort, At: testStart})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(ctx, revision, aborted); err != nil {
		t.Fatal(err)
	}
	before, _, err := store.Cell(ctx)
	if err != nil {
		t.Fatal(err)
	}
	reused := testSpec("r1")
	reused.ToDigest = otherBad
	if _, _, err := store.Begin(ctx, reused, testStart); !errors.Is(err, ErrConflict) {
		t.Fatalf("reused ID = %v", err)
	}
	after, _, err := store.Cell(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after.ActiveRolloutID != "" || !maps.Equal(after.Attempts, before.Attempts) {
		t.Fatalf("a refused Begin changed the cell: %+v -> %+v", before, after)
	}
	fresh := testSpec("r2")
	fresh.ToDigest = otherBad
	if _, _, err := store.Begin(ctx, fresh, testStart); err != nil {
		t.Fatalf("never-started candidate refused: %v", err)
	}
}
