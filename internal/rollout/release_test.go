package rollout

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
)

type recordCreateFailureKV struct {
	jetstream.KeyValue
	key string
	err error
}

func (kv recordCreateFailureKV) Create(ctx context.Context, key string, value []byte, opts ...jetstream.KVCreateOpt) (uint64, error) {
	if key == kv.key {
		return 0, kv.err
	}
	return kv.KeyValue.Create(ctx, key, value, opts...)
}

func TestAbandonedReleaseRefundsReservationAndAllowsFreshIssuance(t *testing.T) {
	store, _ := testStore(t)
	ctx := t.Context()
	first, err := store.PublishRelease(ctx, 7, Release{Digest: toDigest, Actor: "ci", RunNumber: 1, CreatedAt: testStart})
	if err != nil {
		t.Fatal(err)
	}
	id := entityid.Derive(ControllerReleaseDomain, ReleaseRolloutID(first.Generation))
	spec := testSpec(id)
	spec.Policy = DefaultPolicy()
	kv := store.kv
	failure := errors.New("record create unavailable")
	store.kv = recordCreateFailureKV{KeyValue: kv, key: id, err: failure}
	if _, _, err := store.Begin(ctx, spec, testStart); !errors.Is(err, failure) {
		t.Fatalf("record-create failure was not injected: %v", err)
	}
	store.kv = kv
	if cell, _, err := store.Cell(ctx); err != nil || cell.ActiveRolloutID != id || cell.Attempts[toDigest] != 1 {
		t.Fatalf("crash did not retain its reservation: %+v, %v", cell, err)
	}
	if _, _, err := store.Begin(ctx, spec, testStart); !errors.Is(err, ErrAbandonedRollout) {
		t.Fatalf("same-ID crash recovery = %v", err)
	}
	if cell, _, err := store.Cell(ctx); err != nil || cell.ActiveRolloutID != "" || cell.Attempts[toDigest] != 0 {
		t.Fatalf("abandonment did not refund its reservation: %+v, %v", cell, err)
	}
	if _, err := store.PublishRelease(ctx, 7, first); !errors.Is(err, ErrReleaseUnchanged) {
		t.Fatalf("old issuance renewed abandoned generation: %v", err)
	}
	next := first
	next.RunNumber, next.CreatedAt = 2, testStart.Add(time.Second)
	fresh, err := store.PublishRelease(ctx, 7, next)
	if err != nil || fresh.Generation != first.Generation+1 {
		t.Fatalf("fresh abandoned-release retry = %+v, %v", fresh, err)
	}
	spec.RolloutID = entityid.Derive(ControllerReleaseDomain, ReleaseRolloutID(fresh.Generation))
	if _, _, err := store.Begin(ctx, spec, next.CreatedAt); err != nil {
		t.Fatalf("fresh retry failed the one-attempt budget: %v", err)
	}
	for range 2 {
		if err := store.releaseSlot(ctx, 7, id); err != nil {
			t.Fatal(err)
		}
	}
	if cell, _, err := store.Cell(ctx); err != nil || cell.ActiveRolloutID != spec.RolloutID || cell.Attempts[toDigest] != 1 {
		t.Fatalf("old abandonment changed the fresh reservation: %+v, %v", cell, err)
	}
	if _, _, err := store.createRecord(ctx, testSpec(id), CellState{}, testStart); !errors.Is(err, ErrAbandonedRollout) {
		t.Fatalf("abandoned ID could create a late record: %v", err)
	}
}

func TestReleaseGenerationsPublishRollBackAndPause(t *testing.T) {
	store, _ := testStore(t)
	ctx := t.Context()
	if _, _, ok, err := desiredRelease(t, store); ok || err != nil {
		t.Fatalf("empty cell has a release: %v %v", ok, err)
	}
	first, err := store.PublishRelease(ctx, 7, Release{Digest: fromDigest, Receipt: []byte("r1"), Actor: "ci", CreatedAt: testStart})
	if err != nil || first.Generation != 1 {
		t.Fatalf("first publish = %+v %v", first, err)
	}
	if again, err := store.PublishRelease(ctx, 7, Release{Digest: fromDigest, Actor: "ci", CreatedAt: testStart}); !errors.Is(err, ErrReleaseUnchanged) || again.Generation != 1 {
		t.Fatalf("republishing the newest binary = %d %v", again.Generation, err)
	}
	second, err := store.PublishRelease(ctx, 7, Release{Digest: toDigest, Receipt: []byte("r2"), Delegation: []byte("d2"), Actor: "ci", CreatedAt: testStart})
	if err != nil || second.Generation != 2 {
		t.Fatalf("second publish = %+v %v", second, err)
	}
	if receipt, delegation, err := store.Receipt(ctx, fromDigest); err != nil || string(receipt) != "r1" || delegation != nil {
		t.Fatalf("receipt of a retained generation = %q %q %v", receipt, delegation, err)
	}
	if receipt, _, err := store.Receipt(ctx, otherBad); err != nil || receipt != nil {
		t.Fatalf("receipt of an unknown digest = %q %v", receipt, err)
	}

	back, err := store.RollbackRelease(ctx, 7, 1, "ops", testStart)
	if err != nil || back.Generation != 3 || back.Digest != fromDigest || back.RollbackOf != 1 || string(back.Receipt) != "r1" {
		t.Fatalf("rollback = %+v %v", back, err)
	}
	if kept, err := store.ReleaseGeneration(ctx, 2); err != nil || kept.Digest != toDigest {
		t.Fatalf("rollback rewrote history: %+v %v", kept, err)
	}
	if history, err := store.Releases(ctx, 2); err != nil || len(history) != 2 || history[0].Generation != 3 || history[1].Generation != 2 {
		t.Fatalf("history = %+v %v", history, err)
	}
	for _, to := range []uint64{0, 3, 9} {
		if _, err := store.RollbackRelease(ctx, 7, to, "ops", testStart); !errors.Is(err, ErrInvalid) {
			t.Fatalf("rollback to %d: %v", to, err)
		}
	}
	if _, err := store.RollbackRelease(ctx, 7, 1, "ops", testStart); !errors.Is(err, ErrReleaseUnchanged) {
		t.Fatalf("rolling back to the binary already desired: %v", err)
	}

	desired, err := store.PauseReleases(ctx, 7, true)
	if err != nil || !desired.Paused || desired.Generation() != 3 {
		t.Fatalf("pause = %+v %v", desired, err)
	}
	if desired, _, ok, err := desiredRelease(t, store); !ok || err != nil || !desired.Paused {
		t.Fatalf("pause did not persist: %+v %v", desired, err)
	}
	if desired, err := store.PauseReleases(ctx, 7, false); err != nil || desired.Paused {
		t.Fatalf("resume = %+v %v", desired, err)
	}
}

func TestReleaseWritesAreFencedAndRefuseKnownBadAndMalformedReleases(t *testing.T) {
	store, fence := testStore(t)
	ctx := t.Context()
	if _, err := store.PublishRelease(ctx, 6, Release{Digest: toDigest, Actor: "ci", CreatedAt: testStart}); !errors.Is(err, authority.ErrFenced) {
		t.Fatalf("stale epoch publish: %v", err)
	}
	if _, err := store.PauseReleases(ctx, 6, true); !errors.Is(err, authority.ErrFenced) {
		t.Fatalf("stale epoch pause: %v", err)
	}
	for name, release := range map[string]Release{
		"digest":     {Digest: "not-a-digest", Actor: "ci", CreatedAt: testStart},
		"actor":      {Digest: toDigest, Actor: "Not An Actor", CreatedAt: testStart},
		"time":       {Digest: toDigest, Actor: "ci"},
		"delegation": {Digest: toDigest, Delegation: []byte("d"), Actor: "ci", CreatedAt: testStart},
		"rollback":   {Digest: toDigest, RollbackOf: 1, Actor: "ci", CreatedAt: testStart},
		"revision":   {Digest: toDigest, SourceRevision: "main", Actor: "ci", CreatedAt: testStart},
		"run":        {Digest: toDigest, RunNumber: -1, Actor: "ci", CreatedAt: testStart},
	} {
		if _, err := store.PublishRelease(ctx, 7, release); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: malformed release published: %v", name, err)
		}
	}
	if err := store.recordKnownBad(ctx, fence.epoch.Load(), otherBad); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PublishRelease(ctx, 7, Release{Digest: otherBad, Actor: "ci", CreatedAt: testStart}); !errors.Is(err, ErrKnownBad) {
		t.Fatalf("known-bad publish: %v", err)
	}
	if desired, _, err := store.Desired(ctx); err != nil || desired.Generation() != 0 {
		t.Fatalf("refused publishes moved the cell: %+v %v", desired, err)
	}
}

func TestReleaseHistoryIsBounded(t *testing.T) {
	store, _ := testStore(t)
	ctx := t.Context()
	digests := []string{fromDigest, toDigest}
	for range ReleaseHistory + 2 {
		desired, _, err := store.Desired(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.PublishRelease(ctx, 7, Release{Digest: digests[desired.Generation()%2], Actor: "ci", CreatedAt: testStart}); err != nil {
			t.Fatal(err)
		}
	}
	newest := uint64(ReleaseHistory + 2)
	if _, err := store.ReleaseGeneration(ctx, newest-ReleaseHistory); !errors.Is(err, ErrNoRelease) {
		t.Fatalf("generation outside the history is still readable: %v", err)
	}
	if _, err := store.ReleaseGeneration(ctx, newest-ReleaseHistory+1); err != nil {
		t.Fatalf("oldest retained generation: %v", err)
	}
	if _, err := store.RollbackRelease(ctx, 7, 1, "ops", testStart); !errors.Is(err, ErrNoRelease) {
		t.Fatalf("rollback to a purged generation: %v", err)
	}
}

func desiredRelease(t *testing.T, store *Store) (Desired, Release, bool, error) {
	desired, _, err := store.Desired(t.Context())
	return desired, desired.Release, desired.Generation() > 0, err
}
