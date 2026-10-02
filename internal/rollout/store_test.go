package rollout

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

type epochFence struct{ epoch atomic.Uint64 }

func (fence *epochFence) Current() authority.Snapshot {
	return authority.Snapshot{Ready: true, Leader: true, Epoch: fence.epoch.Load(), Revision: 1, ExpiresAt: time.Now().Add(time.Hour)}
}

func (fence *epochFence) Guard(_ context.Context, epoch uint64) error {
	if epoch == 0 || epoch != fence.epoch.Load() {
		return authority.ErrFenced
	}
	return nil
}

func testStore(t *testing.T) (*Store, *epochFence) {
	t.Helper()
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS did not start")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	conn, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	fence := &epochFence{}
	fence.epoch.Store(7)
	store, err := OpenStore(t.Context(), js, "gru", 1, fence)
	if err != nil {
		t.Fatal(err)
	}
	return store, fence
}

func testSpec(id string) Spec {
	return Spec{RolloutID: id, Kind: KindController, Cell: "gru", FromDigest: fromDigest, ToDigest: toDigest,
		Units: controllers(), Policy: testPolicy(), AuthorityEpoch: 7}
}

func TestStoreBeginIsSingleActiveAndIdempotent(t *testing.T) {
	store, _ := testStore(t)
	ctx := t.Context()
	record, revision, err := store.Begin(ctx, testSpec("r1"), testStart)
	if err != nil || record.Phase != PhasePending || revision == 0 {
		t.Fatalf("begin = %s %d %v", record.Phase, revision, err)
	}
	again, againRevision, err := store.Begin(ctx, testSpec("r1"), testStart.Add(time.Minute))
	if err != nil || againRevision != revision || !again.StartedAt.Equal(record.StartedAt) {
		t.Fatalf("repeated begin was not idempotent: %d %v", againRevision, err)
	}
	other := testSpec("r2")
	other.ToDigest = otherBad
	if _, _, err := store.Begin(ctx, other, testStart); !errors.Is(err, ErrActiveRollout) {
		t.Fatalf("second active rollout: %v", err)
	}
	conflicting := testSpec("r1")
	conflicting.ToDigest = otherBad
	if _, _, err := store.Begin(ctx, conflicting, testStart); !errors.Is(err, ErrConflict) {
		t.Fatalf("rollout ID rebound: %v", err)
	}
	cell, _, err := store.Cell(ctx)
	if err != nil || cell.ActiveRolloutID != "r1" || cell.Attempts[toDigest] != 1 {
		t.Fatalf("cell = %+v %v", cell, err)
	}
}

func TestStoreCommitIsCASFencedAndRecordsKnownBad(t *testing.T) {
	store, fence := testStore(t)
	ctx := t.Context()
	record, revision, err := store.Begin(ctx, testSpec("r1"), testStart)
	if err != nil {
		t.Fatal(err)
	}
	started, err := Apply(record, Event{Kind: EventStart, At: testStart})
	if err != nil {
		t.Fatal(err)
	}
	newRevision, err := store.Commit(ctx, revision, started)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(ctx, revision, started); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale revision committed: %v", err)
	}
	tampered := started.Clone()
	tampered.ToDigest = otherBad
	if _, err := store.Commit(ctx, newRevision, tampered); !errors.Is(err, ErrInvalid) {
		t.Fatalf("immutable target changed: %v", err)
	}
	rebound := started.Clone()
	rebound.AuthorityEpoch = 8
	if _, err := store.Commit(ctx, newRevision, rebound); !errors.Is(err, ErrFenced) {
		t.Fatalf("epoch changed without adoption: %v", err)
	}

	// A new leader must adopt before writing; the old epoch is then fenced.
	fence.epoch.Store(8)
	if _, err := store.Commit(ctx, newRevision, started); !errors.Is(err, authority.ErrFenced) {
		t.Fatalf("fenced epoch committed: %v", err)
	}
	adopted, adoptedRevision, err := store.Adopt(ctx, "r1", 8)
	if err != nil || adopted.AuthorityEpoch != 8 {
		t.Fatalf("adopt = %d %v", adopted.AuthorityEpoch, err)
	}
	if _, _, err := store.Adopt(ctx, "r1", 7); !errors.Is(err, authority.ErrFenced) {
		t.Fatalf("older epoch adopted: %v", err)
	}

	passed, err := Apply(adopted, Event{Kind: EventPreflightPassed, At: testStart})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := Apply(passed, Event{Kind: EventPrepared, Unit: "ctrl-b", At: testStart})
	if err != nil {
		t.Fatal(err)
	}
	rolling, err := Apply(prepared, Event{Kind: EventUnhealthy, Unit: "ctrl-b", At: testStart})
	if err != nil {
		t.Fatal(err)
	}
	rollingRevision, err := store.Commit(ctx, adoptedRevision, rolling)
	if err != nil {
		t.Fatal(err)
	}
	cell, _, err := store.Cell(ctx)
	if err != nil || cell.ActiveRolloutID != "r1" || len(cell.KnownBad) != 1 || cell.KnownBad[0] != toDigest {
		t.Fatalf("known-bad target not durable before rollback: %+v %v", cell, err)
	}
	done, err := Apply(rolling, Event{Kind: EventRollbackServing, Unit: "ctrl-b", At: testStart})
	if err != nil || done.Phase != PhaseRolledBack {
		t.Fatalf("rollback = %s %v", done.Phase, err)
	}
	finalRevision, err := store.Commit(ctx, rollingRevision, done)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(ctx, finalRevision, done); !errors.Is(err, ErrTerminal) {
		t.Fatalf("terminal record rewritten: %v", err)
	}
	cell, _, err = store.Cell(ctx)
	if err != nil || cell.ActiveRolloutID != "" {
		t.Fatalf("cell slot not released: %+v %v", cell, err)
	}
	retry := testSpec("r2")
	retry.AuthorityEpoch = 8
	if _, _, err := store.Begin(ctx, retry, testStart); !errors.Is(err, ErrKnownBad) {
		t.Fatalf("known-bad digest restarted: %v", err)
	}
}

func TestStoreBeginEnforcesAttemptBudget(t *testing.T) {
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
	if _, _, err := store.Begin(ctx, testSpec("r2"), testStart); !errors.Is(err, ErrAttemptsExhausted) {
		t.Fatalf("second attempt with max_attempts=1: %v", err)
	}
	spec := testSpec("r3")
	spec.Policy.MaxAttempts = 2
	if _, _, err := store.Begin(ctx, spec, testStart); err != nil {
		t.Fatalf("raised attempt budget refused: %v", err)
	}
	wrongCell := testSpec("r4")
	wrongCell.Cell = "fra"
	if _, _, err := store.Begin(ctx, wrongCell, testStart); !errors.Is(err, ErrInvalid) {
		t.Fatalf("foreign cell accepted: %v", err)
	}
}
