package rollout

import (
	"context"
	"github.com/nats-io/nats.go"

	"errors"
	"fmt"

	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats-server/v2/server"

	"github.com/nats-io/nats.go/jetstream"
)

type epochFence struct{ epoch atomic.Uint64 }

func (fence *epochFence) Current() authority.Snapshot {
	return authority.Snapshot{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Ready: true, Leader: true, Epoch: fence.epoch.Load(), Revision: 1, ExpiresAt: time.Now().Add(time.Hour)}
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

func testStageID(generation uint64) string {
	return entityid.Derive(ControllerReleaseDomain, ReleaseRolloutID(generation))
}

// Seed immutable generations for store contracts without depending on publication retries.
func testBindRelease(t *testing.T, store *Store, generation uint64, digest string) {
	t.Helper()
	ctx := t.Context()
	release := Release{ID: generationKey(store.cell, generation), Generation: generation,
		Digest: digest, Actor: "ci", RunNumber: int64(generation), CreatedAt: testStart}
	if err := store.retain(ctx, 7, release); err != nil {
		t.Fatal(err)
	}
	desired, revision, err := store.Desired(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if generation > desired.Generation() {
		if desired.Generation() > 0 {
			if err := store.retain(ctx, 7, desired.Release); err != nil {
				t.Fatal(err)
			}
		}
		desired.Release = release
		if err := store.writeDesired(ctx, 7, desired, revision); err != nil {
			t.Fatal(err)
		}
	}
}

func testSpec(id string) Spec {
	return Spec{RolloutID: id, Kind: KindController, Cell: "gru", FromDigest: fromDigest, ToDigest: toDigest,
		Units: controllers(), Policy: testPolicy(), AuthorityEpoch: 7}
}

func TestStoreBeginIsSingleActiveAndIdempotent(t *testing.T) {
	store, _ := testStore(t)
	ctx := t.Context()
	testBindRelease(t, store, 1, toDigest)
	testBindRelease(t, store, 2, otherBad)
	record, revision, err := store.Begin(ctx, testSpec(testStageID(1)), testStart)
	if err != nil || record.Phase != PhasePending || revision == 0 {
		t.Fatalf("begin = %s %d %v", record.Phase, revision, err)
	}
	again, againRevision, err := store.Begin(ctx, testSpec(testStageID(1)), testStart.Add(time.Minute))
	if err != nil || againRevision != revision || !again.StartedAt.Equal(record.StartedAt) {
		t.Fatalf("repeated begin was not idempotent: %d %v", againRevision, err)
	}
	other := testSpec(testStageID(2))
	other.ToDigest = otherBad
	if _, _, err := store.Begin(ctx, other, testStart); !errors.Is(err, ErrActiveRollout) {
		t.Fatalf("second active rollout: %v", err)
	}
	conflicting := testSpec(testStageID(1))
	conflicting.ToDigest = otherBad
	if _, _, err := store.Begin(ctx, conflicting, testStart); !errors.Is(err, ErrConflict) {
		t.Fatalf("rollout ID rebound: %v", err)
	}
	cell, _, err := store.Cell(ctx)
	if err != nil || cell.ActiveRolloutID != testStageID(1) || cell.Attempts[toDigest] != 1 {
		t.Fatalf("cell = %+v %v", cell, err)
	}

	{
		ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
		defer cancel()
		store, _ := testStore(t)
		reader, err := BindReader(store.kv, "gru")
		if err != nil {
			t.Fatal(err)
		}
		empty, revision, err := reader.Cell(ctx)
		if err != nil || revision != 0 || empty.SchemaVersion != SchemaVersion || empty.Cell != "gru" ||
			empty.ActiveRolloutID != "" || len(empty.KnownBad) != 0 || len(empty.Attempts) != 0 {
			t.Fatalf("fresh cell = %+v, %d, %v", empty, revision, err)
		}
		if _, err := store.kv.Get(ctx, cellKey); !errors.Is(err, jetstream.ErrKeyNotFound) {
			t.Fatalf("cell key existed before write: %v", err)
		}
		attempts := make(map[string]int, maxAttemptDigest+2)
		digest := func(index int) string { return fmt.Sprintf("%064x", index) }
		for index := range maxAttemptDigest + 2 {
			attempts[digest(index)] = 1
		}
		knownBad := []string{digest(5)}
		target := digest(0)
		boundAttempts(attempts, knownBad, target)
		if len(attempts) != maxAttemptDigest {
			t.Fatalf("bounded to %d entries, want %d", len(attempts), maxAttemptDigest)
		}
		if _, kept := attempts[digest(5)]; kept {
			t.Fatal("a known-bad digest's count was kept over others")
		}
		if attempts[target] != 1 {
			t.Fatal("the current target's count was evicted")
		}
		state := CellState{SchemaVersion: SchemaVersion, Cell: "gru", KnownBad: knownBad, Attempts: attempts}
		if err := state.validate("gru"); err != nil {
			t.Fatal(err)
		}
		wire, err := protocol.EncodeJSON(state)
		if err != nil {
			t.Fatal(err)
		}
		if len(wire) > maxRecordBytes {
			t.Fatalf("bounded cell exceeds the native value limit: %d", len(wire))
		}
		if err := store.writeCell(ctx, 7, state, 0); err != nil {
			t.Fatal(err)
		}
		reader, err = BindReader(store.kv, "gru")
		if err != nil {
			t.Fatal(err)
		}
		stored, revision, err := reader.Cell(ctx)
		if err != nil {
			t.Fatal(err)
		}
		storedWire, err := protocol.EncodeJSON(stored)
		if err != nil {
			t.Fatal(err)
		}
		if revision == 0 || string(storedWire) != string(wire) {
			t.Fatalf("independent cell differs from producer: revision %d, stored bytes %d, want %d", revision, len(storedWire), len(wire))
		}
		entry, err := store.kv.Get(ctx, cellKey)
		if err != nil {
			t.Fatal(err)
		}
		if entry.Bucket() != Bucket || entry.Key() != cellKey || entry.Operation() != jetstream.KeyValuePut ||
			entry.Revision() != revision || string(entry.Value()) != string(wire) {
			t.Fatalf("native cell record differs: bucket %s, key %s, operation %v, revision %d", entry.Bucket(), entry.Key(), entry.Operation(), entry.Revision())
		}
		status, err := store.kv.Status(ctx)
		if err != nil {
			t.Fatal(err)
		}
		config := status.Config()
		if config.Storage != jetstream.FileStorage || config.Replicas != 1 || status.History() != 8 || status.Values() != 1 {
			t.Fatalf("cell storage = %+v, history %d, values %d", config, status.History(), status.Values())
		}
		if len(stored.Attempts) != maxAttemptDigest {
			t.Fatalf("stored cell bounded to %d entries, want %d", len(stored.Attempts), maxAttemptDigest)
		}
		if _, kept := stored.Attempts[digest(5)]; kept {
			t.Fatal("stored cell kept a known-bad digest's count over others")
		}
		if stored.Attempts[target] != 1 {
			t.Fatal("stored cell evicted the current target's count")
		}
		for index := range maxAttemptDigest + 2 {
			count, present := stored.Attempts[digest(index)]
			want := index != 5 && index != 1
			if present != want || present && count != 1 {
				t.Fatalf("stored attempt %d = %d, present %v, want present %v with count 1", index, count, present, want)
			}
		}
	}
}
