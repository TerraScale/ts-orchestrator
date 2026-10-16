package rollout

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
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
}

func TestStoreCommitIsCASFencedAndRecordsKnownBad(t *testing.T) {
	store, fence := testStore(t)
	ctx := t.Context()
	testBindRelease(t, store, 1, toDigest)
	testBindRelease(t, store, 2, toDigest)
	record, revision, err := store.Begin(ctx, testSpec(testStageID(1)), testStart)
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
	moved := started.Clone()
	moved.Cell = "sfo"
	if _, err := store.Commit(ctx, newRevision, moved); !errors.Is(err, ErrInvalid) {
		t.Fatalf("immutable cell changed: %v", err)
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
	adopted, adoptedRevision, err := store.Adopt(ctx, testStageID(1), 8)
	if err != nil || adopted.AuthorityEpoch != 8 {
		t.Fatalf("adopt = %d %v", adopted.AuthorityEpoch, err)
	}
	if _, _, err := store.Adopt(ctx, testStageID(1), 7); !errors.Is(err, authority.ErrFenced) {
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
	if err != nil || cell.ActiveRolloutID != testStageID(1) || len(cell.KnownBad) != 1 || cell.KnownBad[0] != toDigest {
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
	retry := testSpec(testStageID(2))
	retry.AuthorityEpoch = 8
	if _, _, err := store.Begin(ctx, retry, testStart); !errors.Is(err, ErrKnownBad) {
		t.Fatalf("known-bad digest restarted: %v", err)
	}
}

func TestStoreBeginEnforcesAttemptBudget(t *testing.T) {
	store, _ := testStore(t)
	ctx := t.Context()
	testBindRelease(t, store, 2, toDigest)
	testBindRelease(t, store, 3, toDigest)
	cell, revision, err := store.Cell(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cell.Attempts = map[string]int{toDigest: 1}
	if err := store.writeCell(ctx, 7, cell, revision); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Begin(ctx, testSpec(testStageID(2)), testStart); !errors.Is(err, ErrAttemptsExhausted) {
		t.Fatalf("second attempt with max_attempts=1: %v", err)
	}
	spec := testSpec(testStageID(3))
	spec.Policy.MaxAttempts = 2
	if _, _, err := store.Begin(ctx, spec, testStart); err != nil {
		t.Fatalf("raised attempt budget refused: %v", err)
	}
	wrongCell := testSpec("0000000000MBP8NPP7ZMJB9DX8")
	wrongCell.Cell = "fra"
	if _, _, err := store.Begin(ctx, wrongCell, testStart); !errors.Is(err, ErrInvalid) {
		t.Fatalf("foreign cell accepted: %v", err)
	}
}

func TestStoreRefundsAnUntouchedAbortOnlyOnce(t *testing.T) {
	store, _ := testStore(t)
	ctx := t.Context()
	testBindRelease(t, store, 1, toDigest)
	testBindRelease(t, store, 2, toDigest)
	record, revision, err := store.Begin(ctx, testSpec(testStageID(1)), testStart)
	if err != nil {
		t.Fatal(err)
	}
	aborted := apply(t, record, Event{Kind: EventAbort, At: testStart})
	if _, err := store.Commit(ctx, revision, aborted); err != nil {
		t.Fatal(err)
	}
	fresh, _, err := store.Begin(ctx, testSpec(testStageID(2)), testStart)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := store.Settle(ctx, aborted, 7); err != nil {
			t.Fatal(err)
		}
	}
	cell, _, err := store.Cell(ctx)
	if err != nil || cell.ActiveRolloutID != fresh.RolloutID || cell.Attempts[toDigest] != 1 {
		t.Fatalf("old abort refunded the new attempt: %+v, %v", cell, err)
	}
}

func TestStoreBeginRepairsInterruptedCellRelease(t *testing.T) {
	store, _ := testStore(t)
	ctx := t.Context()
	testBindRelease(t, store, 1, toDigest)
	testBindRelease(t, store, 2, otherBad)
	testBindRelease(t, store, 3, strings.Repeat("d", 64))
	record, revision, err := store.Begin(ctx, testSpec(testStageID(1)), testStart)
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
	// Simulate a crash between the terminal record write and the slot release.
	cell, cellRevision, err := store.Cell(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cell.ActiveRolloutID = testStageID(1)
	cell.Attempts = map[string]int{toDigest: 1}
	if err := store.writeCell(ctx, 7, cell, cellRevision); err != nil {
		t.Fatal(err)
	}
	next := testSpec(testStageID(2))
	next.ToDigest = otherBad
	if _, _, err := store.Begin(ctx, next, testStart); err != nil {
		t.Fatalf("terminal rollout kept the cell slot: %v", err)
	}
	third := testSpec(testStageID(3))
	third.ToDigest = strings.Repeat("d", 64)
	if _, _, err := store.Begin(ctx, third, testStart); !errors.Is(err, ErrActiveRollout) {
		t.Fatalf("live rollout lost the cell slot: %v", err)
	}
}

func TestStoreBeginReclaimsASlotWhoseRecordWasNeverCreated(t *testing.T) {
	store, _ := testStore(t)
	ctx := t.Context()
	testBindRelease(t, store, 2, otherBad)
	// Simulate a crash between the cell claim and the record create.
	cell, revision, err := store.Cell(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cell.ActiveRolloutID = "0000000000EVVNWR99ZRR16PYM"
	cell.Attempts = map[string]int{toDigest: 1}
	if err := store.writeCell(ctx, 7, cell, revision); err != nil {
		t.Fatal(err)
	}
	next := testSpec(testStageID(2))
	next.ToDigest = otherBad
	if _, _, err := store.Begin(ctx, next, testStart); err != nil {
		t.Fatalf("a dangling claim kept the cell slot: %v", err)
	}
	// The abandoned ID can never create a live record afterwards.
	lost := testSpec("0000000000EVVNWR99ZRR16PYM")
	if _, _, err := store.createRecord(ctx, lost, cell, testStart); !errors.Is(err, ErrAbandonedRollout) {
		t.Fatalf("an abandoned rollout ID created a record: %v", err)
	}
	rollback, _, err := store.ReleasePins(ctx)
	if err != nil || !slices.Contains(rollback, next.FromDigest) {
		t.Fatalf("pins after abandonment recovery: %v %v", rollback, err)
	}
}

func TestStoreBeginReportsALoadFailureInsteadOfAnActiveRollout(t *testing.T) {
	store, _ := testStore(t)
	ctx := t.Context()
	testBindRelease(t, store, 2, toDigest)
	cell, revision, err := store.Cell(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cell.ActiveRolloutID = "000000000027AH1R37TB6WTXAS"
	cell.Attempts = map[string]int{toDigest: 1}
	if err := store.writeCell(ctx, 7, cell, revision); err != nil {
		t.Fatal(err)
	}
	if _, err := store.kv.Put(ctx, rolloutKey("000000000027AH1R37TB6WTXAS"), []byte(`{"schema_version":1}`)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Begin(ctx, testSpec(testStageID(2)), testStart); err == nil || errors.Is(err, ErrActiveRollout) {
		t.Fatalf("an unreadable active record reported %v, want the load failure", err)
	}
}

func TestStoreBeginRetryMustKeepThePlan(t *testing.T) {
	store, _ := testStore(t)
	ctx := t.Context()
	testBindRelease(t, store, 1, toDigest)
	if _, _, err := store.Begin(ctx, testSpec(testStageID(1)), testStart); err != nil {
		t.Fatal(err)
	}
	grown := testSpec(testStageID(1))
	grown.Units = append(grown.Units, Unit{ID: "ctrl-d", Group: "controllers"})
	if _, _, err := store.Begin(ctx, grown, testStart); !errors.Is(err, ErrConflict) {
		t.Fatalf("a retry with a different unit set returned the stored plan: %v", err)
	}
	tuned := testSpec(testStageID(1))
	tuned.Policy.BatchSoakSeconds++
	if _, _, err := store.Begin(ctx, tuned, testStart); !errors.Is(err, ErrConflict) {
		t.Fatalf("a retry with a different policy returned the stored plan: %v", err)
	}
}

func TestStoreRefundsTheAttemptOfACompletedRollout(t *testing.T) {
	store, _ := testStore(t)
	ctx := t.Context()
	testBindRelease(t, store, 1, toDigest)
	testBindRelease(t, store, 2, toDigest)
	record, revision, err := store.Begin(ctx, testSpec(testStageID(1)), testStart)
	if err != nil {
		t.Fatal(err)
	}
	at := testStart
	record, err = Apply(record, Event{Kind: EventStart, At: at})
	if err != nil {
		t.Fatal(err)
	}
	record, err = Apply(record, Event{Kind: EventPreflightPassed, At: at})
	if err != nil {
		t.Fatal(err)
	}
	for !record.Phase.Terminal() {
		record, at = soakWave(t, record, at)
	}
	if record.Phase != PhaseComplete {
		t.Fatalf("rollout ended %s", record.Phase)
	}
	if _, err := store.Commit(ctx, revision, record); err != nil {
		t.Fatal(err)
	}
	cell, _, err := store.Cell(ctx)
	if err != nil || cell.ActiveRolloutID != "" || cell.Attempts[toDigest] != 0 {
		t.Fatalf("cell after completion = %+v %v", cell, err)
	}
	// The proven digest can be targeted again, for example to restore it.
	restore := testSpec(testStageID(2))
	restore.FromDigest, restore.ToDigest = otherBad, toDigest
	if _, _, err := store.Begin(ctx, restore, at); err != nil {
		t.Fatalf("a completed digest could not be targeted again: %v", err)
	}
}

func TestBoundAttemptsEvictsKnownBadFirstAndKeepsTheTarget(t *testing.T) {
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
}

// An older controller reads the records a newer one wrote during a
// self-update: it skips their new members. A breaking change is a new
// schema_version, which it still refuses.
func TestStoreReadsTheRecordsOfANewerBinary(t *testing.T) {
	store, _ := testStore(t)
	ctx := t.Context()
	testBindRelease(t, store, 1, toDigest)
	record, _, err := store.Begin(ctx, testSpec(testStageID(1)), testStart)
	if err != nil {
		t.Fatal(err)
	}
	newer := func(key string, member string) []byte {
		entry, err := store.kv.Get(ctx, key)
		if err != nil {
			t.Fatal(err)
		}
		return []byte(strings.Replace(string(entry.Value()), "{", "{"+member+",", 1))
	}
	put := func(key string, value []byte) {
		if _, err := store.kv.Put(ctx, key, value); err != nil {
			t.Fatal(err)
		}
	}
	original := newer(rolloutKey(testStageID(1)), `"added_first":true`)
	cellWire := newer(cellKey, `"added_by_newer_binary":{"wave_budget":2}`)
	put(cellKey, cellWire)
	if cell, _, err := store.Cell(ctx); err != nil || cell.ActiveRolloutID != testStageID(1) {
		t.Fatalf("cell slot of a newer binary = %+v, %v", cell, err)
	}
	put(rolloutKey(testStageID(1)), newer(rolloutKey(testStageID(1)), `"added_by_newer_binary":true`))
	if loaded, _, err := store.Load(ctx, testStageID(1)); err != nil || loaded.RolloutID != record.RolloutID || loaded.Phase != record.Phase {
		t.Fatalf("record of a newer binary = %+v, %v", loaded, err)
	}
	for name, value := range map[string]string{
		"breaking schema version": strings.Replace(string(cellWire), `"schema_version":1`, `"schema_version":2`, 1),
		"duplicate member":        strings.Replace(string(cellWire), `"cell":"gru"`, `"cell":"gru","cell":"0000000000V4MRM46HP1SNGDYW"`, 1),
	} {
		put(cellKey, []byte(value))
		if _, _, err := store.Cell(ctx); err == nil {
			t.Errorf("%s: cell slot accepted", name)
		}
	}
	// A rollout policy is bound by its digest: an older controller never runs
	// a rollout under a policy it cannot fully read.
	policy, err := protocol.EncodeJSON(record.Policy)
	if err != nil {
		t.Fatal(err)
	}
	newerPolicy := strings.Replace(string(policy), "{", `{"max_unavailable":2,`, 1)
	newerDigest := sha256.Sum256([]byte(newerPolicy))
	put(rolloutKey(testStageID(1)), []byte(strings.NewReplacer(string(policy), newerPolicy,
		record.PolicyDigest, hex.EncodeToString(newerDigest[:])).Replace(string(newer(rolloutKey(testStageID(1)), `"added_later":true`)))))
	if _, _, err := store.Load(ctx, testStageID(1)); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "policy digest") {
		t.Fatalf("record whose policy has a newer member = %v, want the policy digest refused", err)
	}
	put(rolloutKey("000000000074NHTQ2N7GPEMR41"), []byte(`{"abandoned_rollout":"000000000074NHTQ2N7GPEMR41"}`))
	if _, _, err := store.Load(ctx, "000000000074NHTQ2N7GPEMR41"); !errors.Is(err, ErrAbandonedRollout) {
		t.Fatalf("digest-bound abandoned marker = %v", err)
	}
	// A newer record that happens to carry the marker's member is still a
	// record: it has a schema version.
	put(rolloutKey(testStageID(1)), []byte(strings.Replace(string(original), "{", fmt.Sprintf(`{"abandoned_rollout":%q,`, testStageID(1)), 1)))
	if loaded, _, err := store.Load(ctx, testStageID(1)); err != nil || loaded.RolloutID != testStageID(1) {
		t.Fatalf("record carrying the marker member = %+v, %v", loaded, err)
	}
}

// Retained release generations have no schema version of their own: an
// older controller reads a newer one's generation for a rollback, and the
// desired record's schema version still guards every read.
func TestReleaseGenerationsOfANewerBinary(t *testing.T) {
	store, _ := testStore(t)
	ctx := t.Context()
	for _, digest := range []string{fromDigest, toDigest} {
		if _, err := store.PublishRelease(ctx, 7, Release{Digest: digest, Receipt: []byte("r"), Actor: "ci", CreatedAt: testStart}); err != nil {
			t.Fatal(err)
		}
	}
	entry, err := store.kv.Get(ctx, generationKey("gru", 1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.kv.Put(ctx, generationKey("gru", 1), []byte(strings.Replace(string(entry.Value()), "{", `{"signed_by":"ci-leaf",`, 1))); err != nil {
		t.Fatal(err)
	}
	if back, err := store.RollbackRelease(ctx, 7, 1, "ops", testStart); err != nil || back.Digest != fromDigest || back.RollbackOf != 1 {
		t.Fatalf("rollback to a newer binary's generation = %+v, %v", back, err)
	}
	desired, err := store.kv.Get(ctx, desiredKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.kv.Put(ctx, desiredKey, []byte(strings.Replace(string(desired.Value()), `"schema_version":1`, `"schema_version":2`, 1))); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReleaseGeneration(ctx, 1); !errors.Is(err, ErrInvalid) {
		t.Fatalf("generation read under a breaking desired schema = %v", err)
	}
}

func TestReleasePinsIncludesHistoryActivePredecessorAndDurableKnownBad(t *testing.T) {
	store, _ := testStore(t)
	ctx := t.Context()
	for _, digest := range []string{strings.Repeat("c", 64), strings.Repeat("d", 64)} {
		if _, err := store.PublishRelease(ctx, 7, Release{Digest: digest, Actor: "ops", CreatedAt: testStart}); err != nil {
			t.Fatal(err)
		}
	}
	active := testSpec(testStageID(2))
	active.ToDigest = strings.Repeat("d", 64)
	if _, _, err := store.Begin(ctx, active, testStart); err != nil {
		t.Fatal(err)
	}
	bad := strings.Repeat("e", 64)
	if err := store.recordKnownBad(ctx, 7, bad); err != nil {
		t.Fatal(err)
	}
	rollback, knownBad, err := store.ReleasePins(ctx)
	if err != nil || !slices.Equal(rollback, []string{fromDigest, strings.Repeat("c", 64), strings.Repeat("d", 64)}) ||
		!slices.Equal(knownBad, []string{bad}) {
		t.Fatalf("pins: rollback=%v known_bad=%v err=%v", rollback, knownBad, err)
	}
	if err := store.kv.Delete(ctx, knownBadKey(bad)); err != nil {
		t.Fatal(err)
	}
	_, knownBad, err = store.ReleasePins(ctx)
	if err != nil || len(knownBad) != 0 {
		t.Fatalf("removed known-bad pin: %v %v", knownBad, err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err := store.ReleasePins(cancelled); err == nil {
		t.Fatal("cancelled state read returned complete pins")
	}
}
