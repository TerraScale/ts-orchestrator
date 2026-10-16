package rollout

import (
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/insights"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go/jetstream"
)

type historyReadKV struct {
	jetstream.KeyValue
	t      *testing.T
	reads  []string
	cancel context.CancelFunc
}

func (kv *historyReadKV) Get(ctx context.Context, key string) (jetstream.KeyValueEntry, error) {
	kv.t.Helper()
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > 5*time.Second {
		kv.t.Fatal("history read has no bounded deadline")
	}
	kv.reads = append(kv.reads, key)
	entry, err := kv.KeyValue.Get(ctx, key)
	if kv.cancel != nil {
		kv.cancel()
	}
	return entry, err
}

func (kv *historyReadKV) Keys(context.Context, ...jetstream.WatchOpt) ([]string, error) {
	kv.t.Fatal("history must not scan keys")
	return nil, nil
}

func (kv *historyReadKV) ListKeys(context.Context, ...jetstream.WatchOpt) (jetstream.KeyLister, error) {
	kv.t.Fatal("history must not scan keys")
	return nil, nil
}

func TestRecentRolloutsGenerationWindowAndReadBudget(t *testing.T) {
	for _, newest := range []uint64{0, 1, 64, 65, math.MaxUint64} {
		t.Run(fmt.Sprint(newest), func(t *testing.T) {
			store, _ := testStore(t)
			if newest > 0 {
				desired := Desired{SchemaVersion: SchemaVersion, Cell: store.cell, Release: Release{
					ID: generationKey(store.cell, newest), Generation: newest, Digest: toDigest, Actor: "ci", CreatedAt: testStart}}
				if err := store.writeDesired(t.Context(), 7, desired, 0); err != nil {
					t.Fatal(err)
				}
			}
			kv := &historyReadKV{KeyValue: store.kv, t: t}
			store.kv = kv
			rows, err := store.RecentRollouts(t.Context())
			if err != nil || len(rows) != 0 {
				t.Fatalf("empty history: %+v %v", rows, err)
			}
			want := []string{desiredKey, cellKey}
			for offset := range min(newest, uint64(ReleaseHistory)) {
				for _, domain := range []string{ControllerReleaseDomain, HostReleaseDomain} {
					want = append(want, entityid.Derive(domain, ReleaseRolloutID(newest-offset)))
				}
			}
			if !slices.Equal(kv.reads, want) {
				t.Fatalf("history reads = %v, want %v", kv.reads, want)
			}
		})
	}
}

func historyStage(t *testing.T, store *Store, generation uint64, domain string, at time.Time, terminal bool) Record {
	t.Helper()
	digest := fmt.Sprintf("%064x", generation)
	testBindRelease(t, store, generation, digest)
	spec := testSpec(entityid.Derive(domain, ReleaseRolloutID(generation)))
	spec.ToDigest = digest
	spec.Policy.MaxAttempts = 4
	if domain == HostReleaseDomain {
		spec.Kind = KindHost
	}
	record, revision, err := store.Begin(t.Context(), spec, at)
	if err != nil {
		t.Fatal(err)
	}
	if terminal {
		record = apply(t, record, Event{Kind: EventAbort, At: at})
		if _, err := store.Commit(t.Context(), revision, record); err != nil {
			t.Fatal(err)
		}
	}
	return record
}

func TestRecentRolloutsSparseStagesSortDedupAndActiveOutsideWindow(t *testing.T) {
	store, _ := testStore(t)
	old := historyStage(t, store, 1, ControllerReleaseDomain, testStart, true)
	a := historyStage(t, store, 2, ControllerReleaseDomain, testStart.Add(time.Hour), true)
	b := historyStage(t, store, 2, HostReleaseDomain, testStart.Add(time.Hour), true)
	active := historyStage(t, store, 65, ControllerReleaseDomain, testStart.Add(2*time.Hour), false)
	kv := &historyReadKV{KeyValue: store.kv, t: t}
	store.kv = kv
	rows, err := store.RecentRollouts(t.Context())
	want := []string{active.RolloutID, a.RolloutID, b.RolloutID}
	slices.Sort(want[1:])
	ids := func() []string {
		var ids []string
		for _, row := range rows {
			ids = append(ids, row.ID)
		}
		return ids
	}
	if err != nil || !slices.Equal(ids(), want) {
		t.Fatalf("sparse ordered stages: %+v %v, want %v", rows, err, want)
	}
	if len(kv.reads) != 130 {
		t.Fatalf("active dedup reads = %d, want 130", len(kv.reads))
	}
	if _, _, err := (&Store{kv: kv.KeyValue, cell: store.cell}).Load(t.Context(), old.RolloutID); err != nil {
		t.Fatal("old record lost:", err)
	}
	store.kv = kv.KeyValue
	testBindRelease(t, store, 1024, otherBad)
	kv.reads = nil
	store.kv = kv
	rows, err = store.RecentRollouts(t.Context())
	if err != nil || len(rows) != 1 || rows[0].ID != active.RolloutID || len(kv.reads) != 131 {
		t.Fatalf("active outside window: %+v %v (%d reads)", rows, err, len(kv.reads))
	}
}

func TestRecentRolloutsAbandonedStagesAndReadFailures(t *testing.T) {
	for _, failure := range []string{"missing", "abandoned", "malformed", "wrong-cell", "wrong-id", "bad-desired", "bad-slot", "cancel-before", "cancel-during"} {
		t.Run(failure, func(t *testing.T) {
			store, _ := testStore(t)
			testBindRelease(t, store, 1, toDigest)
			id := testStageID(1)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch failure {
			case "abandoned":
				if err := store.abandon(ctx, 7, id); err != nil {
					t.Fatal(err)
				}
			case "malformed", "bad-desired", "bad-slot":
				key := id
				if failure == "bad-desired" {
					key = desiredKey
				}
				if failure == "bad-slot" {
					key = cellKey
				}
				if _, err := store.kv.Put(ctx, key, []byte("{")); err != nil {
					t.Fatal(err)
				}
			case "wrong-cell", "wrong-id":
				record, err := New(testSpec(id), testStart)
				if err != nil {
					t.Fatal(err)
				}
				if failure == "wrong-cell" {
					record.Cell = "sfo"
				} else {
					record.RolloutID = testStageID(2)
				}
				wire, err := protocol.EncodeJSON(record)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := store.kv.Put(ctx, id, wire); err != nil {
					t.Fatal(err)
				}
			case "cancel-before":
				cancel()
			case "cancel-during":
				store.kv = &historyReadKV{KeyValue: store.kv, t: t, cancel: cancel}
			}
			rows, err := store.RecentRollouts(ctx)
			if failure == "missing" || failure == "abandoned" {
				if err != nil || len(rows) != 0 {
					t.Fatalf("genuine absence: %+v %v", rows, err)
				}
			} else if err == nil || len(rows) != 0 {
				t.Fatalf("failed read returned successful history: %+v %v", rows, err)
			}
			if (failure == "cancel-before" || failure == "cancel-during") && !errors.Is(err, context.Canceled) {
				t.Fatal("lost cancellation:", err)
			}
		})
	}
}

func TestRecentRolloutsRetainedOrphanDoesNotRaiseActiveDeadlineInsight(t *testing.T) {
	store, _ := testStore(t)
	testBindRelease(t, store, 1, toDigest)
	record, err := New(testSpec(testStageID(1)), testStart)
	if err != nil {
		t.Fatal(err)
	}
	record = apply(t, record, Event{Kind: EventStart, At: testStart})
	// A valid retained nonterminal record alone is not authority to hold the active slot.
	wire, err := protocol.EncodeJSON(record)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.kv.Create(t.Context(), record.RolloutID, wire); err != nil {
		t.Fatal(err)
	}
	rows, err := store.RecentRollouts(t.Context())
	if err != nil || len(rows) != 1 || rows[0].Done {
		t.Fatalf("retained nonterminal record: %+v %v", rows, err)
	}
	active, err := store.Rollouts(t.Context())
	if err != nil || len(active) != 0 {
		t.Fatalf("retained orphan became active: %+v %v", active, err)
	}
	engine := insights.NewEngine(insights.Config{Region: store.cell, Rollouts: store,
		Now: func() time.Time { return testStart.Add(3 * time.Hour) }})
	for _, insight := range engine.Evaluate(t.Context()).Insights {
		if insight.Entity.Kind == "rollout" {
			t.Fatalf("historical orphan raised an active deadline alert: %+v", insight)
		}
	}
}
