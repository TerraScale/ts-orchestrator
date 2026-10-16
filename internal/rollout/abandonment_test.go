package rollout

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

func TestStoreRecoversOriginalV1ActiveReservation(t *testing.T) {
	store, fence := testStore(t)
	ctx := t.Context()
	release, err := store.PublishRelease(ctx, 7, Release{Digest: toDigest, Actor: "ci", RunNumber: 1, CreatedAt: testStart})
	if err != nil {
		t.Fatal(err)
	}
	id := entityid.Derive(ControllerReleaseDomain, ReleaseRolloutID(release.Generation))
	spec := testSpec(id)
	spec.StartedAt = release.CreatedAt
	record, err := New(spec, testStart)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := protocol.EncodeJSON(record)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.kv.Create(ctx, id, wire); err != nil {
		t.Fatal(err)
	}
	// These are the previous writer's bytes, not a projection through the new type.
	cell := fmt.Sprintf(`{"schema_version":1,"cell":"gru","active_rollout_id":%q,"attempts":{%q:1}}`, id, toDigest)
	if _, err := store.kv.Create(ctx, cellKey, []byte(cell)); err != nil {
		t.Fatal(err)
	}
	restarted := &Store{kv: store.kv, fencer: fence, cell: "gru"}
	if active, _, ok, err := restarted.Active(ctx); err != nil || !ok || active.RolloutID != id {
		t.Fatalf("new reader cannot recover previous writer's active reservation: %+v, %t, %v", active, ok, err)
	}
	if pins, _, err := restarted.ReleasePins(ctx); err != nil || !slices.Contains(pins, fromDigest) {
		t.Fatalf("restart lost the active predecessor pin: %v, %v", pins, err)
	}
	fence.epoch.Store(8)
	adopted, revision, err := restarted.Adopt(ctx, id, 8)
	if err != nil || !adopted.StartedAt.Equal(record.StartedAt) {
		t.Fatalf("new leader cannot preserve the active observation clock: %+v, %v", adopted, err)
	}
	aborted := apply(t, adopted, Event{Kind: EventAbort, At: testStart.Add(time.Second)})
	if _, err := restarted.Commit(ctx, revision, aborted); err != nil {
		t.Fatal(err)
	}
	if cell, _, err := restarted.Cell(ctx); err != nil || cell.ActiveRolloutID != "" || cell.Attempts[toDigest] != 0 {
		t.Fatalf("new reader cannot settle the old reservation: %+v, %v", cell, err)
	}
}

func TestReleaseStageBindingRefusesTargetKindAndStartSwaps(t *testing.T) {
	for _, retained := range []bool{false, true} {
		for _, changed := range []string{"target", "kind", "start"} {
			t.Run(fmt.Sprintf("retained=%t/%s", retained, changed), func(t *testing.T) {
				store, _ := testStore(t)
				ctx := t.Context()
				first, err := store.PublishRelease(ctx, 7, Release{Digest: toDigest, Actor: "ci", RunNumber: 1, CreatedAt: testStart})
				if err != nil {
					t.Fatal(err)
				}
				if retained {
					if _, err := store.PublishRelease(ctx, 7, Release{Digest: otherBad, Actor: "ci", RunNumber: 2, CreatedAt: testStart.Add(time.Second)}); err != nil {
						t.Fatal(err)
					}
				}
				spec := testSpec(entityid.Derive(ControllerReleaseDomain, ReleaseRolloutID(first.Generation)))
				spec.StartedAt = first.CreatedAt
				switch changed {
				case "target":
					spec.ToDigest = otherBad
				case "kind":
					spec.Kind = KindHost
				case "start":
					spec.StartedAt = testStart.Add(time.Second)
				}
				if _, _, err := store.Begin(ctx, spec, testStart.Add(time.Second)); !errors.Is(err, ErrConflict) {
					t.Fatalf("changed %s was admitted: %v", changed, err)
				}
				if cell, _, err := store.Cell(ctx); err != nil || cell.ActiveRolloutID != "" || len(cell.Attempts) != 0 {
					t.Fatalf("refused stage charged a reservation: %+v, %v", cell, err)
				}
			})
		}
	}
}

func TestUnprovenOrphanNeverRefundsHistoricalAttempts(t *testing.T) {
	store, _ := testStore(t)
	ctx := t.Context()
	id := entityid.Derive("arbitrary", "orphan")
	state := CellState{SchemaVersion: SchemaVersion, Cell: "gru", ActiveRolloutID: id,
		Attempts: map[string]int{toDigest: 1, otherBad: 2}}
	if err := store.writeCell(ctx, 7, state, 0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Begin(ctx, testSpec(id), testStart); !errors.Is(err, ErrAbandonedRollout) {
		t.Fatalf("record-free ID was rebound from the incoming spec: %v", err)
	}
	if err := store.abandon(ctx, 7, id); err != nil {
		t.Fatal(err)
	}
	if err := store.releaseSlot(ctx, 7, id); err != nil {
		t.Fatal(err)
	}
	if cell, _, err := store.Cell(ctx); err != nil || cell.ActiveRolloutID != "" || !maps.Equal(cell.Attempts, state.Attempts) {
		t.Fatalf("unproven refund changed historical attempts: %+v, %v", cell, err)
	}
}

func TestAbandonedReservationRecoveryIsBoundAndExactlyOnce(t *testing.T) {
	for _, marked := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing record", true: "marker before refund"}[marked], func(t *testing.T) {
			store, fence := testStore(t)
			ctx := t.Context()
			first, err := store.PublishRelease(ctx, 7, Release{Digest: toDigest, Actor: "ci", RunNumber: 1, CreatedAt: testStart})
			if err != nil {
				t.Fatal(err)
			}
			oldID := entityid.Derive(ControllerReleaseDomain, ReleaseRolloutID(first.Generation))
			state := CellState{SchemaVersion: SchemaVersion, Cell: "gru", ActiveRolloutID: oldID,
				Attempts: map[string]int{toDigest: 1, otherBad: 2}}
			if err := store.writeCell(ctx, 7, state, 0); err != nil {
				t.Fatal(err)
			}
			swap := testSpec(oldID)
			swap.ToDigest = otherBad
			if _, _, err := store.Begin(ctx, swap, testStart); !errors.Is(err, ErrConflict) {
				t.Fatalf("same reserved ID swapped targets: %v", err)
			}
			if marked {
				if err := store.abandon(ctx, 7, oldID); err != nil {
					t.Fatal(err)
				}
				fence.epoch.Store(8)
				if err := store.releaseSlot(ctx, 7, oldID); !errors.Is(err, authority.ErrFenced) {
					t.Fatalf("stale leader refunded the slot: %v", err)
				}
				fence.epoch.Store(7)
			}
			testBindRelease(t, store, 2, toDigest)
			fresh := testSpec(testStageID(2))
			fresh.Policy = DefaultPolicy()
			if _, _, err := store.Begin(ctx, fresh, testStart); err != nil {
				t.Fatalf("same digest could not start under one-attempt policy: %v", err)
			}
			for range 2 {
				if err := store.releaseSlot(ctx, 7, oldID); err != nil {
					t.Fatal(err)
				}
			}
			after, _, err := store.Cell(ctx)
			if err != nil || after.ActiveRolloutID != fresh.RolloutID ||
				!maps.Equal(after.Attempts, state.Attempts) || len(after.KnownBad) != 0 {
				t.Fatalf("refund changed the wrong reservation: %+v, %v", after, err)
			}
			if _, _, err := store.createRecord(ctx, testSpec(oldID), state, testStart); !errors.Is(err, ErrAbandonedRollout) {
				t.Fatalf("late record creation escaped marker: %v", err)
			}
		})
	}
}

type recordWinsAbandonKV struct {
	jetstream.KeyValue
	key    string
	record []byte
}

func (kv recordWinsAbandonKV) Create(ctx context.Context, key string, value []byte, opts ...jetstream.KVCreateOpt) (uint64, error) {
	if key == kv.key {
		if _, err := kv.KeyValue.Create(ctx, key, kv.record); err != nil {
			return 0, err
		}
	}
	return kv.KeyValue.Create(ctx, key, value, opts...)
}

func TestAbandonmentDoesNotRefundARecordThatWonCreation(t *testing.T) {
	store, _ := testStore(t)
	ctx := t.Context()
	id := entityid.Derive("abandoned", "record wins")
	state := CellState{SchemaVersion: SchemaVersion, Cell: "gru", ActiveRolloutID: id,
		Attempts: map[string]int{toDigest: 1}}
	if err := store.writeCell(ctx, 7, state, 0); err != nil {
		t.Fatal(err)
	}
	record, err := New(testSpec(id), testStart)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := protocol.EncodeJSON(record)
	if err != nil {
		t.Fatal(err)
	}
	store.kv = recordWinsAbandonKV{KeyValue: store.kv, key: id, record: wire}
	if _, _, err := store.Begin(ctx, testSpec(entityid.Derive("abandoned", "loser")), testStart); !errors.Is(err, ErrActiveRollout) {
		t.Fatalf("reclamation of concurrent record = %v", err)
	}
	if after, _, err := store.Cell(ctx); err != nil || after.ActiveRolloutID != id || !maps.Equal(after.Attempts, state.Attempts) {
		t.Fatalf("live record's reservation refunded: %+v, %v", after, err)
	}
}

func TestAbandonedMarkerRejectsMalformedIdentity(t *testing.T) {
	store, _ := testStore(t)
	ctx := t.Context()
	id := entityid.Derive("abandoned", "binding")
	marker := `{"abandoned_rollout":"` + id + `"}`
	for name, wire := range map[string]string{
		"invalid ID":    `{"abandoned_rollout":"short"}`,
		"wrong type":    `{"abandoned_rollout":true}`,
		"wrong ID":      strings.Replace(marker, id, entityid.New(), 1),
		"record fields": strings.Replace(marker, "{", `{"rollout_id":"`+id+`",`, 1),
		"duplicate":     strings.Replace(marker, "{", `{"abandoned_rollout":"`+id+`",`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := store.kv.Put(ctx, id, []byte(wire)); err != nil {
				t.Fatal(err)
			}
			if _, _, err := store.Load(ctx, id); err == nil || errors.Is(err, ErrAbandonedRollout) {
				t.Fatalf("invalid data became abandoned proof: %v", err)
			}
			if _, _, err := store.ReleasePins(ctx); err == nil {
				t.Fatal("invalid abandoned proof was hidden from pins")
			}
		})
	}
	if _, err := store.kv.Put(ctx, id, []byte(marker)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Load(ctx, id); !errors.Is(err, ErrAbandonedRollout) {
		t.Fatalf("original v1 marker refused: %v", err)
	}
	if _, _, err := store.ReleasePins(ctx); err != nil {
		t.Fatalf("retained v1 marker broke pin inventory: %v", err)
	}
}

func TestRetryUntouchedReleaseRequiresBoundProofAndFreshLineage(t *testing.T) {
	for _, mode := range []string{"absent", "wrong marker ID", "wrong record target", "wrong kind", "wrong start", "pending peer", "old run", "old issuance", "rollback ancestry", "known bad"} {
		t.Run(mode, func(t *testing.T) {
			store, _ := testStore(t)
			ctx := t.Context()
			first, err := store.PublishRelease(ctx, 7, Release{Digest: toDigest, Actor: "ci", RunNumber: 1, CreatedAt: testStart})
			if err != nil {
				t.Fatal(err)
			}
			id := entityid.Derive(ControllerReleaseDomain, ReleaseRolloutID(first.Generation))
			if mode != "absent" {
				marker := abandonedMarker{AbandonedRollout: id}
				if mode == "wrong marker ID" {
					marker.AbandonedRollout = entityid.New()
				}
				wire, err := protocol.EncodeJSON(marker)
				if err != nil {
					t.Fatal(err)
				}
				if strings.HasPrefix(mode, "wrong record") || mode == "wrong kind" || mode == "wrong start" {
					spec := testSpec(id)
					spec.StartedAt = first.CreatedAt
					switch mode {
					case "wrong record target":
						spec.ToDigest = otherBad
					case "wrong kind":
						spec.Kind = KindHost
					case "wrong start":
						spec.StartedAt = testStart.Add(time.Second)
					}
					record, err := New(spec, spec.StartedAt)
					if err != nil {
						t.Fatal(err)
					}
					wire, err = protocol.EncodeJSON(apply(t, record, Event{Kind: EventAbort, At: spec.StartedAt}))
					if err != nil {
						t.Fatal(err)
					}
				}
				if _, err := store.kv.Create(ctx, id, wire); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "pending peer" {
				spec := testSpec(entityid.Derive(HostReleaseDomain, ReleaseRolloutID(first.Generation)))
				spec.Kind = KindHost
				if _, _, err := store.Begin(ctx, spec, testStart); err != nil {
					t.Fatal(err)
				}
			}
			next := first
			next.RunNumber, next.CreatedAt = 2, testStart.Add(time.Second)
			switch mode {
			case "old run":
				next.RunNumber = first.RunNumber
			case "old issuance":
				next.CreatedAt = first.CreatedAt
			case "rollback ancestry":
				next.RollbackOf = first.Generation
			case "known bad":
				if err := store.recordKnownBad(ctx, 7, toDigest); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := store.PublishRelease(ctx, 7, next); err == nil {
				t.Fatal("unbound or non-fresh proof renewed observation")
			}
			if desired, _, err := store.Desired(ctx); err != nil || desired.Generation() != first.Generation {
				t.Fatalf("refused retry rewrote desired: %+v, %v", desired, err)
			}
		})
	}
}

type failedPurgeKV struct{ jetstream.KeyValue }

func (kv failedPurgeKV) Purge(context.Context, string, ...jetstream.KVDeleteOpt) error {
	return errors.New("retention purge unavailable")
}

func TestAbandonedReservationUsesAllReadableRetainedGenerations(t *testing.T) {
	store, _ := testStore(t)
	ctx := t.Context()
	store.kv = failedPurgeKV{KeyValue: store.kv}
	first, err := store.PublishRelease(ctx, 7, Release{Digest: toDigest, Actor: "ci", CreatedAt: testStart})
	if err != nil {
		t.Fatal(err)
	}
	for generation := 2; generation <= ReleaseHistory+1; generation++ {
		digest := fromDigest
		if generation%2 == 0 {
			digest = otherBad
		}
		if _, err := store.PublishRelease(ctx, 7, Release{Digest: digest, Actor: "ci", CreatedAt: testStart}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.ReleaseGeneration(ctx, first.Generation); err != nil {
		t.Fatalf("proof really was purged: %v", err)
	}
	id := entityid.Derive(ControllerReleaseDomain, ReleaseRolloutID(first.Generation))
	_, _, found, err := store.releaseStage(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Error("readable retained generation omitted by the new release-stage resolver")
	}
	state := CellState{SchemaVersion: SchemaVersion, Cell: "gru", ActiveRolloutID: id, Attempts: map[string]int{toDigest: 1}}
	if err := store.writeCell(ctx, 7, state, 0); err != nil {
		t.Fatal(err)
	}
	if err := store.abandon(ctx, 7, id); err != nil {
		t.Fatal(err)
	}
	if err := store.releaseSlot(ctx, 7, id); err != nil {
		t.Fatal(err)
	}
	after, _, err := store.Cell(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after.Attempts[toDigest] != 0 {
		t.Errorf("readable immutable proof was ignored; old charge remains %d", after.Attempts[toDigest])
	}
}
