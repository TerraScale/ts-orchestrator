package rollout

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go/jetstream"
)

type stageLookupKV struct {
	jetstream.KeyValue
	reads  []string
	cancel context.CancelFunc
}

func (kv *stageLookupKV) Get(ctx context.Context, key string) (jetstream.KeyValueEntry, error) {
	kv.reads = append(kv.reads, key)
	entry, err := kv.KeyValue.Get(ctx, key)
	if key == desiredKey && kv.cancel != nil {
		kv.cancel()
	}
	return entry, err
}

func (*stageLookupKV) WatchFiltered(context.Context, []string, ...jetstream.WatchOpt) (jetstream.KeyWatcher, error) {
	return nil, errors.New("stage lookup must not inventory operational history")
}

func TestReleaseStageUsesOnlyDesiredAndMatchingGeneration(t *testing.T) {
	for _, domain := range []string{ControllerReleaseDomain, HostReleaseDomain} {
		t.Run(domain, func(t *testing.T) {
			store, _ := testStore(t)
			ctx := t.Context()
			testBindRelease(t, store, 1, toDigest)
			testBindRelease(t, store, 1024, otherBad)
			for generation := range 128 {
				if err := store.abandon(ctx, 7, entityid.Derive("old-stage", ReleaseRolloutID(uint64(generation)))); err != nil {
					t.Fatal(err)
				}
			}
			unrelated := entityid.Derive("unrelated", "broken operational record")
			if _, err := store.kv.Put(ctx, unrelated, []byte("{")); err != nil {
				t.Fatal(err)
			}
			kv := &stageLookupKV{KeyValue: store.kv}
			store.kv = kv
			kind := KindController
			if domain == HostReleaseDomain {
				kind = KindHost
			}
			for _, generation := range []uint64{1024, 1} {
				kv.reads = nil
				id := entityid.Derive(domain, ReleaseRolloutID(generation))
				release, gotKind, found, err := store.releaseStage(ctx, id)
				if err != nil || !found || release.Generation != generation || gotKind != kind {
					t.Fatalf("stage %d: %+v %s found=%t, %v", generation, release, gotKind, found, err)
				}
				want := []string{desiredKey}
				if generation != 1024 {
					want = append(want, generationKey(store.cell, generation))
				}
				if !slices.Equal(kv.reads, want) {
					t.Fatalf("stage %d read %v, want %v", generation, kv.reads, want)
				}
			}
			id := entityid.Derive(domain, ReleaseRolloutID(1))
			spec := testSpec(id)
			spec.Kind = kind
			failure := errors.New("record Create failed")
			store.kv = recordCreateFailureKV{KeyValue: kv, key: id, err: failure}
			if _, _, err := store.Begin(ctx, spec, testStart); !errors.Is(err, failure) {
				t.Fatalf("historical admission did not reach record Create: %v", err)
			}
			store.kv = kv
			kv.reads = nil
			if err := store.RecoverReservation(ctx, 7); err != nil {
				t.Fatal(err)
			}
			proofReads := 0
			for _, key := range kv.reads {
				if key == generationKey(store.cell, 1) {
					proofReads++
				}
				if key == unrelated {
					t.Fatal("recovery read unrelated operational history")
				}
			}
			if proofReads != 1 {
				t.Fatalf("recovery read generation proof %d times, want 1", proofReads)
			}
			if state, _, err := store.Cell(ctx); err != nil || state.ActiveRolloutID != "" || state.Attempts[toDigest] != 0 {
				t.Fatalf("historical recovery lost its refund: %+v, %v", state, err)
			}
		})
	}
}

func TestReleaseStageRequiresReadableValidatedHistoricalProof(t *testing.T) {
	for _, changed := range []string{"purged", "corrupt", "misbound", "unavailable", "cancelled"} {
		t.Run(changed, func(t *testing.T) {
			store, _ := testStore(t)
			ctx := t.Context()
			testBindRelease(t, store, 1, toDigest)
			testBindRelease(t, store, 2, otherBad)
			testBindRelease(t, store, 3, fromDigest)
			key := generationKey(store.cell, 1)
			want := ErrInvalid
			switch changed {
			case "purged":
				if err := store.kv.Purge(ctx, key); err != nil {
					t.Fatal(err)
				}
				want = nil
			case "corrupt":
				if _, err := store.kv.Put(ctx, key, []byte("{")); err != nil {
					t.Fatal(err)
				}
			case "misbound":
				entry, err := store.kv.Get(ctx, generationKey(store.cell, 2))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := store.kv.Put(ctx, key, entry.Value()); err != nil {
					t.Fatal(err)
				}
			case "unavailable":
				want = errors.New("proof unavailable")
				store.kv = &releasePinReadFailureKV{KeyValue: store.kv, key: key, err: want}
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				defer cancel()
				store.kv = &stageLookupKV{KeyValue: store.kv, cancel: cancel}
				want = context.Canceled
			}
			_, _, found, err := store.releaseStage(ctx, testStageID(1))
			if found || changed == "corrupt" && err == nil || changed != "corrupt" && !errors.Is(err, want) {
				t.Fatalf("%s historical proof: found=%t, err=%v, want %v", changed, found, err, want)
			}
		})
	}
}

func TestReleaseStageRefusesMisboundDesiredProofWithoutCharging(t *testing.T) {
	store, _ := testStore(t)
	ctx := t.Context()
	testBindRelease(t, store, 1, toDigest)
	desired, _, err := store.Desired(ctx)
	if err != nil {
		t.Fatal(err)
	}
	desired.Release.ID = generationKey("sjc", 1)
	wire, err := protocol.EncodeJSON(desired)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.kv.Put(ctx, desiredKey, wire); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Begin(ctx, testSpec(testStageID(1)), testStart); !errors.Is(err, ErrInvalid) {
		t.Fatalf("misbound desired release admitted: %v", err)
	}
	if state, _, err := store.Cell(ctx); err != nil || state.ActiveRolloutID != "" || len(state.Attempts) != 0 {
		t.Fatalf("invalid desired proof charged a reservation: %+v, %v", state, err)
	}
}

func TestReleaseStagePreservesCancellationWithoutDesiredGeneration(t *testing.T) {
	store, _ := testStore(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	store.kv = &stageLookupKV{KeyValue: store.kv, cancel: cancel}
	_, _, found, err := store.releaseStage(ctx, testStageID(1))
	if found || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled empty lookup returned no-proof success: found=%t, %v", found, err)
	}
}
