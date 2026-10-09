package rollout

import (
	"context"
	"crypto/ed25519"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nats.go/jetstream"
)

type releasePinPurgeFailureKV struct{ jetstream.KeyValue }

func (kv releasePinPurgeFailureKV) Purge(context.Context, string, ...jetstream.KVDeleteOpt) error {
	return errors.New("purge unavailable")
}

func TestReleasePinsIncludesAllRetainedGenerationsAfterFailedPurges(t *testing.T) {
	store, _ := testStore(t)
	store.kv = releasePinPurgeFailureKV{store.kv}
	ctx := t.Context()
	recent := []string{toDigest, strings.Repeat("c", 64)}
	head := strings.Repeat("d", 64)
	for generation := 1; generation <= ReleaseHistory+3; generation++ {
		digest := recent[generation%len(recent)]
		if generation == 1 {
			digest = fromDigest
		} else if generation == ReleaseHistory+3 {
			digest = head
		}
		if _, err := store.PublishRelease(ctx, 7, Release{Digest: digest, Actor: "ops", CreatedAt: testStart}); err != nil {
			t.Fatal(err)
		}
	}
	if retained, err := store.ReleaseGeneration(ctx, 1); err != nil || retained.Digest != fromDigest {
		t.Fatalf("old rollback generation: %+v %v", retained, err)
	}
	history, err := store.Releases(ctx, ReleaseHistory)
	if err != nil || len(history) != ReleaseHistory {
		t.Fatalf("bounded history: %d generations, %v", len(history), err)
	}
	for _, release := range history {
		if release.Digest == fromDigest {
			t.Fatal("fixture's old rollback target is still in the bounded history")
		}
	}
	if _, err := store.kv.Get(ctx, generationKey(store.cell, ReleaseHistory+3)); !errors.Is(err, jetstream.ErrKeyNotFound) {
		t.Fatalf("desired head already has a retained copy: %v", err)
	}
	_, signer, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := trust.Sign([]byte(`{}`), trust.Scope{Domain: "terrascale.orchestrator.rollout-step",
		DeploymentID: entityid.New(), Cell: store.cell, Environment: "production", Role: "prepare", Slot: "controller-a"},
		testStart, testStart.Add(time.Minute), signer)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.kv.Put(ctx, entityid.Derive("rollout-step", "controller-a"), wire); err != nil {
		t.Fatal(err)
	}
	if _, err := store.kv.Put(ctx, entityid.Derive("rollout-step-reply", "controller-a"),
		[]byte(`{"unit":"controller-a","operation_id":"`+envelope.Scope.DeploymentID+`","outcome":"current","epoch":7}`)); err != nil {
		t.Fatal(err)
	}
	want := []string{fromDigest, toDigest, recent[1], head}
	rollback, knownBad, err := store.ReleasePins(ctx)
	if err != nil || !slices.Equal(rollback, want) || len(knownBad) != 0 {
		t.Fatalf("pins: rollback=%v known_bad=%v err=%v, want %v", rollback, knownBad, err, want)
	}
	if back, err := store.RollbackRelease(ctx, 7, 1, "ops", testStart); err != nil || back.Digest != fromDigest || back.RollbackOf != 1 {
		t.Fatalf("rollback outside bounded history: %+v %v", back, err)
	}
	if rollback, _, err := store.ReleasePins(ctx); err != nil || !slices.Equal(rollback, want) {
		t.Fatalf("pins after rollback: %v %v, want %v", rollback, err, want)
	}
}

func TestReleasePinsRefusesInvalidRetainedRecords(t *testing.T) {
	store, _ := testStore(t)
	ctx := t.Context()
	head, err := store.PublishRelease(ctx, 7, Release{Digest: fromDigest, Actor: "ops", CreatedAt: testStart})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := protocol.EncodeJSON(head)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		key  string
		wire []byte
	}{
		{"corrupt JSON", generationKey(store.cell, 1), []byte("{")},
		{"invalid digest", generationKey(store.cell, 1), []byte(strings.Replace(string(wire), fromDigest, "short", 1))},
		{"mismatched generation", generationKey(store.cell, 2), wire},
		{"noncanonical key", "release.gen.01", wire},
		{"zero generation", generationKey(store.cell, 0), []byte(strings.Replace(string(wire), `"generation":1`, `"generation":0`, 1))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := store.kv.Put(ctx, tc.key, tc.wire); err != nil {
				t.Fatal(err)
			}
			rollback, knownBad, err := store.ReleasePins(ctx)
			if err == nil || rollback != nil || knownBad != nil {
				t.Fatalf("invalid retained record returned pins: %v %v %v", rollback, knownBad, err)
			}
			if err := store.kv.Delete(ctx, tc.key); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type releasePinReadFailureKV struct {
	jetstream.KeyValue
	key string
	err error
}

func (kv releasePinReadFailureKV) Get(ctx context.Context, key string) (jetstream.KeyValueEntry, error) {
	if key == kv.key {
		return nil, kv.err
	}
	return kv.KeyValue.Get(ctx, key)
}

func TestReleasePinsRefusesIncompleteRetainedReads(t *testing.T) {
	store, _ := testStore(t)
	ctx := t.Context()
	head, err := store.PublishRelease(ctx, 7, Release{Digest: fromDigest, Actor: "ops", CreatedAt: testStart})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.retain(ctx, 7, head); err != nil {
		t.Fatal(err)
	}
	kv := store.kv
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"missing after enumeration", jetstream.ErrKeyNotFound},
		{"cancelled read", context.Canceled},
		{"unavailable read", errors.New("generation unavailable")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store.kv = releasePinReadFailureKV{KeyValue: kv, key: generationKey(store.cell, 1), err: tc.err}
			rollback, knownBad, err := store.ReleasePins(ctx)
			if !errors.Is(err, tc.err) || rollback != nil || knownBad != nil {
				t.Fatalf("incomplete read returned pins: %v %v %v", rollback, knownBad, err)
			}
		})
	}
}

type releasePinWatchFailureKV struct {
	jetstream.KeyValue
	watcher jetstream.KeyWatcher
	err     error
	filters []string
}

func (kv *releasePinWatchFailureKV) WatchFiltered(_ context.Context, filters []string, _ ...jetstream.WatchOpt) (jetstream.KeyWatcher, error) {
	kv.filters = slices.Clone(filters)
	return kv.watcher, kv.err
}

type releasePinPartialWatcher struct {
	updates chan jetstream.KeyValueEntry
	stopped bool
}

func (watcher *releasePinPartialWatcher) Updates() <-chan jetstream.KeyValueEntry {
	return watcher.updates
}

func (watcher *releasePinPartialWatcher) Stop() error {
	watcher.stopped = true
	return nil
}

func TestReleasePinsRefusesIncompleteRetainedInventory(t *testing.T) {
	store, _ := testStore(t)
	ctx := t.Context()
	for _, digest := range []string{fromDigest, toDigest} {
		if _, err := store.PublishRelease(ctx, 7, Release{Digest: digest, Actor: "ops", CreatedAt: testStart}); err != nil {
			t.Fatal(err)
		}
	}
	entry, err := store.kv.Get(ctx, generationKey(store.cell, 1))
	if err != nil {
		t.Fatal(err)
	}
	kv := store.kv
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"partial inventory", nil},
		{"watch creation failure", errors.New("watcher unavailable")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			watcher := &releasePinPartialWatcher{updates: make(chan jetstream.KeyValueEntry, 1)}
			watcher.updates <- entry
			close(watcher.updates)
			failed := &releasePinWatchFailureKV{KeyValue: kv, watcher: watcher, err: tc.err}
			store.kv = failed
			rollback, knownBad, err := store.ReleasePins(ctx)
			if err == nil || rollback != nil || knownBad != nil {
				t.Fatalf("incomplete watcher returned pins: %v %v %v", rollback, knownBad, err)
			}
			if !slices.Equal(failed.filters, []string{">"}) || tc.err == nil && !watcher.stopped {
				t.Fatalf("filters=%v stopped=%v", failed.filters, watcher.stopped)
			}
		})
	}
}
