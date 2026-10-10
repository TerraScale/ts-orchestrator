package rollout

import (
	"context"
	"crypto/ed25519"
	"errors"
	"slices"
	"strings"
	"sync/atomic"
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

type pausedPinReadKV struct {
	jetstream.KeyValue
	key     string
	before  bool
	paused  atomic.Bool
	entered chan struct{}
	resume  chan struct{}
}

func (kv *pausedPinReadKV) Get(ctx context.Context, key string) (jetstream.KeyValueEntry, error) {
	var entry jetstream.KeyValueEntry
	var err error
	if !kv.before {
		entry, err = kv.KeyValue.Get(ctx, key)
	}
	if key == kv.key && kv.paused.CompareAndSwap(false, true) {
		close(kv.entered)
		select {
		case <-kv.resume:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if kv.before {
		return kv.KeyValue.Get(ctx, key)
	}
	return entry, err
}

type pausedPinPurgeKV struct {
	jetstream.KeyValue
	key     string
	paused  atomic.Bool
	entered chan struct{}
	resume  chan struct{}
}

func (kv *pausedPinPurgeKV) Purge(ctx context.Context, key string, opts ...jetstream.KVDeleteOpt) error {
	if key == kv.key && kv.paused.CompareAndSwap(false, true) {
		close(kv.entered)
		select {
		case <-kv.resume:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return kv.KeyValue.Purge(ctx, key, opts...)
}

func TestReleasePinsRetriesConcurrentPurge(t *testing.T) {
	for _, phase := range []string{"publication during inventory", "purge after desired changed"} {
		t.Run(phase, func(t *testing.T) {
			store, _ := testStore(t)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			if _, err := store.PublishRelease(ctx, 7, Release{Digest: fromDigest, Actor: "ops", CreatedAt: testStart}); err != nil {
				t.Fatal(err)
			}
			testBindRelease(t, store, ReleaseHistory, toDigest)
			kv := store.kv
			key := generationKey(store.cell, 1)
			purge := &pausedPinPurgeKV{KeyValue: kv, key: key, entered: make(chan struct{}), resume: make(chan struct{})}
			read := &pausedPinReadKV{KeyValue: purge, key: key, before: true, entered: make(chan struct{}), resume: make(chan struct{})}
			store.kv = read
			published := make(chan error, 1)
			publish := func() {
				go func() {
					_, err := store.PublishRelease(ctx, 7, Release{Digest: otherBad, Actor: "ops", CreatedAt: testStart})
					published <- err
				}()
			}
			if phase == "purge after desired changed" {
				publish()
				select {
				case <-purge.entered:
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
			type result struct {
				rollback, knownBad []string
				err                error
			}
			finished := make(chan result, 1)
			go func() {
				rollback, knownBad, err := store.ReleasePins(ctx)
				finished <- result{rollback, knownBad, err}
			}()
			select {
			case <-read.entered:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if phase == "publication during inventory" {
				publish()
				select {
				case <-purge.entered:
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
			close(purge.resume)
			if err := <-published; err != nil {
				t.Fatal(err)
			}
			if _, err := kv.Get(ctx, key); !errors.Is(err, jetstream.ErrKeyNotFound) {
				t.Fatalf("publication did not purge the enumerated generation: %v", err)
			}
			close(read.resume)
			got := <-finished
			if got.err != nil || !slices.Equal(got.rollback, []string{toDigest, otherBad}) || len(got.knownBad) != 0 {
				t.Fatalf("concurrent purge lost complete pins: %v %v %v", got.rollback, got.knownBad, got.err)
			}
		})
	}
}

func TestReleasePinsRetriesConcurrentPublication(t *testing.T) {
	for _, phase := range []string{"after desired", "during inventory"} {
		t.Run(phase, func(t *testing.T) {
			store, _ := testStore(t)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			if _, err := store.PublishRelease(ctx, 7, Release{Digest: fromDigest, Actor: "ops", CreatedAt: testStart}); err != nil {
				t.Fatal(err)
			}
			key := desiredKey
			digests := []string{toDigest, otherBad}
			want := []string{fromDigest, toDigest, otherBad}
			if phase == "during inventory" {
				testBindRelease(t, store, ReleaseHistory, toDigest)
				key = generationKey(store.cell, 1)
				head := strings.Repeat("d", 64)
				digests = []string{otherBad, head}
				want = []string{toDigest, otherBad, head}
			}
			paused := &pausedPinReadKV{KeyValue: store.kv, key: key, entered: make(chan struct{}), resume: make(chan struct{})}
			store.kv = paused
			type result struct {
				rollback, knownBad []string
				err                error
			}
			finished := make(chan result, 1)
			go func() {
				rollback, knownBad, err := store.ReleasePins(ctx)
				finished <- result{rollback, knownBad, err}
			}()
			select {
			case <-paused.entered:
			case <-ctx.Done():
				close(paused.resume)
				t.Fatal(ctx.Err())
			}
			for _, digest := range digests {
				if _, err := store.PublishRelease(ctx, 7, Release{Digest: digest, Actor: "ops", CreatedAt: testStart}); err != nil {
					close(paused.resume)
					<-finished
					t.Fatal(err)
				}
			}
			close(paused.resume)
			got := <-finished
			if got.err != nil || !slices.Equal(got.rollback, want) || len(got.knownBad) != 0 {
				t.Fatalf("concurrent publication lost complete pins: %v %v %v, want %v", got.rollback, got.knownBad, got.err, want)
			}
		})
	}
}

func TestReleasePinsProtectsUnpublishedCopyWithoutAdmittingItsStage(t *testing.T) {
	store, _ := testStore(t)
	ctx := t.Context()
	if _, err := store.PublishRelease(ctx, 7, Release{Digest: fromDigest, Actor: "ops", CreatedAt: testStart}); err != nil {
		t.Fatal(err)
	}
	future := Release{ID: generationKey(store.cell, 2), Generation: 2, Digest: toDigest, Actor: "ops", CreatedAt: testStart}
	if err := store.retain(ctx, 7, future); err != nil {
		t.Fatal(err)
	}
	rollback, knownBad, err := store.ReleasePins(ctx)
	if err != nil || !slices.Equal(rollback, []string{fromDigest, toDigest}) || len(knownBad) != 0 {
		t.Fatalf("readable copy lost conservative pins: %v %v %v", rollback, knownBad, err)
	}
	if _, _, err := store.Begin(ctx, testSpec(testStageID(2)), testStart); !errors.Is(err, ErrNoRelease) {
		t.Fatalf("artifact pin authorized an unpublished stage: %v", err)
	}
	if state, _, err := store.Cell(ctx); err != nil || state.ActiveRolloutID != "" || len(state.Attempts) != 0 {
		t.Fatalf("unpublished stage charged a reservation: %+v, %v", state, err)
	}
}

type changingPinDesiredKV struct {
	jetstream.KeyValue
	reads int
}

func (kv *changingPinDesiredKV) Get(ctx context.Context, key string) (jetstream.KeyValueEntry, error) {
	entry, err := kv.KeyValue.Get(ctx, key)
	if key != desiredKey || err != nil {
		return entry, err
	}
	kv.reads++
	if _, err := kv.KeyValue.Put(ctx, key, entry.Value()); err != nil {
		return nil, err
	}
	return kv.KeyValue.Get(ctx, key)
}

func TestReleasePinsBoundsDesiredRevisionChurn(t *testing.T) {
	store, _ := testStore(t)
	ctx := t.Context()
	if _, err := store.PublishRelease(ctx, 7, Release{Digest: fromDigest, Actor: "ops", CreatedAt: testStart}); err != nil {
		t.Fatal(err)
	}
	kv := &changingPinDesiredKV{KeyValue: store.kv}
	store.kv = kv
	rollback, knownBad, err := store.ReleasePins(ctx)
	if !errors.Is(err, ErrConflict) || rollback != nil || knownBad != nil || kv.reads != 2*cellCASAttempts {
		t.Fatalf("unbounded or incomplete churn result: %v %v %v, desired reads=%d", rollback, knownBad, err, kv.reads)
	}
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
		{"misbound abandonment", entityid.Derive("abandoned", "one"), []byte(`{"abandoned_rollout":"` + entityid.Derive("abandoned", "two") + `"}`)},
		{"versioned abandonment", entityid.Derive("abandoned", "one"), []byte(`{"abandoned_rollout":"` + entityid.Derive("abandoned", "one") + `","schema_version":1}`)},
		{"misbound membership", HostMembershipKey("ts-gru-1"), []byte(`{"node":"ts-gru-2","public_key":"key"}`)},
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
	key   string
	err   error
	reads int
}

func (kv *releasePinReadFailureKV) Get(ctx context.Context, key string) (jetstream.KeyValueEntry, error) {
	if key == kv.key {
		kv.reads++
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
	unavailable := errors.New("generation unavailable")
	for _, tc := range []struct {
		name      string
		err       error
		wantErr   error
		wantReads int
	}{
		{"missing after enumeration", jetstream.ErrKeyNotFound, ErrConflict, cellCASAttempts},
		{"cancelled read", context.Canceled, context.Canceled, 1},
		{"unavailable read", unavailable, unavailable, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			failed := &releasePinReadFailureKV{KeyValue: kv, key: generationKey(store.cell, 1), err: tc.err}
			store.kv = failed
			rollback, knownBad, err := store.ReleasePins(ctx)
			if !errors.Is(err, tc.wantErr) || rollback != nil || knownBad != nil || failed.reads != tc.wantReads {
				t.Fatalf("incomplete read returned pins: %v %v %v, reads=%d", rollback, knownBad, err, failed.reads)
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
