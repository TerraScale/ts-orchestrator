package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/oklog/ulid/v2"

	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/terrabase"
	"github.com/TerraScale/ts-orchestrator/internal/tsauth"
)

func servicePinsFixture(t *testing.T) (*serviceReleases, jetstream.KeyValue, *channelBucket, releasechannel.Location) {
	t.Helper()
	js := testRolloutJetStream(t)
	kv, err := openChannelBucket(t.Context(), js, 1)
	if err != nil {
		t.Fatal(err)
	}
	bucket := newChannelBucket()
	location := releasechannel.Location{Client: bucket, Namespace: "ns", Bucket: "gru-1-head"}
	r := &serviceReleases{js: js, cell: "gru", channel: &channelSource{location: &location}, fencer: rolloutTestFence{epoch: 7}}
	return r, kv, bucket, location
}

func TestServiceReleasePinsCompletedPassRefresh(t *testing.T) {
	r, kv, bucket, location := servicePinsFixture(t)
	ctx, role := t.Context(), terrabase.Role
	claim := []byte("persisted completed release claim")
	sum := sha256.Sum256(claim)
	state := serviceReleaseState{Claim: hex.EncodeToString(sum[:]), Digest: strings.Repeat("f", 64),
		Previous: strings.Repeat("a", 64), IssuedAt: time.Now().UTC(), State: releasechannel.StateComplete}
	key := releasechannel.ServiceStatusKey("GRU", role)
	revision, err := saveServiceRelease(ctx, kv, key, state, 0)
	if err != nil {
		t.Fatal(err)
	}
	bucket.objects[releasechannel.ServiceReleaseObject(role)] = claim
	bucket.etags[releasechannel.ServiceReleaseObject(role)] = "completed-claim"
	// Older withdrawn digests remain pinned even when neither is the latest release.
	older, newer := strings.Repeat("b", 64), strings.Repeat("c", 64)
	for _, digest := range []string{newer, older} {
		if err := markKnownBad(ctx, kv, role, digest, errors.New("withdrawn")); err != nil {
			t.Fatal(err)
		}
	}
	if err := markKnownBad(ctx, kv, tsauth.Role, strings.Repeat("d", 64), errors.New("other role")); err != nil {
		t.Fatal(err)
	}
	// A report without an inventory must be refreshed even without progress.
	if err := releasechannel.WriteServiceStatus(ctx, location, releasechannel.ServiceStatus{Cell: "GRU", Role: role,
		Digest: state.Digest, IssuedAt: state.IssuedAt, State: state.State}); err != nil {
		t.Fatal(err)
	}
	check := func(rollback, bad []string, writes int) {
		t.Helper()
		if err := r.nativePass(ctx, kv, role); err != nil {
			t.Fatal(err)
		}
		status, found, err := releasechannel.ReadServiceStatus(ctx, location, role)
		if err != nil || !found || status.Pins == nil || !slices.Equal(status.Pins.Rollback, rollback) ||
			!slices.Equal(status.Pins.KnownBad, bad) || status.Digest != state.Digest || status.State != state.State {
			t.Fatalf("status %+v, pins %+v, found %v: %v", status, status.Pins, found, err)
		}
		if got := bucket.puts[releasechannel.ServiceStatusObject(role)]; got != writes {
			t.Fatalf("status writes = %d, want %d", got, writes)
		}
	}
	check([]string{state.Previous}, []string{older, newer}, 2)
	check([]string{state.Previous}, []string{older, newer}, 2)
	added := strings.Repeat("e", 64)
	if err := markKnownBad(ctx, kv, role, added, errors.New("withdrawn after completion")); err != nil {
		t.Fatal(err)
	}
	check([]string{state.Previous}, []string{older, newer, added}, 3)
	for _, digest := range []string{older, newer, added} {
		if err := kv.Delete(ctx, knownBadKey(role, digest)); err != nil {
			t.Fatal(err)
		}
	}
	check([]string{state.Previous}, nil, 4)
	state.Previous = ""
	if _, err := saveServiceRelease(ctx, kv, key, state, revision); err != nil {
		t.Fatal(err)
	}
	check(nil, nil, 5)
}

func TestServiceReleasePinsInvalidClaimPreservesState(t *testing.T) {
	r, kv, bucket, location := servicePinsFixture(t)
	ctx, role := t.Context(), terrabase.Role
	state := serviceReleaseState{Claim: strings.Repeat("1", 64), Digest: strings.Repeat("f", 64),
		Previous: strings.Repeat("a", 64), IssuedAt: time.Now().UTC(), State: releasechannel.StateComplete}
	state.Intent = &delivery.Intent{OperationID: ulid.Make().String(), ArtifactDigest: state.Digest}
	key := releasechannel.ServiceStatusKey("GRU", role)
	revision, err := saveServiceRelease(ctx, kv, key, state, 0)
	if err != nil {
		t.Fatal(err)
	}
	bad := strings.Repeat("b", 64)
	if err := markKnownBad(ctx, kv, role, bad, errors.New("withdrawn earlier")); err != nil {
		t.Fatal(err)
	}
	bucket.objects[releasechannel.ServiceReleaseObject(role)] = []byte(`{"unverified":"newer claim"}`)
	bucket.etags[releasechannel.ServiceReleaseObject(role)] = "invalid-claim"
	for range 2 {
		if err := r.nativePass(ctx, kv, role); err != nil {
			t.Fatal(err)
		}
		status, found, err := releasechannel.ReadServiceStatus(ctx, location, role)
		if err != nil || !found || status.State != releasechannel.StateFailed || status.Pins == nil ||
			!slices.Equal(status.Pins.Rollback, []string{state.Previous, state.Digest}) || !slices.Equal(status.Pins.KnownBad, []string{bad}) {
			t.Fatalf("invalid claim status %+v, pins %+v: %v", status, status.Pins, err)
		}
		persisted, gotRevision, err := loadServiceRelease(ctx, kv, key)
		if err != nil || gotRevision != revision || persisted.Previous != state.Previous || persisted.Claim != state.Claim ||
			persisted.Digest != state.Digest || persisted.State != state.State || !persisted.IssuedAt.Equal(state.IssuedAt) {
			t.Fatalf("invalid claim changed durable state: %+v revision %d: %v", persisted, gotRevision, err)
		}
	}
}

// Override only key enumeration; the remaining KV behavior stays real.
type servicePinsWatch struct {
	jetstream.KeyValue
	keys       []string
	err        error
	incomplete bool
}

func (kv servicePinsWatch) WatchFiltered(_ context.Context, _ []string, _ ...jetstream.WatchOpt) (jetstream.KeyWatcher, error) {
	if kv.err != nil {
		return nil, kv.err
	}
	updates := make(chan jetstream.KeyValueEntry, len(kv.keys)+1)
	for _, key := range kv.keys {
		updates <- servicePinsEntry{key: key}
	}
	if !kv.incomplete {
		updates <- nil
	}
	close(updates)
	return servicePinsWatcher{updates: updates}, nil
}

type servicePinsEntry struct {
	jetstream.KeyValueEntry
	key string
}

func (entry servicePinsEntry) Key() string { return entry.key }

type servicePinsWatcher struct {
	updates <-chan jetstream.KeyValueEntry
}

func (watcher servicePinsWatcher) Updates() <-chan jetstream.KeyValueEntry { return watcher.updates }
func (servicePinsWatcher) Stop() error                                     { return nil }

func TestServiceReleasePinsRejectIncompleteReports(t *testing.T) {
	watchErr := errors.New("pin watcher unavailable")
	for _, tc := range []struct {
		name       string
		keys       []string
		err        error
		incomplete bool
		previous   string
	}{
		{name: "watcher creation failure", err: watchErr},
		{name: "closed before completion marker", keys: []string{knownBadKey(terrabase.Role, strings.Repeat("b", 64))}, incomplete: true},
		{name: "invalid digest", keys: []string{knownBadKey(terrabase.Role, "not-a-digest")}},
		{name: "uppercase digest", keys: []string{knownBadKey(terrabase.Role, strings.Repeat("B", 64))}},
		{name: "extra suffix", keys: []string{knownBadKey(terrabase.Role, strings.Repeat("b", 64)+".extra")}},
		{name: "invalid rollback", previous: "not-a-digest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, kv, bucket, _ := servicePinsFixture(t)
			ctx := t.Context()
			err := r.report(ctx, servicePinsWatch{KeyValue: kv, keys: tc.keys, err: tc.err, incomplete: tc.incomplete}, terrabase.Role,
				serviceReleaseState{Previous: tc.previous, State: releasechannel.StateComplete})
			if err == nil || tc.err != nil && !errors.Is(err, tc.err) {
				t.Fatalf("report error = %v, want refusal preserving watcher errors", err)
			}
			if ctx.Err() != nil {
				t.Fatalf("report context changed: %v", ctx.Err())
			}
			if bucket.puts[releasechannel.ServiceStatusObject(terrabase.Role)] != 0 {
				t.Fatal("published incomplete pins")
			}
		})
	}
}

func TestServiceReleasePinsEmptySupportAndDeduplication(t *testing.T) {
	r, kv, bucket, location := servicePinsFixture(t)
	ctx, role := t.Context(), terrabase.Role
	state := serviceReleaseState{State: releasechannel.StateComplete}
	if err := r.report(ctx, servicePinsWatch{KeyValue: kv}, role, state); err != nil {
		t.Fatal(err)
	}
	status, found, err := releasechannel.ReadServiceStatus(ctx, location, role)
	if err != nil || !found || status.Pins == nil || len(status.Pins.Rollback) != 0 || len(status.Pins.KnownBad) != 0 {
		t.Fatalf("empty pin support missing: %+v: %v", status, err)
	}
	older, newer := strings.Repeat("b", 64), strings.Repeat("c", 64)
	keys := []string{knownBadKey(role, newer), knownBadKey(role, older), knownBadKey(role, newer), knownBadKey(tsauth.Role, "invalid")}
	if err := r.report(ctx, servicePinsWatch{KeyValue: kv, keys: keys}, role, state); err != nil {
		t.Fatal(err)
	}
	status, _, err = releasechannel.ReadServiceStatus(ctx, location, role)
	if err != nil || status.Pins == nil || !slices.Equal(status.Pins.KnownBad, []string{older, newer}) {
		t.Fatalf("known-bad pins are not sorted and deduplicated: %+v: %v", status.Pins, err)
	}
	// Loss of leadership cannot remove the report's durable pins.
	r.fencer = followerLeadership{}
	if err := r.report(ctx, kv, role, state); err == nil {
		t.Fatal("follower published release pins")
	}
	if bucket.puts[releasechannel.ServiceStatusObject(role)] != 2 {
		t.Fatal("follower overwrote the leader's pins")
	}
	// Even a completion marker received after cancellation is refused.
	r.fencer = rolloutTestFence{epoch: 7}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := r.report(canceled, servicePinsWatch{KeyValue: kv, keys: keys[:1]}, role, state); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled watch = %v", err)
	}
	if bucket.puts[releasechannel.ServiceStatusObject(role)] != 2 {
		t.Fatal("canceled watch published partial pins")
	}
}
