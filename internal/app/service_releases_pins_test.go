package app

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"

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
