package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"

	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
)

type failingChannelStatusBucket struct{ releasechannel.ObjectClient }

func (failingChannelStatusBucket) PutObject(context.Context, objectstorage.PutObjectRequest) (objectstorage.PutObjectResponse, error) {
	return objectstorage.PutObjectResponse{}, errors.New("status write unavailable")
}

func TestReleaseChannelInventoryHeartbeat(t *testing.T) {
	f := newChannelFixture(t)
	ctx := t.Context()
	now := time.Now().UTC()
	old := now.Add(-2 * releasechannel.PinRefreshInterval)
	consume := func(at time.Time) {
		t.Helper()
		if err := f.control.consumeChannel(ctx, f.store, f.kv, 7, nil, at); err != nil {
			t.Fatal(err)
		}
		if err := f.control.bridgePass(ctx, f.kv); err != nil {
			t.Fatal(err)
		}
	}
	consume(old)
	before, revision := f.report(t)
	consume(old.Add(time.Second))
	if _, got := f.report(t); got != revision {
		t.Fatal("unchanged inventory rewritten before heartbeat")
	}
	consume(now)
	fresh, got := f.report(t)
	stored, writes := f.bucket.status(t)
	if got == revision || !sameReport(before, fresh) || !fresh.UpdatedAt.Equal(now) || !stored.UpdatedAt.Equal(now) || writes != 2 {
		t.Fatalf("heartbeat did not reach status.json: KV %+v bucket %+v writes %d", fresh, stored, writes)
	}
	// Failed publication keeps the previous collection time in Object Storage.
	f.control.channel.location.Client = failingChannelStatusBucket{f.bucket}
	if err := f.control.consumeChannel(ctx, f.store, f.kv, 7, nil, now.Add(releasechannel.PinRefreshInterval)); err != nil {
		t.Fatal(err)
	}
	if err := f.control.bridgePass(ctx, f.kv); err == nil {
		t.Fatal("failed write succeeded")
	}
	f.control.channel.location.Client = f.bucket
	stored, writes = f.bucket.status(t)
	if !stored.UpdatedAt.Equal(now) || writes != 2 {
		t.Fatal("failed write renewed inventory freshness")
	}
	// A failed complete inventory cannot renew the KV report either.
	if _, err := f.rolloutKV.Put(ctx, "release.gen.1", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	prior, revision := f.report(t)
	if err := f.control.consumeChannel(ctx, f.store, f.kv, 7, nil, now.Add(releasechannel.MaxPinAge)); err == nil {
		t.Fatal("invalid inventory was published")
	}
	after, got := f.report(t)
	if got != revision || !after.UpdatedAt.Equal(prior.UpdatedAt) {
		t.Fatal("failed collection renewed the KV report")
	}
	if err := f.control.bridgePass(ctx, f.kv); err != nil {
		t.Fatal(err)
	}
	stored, _ = f.bucket.status(t)
	if !stored.UpdatedAt.Equal(prior.UpdatedAt) || stored.Pins.ValidateFresh(stored.UpdatedAt, now.Add(2*releasechannel.MaxPinAge)) == nil {
		t.Fatal("bridge renewed an expired inventory without collecting pins")
	}
}

func TestReleaseChannelRefreshesPinsWithoutExecutorTicks(t *testing.T) {
	f := newChannelFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	channel, err := f.kv.Watch(ctx, releasechannel.ChannelKey("GRU"))
	if err != nil {
		t.Fatal(err)
	}
	defer channel.Stop()
	statuses, err := f.kv.Watch(ctx, releasechannel.StatusKey("GRU"), jetstream.UpdatesOnly())
	if err != nil {
		t.Fatal(err)
	}
	defer statuses.Stop()
	f.control.interval = time.Millisecond
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.control.consumeUpdates(ctx, f.store, rolloutTestFence{epoch: 7}, f.kv, channel)
	}()
	defer func() { cancel(); <-done }()
	await := func(bad []string) {
		t.Helper()
		for {
			select {
			case entry, open := <-statuses.Updates():
				if !open {
					t.Fatal("status watcher closed")
				}
				if entry == nil {
					continue
				}
				var status releasechannel.Status
				if err := json.Unmarshal(entry.Value(), &status); err != nil {
					t.Fatal(err)
				}
				if status.Pins != nil && slices.Equal(status.Pins.KnownBad, bad) {
					return
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		}
	}
	await(nil)
	bad := strings.Repeat("e", 64)
	if _, err := f.rolloutKV.Put(ctx, "knownbad."+bad, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	await([]string{bad})
}
