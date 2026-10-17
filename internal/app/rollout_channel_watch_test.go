package app

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/rollout"
)

type channelUpdatesWatcher struct {
	ctx     context.Context
	updates chan jetstream.KeyValueEntry
	loops   chan struct{}
}

func (w channelUpdatesWatcher) Updates() <-chan jetstream.KeyValueEntry {
	// Entering the next select proves the previous event finished processing.
	select {
	case w.loops <- struct{}{}:
	case <-w.ctx.Done():
	}
	return w.updates
}

func (channelUpdatesWatcher) Stop() error { return nil }

type deletedChannelEntry struct{ jetstream.KeyValueEntry }

func (deletedChannelEntry) Operation() jetstream.KeyValueOp { return jetstream.KeyValueDelete }

func TestReleaseChannelWatcherInitialization(t *testing.T) {
	for _, present := range []bool{false, true} {
		name := "absent channel"
		if present {
			name = "existing channel"
		}
		t.Run(name, func(t *testing.T) {
			f := newChannelFixture(t)
			manual := strings.Repeat("a", 64)
			if _, err := f.store.PublishRelease(t.Context(), 7, rollout.Release{Digest: manual, Actor: "01ARZ3NDEKTSV4RRFFQ69G5FAV", CreatedAt: f.signer.now}); err != nil {
				t.Fatal(err)
			}
			var initial jetstream.KeyValueEntry
			wantRollback := []string{manual}
			var wantRun int64
			if present {
				f.setChannel(t, f.signer.channel(t, "GRU", 620, []byte("run 620")))
				var err error
				initial, err = f.kv.Get(t.Context(), releasechannel.ChannelKey("GRU"))
				if err != nil {
					t.Fatal(err)
				}
				wantRun = 620
				wantRollback = append(wantRollback, digestOf([]byte("run 620")))
				slices.Sort(wantRollback)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			watcher := channelUpdatesWatcher{ctx: ctx, updates: make(chan jetstream.KeyValueEntry), loops: make(chan struct{})}
			fencer := &switchingFencer{snapshot: rolloutTestFence{epoch: 7}.Current()}
			done := make(chan struct{})
			f.control.ticks <- struct{}{}
			go func() {
				defer close(done)
				f.control.consumeUpdates(ctx, f.store, fencer, f.kv, watcher)
			}()
			defer func() { cancel(); <-done }()
			next := func() {
				t.Helper()
				select {
				case <-watcher.loops:
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
			update := func(entry jetstream.KeyValueEntry) {
				t.Helper()
				select {
				case watcher.updates <- entry:
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				next()
			}
			next()
			next()
			if _, err := f.kv.Get(ctx, releasechannel.StatusKey("GRU")); !errors.Is(err, jetstream.ErrKeyNotFound) || f.control.reported.Load() != nil {
				t.Fatalf("queued tick reported before watcher initialization: %v", err)
			}
			update(initial)
			status, revision := f.report(t)
			if status.RunNumber != wantRun || status.Pins == nil || !slices.Equal(status.Pins.Rollback, wantRollback) ||
				!present && status.Reason != "the cell has no release channel" {
				t.Fatalf("initialized report = %+v, pins = %+v", status, status.Pins)
			}
			if present {
				update(nil)
				if after, got := f.report(t); got != revision || !sameReport(status, after) {
					t.Fatalf("completion marker changed the channel report: %+v", after)
				}
				update(deletedChannelEntry{initial})
				status, revision = f.report(t)
				if status.RunNumber != 0 || status.Reason != "the cell has no release channel" {
					t.Fatalf("deleted channel report = %+v", status)
				}
			}
			bad := strings.Repeat("e", 64)
			if _, err := f.rolloutKV.Put(ctx, "knownbad."+bad, []byte(`{}`)); err != nil {
				t.Fatal(err)
			}
			f.control.ticks <- struct{}{}
			next()
			refreshed, got := f.report(t)
			if got == revision || refreshed.Reason != status.Reason || refreshed.Pins == nil ||
				!slices.Equal(refreshed.Pins.Rollback, wantRollback) || !slices.Equal(refreshed.Pins.KnownBad, []string{bad}) {
				t.Fatalf("pin-only tick report = %+v, pins = %+v", refreshed, refreshed.Pins)
			}
			fencer.set(followerLeadership{}.Current())
			f.control.ticks <- struct{}{}
			next()
			if _, after := f.report(t); after != got || f.control.reported.Load() != nil {
				t.Fatal("follower changed the report or retained the leader's local status")
			}
			if present {
				cancel()
			} else {
				close(watcher.updates)
			}
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("consumer did not stop after watcher closure or cancellation")
			}
		})
	}
}
