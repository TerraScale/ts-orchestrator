package releasechannel

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/nats-io/nats.go/jetstream"
)

type pinWatchKV struct {
	jetstream.KeyValue
	watcher *pinWatcher
	err     error
	filters []string
}

func (kv *pinWatchKV) WatchFiltered(_ context.Context, filters []string, _ ...jetstream.WatchOpt) (jetstream.KeyWatcher, error) {
	kv.filters = slices.Clone(filters)
	return kv.watcher, kv.err
}

type pinWatcher struct {
	updates chan jetstream.KeyValueEntry
	stopped bool
}

func (watcher *pinWatcher) Updates() <-chan jetstream.KeyValueEntry { return watcher.updates }
func (watcher *pinWatcher) Stop() error {
	watcher.stopped = true
	return nil
}

type pinEntry struct {
	jetstream.KeyValueEntry
	key    string
	cancel context.CancelFunc
}

func (entry pinEntry) Key() string {
	if entry.cancel != nil {
		entry.cancel()
	}
	return entry.key
}

func TestPinKeysRequiresCompletionMarker(t *testing.T) {
	for _, tc := range []struct {
		name    string
		entries []jetstream.KeyValueEntry
		want    []string
		refused bool
	}{
		{name: "complete", entries: []jetstream.KeyValueEntry{pinEntry{key: "knownbad.b"}, pinEntry{key: "knownbad.a"}, nil,
			pinEntry{key: "knownbad.after-snapshot"}}, want: []string{"knownbad.b", "knownbad.a"}},
		{name: "empty complete", entries: []jetstream.KeyValueEntry{nil}},
		{name: "closed with partial keys", entries: []jetstream.KeyValueEntry{pinEntry{key: "knownbad.a"}}, refused: true},
		{name: "closed without keys", refused: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			watcher := &pinWatcher{updates: make(chan jetstream.KeyValueEntry, len(tc.entries))}
			for _, entry := range tc.entries {
				watcher.updates <- entry
			}
			close(watcher.updates)
			kv := &pinWatchKV{watcher: watcher}
			keys, err := PinKeys(t.Context(), kv, "knownbad.*")
			if tc.refused {
				if err == nil || keys != nil {
					t.Fatalf("partial inventory returned keys=%v err=%v", keys, err)
				}
			} else if err != nil || !slices.Equal(keys, tc.want) {
				t.Fatalf("keys=%v err=%v, want %v", keys, err, tc.want)
			}
			if t.Context().Err() != nil {
				t.Fatal("watcher closure canceled the context")
			}
			if !watcher.stopped || !slices.Equal(kv.filters, []string{"knownbad.*"}) {
				t.Fatalf("stopped=%v filters=%v", watcher.stopped, kv.filters)
			}
		})
	}
}

func TestPinKeysRefusesCancellation(t *testing.T) {
	for _, completed := range []bool{false, true} {
		t.Run(map[bool]string{false: "waiting for marker", true: "marker already queued"}[completed], func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			watcher := &pinWatcher{updates: make(chan jetstream.KeyValueEntry, 2)}
			watcher.updates <- pinEntry{key: "knownbad.a", cancel: cancel}
			if completed {
				watcher.updates <- nil
			}
			keys, err := PinKeys(ctx, &pinWatchKV{watcher: watcher}, "knownbad.*")
			if !errors.Is(err, context.Canceled) || keys != nil || !watcher.stopped {
				t.Fatalf("canceled inventory keys=%v err=%v stopped=%v", keys, err, watcher.stopped)
			}
		})
	}
}

func TestPinKeysRefusesWatcherCreationFailure(t *testing.T) {
	want := errors.New("watcher unavailable")
	keys, err := PinKeys(t.Context(), &pinWatchKV{err: want}, "knownbad.*")
	if !errors.Is(err, want) || keys != nil {
		t.Fatalf("failed watch keys=%v err=%v", keys, err)
	}
}
