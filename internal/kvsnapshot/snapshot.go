package kvsnapshot

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/nats-io/nats.go/jetstream"
)

// ErrNewerLineage means the stored snapshot was read from a stream created
// after this cell's: this cell is the older one and never overwrites it.
var ErrNewerLineage = errors.New("kv snapshot belongs to a newer stream")

const (
	captureTimeout = 30 * time.Second
	drainTimeout   = time.Minute
	// The full pass includes stream inspection, capture and Object Storage I/O.
	snapshotPassTimeout = 2 * time.Minute
)

// Snapshotter uploads every changed bucket while this controller leads.
type Snapshotter struct {
	JS       jetstream.JetStream
	Objects  *Objects
	Buckets  []string
	Leader   func() bool
	Interval time.Duration
	// Schedule, when set, returns the current interval and pause; Run reads
	// it at least every five seconds, so a change applies without a
	// restart.
	Schedule func() (time.Duration, bool)
	Now      func() time.Time

	passMu     sync.Mutex
	nextBucket int
	uploaded   map[string]upload
	statusMu   sync.RWMutex
	// One record per configured bucket; no document or error text is retained.
	status      map[string]observability.KVSnapshotBucketView
	lastCheckAt time.Time
}

// upload is the last object this snapshotter wrote or found current.
type upload struct {
	created  time.Time
	sequence uint64
	etag     string
}

// Run checks the buckets every Interval until ctx ends.
func (snapshotter *Snapshotter) Run(ctx context.Context) error {
	if err := validBuckets(snapshotter.Buckets); err != nil {
		return err
	}
	if snapshotter.JS == nil || snapshotter.Objects == nil || snapshotter.Leader == nil || snapshotter.Interval <= 0 {
		return errors.New("kv snapshotter requires JetStream, Object Storage, a leader check and an interval")
	}
	ticker := time.NewTicker(min(snapshotter.Interval, 5*time.Second))
	defer ticker.Stop()
	var last time.Time
	paused := false
	for {
		interval, pause := snapshotter.Interval, false
		if snapshotter.Schedule != nil {
			interval, pause = snapshotter.Schedule()
		}
		if pause != paused {
			slog.WarnContext(ctx, "kv snapshot schedule changed", "paused", pause)
			paused = pause
		}
		if !paused && snapshotter.Leader() && time.Since(last) >= interval {
			last = time.Now()
			written, err := snapshotter.SnapshotOnce(ctx)
			if err != nil && ctx.Err() == nil {
				slog.WarnContext(ctx, "kv snapshot failed", "error", err)
			}
			if len(written) > 0 {
				slog.InfoContext(ctx, "kv snapshots written", "buckets", written)
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// SnapshotOnce uploads each bucket whose stream changed since its last
// upload and returns the buckets it wrote. Errors are collected; the starting
// bucket rotates so a timed-out pass cannot repeatedly starve the same buckets.
func (snapshotter *Snapshotter) SnapshotOnce(ctx context.Context) ([]string, error) {
	snapshotter.passMu.Lock()
	defer snapshotter.passMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, snapshotPassTimeout)
	defer cancel()
	if snapshotter.uploaded == nil {
		snapshotter.uploaded = map[string]upload{}
	}
	var written []string
	var failures []error
	start := snapshotter.nextBucket
	for index := range len(snapshotter.Buckets) {
		bucket := snapshotter.Buckets[(start+index)%len(snapshotter.Buckets)]
		wrote, state, err := snapshotter.snapshot(ctx, bucket)
		snapshotter.recordCheck(bucket, wrote, state, err)
		if err != nil {
			failures = append(failures, err)
		} else if wrote {
			written = append(written, bucket)
		}
	}
	if len(snapshotter.Buckets) > 0 {
		snapshotter.nextBucket = (start + 1) % len(snapshotter.Buckets)
	}
	checkedAt := snapshotter.now()
	snapshotter.statusMu.Lock()
	snapshotter.lastCheckAt = checkedAt
	snapshotter.statusMu.Unlock()
	return written, errors.Join(failures...)
}

func (snapshotter *Snapshotter) snapshot(ctx context.Context, bucket string) (wrote bool, state string, err error) {
	// Stream asks the stream leader for its current info on every call;
	// CachedInfo returns that reply.
	stream, err := snapshotter.JS.Stream(ctx, "KV_"+bucket)
	if errors.Is(err, jetstream.ErrStreamNotFound) {
		return false, "absent", nil
	}
	if err != nil {
		return false, "", fmt.Errorf("inspect %s: %w", bucket, err)
	}
	info := stream.CachedInfo()
	created, sequence := info.Created, info.State.LastSeq
	last, known := snapshotter.uploaded[bucket]
	if sequence == 0 {
		return false, "empty", nil
	}
	// An unchanged ETag proves the object still holds this stream at a lower
	// sequence, so the write needs no read.
	if known && last.created.Equal(created) && sequence > last.sequence {
		if err := snapshotter.writeSnapshot(ctx, info, bucket, last.etag); err == nil {
			return true, "current", nil
		}
		// The object moved, vanished or could not be written: forget it
		// and decide from a fresh read.
		delete(snapshotter.uploaded, bucket)
	}
	stored, etag, found, err := snapshotter.Objects.Get(ctx, bucket)
	if err != nil {
		return false, "", err
	}
	if found {
		if stored.StreamCreated.After(created) {
			return false, "", fmt.Errorf("%w: %s was snapshotted from a stream created at %s, after this one (%s)",
				ErrNewerLineage, bucket, stored.StreamCreated.Format(time.RFC3339Nano), created.Format(time.RFC3339Nano))
		}
		if stored.StreamCreated.Equal(created) && stored.Sequence >= sequence {
			snapshotter.uploaded[bucket] = upload{created: created, sequence: stored.Sequence, etag: etag}
			return false, "current", nil
		}
	}
	if err := snapshotter.writeSnapshot(ctx, info, bucket, etag); err != nil {
		return false, "", err
	}
	return true, "current", nil
}

func (snapshotter *Snapshotter) writeSnapshot(ctx context.Context, info *jetstream.StreamInfo, bucket, etag string) error {
	document, err := capture(ctx, snapshotter.JS, info, snapshotter.Objects.Cell, bucket, snapshotter.now())
	if err != nil {
		return err
	}
	etag, err = snapshotter.Objects.Put(ctx, document, etag)
	if err != nil {
		return err
	}
	snapshotter.uploaded[bucket] = upload{created: info.Created, sequence: info.State.LastSeq, etag: etag}
	return nil
}

// capture reads the latest value of every key. Sequence is the stream's last
// sequence before the read, so the snapshot holds at least that state; a
// change during the read moves the sequence and is captured next pass.
func capture(ctx context.Context, js jetstream.JetStream, info *jetstream.StreamInfo, cell, bucket string,
	now time.Time,
) (Document, error) {
	ctx, cancel := context.WithTimeout(ctx, captureTimeout)
	defer cancel()
	kv, err := js.KeyValue(ctx, bucket)
	if err != nil {
		return Document{}, fmt.Errorf("open %s: %w", bucket, err)
	}
	watcher, err := kv.WatchAll(ctx, jetstream.IgnoreDeletes())
	if err != nil {
		return Document{}, fmt.Errorf("read %s: %w", bucket, err)
	}
	defer func() {
		_ = watcher.Stop()
		// The watcher closes Updates only once a delivery blocked on its full
		// channel returns, so drain until it closes, for at most a minute.
		go func() {
			timeout := time.NewTimer(drainTimeout)
			defer timeout.Stop()
			for {
				select {
				case _, ok := <-watcher.Updates():
					if !ok {
						return
					}
				case <-timeout.C:
					return
				}
			}
		}()
	}()
	values := map[string][]byte{}
	size := 0
	for {
		var entry jetstream.KeyValueEntry
		var ok bool
		select {
		case entry, ok = <-watcher.Updates():
		case <-ctx.Done():
			return Document{}, fmt.Errorf("read %s: %w", bucket, ctx.Err())
		}
		if !ok {
			return Document{}, fmt.Errorf("read %s: watcher closed before its initial values", bucket)
		}
		if entry == nil {
			break
		}
		values[entry.Key()] = entry.Value()
		if size += len(entry.Key()) + len(entry.Value()); size > maxDocumentBytes {
			return Document{}, fmt.Errorf("kv snapshot of %s exceeds %d bytes", bucket, maxDocumentBytes)
		}
	}
	entries := make([]Entry, 0, len(values))
	for key, value := range values {
		entries = append(entries, Entry{Key: key, Value: value})
	}
	slices.SortFunc(entries, func(a, b Entry) int { return strings.Compare(a.Key, b.Key) })
	config := info.Config
	return Document{Version: documentVersion, Cell: cell, Bucket: bucket, StreamCreated: info.Created.UTC(),
		Sequence: info.State.LastSeq, TakenAt: now, Entries: entries,
		Config: BucketConfig{Description: config.Description, History: uint8(config.MaxMsgsPerSubject),
			MaxValueSize: config.MaxMsgSize, Compression: config.Compression != jetstream.NoCompression}}, nil
}
