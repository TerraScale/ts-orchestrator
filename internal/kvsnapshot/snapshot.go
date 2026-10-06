package kvsnapshot

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

// ErrNewerLineage means the stored snapshot was read from a stream created
// after this cell's: this cell is the older one and never overwrites it.
var ErrNewerLineage = errors.New("kv snapshot belongs to a newer stream")

const (
	captureTimeout = 30 * time.Second
	drainTimeout   = time.Minute
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

	uploaded map[string]upload
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
			slog.Warn("kv snapshot schedule changed", "paused", pause)
			paused = pause
		}
		if !paused && snapshotter.Leader() && time.Since(last) >= interval {
			last = time.Now()
			written, err := snapshotter.SnapshotOnce(ctx)
			if err != nil && ctx.Err() == nil {
				slog.Warn("kv snapshot failed", "error", err)
			}
			if len(written) > 0 {
				slog.Info("kv snapshots written", "buckets", written)
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
// upload and returns the buckets it wrote. One failing bucket does not stop
// the others.
func (snapshotter *Snapshotter) SnapshotOnce(ctx context.Context) ([]string, error) {
	if snapshotter.uploaded == nil {
		snapshotter.uploaded = map[string]upload{}
	}
	var written []string
	var failures []error
	for _, bucket := range snapshotter.Buckets {
		wrote, err := snapshotter.snapshot(ctx, bucket)
		if err != nil {
			failures = append(failures, err)
		} else if wrote {
			written = append(written, bucket)
		}
	}
	return written, errors.Join(failures...)
}

func (snapshotter *Snapshotter) snapshot(ctx context.Context, bucket string) (bool, error) {
	// Stream asks the stream leader for its current info on every call;
	// CachedInfo returns that reply.
	stream, err := snapshotter.JS.Stream(ctx, "KV_"+bucket)
	if errors.Is(err, jetstream.ErrStreamNotFound) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect %s: %w", bucket, err)
	}
	info := stream.CachedInfo()
	created, sequence := info.Created, info.State.LastSeq
	last, known := snapshotter.uploaded[bucket]
	if sequence == 0 || known && last.created.Equal(created) && sequence <= last.sequence {
		return false, nil
	}
	now := time.Now
	if snapshotter.Now != nil {
		now = snapshotter.Now
	}
	document, err := capture(ctx, snapshotter.JS, info, snapshotter.Objects.Cell, bucket, now().UTC())
	if err != nil {
		return false, err
	}
	// An unchanged ETag proves the object still holds this stream at a lower
	// sequence, so the write needs no read.
	if known && last.created.Equal(created) {
		etag, err := snapshotter.Objects.Put(ctx, document, last.etag)
		if err == nil {
			snapshotter.uploaded[bucket] = upload{created: created, sequence: sequence, etag: etag}
			return true, nil
		}
		// The object moved, vanished or could not be written: forget it
		// and decide from a fresh read.
		delete(snapshotter.uploaded, bucket)
	}
	current, etag, found, err := snapshotter.Objects.Get(ctx, bucket)
	if err != nil {
		return false, err
	}
	if found {
		if current.StreamCreated.After(created) {
			return false, fmt.Errorf("%w: %s was snapshotted from a stream created at %s, after this one (%s)",
				ErrNewerLineage, bucket, current.StreamCreated.Format(time.RFC3339Nano), created.Format(time.RFC3339Nano))
		}
		if current.StreamCreated.Equal(created) && current.Sequence >= sequence {
			snapshotter.uploaded[bucket] = upload{created: created, sequence: current.Sequence, etag: etag}
			return false, nil
		}
	}
	etag, err = snapshotter.Objects.Put(ctx, document, etag)
	if err != nil {
		return false, err
	}
	snapshotter.uploaded[bucket] = upload{created: created, sequence: sequence, etag: etag}
	return true, nil
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
