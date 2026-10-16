package kvsnapshot

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

// Status reads metadata without waiting for an upload or contacting storage.
// Authority and schedule are read now, so a former leader's successful upload
// cannot hide its current follower or paused state.
func (snapshotter *Snapshotter) Status() observability.KVSnapshotView {
	interval := snapshotter.Interval
	view := observability.KVSnapshotView{State: "current", CheckTimeoutSeconds: snapshotPassTimeout.Seconds(),
		Buckets: make([]observability.KVSnapshotBucketView, 0, len(snapshotter.Buckets))}
	if len(snapshotter.Buckets) == 0 {
		view.State = "unknown"
	}
	snapshotter.statusMu.RLock()
	view.LastCheckAt = snapshotter.lastCheckAt
	for _, bucket := range snapshotter.Buckets {
		status, ok := snapshotter.status[bucket]
		if !ok {
			status = observability.KVSnapshotBucketView{Bucket: bucket, State: "unknown"}
		}
		view.Buckets = append(view.Buckets, status)
		switch status.State {
		case "current", "absent", "empty":
		case "failed":
			view.State = "failed"
		default:
			if view.State != "failed" {
				view.State = "unknown"
			}
		}
	}
	snapshotter.statusMu.RUnlock()
	if view.LastCheckAt.IsZero() && view.State != "failed" {
		view.State = "unknown"
	}
	paused := false
	if snapshotter.Schedule != nil {
		interval, paused = snapshotter.Schedule()
	}
	view.IntervalSeconds = interval.Seconds()
	if paused {
		view.State = "paused"
	} else if snapshotter.Leader != nil && !snapshotter.Leader() {
		view.State = "follower"
	} else if !view.LastCheckAt.IsZero() {
		view.Overdue = snapshotter.now().After(view.LastCheckAt.Add(interval + snapshotPassTimeout))
		if view.Overdue && view.State != "failed" {
			view.State = "unknown"
		}
	}
	return view
}

func (snapshotter *Snapshotter) recordCheck(bucket string, wrote bool, state string, err error) {
	now := snapshotter.now()
	snapshotter.statusMu.Lock()
	defer snapshotter.statusMu.Unlock()
	if snapshotter.status == nil {
		snapshotter.status = map[string]observability.KVSnapshotBucketView{}
	}
	status := snapshotter.status[bucket]
	status.Bucket, status.LastCheckAt = bucket, now
	status.State, status.ErrorClass = state, ""
	if err != nil {
		status.State, status.ErrorClass = "failed", snapshotErrorClass(err)
	} else if state == "current" {
		status.State, status.LastCurrentAt = "current", now
		status.Sequence = snapshotter.uploaded[bucket].sequence
		if wrote {
			status.LastUploadedAt = now
		}
	}
	snapshotter.status[bucket] = status
}

func (snapshotter *Snapshotter) now() time.Time {
	if snapshotter.Now != nil {
		return snapshotter.Now().UTC()
	}
	return time.Now().UTC()
}

func snapshotErrorClass(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, ErrNewerLineage):
		return "newer_lineage"
	case errors.Is(err, ErrConflict):
		return "conflict"
	}
	if serviceErr, ok := errors.AsType[serviceError](err); ok {
		switch serviceErr.GetHTTPStatusCode() {
		case http.StatusUnauthorized, http.StatusForbidden:
			return "unauthorized"
		case http.StatusTooManyRequests:
			return "throttled"
		}
	}
	return "unavailable"
}
