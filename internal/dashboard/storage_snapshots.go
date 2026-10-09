package dashboard

import (
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionview"
)

func (current view) snapshotState(member observability.MemberSnapshot) string {
	view := member.KVSnapshots
	if view == nil {
		return "unavailable"
	}
	if member.ObservedAt.IsZero() || member.ObservedAt.After(current.Now) || current.Now.Sub(member.ObservedAt) > regionview.ResourceFreshFor {
		return "stale"
	}
	if view.State == "failed" {
		return "failed"
	}
	if view.Overdue || view.State == "current" && (view.LastCheckAt.IsZero() || current.Now.After(view.LastCheckAt.Add(snapshotCheckWindow(view)))) {
		return "overdue"
	}
	return view.State
}

func snapshotCheckWindow(view *observability.KVSnapshotView) time.Duration {
	return time.Duration((view.IntervalSeconds + view.CheckTimeoutSeconds) * float64(time.Second))
}

func (current view) snapshotBucketState(view *observability.KVSnapshotView, bucket observability.KVSnapshotBucketView) string {
	if bucket.State == "current" && (bucket.LastCurrentAt.IsZero() || current.Now.After(bucket.LastCurrentAt.Add(snapshotCheckWindow(view)))) {
		return "stale"
	}
	return bucket.State
}

func snapshotStatus(state string) string {
	switch state {
	case "current":
		return "ok"
	case "failed":
		return "bad"
	case "paused", "overdue", "stale":
		return "warn"
	default:
		return "idle"
	}
}
