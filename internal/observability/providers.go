package observability

import "context"

// SnapshotSource is the dashboard's view-model provider for this member.
// Collector implements it.
type SnapshotSource interface {
	Snapshot(ctx context.Context, includeMetrics bool) (MemberSnapshot, error)
}

// ClusterSource is the dashboard's view-model provider for the whole cell.
// Aggregator implements it; members that do not answer in time are listed as
// missing instead of failing the call.
type ClusterSource interface {
	Cluster(ctx context.Context, includeMetrics bool) (ClusterSnapshot, error)
}

// EventSource is the dashboard's provider of recent and live events.
// EventBus implements it.
type EventSource interface {
	Recent(limit int) []Event
	Since(after uint64, limit int) []Event
	Subscribe(ctx context.Context, buffer int) <-chan Event
}

// ReadinessSource reports readiness for /readyz and the dashboard banner.
// Health implements it.
type ReadinessSource interface {
	Evaluate(ctx context.Context) (bool, []CheckResult)
}

var (
	_ SnapshotSource  = (*Collector)(nil)
	_ ClusterSource   = (*Aggregator)(nil)
	_ EventSource     = (*EventBus)(nil)
	_ ReadinessSource = (*Health)(nil)
)
