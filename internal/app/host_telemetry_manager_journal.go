package app

import (
	"context"
	"errors"
	"maps"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/hostload"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
)

// Replay is selected after the preceding journal point committed. It can prove
// that earlier interval even though this snapshot precedes the current append.
func readUsageSnapshot(ctx context.Context, client swarmruntime.ManagementObservationClient, prior []host.CommittedUsage) (*api.StoreSnapshot, swarmruntime.ManagementObservationCursor, bool, error) {
	var resume *swarmruntime.ManagementObservationCursor
	if len(prior) == 2 {
		source := prior[0].Observation.Source
		resume = &swarmruntime.ManagementObservationCursor{Version: source.Version, NodeID: source.NodeID, ClusterID: source.ClusterID, ServerEpoch: source.ServerEpoch, Term: source.Term, Leader: source.Leader}
	}
	for attempt := range 2 {
		streamCtx, cancel := context.WithCancel(ctx)
		stream, err := client.Observe(streamCtx, resume)
		continuous := resume != nil
		var snapshot *api.StoreSnapshot
		var cursor swarmruntime.ManagementObservationCursor
		if err == nil {
			for {
				var message swarmruntime.ManagementObservationMessage
				message, err = stream.Recv()
				if err != nil {
					break
				}
				if message.Snapshot != nil {
					snapshot, cursor = message.Snapshot, message.Cursor
				}
				if message.Transaction != nil && len(message.Transaction.Events) != 0 {
					continuous = false
				}
				if message.ReplayThrough != nil {
					break
				}
			}
		}
		cancel()
		if err == nil && snapshot != nil {
			return snapshot, cursor, continuous, nil
		}
		if resume == nil || attempt == 1 {
			return nil, cursor, false, errors.Join(err, errors.New("authenticated manager usage snapshot is unavailable"))
		}
		// A new leader/source or unavailable WAL starts a fresh point, never a
		// replacement proof for the failed historical interval.
		resume = nil
	}
	return nil, swarmruntime.ManagementObservationCursor{}, false, errors.New("manager usage observation failed")
}

func (t *hostTelemetry) restoreManagedUsage(ctx context.Context, controller *host.Controller, usage *runtimeObservability) ([]host.CommittedUsage, error) {
	t.usageHistoryMu.Lock()
	defer t.usageHistoryMu.Unlock()
	observations, err := controller.UsageObservations(ctx)
	if err != nil && !errors.Is(err, authority.ErrUsageHistoryTruncated) {
		return nil, err
	}
	for _, value := range observations {
		if value.Entry.Sequence <= t.usageSequence {
			continue
		}
		registration := value.Observation.Registration
		origin := hostload.Origin{Cell: registration.Cell, Node: registration.Node, Environment: registration.Environment}
		if err := usage.usage.RecordCommitted(value.Entry.CreatedAt, origin, value.Observation.Report, value.Observation.Requests); err != nil {
			return nil, err
		}
		t.usageSequence = value.Entry.Sequence
	}
	return observations, err
}

func (t *hostTelemetry) managedExpectedUsage(history *nativeHistory, usage *runtimeObservability, owns func(string) bool) func(context.Context, time.Time, time.Time) ([]hostload.UsageInterval, error) {
	return func(ctx context.Context, from, to time.Time) ([]hostload.UsageInterval, error) {
		observations, err := t.restoreManagedUsage(ctx, history.hosts, usage)
		if err != nil && !errors.Is(err, authority.ErrUsageHistoryTruncated) {
			return nil, err
		}
		native, nativeErr := history.hosts.ExpectedUsage(ctx, from, to)
		result := managedUsageIntervals(observations, native, nativeErr, owns, from, to)
		if errors.Is(err, authority.ErrUsageHistoryTruncated) {
			result = append(result, hostload.UsageInterval{From: from, To: to, Unknown: "retained manager usage history was truncated", Truncated: true})
		}
		return result, nil
	}
}

func managedUsageIntervals(observations []host.CommittedUsage, native []hostload.UsageInterval, nativeErr error, owns func(string) bool, from, to time.Time) []hostload.UsageInterval {
	type identity struct{ node, environment string }
	points := make(map[uint64]host.CommittedUsage, len(observations))
	identities := map[identity]bool{}
	managedRoles := map[string]bool{}
	for _, value := range observations {
		points[value.Entry.Sequence] = value
		registration := value.Observation.Registration
		identities[identity{registration.Node, registration.Environment}] = true
		for _, task := range value.Observation.Tasks {
			managedRoles[task.Role] = true
		}
	}
	var result []hostload.UsageInterval
	lifetimes := map[identity][]hostload.UsageInterval{}
	for _, interval := range native {
		if interval.Role == "" {
			key := identity{interval.Node, interval.Environment}
			identities[key] = true
			lifetimes[key] = append(lifetimes[key], interval)
		}
		if interval.Role == "" || !owns(interval.Role) && !managedRoles[interval.Role] {
			result = append(result, interval)
		}
	}
	if nativeErr != nil {
		result = append(result, hostload.UsageInterval{From: from, To: to, Unknown: "native admission history has no retained baseline"})
	}
	covered := map[identity][]hostload.UsageInterval{}
	for _, value := range observations {
		observation := value.Observation
		first, firstOK := points[observation.PreviousSequence]
		last, lastOK := points[observation.CoveredSequence]
		if !firstOK || !lastOK || observation.CoveredSequence != observation.PriorSequence || last.Observation.PriorSequence != first.Entry.Sequence ||
			first.Entry.SubjectKey != value.Entry.SubjectKey || last.Entry.SubjectKey != value.Entry.SubjectKey ||
			!first.Entry.CreatedAt.Before(last.Entry.CreatedAt) || !last.Entry.CreatedAt.Before(value.Entry.CreatedAt) {
			continue
		}
		start, end := first.Entry.CreatedAt, last.Entry.CreatedAt
		if start.Before(from) {
			start = from
		}
		if end.After(to) {
			end = to
		}
		if !start.Before(end) {
			continue
		}
		registration := first.Observation.Registration
		key := identity{registration.Node, registration.Environment}
		interval := hostload.UsageInterval{Node: key.node, Environment: key.environment, From: start, To: end}
		covered[key] = append(covered[key], interval)
		roles := map[string]bool{}
		for _, task := range first.Observation.Tasks {
			roles[task.Role] = true
		}
		for _, role := range slices.Sorted(maps.Keys(roles)) {
			interval.Role = role
			result = append(result, interval)
		}
	}
	if len(identities) == 0 {
		return append(result, hostload.UsageInterval{From: from, To: to, Unknown: "manager allocation history is unavailable"})
	}
	keys := slices.Collect(maps.Keys(identities))
	slices.SortFunc(keys, func(a, b identity) int {
		if a.node < b.node {
			return -1
		}
		if a.node > b.node {
			return 1
		}
		if a.environment < b.environment {
			return -1
		}
		if a.environment > b.environment {
			return 1
		}
		return 0
	})
	for _, key := range keys {
		active := lifetimes[key]
		if len(active) == 0 {
			active = []hostload.UsageInterval{{From: from, To: to}}
		}
		intervals := covered[key]
		slices.SortFunc(intervals, func(a, b hostload.UsageInterval) int { return a.From.Compare(b.From) })
		for _, lifetime := range active {
			cursor := lifetime.From
			for _, interval := range intervals {
				if !interval.To.After(cursor) || !interval.From.Before(lifetime.To) {
					continue
				}
				if cursor.Before(interval.From) {
					result = append(result, hostload.UsageInterval{Node: key.node, Environment: key.environment, From: cursor, To: interval.From, Unknown: "manager allocation continuity is unproven"})
				}
				if interval.To.After(cursor) {
					cursor = interval.To
				}
				if !cursor.Before(lifetime.To) {
					break
				}
			}
			if cursor.Before(lifetime.To) {
				result = append(result, hostload.UsageInterval{Node: key.node, Environment: key.environment, From: cursor, To: lifetime.To, Unknown: "manager allocation continuity is unproven"})
			}
		}
	}
	return result
}
