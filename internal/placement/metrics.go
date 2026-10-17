package placement

import (
	"context"
	"errors"
	"math"
	"sync/atomic"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/VictoriaMetrics/metrics"
)

// Metrics is the placement slice's metric set.
var Metrics = metrics.NewSet()

// maxSummarizedPartitions bounds one Summarize call. Each partition costs a
// member list and a terminal-intent read; the summary is cached by its caller.
const maxSummarizedPartitions = 256

var (
	reconcileSeries = func(result string) *metrics.Counter {
		return Metrics.NewCounter(observability.Series(observability.MetricPrefix+"reconcile_total",
			"loop", "placement", "result", result))
	}
	reconcileOK      = reconcileSeries("ok")
	reconcileError   = reconcileSeries("error")
	reconcileStandby = reconcileSeries("standby")
	reconcileSeconds = Metrics.NewPrometheusHistogram(observability.Series(
		observability.MetricPrefix+"reconcile_duration_seconds", "loop", "placement"))
	lastReconcileSuccess atomic.Int64
	_                    = Metrics.NewGauge(observability.Series(
		observability.MetricPrefix+"reconcile_last_success_timestamp_seconds", "loop", "placement"),
		func() float64 {
			if at := lastReconcileSuccess.Load(); at > 0 {
				return float64(at) / 1e9
			}
			return math.NaN()
		})
)

// recordReconcile counts one Run tick. A standby tick is one where this
// member did not hold a writable lease when the tick started.
func recordReconcile(started time.Time, standby bool, err error) {
	switch {
	case standby:
		reconcileStandby.Inc()
		return
	case err != nil:
		reconcileError.Inc()
	default:
		reconcileOK.Inc()
		lastReconcileSuccess.Store(time.Now().UnixNano())
	}
	reconcileSeconds.UpdateDuration(started)
}

// Summarize reads durable placement state into a dashboard view: every
// admitted partition's roster progress, stage counts and the progress of its
// most recently prepared managed runtime update. It is read-only.
func Summarize(ctx context.Context, store Store) (observability.PlacementView, error) {
	if store == nil {
		return observability.PlacementView{}, errors.New("placement summary requires a store")
	}
	intents, err := store.ListIntents(ctx)
	if err != nil {
		return observability.PlacementView{}, err
	}
	view := observability.PlacementView{StageCounts: map[string]int{}}
	for index, intent := range intents {
		if index >= maxSummarizedPartitions {
			view.Truncated = true
			break
		}
		members, err := store.ListMembers(ctx, intent.DatabaseID, intent.PartitionID)
		if err != nil {
			return observability.PlacementView{}, err
		}
		database := summarizePartition(intent, members)
		if _, err := store.ReadTerminalIntent(ctx, intent.DatabaseID, intent.PartitionID); err == nil {
			database.Terminal = true
		} else if !errors.Is(err, authority.ErrNotFound) {
			return observability.PlacementView{}, err
		}
		for stage, count := range database.Stages {
			view.StageCounts[stage] += count
		}
		view.Databases = append(view.Databases, database)
	}
	return view, nil
}

func summarizePartition(intent Intent, members []VersionedMemberState) observability.DatabaseView {
	database := observability.DatabaseView{DatabaseID: intent.DatabaseID, PartitionID: intent.PartitionID,
		Generation: intent.Generation, DesiredSeats: len(intent.CanonicalRoster.Rows), Stages: map[string]int{},
		Readiness: "unknown", ReadinessReason: "current native root task and member readiness source is unavailable"}
	var latest *ManagedRuntimeTarget
	for index := range members {
		state := members[index].State
		stage := string(state.Stage)
		database.Stages[stage]++
		database.Members = append(database.Members, observability.MemberView{SeatID: state.MemberID,
			Stage: stage, HostNode: state.HostNode, FailureDomain: state.FailureDomain,
			UpdatePhase: string(state.ManagedRuntimeTarget.Phase), UpdatedAt: state.UpdatedAt})
		target := &members[index].State.ManagedRuntimeTarget
		if target.OperationID != "" && (latest == nil || target.PreparedAt.After(latest.PreparedAt)) {
			latest = target
		}
	}
	if latest == nil {
		return database
	}
	// A managed update operation targets its own seats (one canary per
	// operation), so its progress is over the seats it targets, not every
	// placement seat: otherwise a finished update reads as stalled at 1/2.
	rollout := &observability.RolloutView{OperationID: latest.OperationID, ArtifactDigest: latest.ArtifactDigest,
		Phases: map[string]int{}}
	for _, member := range members {
		target := member.State.ManagedRuntimeTarget
		if target.OperationID != latest.OperationID {
			continue
		}
		rollout.Seats++
		rollout.Phases[string(target.Phase)]++
		if target.Phase == ManagedUpdateSeatCanaryServing && member.State.Stage == StageServing {
			rollout.Completed++
		}
	}
	database.Rollout = rollout
	return database
}
