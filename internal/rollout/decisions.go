package rollout

import (
	"context"
	"fmt"
	"strconv"

	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
	"github.com/TerraScale/ts-orchestrator/internal/insights"
)

// ReleaseCorrelation is the decisionlog correlation key of a rollout's root
// decision. Later decisions of the same release, by this slice or another,
// chain under it.
func ReleaseCorrelation(digest string) string { return "release:" + digest }

// recordAdmitted journals a newly created rollout record as the chain root.
// It runs only after the KV create committed, so an idempotent Begin replay
// that returns the existing record does not record again.
func recordAdmitted(ctx context.Context, record Record) {
	id := decisionlog.Record(ctx, decisionlog.Decision{
		Region:  record.Cell,
		Actor:   decisionlog.Actor{Slice: "rollout"},
		Kind:    decisionlog.KindReleaseAdmitted,
		Subject: decisionlog.Subject{Kind: "release", ID: record.ToDigest, Name: string(record.Kind) + "/" + record.RolloutID},
		Summary: fmt.Sprintf("Admitted %s rollout %s of %d units in %d waves", record.Kind, record.RolloutID,
			len(record.Units), len(record.Waves)),
		Reason: "The target digest is not known bad and has attempts left.",
		Rule:   "rollout.begin",
		Status: decisionlog.StatusPending,
		Epoch:  record.AuthorityEpoch,
		Attrs: map[string]string{"rollout": record.RolloutID, "from": record.FromDigest,
			"policy": record.PolicyDigest},
	})
	decisionlog.Correlate(ReleaseCorrelation(record.ToDigest), id)
}

// recordTransition journals a committed phase change. Commit calls it after
// the CAS succeeded, so every transition is recorded exactly once.
func recordTransition(ctx context.Context, previous, next Record) {
	if previous.Phase == next.Phase && previous.WaveIndex == next.WaveIndex {
		return
	}
	kind, status, summary := transitionDecision(previous, next)
	if kind == "" {
		return
	}
	decisionlog.Record(ctx, decisionlog.Decision{
		Region:   next.Cell,
		Actor:    decisionlog.Actor{Slice: "rollout"},
		Kind:     kind,
		Subject:  decisionlog.Subject{Kind: "release", ID: next.ToDigest, Name: string(next.Kind) + "/" + next.RolloutID},
		Summary:  summary,
		Reason:   next.Reason,
		Rule:     "rollout." + string(next.Phase),
		Status:   status,
		Epoch:    next.AuthorityEpoch,
		ParentID: decisionlog.Correlated(ReleaseCorrelation(next.ToDigest)),
		Signals: []decisionlog.Signal{{Name: "wave", Value: float64(next.WaveIndex + 1),
			Comparison: "<=", Threshold: decisionlog.Threshold(float64(len(next.Waves)))}},
		Attrs: map[string]string{"rollout": next.RolloutID, "from_phase": string(previous.Phase),
			"phase": string(next.Phase), "wave": strconv.Itoa(next.WaveIndex)},
	})
}

func transitionDecision(previous, next Record) (decisionlog.Kind, decisionlog.Status, string) {
	id := next.RolloutID
	switch next.Phase {
	case PhaseCanary:
		return decisionlog.KindUpgradeStarted, decisionlog.StatusInProgress, "Started canary of rollout " + id
	case PhaseBatch:
		if previous.Phase == PhaseCanarySoak {
			return decisionlog.KindCanaryPromoted, decisionlog.StatusInProgress, "Promoted the canary of rollout " + id
		}
		return decisionlog.KindBatchPromoted, decisionlog.StatusInProgress,
			fmt.Sprintf("Promoted wave %d of rollout %s", next.WaveIndex, id)
	case PhaseComplete:
		return decisionlog.KindRolloutCompleted, decisionlog.StatusSucceeded, "Completed rollout " + id
	case PhaseRollingBack:
		return decisionlog.KindRollback, decisionlog.StatusInProgress, "Rolling back rollout " + id
	case PhaseRolledBack:
		return decisionlog.KindRollback, decisionlog.StatusRolledBack, "Rolled back rollout " + id
	case PhaseFrozen:
		return decisionlog.KindFrozen, decisionlog.StatusPending, "Froze rollout " + id + " for operator review"
	case PhaseAborted:
		return decisionlog.KindHeld, decisionlog.StatusFailed, "Aborted rollout " + id
	}
	return "", "", ""
}

// Rollouts lists the cell's active rollout for the insight engine's deadline
// rule. It implements insights.RolloutProvider.
func (s *Store) Rollouts(ctx context.Context) ([]insights.Rollout, error) {
	record, _, active, err := s.Active(ctx)
	if err != nil || !active {
		return nil, err
	}
	return []insights.Rollout{InsightRollout(record)}, nil
}

// InsightRollout is the insight view of one rollout record.
func InsightRollout(record Record) insights.Rollout {
	return insights.Rollout{ID: record.RolloutID, Release: record.ToDigest, Phase: string(record.Phase),
		PhaseStarted: record.PhaseStartedAt, PhaseDeadline: record.PhaseDeadline, Done: record.Phase.Terminal()}
}

var _ insights.RolloutProvider = (*Store)(nil)
