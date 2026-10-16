package rolloutexec

import (
	"context"
	"log/slog"

	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
	"github.com/TerraScale/ts-orchestrator/internal/rollout"
)

// The rollout store journals every committed phase change. The executor
// adds what only it decides: holding a step behind a gate, clearing that
// hold, and each unit step it sent. Each is recorded once, when it first
// happens on this leader, and chains under the release's admission.

func unitSubject(record rollout.Record, unit string) decisionlog.Subject {
	return decisionlog.Subject{Kind: "member", ID: unit, Name: string(record.Kind) + "/" + record.RolloutID}
}

func holdKey(unit string) string {
	if unit == "" {
		return "preflight"
	}
	return unit
}

// hold records that a step for unit ("" is preflight) waits on reason.
func (e *Executor) hold(record rollout.Record, unit, reason string) {
	key := holdKey(unit)
	if e.holds[key] == reason {
		return
	}
	e.holds[key] = reason
	decisionlog.Record(context.Background(), decisionlog.Decision{
		Region:   record.Cell,
		Actor:    decisionlog.Actor{Slice: "rollout"},
		Kind:     decisionlog.KindHeld,
		Subject:  unitSubject(record, key),
		Summary:  "Held the " + string(record.Phase) + " step of " + key + " in rollout " + record.RolloutID,
		Reason:   reason,
		Rule:     "rollout.executor.gate",
		Status:   decisionlog.StatusPending,
		Epoch:    record.AuthorityEpoch,
		ParentID: decisionlog.Correlated(rollout.ReleaseCorrelation(record.ToDigest)),
		Attrs:    map[string]string{"rollout": record.RolloutID, "phase": string(record.Phase)},
	})
	slog.Info("rollout step held", "component", "rollout", "rollout", record.RolloutID, "unit", key, "reason", reason)
}

// release clears a hold of unit once its step proceeds.
func (e *Executor) release(record rollout.Record, unit string) {
	key := holdKey(unit)
	if _, held := e.holds[key]; !held {
		return
	}
	delete(e.holds, key)
	decisionlog.Record(context.Background(), decisionlog.Decision{
		Region:   record.Cell,
		Actor:    decisionlog.Actor{Slice: "rollout"},
		Kind:     decisionlog.KindHoldCleared,
		Subject:  unitSubject(record, key),
		Summary:  "Released the " + string(record.Phase) + " step of " + key + " in rollout " + record.RolloutID,
		Reason:   "Its gate and group peers are healthy again.",
		Rule:     "rollout.executor.gate",
		Status:   decisionlog.StatusSucceeded,
		Epoch:    record.AuthorityEpoch,
		ParentID: decisionlog.Correlated(rollout.ReleaseCorrelation(record.ToDigest)),
		Attrs:    map[string]string{"rollout": record.RolloutID, "phase": string(record.Phase)},
	})
}

// recordStep journals a unit step the unit's agent accepted.
func recordStep(record rollout.Record, unit string, action StepAction, outcome StepOutcome) {
	kind, summary, digest := decisionlog.KindStageChanged, "Moved "+unit+" to the target release", record.ToDigest
	if action == StepRollback {
		kind, summary, digest = decisionlog.KindRollback, "Returned "+unit+" to the previous release", record.FromDigest
	}
	decisionlog.Record(context.Background(), decisionlog.Decision{
		Region:   record.Cell,
		Actor:    decisionlog.Actor{Slice: "rollout"},
		Kind:     kind,
		Subject:  unitSubject(record, unit),
		Summary:  summary + " in rollout " + record.RolloutID,
		Reason:   "The unit's group peers were serving and the cluster gate passed.",
		Rule:     "rollout.executor." + string(action),
		Status:   decisionlog.StatusInProgress,
		Epoch:    record.AuthorityEpoch,
		ParentID: decisionlog.Correlated(rollout.ReleaseCorrelation(record.ToDigest)),
		Attrs: map[string]string{"rollout": record.RolloutID, "digest": digest, "outcome": string(outcome),
			"phase": string(record.Phase)},
	})
}
