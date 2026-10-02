package rollout

import (
	"slices"
	"time"
)

// ActionKind names the effect an executor should perform next.
type ActionKind string

const (
	// ActionPreflight asks the executor to run the preflight checks.
	ActionPreflight ActionKind = "preflight"
	// ActionPrepare moves one unit to Digest. The executor must first confirm
	// that every unit in Peers is serving, then use OperationID so a retry is
	// idempotent.
	ActionPrepare ActionKind = "prepare"
	// ActionAwaitHealth asks for fresh serving reports from one unit.
	ActionAwaitHealth ActionKind = "await-health"
	// ActionRollback returns one unit to Digest, which is always FromDigest.
	ActionRollback ActionKind = "rollback"
	// ActionPage alerts a human: the rollout is frozen.
	ActionPage ActionKind = "page"
)

// Action is one effect implied by a durably stored record.
type Action struct {
	Kind        ActionKind
	Unit        string
	Digest      string
	OperationID string
	Peers       []string
	Deadline    time.Time
}

// NextActions derives the executor's next effects from a stored record. It
// never returns a forward step while rolling back, and never a step for a
// unit outside the current wave.
func NextActions(record Record) []Action {
	if record.Validate() != nil {
		return nil
	}
	switch {
	case record.Phase == PhasePreflight:
		return []Action{{Kind: ActionPreflight, Deadline: record.PhaseDeadline}}
	case record.Phase.preparing() || record.Phase.soaking():
		var actions []Action
		for _, id := range record.Waves[record.WaveIndex] {
			progress := record.Units[id]
			switch progress.State {
			case UnitPreparing:
				actions = append(actions, Action{
					Kind: ActionPrepare, Unit: id, Digest: record.ToDigest,
					OperationID: OperationID(record.RolloutID, id, record.Phase, progress.Attempts),
					Peers:       record.peers(id), Deadline: record.PhaseDeadline,
				})
			case UnitSoaking:
				actions = append(actions, Action{Kind: ActionAwaitHealth, Unit: id, Digest: record.ToDigest, Deadline: record.PhaseDeadline})
			}
		}
		return actions
	case record.Phase == PhaseRollingBack:
		head := record.rollbackHead()
		if head == "" {
			return nil
		}
		return []Action{{
			Kind: ActionRollback, Unit: head, Digest: record.FromDigest,
			OperationID: OperationID(record.RolloutID, head, PhaseRollingBack, record.Units[head].Attempts),
			Peers:       record.peers(head), Deadline: record.PhaseDeadline,
		}}
	case record.Phase == PhaseFrozen:
		return []Action{{Kind: ActionPage}}
	}
	return nil
}

// peers lists the other units of id's group. A step may only start while
// they are serving, which keeps the group above quorum.
func (record Record) peers(id string) []string {
	group := record.Units[id].Group
	var peers []string
	for other, progress := range record.Units {
		if other != id && progress.Group == group {
			peers = append(peers, other)
		}
	}
	slices.Sort(peers)
	return peers
}
