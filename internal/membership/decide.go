package membership

import (
	"fmt"
	"slices"
)

// Hold reasons are stable strings so operators and tests can match them.
const (
	ReasonOnline              = "peer online"
	ReasonLocal               = "local controller"
	ReasonOfflineWithinGrace  = "peer offline within grace"
	ReasonSeedSlot            = "seed slot replacement requires an operator seed handoff"
	ReasonLedgerIncomplete    = "slot has no completed ledger attempt to retire"
	ReasonInstanceUnobserved  = "pinned instance lifecycle is unobservable"
	ReasonInstanceAlive       = "unresponsive pinned instance must be terminated before replacement"
	ReasonTerminatedButOnline = "pinned instance is terminated but its server name is online"
	ReasonQuorumLost          = "metadata quorum lost; use break-glass quorum recovery"
	ReasonOtherReplacement    = "another slot replacement is in progress"
	ReasonAwaitingEvidence    = "awaiting root-signed retirement evidence"
	ReasonObserveOnly         = "replacement disabled; observe-only"
	ReasonRetryBackoff        = "replacement retry backoff"
	ReasonReplacing           = "replacement in progress"
	ReasonRejoining           = "replacement completed; waiting for peer to rejoin"
)

// Decide is the pure supervision state machine. It never acts on the local
// slot, the seed slot, an instance that may still run, a slot whose ledger
// attempt is not complete, or without metadata quorum. At most one slot is
// replaced at a time, and only with evidence bound to the exact prior attempt
// and instance. Actions are idempotent: a replayed action resumes the same
// successor attempt.
func Decide(cfg Config, topology Topology, previous State, observation Observation) (State, []Action) {
	next := previous.clone()
	slots := slices.Clone(topology.Slots)
	slices.Sort(slots)
	online := make(map[string]bool, len(slots))
	for _, peer := range observation.Meta.Peers {
		online[peer.Name] = peer.Online
	}
	onlineSlots := 0
	for _, slot := range slots {
		if slot == topology.SelfSlot || online[topology.ServerName(slot)] {
			onlineSlots++
		}
	}
	quorum := observation.Meta.Leader != "" && onlineSlots >= topology.quorum()
	replacing := false
	for _, slot := range slots {
		status, ok := next.Slots[slot]
		if (!ok || status.Phase != PhaseReplacing) && slot != topology.SelfSlot && slot != topology.SeedSlot {
			if pending, inFlight := inFlightSuccessor(slot, observation); inFlight {
				// A new term, or a restarted leader, has no memory of a
				// replacement an earlier term admitted. The ledger does: its
				// incomplete successor HEAD is bound to this exact evidence, so
				// resume it instead of holding the slot as ledger-incomplete
				// and letting another slot start a concurrent replacement.
				status.Slot, status.Phase, status.PendingAttempt = slot, PhaseReplacing, pending
				next.Slots[slot] = status
				ok = true
			}
		}
		if ok && status.Phase == PhaseReplacing && abandonedBeforeAdmission(slot, status, observation) {
			// The successor was never admitted (the ledger still holds the
			// completed prior attempt) and the evidence that would let it be
			// admitted is gone. Nothing was launched, so release the gate and
			// hold the slot for fresh evidence instead of blocking every
			// other replacement for the rest of the term.
			status.Phase, status.PendingAttempt, status.LastFailure, status.LastError = PhaseHeld, 0, timeZero, ""
			next.Slots[slot] = status
		}
		if ok && status.Phase == PhaseReplacing || admittedSuccessor(observation.Ledger[slot]) {
			// The verified ledger HEAD reserves the single replacement slot
			// even when the evidence needed to resume it is not on hand:
			// the founder persists the successor HEAD before any OCI launch.
			replacing = true
		}
	}
	var actions []Action
	for _, slot := range slots {
		status := next.Slots[slot]
		status.Slot = slot
		ledger := observation.Ledger[slot]
		lifecycle := observation.Lifecycle[slot]
		status.Attempt, status.InstanceOCID, status.Lifecycle = ledger.Attempt, ledger.InstanceOCID, lifecycle
		status.Online = slot == topology.SelfSlot || online[topology.ServerName(slot)]
		evidence, hasEvidence := observation.Evidence[slot]
		if status.Phase == PhaseReplacing {
			status, actions = decideReplacing(cfg, status, ledger, evidence, hasEvidence, quorum, observation, actions)
			next.Slots[slot] = status
			continue
		}
		switch {
		case slot == topology.SelfSlot:
			status = healthy(status, ReasonLocal)
			next.Slots[slot] = status
			continue
		case status.Online && lifecycle == LifecycleTerminated && ledger.Complete:
			status.Phase, status.Reason = PhaseHeld, ReasonTerminatedButOnline
			next.Slots[slot] = status
			continue
		case status.Online:
			next.Slots[slot] = healthy(status, ReasonOnline)
			continue
		}
		if status.OfflineSince.IsZero() {
			status.OfflineSince = observation.At
		}
		terminated := lifecycle == LifecycleTerminated
		if !terminated && observation.At.Sub(status.OfflineSince) < cfg.OfflineGrace() {
			status.Phase, status.Reason = PhaseSuspect, ReasonOfflineWithinGrace
			next.Slots[slot] = status
			continue
		}
		status.Phase = PhaseHeld
		switch {
		case slot == topology.SeedSlot:
			status.Reason = ReasonSeedSlot
		case !ledger.Complete || ledger.Attempt == 0 || ledger.InstanceOCID == "":
			status.Reason = ReasonLedgerIncomplete
		case lifecycle == "":
			status.Reason = ReasonInstanceUnobserved
		case !terminated:
			status.Reason = fmt.Sprintf("%s (%s is %s)", ReasonInstanceAlive, ledger.InstanceOCID, lifecycle)
		case !quorum:
			status.Reason = ReasonQuorumLost
		case replacing:
			status.Reason = ReasonOtherReplacement
		case !hasEvidence || evidence.Slot != slot || evidence.PreviousAttempt != ledger.Attempt ||
			evidence.PriorInstanceOCID != ledger.InstanceOCID || len(evidence.Wire) == 0:
			status.Reason = fmt.Sprintf("%s for %s attempt %d instance %s", ReasonAwaitingEvidence, slot,
				ledger.Attempt, ledger.InstanceOCID)
		case !cfg.Replace:
			status.Reason = ReasonObserveOnly
		case !status.LastFailure.IsZero() && observation.At.Sub(status.LastFailure) < cfg.RetryBackoff():
			status.Reason = ReasonRetryBackoff
		default:
			status.Phase, status.Reason = PhaseReplacing, ReasonReplacing
			status.PendingAttempt = ledger.Attempt + 1
			replacing = true
			actions = append(actions, Action{Slot: slot, PreviousAttempt: ledger.Attempt,
				PriorInstanceOCID: ledger.InstanceOCID, Retirement: evidence,
				Reason: "pinned instance " + ledger.InstanceOCID + " is terminated"})
		}
		next.Slots[slot] = status
	}
	return next, actions
}

// decideReplacing follows one in-flight replacement until the successor
// attempt completes. It re-emits the same action, bound to the same evidence,
// until the ledger reports completion, so a crashed or failed actuator call is
// resumed rather than restarted with a new attempt.
func decideReplacing(cfg Config, status SlotStatus, ledger LedgerSlot, evidence Evidence, hasEvidence bool,
	quorum bool, observation Observation, actions []Action,
) (SlotStatus, []Action) {
	previous := status.PendingAttempt - 1
	if ledger.Attempt >= status.PendingAttempt && ledger.Complete {
		status.PendingAttempt, status.LastFailure, status.LastError = 0, timeZero, ""
		if status.Online {
			return healthy(status, ReasonOnline), actions
		}
		// The successor gets a fresh grace to start and catch up.
		status.Phase, status.Reason, status.OfflineSince = PhaseSuspect, ReasonRejoining, observation.At
		return status, actions
	}
	switch {
	case !quorum:
		status.Reason = ReasonQuorumLost
	case !hasEvidence || evidence.Slot != status.Slot || evidence.PreviousAttempt != previous ||
		ledger.Attempt != previous && ledger.Attempt != status.PendingAttempt || len(evidence.Wire) == 0:
		status.Reason = fmt.Sprintf("%s for %s attempt %d", ReasonAwaitingEvidence, status.Slot, previous)
	case !cfg.Replace:
		status.Reason = ReasonObserveOnly
	case !status.LastFailure.IsZero() && observation.At.Sub(status.LastFailure) < cfg.RetryBackoff():
		status.Reason = ReasonRetryBackoff
	default:
		status.Reason = ReasonReplacing
		actions = append(actions, Action{Slot: status.Slot, PreviousAttempt: previous,
			PriorInstanceOCID: evidence.PriorInstanceOCID, Retirement: evidence, Reason: "resume replacement"})
	}
	return status, actions
}

// inFlightSuccessor reports an admitted but incomplete successor attempt whose
// HEAD was advanced with the retirement evidence currently on hand.
func inFlightSuccessor(slot string, observation Observation) (uint64, bool) {
	ledger := observation.Ledger[slot]
	evidence, ok := observation.Evidence[slot]
	if !ok || ledger.Complete || ledger.Attempt < 2 || ledger.Retirement == "" ||
		evidence.Slot != slot || evidence.Digest != ledger.Retirement ||
		evidence.PreviousAttempt+1 != ledger.Attempt || len(evidence.Wire) == 0 {
		return 0, false
	}
	return ledger.Attempt, true
}

// admittedSuccessor reports a ledger HEAD that already admitted an incomplete
// successor attempt through a retirement, whether or not this term holds the
// evidence that admitted it.
func admittedSuccessor(ledger LedgerSlot) bool {
	return !ledger.Complete && ledger.Attempt >= 2 && ledger.Retirement != ""
}

// abandonedBeforeAdmission reports a remembered replacement whose successor
// the ledger never admitted and whose evidence is no longer usable to admit
// it: the ledger still records the completed prior attempt.
func abandonedBeforeAdmission(slot string, status SlotStatus, observation Observation) bool {
	previous := status.PendingAttempt - 1
	ledger := observation.Ledger[slot]
	if status.PendingAttempt == 0 || !ledger.Complete || ledger.Attempt != previous {
		return false
	}
	evidence, ok := observation.Evidence[slot]
	return !ok || evidence.Slot != slot || evidence.PreviousAttempt != previous || len(evidence.Wire) == 0
}

func healthy(status SlotStatus, reason string) SlotStatus {
	status.Phase, status.Reason = PhaseHealthy, reason
	status.OfflineSince, status.PendingAttempt, status.LastFailure, status.LastError = timeZero, 0, timeZero, ""
	return status
}
