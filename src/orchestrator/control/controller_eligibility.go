package control

import (
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/protocol"
)

// ControllerEligibilityClass mirrors the C# enum.
type ControllerEligibilityClass int

const (
	ControllerEligibilityClassUnspecified ControllerEligibilityClass = 0
	// ControllerEligibilityClassMutatingLeader: live fenced claim, current
	// epoch, healthy regional evidence — may mutate.
	ControllerEligibilityClassMutatingLeader ControllerEligibilityClass = 1
	// ControllerEligibilityClassReadOnlyFollower: live fenced claim held by a
	// peer — serves reads, never mutates.
	ControllerEligibilityClassReadOnlyFollower ControllerEligibilityClass = 2
	// ControllerEligibilityClassReadOnlyUncertain: regional quorum lost — the
	// controller becomes read-only and holds new mutations.
	ControllerEligibilityClassReadOnlyUncertain ControllerEligibilityClass = 3
	// ControllerEligibilityClassNotEligible: no live claim, or a claim fenced
	// by a newer epoch — not eligible for anything authoritative.
	ControllerEligibilityClassNotEligible ControllerEligibilityClass = 4
)

func (c ControllerEligibilityClass) String() string {
	switch c {
	case ControllerEligibilityClassUnspecified:
		return "Unspecified"
	case ControllerEligibilityClassMutatingLeader:
		return "MutatingLeader"
	case ControllerEligibilityClassReadOnlyFollower:
		return "ReadOnlyFollower"
	case ControllerEligibilityClassReadOnlyUncertain:
		return "ReadOnlyUncertain"
	case ControllerEligibilityClassNotEligible:
		return "NotEligible"
	default:
		return ""
	}
}

// ControllerEligibilityRules mirrors the C# static class: pure
// controller-eligibility rules composing the watched regional membership
// health and the fenced authority lease claim.
var ControllerEligibilityRules controllerEligibilityRules

type controllerEligibilityRules struct{}

// Decide mirrors ControllerEligibilityRules.Decide.
func (controllerEligibilityRules) Decide(
	membership *RegionalRuntimeMembershipHealth,
	claim *protocol.AuthorityLeaseClaim,
	isLeader bool,
	maximumObservedEpoch int64,
	now time.Time,
) ControllerEligibilityClass {
	if membership != nil {
		membership.Validate()
	}

	// No live, well-formed fenced claim: nothing this controller observes
	// about connectivity can make it eligible.
	if claim == nil || !claim.IsWellFormed() || !claim.IsLive(now) {
		return ControllerEligibilityClassNotEligible
	}

	// A claim fenced by a newer observed epoch is dead even while its lease
	// timestamp is still in the future.
	if claim.Epoch < maximumObservedEpoch {
		return ControllerEligibilityClassNotEligible
	}

	// Without regional quorum the controller is uncertain: it stops new
	// mutations and serves read-only until evidence returns.
	if membership == nil || !membership.QuorumAvailable {
		return ControllerEligibilityClassReadOnlyUncertain
	}

	if isLeader {
		return ControllerEligibilityClassMutatingLeader
	}

	return ControllerEligibilityClassReadOnlyFollower
}
