package selfupdate

import (
	"context"
	"fmt"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
)

// Restore returns unit to digest, a release it ran before, on a rollout's
// order to roll back the rejected release. Unlike Activate it creates no
// pending activation, so a restore whose restart or proof fails never lets
// the watchdog flip the node back to the rejected release: the node stays on
// digest and the rollout's own deadline decides what happens next.
//
// rejected is marked known bad on this node and a restart obligation for
// unit is recorded before Restore returns, so a failed or interrupted
// restart is retried by the watchdog. A pending activation of rejected over
// digest is rolled back exactly as the watchdog would. Restore reports
// whether it changed anything; it refuses a known-bad or unverifiable
// digest, and a node that runs neither release. The caller holds Lock.
func Restore(layout Layout, digest, rejected, unit string) (bool, error) {
	if !digestRE.MatchString(digest) || !digestRE.MatchString(rejected) || digest == rejected || !unitRE.MatchString(unit) {
		return false, fmt.Errorf("%w: restore target", ErrInvalid)
	}
	if knownBad, err := layout.KnownBad(); err != nil {
		return false, err
	} else if knownBad[digest] {
		return false, ErrKnownBad
	}
	if err := layout.VerifyRelease(digest); err != nil {
		return false, err
	}
	activation, pending, err := layout.Pending()
	if err != nil {
		return false, err
	}
	if pending {
		if activation.Unit != unit || activation.Target != rejected || activation.Previous != digest {
			return false, fmt.Errorf("%w: activation %s is pending for another release", ErrInvalid, activation.ActivationID)
		}
		if err := layout.rollback(activation); err != nil {
			return true, err
		}
		recordResolution(activation, OutcomeRolledBack)
		return true, nil
	}
	current, err := layout.Current()
	if err != nil {
		return false, err
	}
	switch current {
	case digest:
		return false, nil
	case rejected:
	default:
		return false, fmt.Errorf("%w: the current release is neither the restore target nor the rejected release", ErrInvalid)
	}
	if err := layout.markKnownBad(rejected); err != nil {
		return false, err
	}
	// The restart obligation is durable before the link moves: there is no
	// activation record to recover from, so an interruption after the flip
	// must still leave the watchdog and a retry something to finish.
	if err := layout.markRestartPending(unit); err != nil {
		return false, err
	}
	if err := layout.flipCurrent(digest); err != nil {
		return true, err
	}
	decisionlog.Record(context.Background(), decisionlog.Decision{
		Actor:   decisionlog.Actor{Slice: "selfupdate"},
		Kind:    decisionlog.KindRollback,
		Subject: memberSubject(unit),
		Summary: "Restored release " + shortDigest(digest) + " on " + unit,
		Reason:  "A rollout rolled back the release this unit ran; that release is now known bad on this node.",
		Rule:    "selfupdate.restore",
		Status:  decisionlog.StatusRolledBack,
		Attrs:   map[string]string{"version": digest, "rejected": rejected},
	})
	return true, syncDir(layout.Root)
}

// MarkRestartPending records that unit still owes a restart, so the
// watchdog retries it until the unit starts. The caller holds Lock.
func (layout Layout) MarkRestartPending(unit string) error {
	return layout.markRestartPending(unit)
}
