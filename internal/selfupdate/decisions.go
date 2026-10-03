package selfupdate

import (
	"context"
	"os"
	"strings"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
)

// The self-update CLI runs as a one-shot process with no journal installed,
// so these decisions reach the structured log as component=decision events;
// a controller that installs its journal publishes them to TS_DECISIONS.

func activationCorrelation(activation Activation) string {
	return "selfupdate:" + activation.ActivationID
}

func memberSubject(unit string) decisionlog.Subject {
	name, err := os.Hostname()
	if err != nil || name == "" {
		name = strings.TrimSuffix(unit, ".service")
	}
	return decisionlog.Subject{Kind: "member", ID: name, Name: unit}
}

func shortDigest(digest string) string {
	if len(digest) > 12 {
		return digest[:12]
	}
	return digest
}

// recordActivation journals a new pending A/B switch after the current link
// moved to the target. A replayed activation of the same target is not new.
func recordActivation(activation Activation) {
	id := decisionlog.Record(context.Background(), decisionlog.Decision{
		Actor:   decisionlog.Actor{Slice: "selfupdate"},
		Kind:    decisionlog.KindUpgradeStarted,
		Subject: memberSubject(activation.Unit),
		Summary: "Activated release " + shortDigest(activation.Target) + " for " + activation.Unit,
		Reason:  "The staged release verified; it must prove its version before the deadline or it is rolled back.",
		Rule:    "selfupdate.activate",
		Status:  decisionlog.StatusInProgress,
		Attrs: map[string]string{"version": activation.Target, "previous": activation.Previous,
			"activation": activation.ActivationID, "deadline": activation.Deadline.Format("2006-01-02T15:04:05Z07:00")},
	})
	decisionlog.Correlate(activationCorrelation(activation), id)
}

// recordResolution journals the watchdog's confirmation or rollback of an
// activation, chained under the activation when this process recorded it.
func recordResolution(activation Activation, outcome Outcome) {
	decision := decisionlog.Decision{
		Actor:    decisionlog.Actor{Slice: "selfupdate"},
		Subject:  memberSubject(activation.Unit),
		Rule:     "selfupdate.watchdog",
		ParentID: decisionlog.Correlated(activationCorrelation(activation)),
		Attrs: map[string]string{"version": activation.Target, "previous": activation.Previous,
			"activation": activation.ActivationID},
	}
	switch outcome {
	case OutcomeConfirmed:
		decision.Kind, decision.Status = decisionlog.KindUpgradeStarted, decisionlog.StatusSucceeded
		decision.Summary = "Confirmed release " + shortDigest(activation.Target) + " on " + activation.Unit
		decision.Reason = "The restarted unit signed a fresh version proof before its deadline."
	case OutcomeRolledBack:
		decision.Kind, decision.Status = decisionlog.KindRollback, decisionlog.StatusRolledBack
		decision.Summary = "Rolled " + activation.Unit + " back to release " + shortDigest(activation.Previous)
		decision.Reason = "No valid version proof arrived before the deadline, or the target no longer verified; the target is now known bad on this node."
	default:
		return
	}
	decisionlog.Record(context.Background(), decision)
}
