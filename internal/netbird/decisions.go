package netbird

import (
	"context"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
)

// recordEnrollment journals one enrollment outcome. Enrollment runs as a
// one-shot command without a regional journal, so the record goes to the
// structured log (and the journal when a caller installed one).
func recordEnrollment(ctx context.Context, cfg Config, hostname func() (string, error), result error) {
	name := "this host"
	if hostname != nil {
		if host, err := hostname(); err == nil && host != "" {
			name = host
		}
	}
	decision := decisionlog.Decision{
		Region:  cfg.Region,
		Actor:   decisionlog.Actor{Slice: "netbird"},
		Kind:    decisionlog.KindPeerEnrolled,
		Subject: decisionlog.Subject{Kind: "peer", ID: name},
		Rule:    "NetBird private overlay enrollment",
		Attrs:   map[string]string{"management_url": cfg.ManagementURL},
	}
	if result != nil {
		decision.Status = decisionlog.StatusFailed
		decision.Summary = "NetBird enrollment of " + name + " failed"
		decision.Reason = "The peer did not reach a connected management and signal state within the enrollment limit."
		decision.Outcome = "not connected"
	} else {
		decision.Status = decisionlog.StatusSucceeded
		decision.Summary = "NetBird peer " + name + " enrolled"
		decision.Reason = "The peer connected to TerraScale management and signal with the reviewed settings."
		decision.Outcome = "connected"
	}
	decisionlog.Record(ctx, decision)
}
