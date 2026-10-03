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
		// Enrollment also fails before connecting (runtime lock, hosts
		// file, Vault, settings) and in setup-key cleanup after connecting,
		// so the failure does not say the peer is disconnected.
		decision.Reason = "The enrollment did not complete; the failure may be in preparation, connectivity or setup-key cleanup."
		decision.Outcome = "enrollment failed"
	} else {
		decision.Status = decisionlog.StatusSucceeded
		decision.Summary = "NetBird peer " + name + " enrolled"
		decision.Reason = "The peer connected to TerraScale management and signal with the reviewed settings."
		decision.Outcome = "connected"
	}
	decisionlog.Record(ctx, decision)
}
