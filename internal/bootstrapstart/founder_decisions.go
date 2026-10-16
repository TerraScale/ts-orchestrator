package bootstrapstart

import (
	"context"
	"fmt"

	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
)

// recordFounderLaunch journals the outcome of one founder peer launch. The
// founder runs before the regional journal exists, so the record usually goes
// to the structured log; it is best effort and never changes the result.
func recordFounderLaunch(ctx context.Context, cell, deploymentID, slot string, attempt FounderOCIAttempt,
	instanceID string, launchErr error,
) {
	decision := decisionlog.Decision{
		Region:  cell,
		Actor:   decisionlog.Actor{Slice: "bootstrap"},
		Kind:    decisionlog.KindFounderLaunched,
		Subject: decisionlog.Subject{Kind: "host", ID: slot, Name: "founder slot " + slot},
		Rule:    "founder plan peer launch",
		Signals: []decisionlog.Signal{
			{Name: "attempt", Value: float64(attempt.request.Attempt)},
			{Name: "generation", Value: float64(attempt.request.Generation)},
		},
		Attrs: map[string]string{"deployment_id": deploymentID, "node": attempt.request.Node},
	}
	if launchErr != nil {
		decision.Status = decisionlog.StatusFailed
		decision.Summary = fmt.Sprintf("Founder peer launch for slot %s failed", slot)
		// A lost launch response is ambiguous, and the attempt may end on
		// cancellation or an authority refresh error: do not claim that no
		// instance exists.
		decision.Reason = "The signed founder plan authorized the launch, but the launch attempt ended with an error; " +
			"whether OCI created an instance could not be confirmed."
		decision.Outcome = "launch unconfirmed"
	} else {
		decision.Status = decisionlog.StatusSucceeded
		decision.Summary = fmt.Sprintf("Founder peer launched for slot %s", slot)
		decision.Reason = "The signed founder plan authorized this slot and its reserved launch token was current."
		decision.Outcome = "instance created"
		decision.Attrs["instance_id"] = instanceID
	}
	decisionlog.Record(ctx, decision)
}
