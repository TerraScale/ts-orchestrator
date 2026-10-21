package delivery

import (
	"context"
	"fmt"

	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
)

// The delivery consumer journals the outcome of each intent it settles:
// applied, held or rejected. Recording is best effort and happens only on
// the path that durably wrote the receipt, so a redelivered intent is not
// journaled twice.

func recordIntentDecision(ctx context.Context, intent Intent, kind decisionlog.Kind, status decisionlog.Status,
	plan int, reason string,
) {
	identity := shortDigest(intent.ArtifactDigest)
	if intent.Container != nil {
		identity = "signed OCI image"
	}
	summary := fmt.Sprintf("Delivery %s of %s to %s/%s", deliveryVerb(kind), identity,
		intent.Role, intent.Environment)
	decisionlog.Record(ctx, decisionlog.Decision{
		Region:  intent.Cell,
		Actor:   decisionlog.Actor{Slice: "delivery"},
		Kind:    kind,
		Subject: decisionlog.Subject{Kind: "intent", ID: intent.OperationID, Name: intent.Role + "/" + intent.Environment},
		Summary: summary,
		Reason:  reason,
		Rule:    "signed delivery intent admission",
		Status:  status,
		Outcome: reason,
		Epoch:   intent.AuthorityEpoch,
		Signals: []decisionlog.Signal{
			{Name: "generation", Value: float64(intent.Generation)},
			{Name: "desired_replicas", Value: float64(intent.DesiredReplicas)},
			{Name: "planned_hosts", Value: float64(plan)},
		},
		Attrs: map[string]string{"artifact_digest": intent.ArtifactDigest, "manifest_digest": intent.ManifestDigest},
	})
}

func recordRejectedWire(ctx context.Context, fingerprint, reason string) {
	decisionlog.Record(ctx, decisionlog.Decision{
		Actor:   decisionlog.Actor{Slice: "delivery"},
		Kind:    decisionlog.KindDeliveryRejected,
		Subject: decisionlog.Subject{Kind: "intent", ID: "sha256:" + fingerprint},
		Summary: "Delivery request rejected before it could be read",
		Reason:  reason,
		Rule:    "signed delivery intent admission",
		Status:  decisionlog.StatusFailed,
		Outcome: reason,
	})
}

func deliveryVerb(kind decisionlog.Kind) string {
	switch kind {
	case decisionlog.KindDeliveryApplied:
		return "applied"
	case decisionlog.KindDeliveryHeld:
		return "held"
	default:
		return "rejected"
	}
}

func shortDigest(digest string) string {
	if len(digest) > 19 {
		return digest[:19]
	}
	return digest
}
