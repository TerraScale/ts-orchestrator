package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
	staged "git.terrascale.tech/TerraScale/ts-orchestrator/internal/rollout"
	"github.com/nats-io/nats.go"
)

// When artifact admission exhausts its own recovery window on retryable
// controller replies while the caller is still live, the failure must stay
// transient so terrabase-sync applies its retry policy instead of blocking
// at once (#127 12012).
func TestArtifactAdmissionRecoveryExpiryStaysTransient(t *testing.T) {
	previous := operatorAdmissionRecoveryTimeout
	operatorAdmissionRecoveryTimeout = 300 * time.Millisecond
	t.Cleanup(func() { operatorAdmissionRecoveryTimeout = previous })
	conn := testOperatorAdmissionConnection(t)
	wire, err := json.Marshal(artifactAdmissionResponse{Error: "temporary admission metadata failure", Retryable: true})
	if err != nil {
		t.Fatal(err)
	}
	sub, err := conn.Subscribe(delivery.ArtifactClaimSubject("lab"), func(message *nats.Msg) { _ = message.Respond(wire) })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	if err := conn.FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	err = requestArtifactAdmission(ctx, conn, "lab", delivery.ArtifactRecord{}, []byte("signed claim"))
	if err == nil || ctx.Err() != nil {
		t.Fatalf("recovery window did not expire first: %v (caller %v)", err, ctx.Err())
	}
	if !errors.Is(err, errControllerRetryable) || !staged.IsTransient(classifyControllerError(err)) {
		t.Fatalf("expired retryable admission classified terminal: %v", err)
	}
	if staged.IsTransient(classifyControllerError(errors.New("admission denied"))) {
		t.Fatal("a plain rejection became transient")
	}
}
