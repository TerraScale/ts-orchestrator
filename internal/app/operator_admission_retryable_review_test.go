package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
	staged "git.terrascale.tech/TerraScale/ts-orchestrator/internal/rollout"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

// When artifact admission exhausts its own recovery window on retryable
// controller replies while the caller is still live, the failure must stay
// transient so terrabase-sync applies its retry policy instead of blocking
// at once (#127 12012).
func TestArtifactAdmissionRecoveryExpiryStaysTransient(t *testing.T) {
	previous := operatorAdmissionRecoveryTimeout
	// Expire inside the second backoff, not at the same instant as its timer.
	operatorAdmissionRecoveryTimeout = 250 * time.Millisecond
	t.Cleanup(func() { operatorAdmissionRecoveryTimeout = previous })
	synctest.Test(t, func(t *testing.T) {
		// Keep NATS inside the fake-clock bubble; socket I/O cannot be advanced.
		srv, err := server.NewServer(&server.Options{DontListen: true, NoLog: true, NoSigs: true})
		if err != nil {
			t.Fatal(err)
		}
		srv.Start()
		defer func() { srv.Shutdown(); srv.WaitForShutdown() }()
		conn, err := nats.Connect("", nats.InProcessServer(srv))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		wire, err := json.Marshal(artifactAdmissionResponse{Error: "temporary admission metadata failure", Retryable: true})
		if err != nil {
			t.Fatal(err)
		}
		sub, err := conn.Subscribe(delivery.ArtifactClaimSubject("lab"), func(message *nats.Msg) { _ = message.Respond(wire) })
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = sub.Unsubscribe() })
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		if err := conn.FlushWithContext(ctx); err != nil {
			t.Fatal(err)
		}
		started := time.Now()
		err = requestArtifactAdmission(ctx, conn, "lab", delivery.ArtifactRecord{}, []byte("signed claim"))
		if err == nil || ctx.Err() != nil {
			t.Fatalf("recovery window did not expire first: %v (caller %v)", err, ctx.Err())
		}
		if !errors.Is(err, errControllerRetryable) || !staged.IsTransient(classifyControllerError(err)) {
			t.Fatalf("expired retryable admission classified terminal: %v", err)
		}
		if elapsed := time.Since(started); elapsed != operatorAdmissionRecoveryTimeout {
			t.Fatalf("recovery expired after %s, want %s", elapsed, operatorAdmissionRecoveryTimeout)
		}
		if staged.IsTransient(classifyControllerError(errors.New("admission denied"))) {
			t.Fatal("a plain rejection became transient")
		}
	})
}
