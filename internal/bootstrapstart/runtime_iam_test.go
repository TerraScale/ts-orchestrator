package bootstrapstart

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
)

func TestRuntimeIAMOriginalExpiryPrecedesReaderAndProvider(t *testing.T) {
	// Uninitialized dependencies would reject or panic if an expired proof
	// reached the signed selection reader or authenticated OCI provider.
	proof := VerifiedRuntimeIAM{reader: &CurrentFounderAuthorityReader{}, factory: &ociclient.Factory{}, observer: &OCIInstanceObserver{}, anchor: "original", expires: time.Now().Add(-time.Second)}
	if !proof.IsVerified() {
		t.Fatal("fixture must reach the original lifetime check")
	}
	if deadline, err := proof.CurrentDeadline(t.Context()); !deadline.IsZero() || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired original reached reader/provider: deadline=%v err=%v", deadline, err)
	}
	proof.expires = time.Now().Add(time.Hour)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if deadline, err := proof.CurrentDeadline(ctx); !deadline.IsZero() || !errors.Is(err, context.Canceled) {
		t.Fatalf("original caller cancellation lost: deadline=%v err=%v", deadline, err)
	}
	if err := proof.VerifyCurrent(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("error-only compatibility guard lost cancellation: %v", err)
	}
}
