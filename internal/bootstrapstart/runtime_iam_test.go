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
	proof := VerifiedRuntimeIAM{original: t.Context(), reader: &CurrentFounderAuthorityReader{}, factory: &ociclient.Factory{}, observer: &OCIInstanceObserver{}, anchor: "original", expires: time.Now().Add(-time.Second)}
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

func TestRuntimeIAMOriginalAcquisitionCancellationPrecedesFreshCaller(t *testing.T) {
	original, cancel := context.WithCancel(t.Context())
	proof := VerifiedRuntimeIAM{original: original, reader: &CurrentFounderAuthorityReader{}, factory: &ociclient.Factory{}, observer: &OCIInstanceObserver{}, anchor: "original", expires: time.Now().Add(time.Hour)}
	if !proof.IsVerified() {
		t.Fatal("fixture must reach the original acquisition cancellation check")
	}
	cancel()
	if deadline, err := proof.CurrentDeadline(context.Background()); !deadline.IsZero() || !errors.Is(err, context.Canceled) {
		t.Fatalf("fresh caller reopened canceled original acquisition: deadline=%v err=%v", deadline, err)
	}
	if err := proof.VerifyCurrent(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatalf("compatibility guard reopened canceled original acquisition: %v", err)
	}
	if factory, _, err := proof.GuardedFactory(context.Background()); factory != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("guarded factory reopened canceled original acquisition: factory=%v err=%v", factory, err)
	}
}
