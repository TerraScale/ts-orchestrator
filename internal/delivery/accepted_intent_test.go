package delivery

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

func TestAcceptedIntentIgnoresVerifiedCacheButRejectsAmbiguousOperations(t *testing.T) {
	s, ctx := testService(t, &testWriter{})
	intent := testIntent(t, s, ctx)
	if err := s.SubmitVerified(ctx, intent, "operator"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcceptedIntent(ctx, intent); !errors.Is(err, ErrPending) {
		t.Fatalf("unconsumed verified intent: %v", err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- s.Run(runCtx) }()
	defer func() { cancel(); <-done }()
	waitAccepted := func(i Intent) {
		t.Helper()
		for {
			receipt, err := s.StatusFor(ctx, i)
			if err == nil {
				if receipt.Status != "accepted" {
					t.Fatalf("receipt: %+v", receipt)
				}
				return
			}
			if !errors.Is(err, ErrPending) {
				t.Fatal(err)
			}
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(10 * time.Millisecond):
			}
		}
	}
	waitAccepted(intent)
	got, err := s.AcceptedIntent(ctx, intent)
	if err != nil || got != intent {
		t.Fatalf("cache plus accepted operation: intent=%+v error=%v", got, err)
	}
	second := intent
	second.OperationID = entityid.Derive("test-accepted-intent", "second")
	if err := s.SubmitVerified(ctx, second, "operator"); err != nil {
		t.Fatal(err)
	}
	waitAccepted(second)
	if _, err := s.AcceptedIntent(ctx, intent); !errors.Is(err, ErrConflict) {
		t.Fatalf("two accepted operations for one baseline: %v", err)
	}
}
