package app

import (
	"context"
	"errors"
	"testing"
)

func TestHostRunResultOnlyTreatsParentCancellationAsShutdown(t *testing.T) {
	if err := hostRunResult(t.Context(), context.Canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("live parent concealed agent cancellation: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := hostRunResult(ctx, context.Canceled); err != nil {
		t.Fatalf("canceled parent was treated as a host failure: %v", err)
	}

	failure := errors.New("host session lost")
	if err := hostRunResult(ctx, failure); !errors.Is(err, failure) {
		t.Fatalf("canceled parent concealed an unrelated host failure: %v", err)
	}
}
