package app

import (
	"context"
	"errors"
	"testing"
)

func TestManagedRuntimeRootSourcesKeepsCancellationCause(t *testing.T) {
	ctx, cancel := context.WithCancelCause(t.Context())
	cause := errors.New("original runtime authority ended")
	cancel(cause)
	if err := runManagedRuntimeRootSources(ctx, Config{}, nil, nil, nil, nil); !errors.Is(err, cause) {
		t.Fatalf("source supervisor cancellation = %v, want original cause %v", err, cause)
	}
}
