package swarmruntime

import (
	"context"
	"errors"
	"fmt"
	"testing"

	pkgerrors "github.com/pkg/errors"
)

// SwarmKit retries only when pkg/errors.Cause yields context.Canceled itself.
func TestCanceledOperationIsRetriedNotFatal(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	wrapped := fmt.Errorf("load admitted container image: %w", context.Canceled)
	if err := canceledAsRetry(ctx, wrapped); err != wrapped {
		t.Fatalf("live operation error changed: %v", err)
	}
	cancel()
	if err := canceledAsRetry(ctx, wrapped); pkgerrors.Cause(err) != context.Canceled {
		t.Fatalf("canceled operation error = %v, SwarmKit would fail the task", err)
	}
	if err := canceledAsRetry(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if errors.Is(canceledAsRetry(t.Context(), errors.New("x")), context.Canceled) {
		t.Fatal("unrelated error mapped to cancellation")
	}
}
