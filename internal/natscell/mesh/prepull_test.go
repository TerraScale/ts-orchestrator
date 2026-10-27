package mesh

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

type pullingApplier struct {
	Applier
	failures int
	calls    int
}

func (a *pullingApplier) PrePull(context.Context, swarmruntime.ServiceSpec) error {
	a.calls++
	if a.calls <= a.failures {
		return errors.New("failed to copy: context deadline exceeded")
	}
	return nil
}

// A registry blip is retried; a pull that keeps failing is returned, so the
// release fails before the update stops the serving task.
func TestPrePullRetriesThenRefuses(t *testing.T) {
	spec := swarmruntime.ServiceSpec{Name: "terrabase", Image: "ghcr.io/terrascale/terrabase"}
	blip := &pullingApplier{failures: 1}
	if err := prePull(t.Context(), blip, spec); err != nil || blip.calls != 2 {
		t.Fatalf("blip: %v after %d pulls", err, blip.calls)
	}
	down := &pullingApplier{failures: prePullAttempts}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	if err := prePull(ctx, down, spec); err == nil || down.calls != prePullAttempts {
		t.Fatalf("registry down: %v after %d pulls", err, down.calls)
	}
	gone := &pullingApplier{failures: prePullAttempts}
	canceled, stop := context.WithCancel(t.Context())
	stop()
	if err := prePull(canceled, gone, spec); !errors.Is(err, context.Canceled) || gone.calls != 1 {
		t.Fatalf("canceled release: %v after %d pulls", err, gone.calls)
	}
}
