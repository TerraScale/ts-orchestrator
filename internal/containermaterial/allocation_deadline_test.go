package containermaterial

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

func TestAllocationContextRetainsOriginalDeadline(t *testing.T) {
	expires := time.Now().Add(time.Minute)
	ctx, cancel := allocationContext(t.Context(), expires, nil, swarmruntime.VerifiedWorkerMembership{})
	defer cancel()
	want := expires
	if inherited, ok := t.Context().Deadline(); ok && inherited.Before(want) {
		want = inherited
	}
	if deadline, ok := ctx.Deadline(); !ok || !deadline.Equal(want) {
		t.Fatal("allocation reads are not bounded by the original release proof")
	}
	parentExpiry := expires.Add(-time.Second)
	parent, stop := context.WithDeadline(t.Context(), parentExpiry)
	defer stop()
	child, finish := allocationContext(parent, expires, nil, swarmruntime.VerifiedWorkerMembership{})
	defer finish()
	want, _ = parent.Deadline()
	if deadline, ok := child.Deadline(); !ok || !deadline.Equal(want) {
		t.Fatal("allocation context extended its caller deadline")
	}
	expired, end := allocationContext(t.Context(), time.Now().Add(-time.Second), nil, swarmruntime.VerifiedWorkerMembership{})
	defer end()
	if !errors.Is(expired.Err(), context.DeadlineExceeded) {
		t.Fatal("expired original proof can still start awaited work")
	}
	// An opaque recipient's zero value must cancel before any source read.
	missing, abort := allocationContext(t.Context(), expires, new(bootstrapstart.ControllerHostRecipient), swarmruntime.VerifiedWorkerMembership{})
	defer abort()
	if !errors.Is(missing.Err(), context.DeadlineExceeded) {
		t.Fatal("missing recipient deadline did not cancel allocation work")
	}
}
