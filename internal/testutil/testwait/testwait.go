// Package testwait waits for readiness within the test binary's deadline.
package testwait

import (
	"context"
	"testing"
	"time"
)

func Until(t *testing.T, what string, ready func() bool) {
	t.Helper()
	ctx := t.Context()
	if deadline, ok := t.Deadline(); ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline.Add(-100*time.Millisecond))
		defer cancel()
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if ready() {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("%s: %v", what, ctx.Err())
		case <-ticker.C:
		}
	}
}

// Budget is the remaining binary deadline, leaving time to report a failure.
func Budget(t *testing.T) time.Duration {
	t.Helper()
	if deadline, ok := t.Deadline(); ok {
		return max(time.Millisecond, time.Until(deadline)-100*time.Millisecond)
	}
	return 30 * time.Second
}
