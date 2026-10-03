package netbird

import (
	"context"
	"testing"
	"time"
)

// A status query that hangs past the observation limit is cut at the limit,
// not at the CLI's much longer command timeout, and reads as the limit
// elapsing (#127 12059).
func TestObserveBoundsEveryStatusQueryByItsLimit(t *testing.T) {
	e := testEnroller(t)
	e.poll = 2 * time.Millisecond
	queries := 0
	e.run = func(ctx context.Context, _ string, _ ...string) ([]byte, error) {
		if queries++; queries == 1 {
			return statusJSON("Connecting", DefaultManagementURL, false), nil
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	started := time.Now()
	status, done, err := e.observe(t.Context(), 100*time.Millisecond, nil, func(daemonStatus) bool { return false })
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("a hung status query ran %v past a 100ms limit", elapsed)
	}
	if err != nil || done || status.DaemonStatus != "Connecting" {
		t.Fatalf("observe = %v %t %v; want the last observation at the limit", status, done, err)
	}
}
