// Package testwait sizes test waits from the test binary's own deadline, so a
// starved shard keeps waiting for its condition instead of failing a fixed
// wall-clock budget that a packed 2-core runner cannot meet.
package testwait

import (
	"context"
	"testing"
	"time"
)

// margin stays between the condition's budget and the binary's own deadline.
const margin = 5 * time.Second

// floor keeps a bare `go test` without -timeout from budgeting nothing.
const floor = 20 * time.Second

// Test is the testing.TB methods testwait needs; *testing.T and *testing.B
// both satisfy it, while testing.TB itself does not expose Deadline.
type Test interface {
	testing.TB
	Deadline() (deadline time.Time, ok bool)
}

// Budget reports the condition budget Until and Attempt use: the test's
// remaining own deadline minus a margin, floored so a bare `go test` without
// -timeout still budgets a finite wait.
func Budget(t Test) time.Duration {
	t.Helper()
	deadline, ok := t.Deadline()
	if !ok {
		return floor
	}
	if wait := time.Until(deadline) - margin; wait > floor {
		return wait
	}
	return floor
}

// Until polls condition until it holds or the test's remaining deadline
// (minus a margin, floored) runs out, and fails the test with what when it
// never held.
func Until(t Test, what string, condition func() bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), Budget(t))
	defer cancel()
	Deadline(ctx, t, what, condition)
}

// Deadline is Until for callers that already carry their own bounded context.
func Deadline(ctx context.Context, t testing.TB, what string, condition func() bool) {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if condition() {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("%s: %v", what, ctx.Err())
		case <-ticker.C:
		}
	}
}

// Attempt runs try until it succeeds or the test's remaining deadline (minus a
// margin, floored) runs out, returning its last error.
func Attempt(t Test, try func() error) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), Budget(t))
	defer cancel()
	return Retry(ctx, try)
}

// Retry is Attempt for callers that already carry their own bounded context.
func Retry(ctx context.Context, try func() error) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		err := try()
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return err
		case <-ticker.C:
		}
	}
}
