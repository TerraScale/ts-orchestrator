package app

import (
	"context"
	"testing"
	"time"
)

// A founder stuck in a call that ignores cancellation (the OCI SDK's
// instance-principal retry sleeps) must not hold controller shutdown past
// its join bound.
func TestFounderJoinIsBoundedWhenTheFounderIgnoresCancellation(t *testing.T) {
	shortFounderBackoff(t)
	previous := controllerFounderJoinTimeout
	controllerFounderJoinTimeout = 50 * time.Millisecond
	t.Cleanup(func() { controllerFounderJoinTimeout = previous })
	release := make(chan struct{})
	defer close(release)
	entered := make(chan struct{})
	_, stop, err := superviseFounderAndWaitCluster(t.Context(), func(context.Context) error { return nil },
		func(context.Context) error {
			close(entered)
			<-release // Ignores ctx, like an SDK retry sleep.
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	<-entered
	stopped := make(chan struct{})
	go func() {
		stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown waited on a founder that ignores cancellation")
	}
}
