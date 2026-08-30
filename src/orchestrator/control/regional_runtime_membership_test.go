package control

import (
	"context"
	"testing"
	"time"
)

func TestRegionalRuntimeMembershipDisposeWaitsForHeartbeat(t *testing.T) {
	stoppingCtx, stopping := context.WithCancel(context.Background())
	membership := &RegionalRuntimeMembership{
		stopping:      stopping,
		stoppingCtx:   stoppingCtx,
		watchLoopDone: make(chan struct{}),
		heartbeatDone: make(chan struct{}),
	}
	// This models a normally started membership. The heartbeat must finish
	// before Dispose proceeds to its compare-and-delete section.
	membership.watchStarted = 1
	membership.heartbeatStarted = 1
	close(membership.watchLoopDone)

	disposed := make(chan struct{})
	go func() {
		_ = membership.Dispose()
		close(disposed)
	}()

	select {
	case <-disposed:
		t.Fatal("Dispose returned before heartbeat completion")
	case <-time.After(25 * time.Millisecond):
	}

	close(membership.heartbeatDone)
	select {
	case <-disposed:
	case <-time.After(time.Second):
		t.Fatal("Dispose did not complete after heartbeat completion")
	}
}

func TestRegionalRuntimeMembershipDisposeBeforeHeartbeatStartDoesNotBlock(t *testing.T) {
	stoppingCtx, stopping := context.WithCancel(context.Background())
	membership := &RegionalRuntimeMembership{
		stopping:      stopping,
		stoppingCtx:   stoppingCtx,
		watchLoopDone: make(chan struct{}),
		heartbeatDone: make(chan struct{}),
	}

	done := make(chan struct{})
	go func() {
		_ = membership.Dispose()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Dispose blocked before heartbeat startup")
	}
}
