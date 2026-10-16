package membership

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
)

type blockingReplacer struct {
	started chan struct{}
	fence   func(context.Context) error
	ended   chan error
}

func (replacer *blockingReplacer) Replace(ctx context.Context, action Action) error {
	replacer.fence = action.Fence
	close(replacer.started)
	<-ctx.Done()
	replacer.ended <- context.Cause(ctx)
	return ctx.Err()
}

// The authority fence extends through a running replacement: the action
// carries the term's guard, and losing the term cancels the replacement.
func TestReplacementIsCancelledWhenTheTermEnds(t *testing.T) {
	previous := termFencePoll
	termFencePoll = 5 * time.Millisecond
	t.Cleanup(func() { termFencePoll = previous })
	clock := testEpoch
	leader := &fakeLeadership{snapshot: leaderSnapshot(4)}
	cell := newFakeCell()
	replacer := &blockingReplacer{started: make(chan struct{}), ended: make(chan error, 1)}
	reconciler := newTestReconciler(t, testConfig(), leader, cell, replacer, &clock)
	done := make(chan error, 1)
	go func() { done <- reconciler.Tick(t.Context()) }()
	select {
	case <-replacer.started:
	case <-time.After(5 * time.Second):
		t.Fatal("replacement did not start")
	}
	if replacer.fence == nil {
		t.Fatal("the action carries no authority fence")
	}
	if err := replacer.fence(t.Context()); err != nil {
		t.Fatalf("fence while the term holds = %v", err)
	}
	leader.mu.Lock()
	leader.snapshot = leaderSnapshot(5)
	leader.mu.Unlock()
	select {
	case cause := <-replacer.ended:
		if cause == nil || errors.Is(cause, context.Canceled) {
			t.Fatalf("replacement ended for %v, not the lost term", cause)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a replacement kept running after its authority term ended")
	}
	if err := replacer.fence(t.Context()); !errors.Is(err, authority.ErrFenced) {
		t.Fatalf("fence after the term ended = %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
