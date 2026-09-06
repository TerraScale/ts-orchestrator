package lifecycle

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// A provider error ends one service generation. The production supervisor
// turns that completion into a process restart; the next generation must
// immediately retry the same durable callback with a fresh context.
func TestScheduledServiceReconstructionRetriesDurableCallback(t *testing.T) {
	var calls atomic.Int32
	transient := errors.New("transient provider failure")
	run := func(ctx context.Context, _ time.Time) error {
		if ctx == nil {
			return errors.New("callback received nil context")
		}
		if calls.Add(1) == 1 {
			return transient
		}
		return nil
	}

	first := NewScheduledService("key rotation", time.Hour, run)
	if err := first.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-first.Completion():
	case <-time.After(time.Second):
		t.Fatal("failed service generation did not stop")
	}
	if err := first.Close(); !errors.Is(err, transient) {
		t.Fatalf("first generation error = %v, want transient failure", err)
	}

	second := NewScheduledService("key rotation", time.Hour, run)
	if err := second.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(time.Second)
	for calls.Load() < 2 {
		select {
		case <-second.Completion():
			t.Fatal("reconstructed service stopped before retry")
		case <-deadline:
			t.Fatal("reconstructed service did not retry durable callback")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}
