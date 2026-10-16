package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell"
)

// A startup open that is retrying when the embedded broker dies is
// cancelled, and the controller reports the stopped broker rather than a
// plain cancellation.
func TestBrokerLifetimeCancelsStartupOpensWhenTheBrokerStops(t *testing.T) {
	brokerStopped := make(chan struct{})
	ctx, stop := brokerLifetimeContext(t.Context(), brokerStopped)
	defer stop()
	opened := make(chan error, 1)
	go func() {
		_, _, err := retryControllerOpen(ctx, "open test store", func() bool { return true }, false,
			func(attempt context.Context) (struct{}, error) {
				<-attempt.Done()
				return struct{}{}, errors.New("nats: timeout")
			}, nil)
		opened <- err
	}()
	close(brokerStopped)
	select {
	case err := <-opened:
		if err == nil {
			t.Fatal("open succeeded after the broker stopped")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a retrying startup open ignored the stopped broker")
	}
	if !brokerLifetimeEnded(t.Context(), ctx) {
		t.Fatalf("cause = %v", context.Cause(ctx))
	}
	if !errors.Is(context.Cause(ctx), natscell.ErrEmbeddedServerStopped) {
		t.Fatalf("cause = %v", context.Cause(ctx))
	}
}

func TestBrokerLifetimeIsNotBlamedForParentShutdown(t *testing.T) {
	parent, cancel := context.WithCancel(t.Context())
	brokerStopped := make(chan struct{})
	ctx, stop := brokerLifetimeContext(parent, brokerStopped)
	defer stop()
	cancel()
	<-ctx.Done()
	close(brokerStopped)
	if brokerLifetimeEnded(parent, ctx) {
		t.Fatal("a parent shutdown was reported as a stopped broker")
	}
	_, stopLive := brokerLifetimeContext(t.Context(), make(chan struct{}))
	stopLive()
}
