package natsconnect

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

// deadlineBeforeTimer models an expired socket deadline whose context timer
// callback has not yet run. No timing or scheduler assumptions are needed.
type deadlineBeforeTimer struct {
	context.Context
	deadline time.Time
}

func (ctx deadlineBeforeTimer) Deadline() (time.Time, bool) { return ctx.deadline, true }

func TestConnectionFailureNormalizesDeadlineBeforeContextTimer(t *testing.T) {
	ctx := deadlineBeforeTimer{Context: context.Background(), deadline: time.Now().Add(-time.Second)}
	if err := connectionFailure(ctx, os.ErrDeadlineExceeded); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired handshake returned socket error instead of context deadline: %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	ctx.Context = canceled
	if err := connectionFailure(ctx, os.ErrDeadlineExceeded); !errors.Is(err, context.Canceled) {
		t.Fatalf("explicit cancellation lost precedence: %v", err)
	}
	cause := errors.New("handshake refused")
	ctx.Context = context.Background()
	ctx.deadline = time.Now().Add(time.Minute)
	if err := connectionFailure(ctx, cause); err != cause {
		t.Fatalf("unexpired connection error replaced: %v", err)
	}
	if err := connectionFailure(context.Background(), cause); err != cause {
		t.Fatalf("connection without deadline error replaced: %v", err)
	}
}
