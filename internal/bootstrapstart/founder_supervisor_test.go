package bootstrapstart

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
)

func instantAfter(delays *[]time.Duration) func(time.Duration) <-chan time.Time {
	return func(delay time.Duration) <-chan time.Time {
		*delays = append(*delays, delay)
		ready := make(chan time.Time, 1)
		ready <- time.Time{}
		return ready
	}
}

func TestFounderSupervisorRetriesWithBackoffUntilComplete(t *testing.T) {
	var delays []time.Duration
	attempts := 0
	supervisor := &FounderSupervisor{MinBackoff: time.Second, MaxBackoff: 4 * time.Second,
		Logger: slog.New(slog.DiscardHandler), After: instantAfter(&delays),
		Found: func(context.Context) error {
			attempts++
			if attempts < 5 {
				return fmt.Errorf("%w: launch out of capacity", ErrFounderRuntime)
			}
			return nil
		}}
	if !supervisor.Supervise(t.Context()) {
		t.Fatal("founder supervisor did not report completion")
	}
	if attempts != 5 || len(delays) != 4 {
		t.Fatalf("attempts=%d delays=%v", attempts, delays)
	}
	for index, base := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 4 * time.Second} {
		if delays[index] < base || delays[index] > base+base/5 {
			t.Fatalf("delay %d = %s, want %s plus at most 20%% jitter", index, delays[index], base)
		}
	}
	if status := supervisor.Status(); status.Phase != FounderPhaseComplete || status.Attempt != 5 {
		t.Fatalf("status = %+v", status)
	}
}

func TestFounderSupervisorReportsPlanExpiryAsOperatorAction(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var delays []time.Duration
	var observed FounderStatus
	supervisor := &FounderSupervisor{MinBackoff: time.Second, MaxBackoff: time.Minute,
		Logger: slog.New(slog.DiscardHandler)}
	supervisor.After = func(delay time.Duration) <-chan time.Time {
		delays = append(delays, delay)
		observed = supervisor.Status()
		cancel()
		return make(chan time.Time)
	}
	supervisor.Found = func(context.Context) error {
		return fmt.Errorf("%w: peer %q: reserve planned peer slot: %w", ErrFounderRuntime, "controller-b",
			bootstrap.ErrFounderPlanExpired)
	}
	if supervisor.Supervise(ctx) {
		t.Fatal("expired plan reported completion")
	}
	if observed.Phase != FounderPhaseOperatorAction || observed.LastError == "" || observed.NextRetry.IsZero() {
		t.Fatalf("status before retry = %+v", observed)
	}
	if len(delays) != 1 || delays[0] < time.Minute {
		t.Fatalf("operator-action retry delay = %v, want the slow maximum", delays)
	}
	if status := supervisor.Status(); status.Phase != FounderPhaseStopped {
		t.Fatalf("status after cancellation = %+v", status)
	}
}

func TestFounderSupervisorStopsOnCancellationWithoutError(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	started := make(chan struct{})
	supervisor := &FounderSupervisor{Logger: slog.New(slog.DiscardHandler),
		Found: func(ctx context.Context) error {
			close(started)
			<-ctx.Done()
			return ctx.Err()
		}}
	done := make(chan bool, 1)
	go func() { done <- supervisor.Supervise(ctx) }()
	<-started
	cancel()
	select {
	case complete := <-done:
		if complete {
			t.Fatal("cancelled founder reported completion")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("founder supervisor ignored cancellation")
	}
	if !founderNeedsOperator(fmt.Errorf("wrapped: %w", ErrFounderSigner)) ||
		founderNeedsOperator(errors.New("transient OCI 500")) {
		t.Fatal("founder error classification changed")
	}
}
