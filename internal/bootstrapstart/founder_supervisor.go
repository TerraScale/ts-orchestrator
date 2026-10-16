package bootstrapstart

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
)

// FounderPhase is the seed founder worker's externally visible state.
type FounderPhase string

const (
	FounderPhaseRunning  FounderPhase = "running"
	FounderPhaseRetrying FounderPhase = "retrying"
	// FounderPhaseOperatorAction means retrying cannot succeed without an
	// operator, for example after the signed plan's launch deadline. The
	// worker keeps polling slowly so a re-signed plan resumes founding.
	FounderPhaseOperatorAction FounderPhase = "operator_action_required"
	FounderPhaseComplete       FounderPhase = "complete"
	FounderPhaseStopped        FounderPhase = "stopped"
)

// FounderStatus is the latest founder worker state for logs and diagnostics.
type FounderStatus struct {
	Phase     FounderPhase `json:"phase"`
	Attempt   int          `json:"attempt"`
	LastError string       `json:"lastError,omitempty"`
	NextRetry time.Time    `json:"nextRetry,omitzero"`
	UpdatedAt time.Time    `json:"updatedAt"`
}

const (
	defaultFounderMinBackoff = 5 * time.Second
	defaultFounderMaxBackoff = 5 * time.Minute
)

// FounderSupervisor runs the seed founder off the controller's startup
// critical path. A founder error never stops the embedded broker or the
// process: it is logged, recorded in Status, and retried with exponential
// backoff and jitter. Every attempt re-enters the full founder, so each retry
// repeats all signed-plan, floor, and ledger checks from scratch.
type FounderSupervisor struct {
	Found      func(context.Context) error
	MinBackoff time.Duration
	MaxBackoff time.Duration
	Logger     *slog.Logger
	Now        func() time.Time
	// After is a test seam for the backoff timer.
	After func(time.Duration) <-chan time.Time

	mu     sync.Mutex
	status FounderStatus
}

// Status returns the most recent founder worker state.
func (supervisor *FounderSupervisor) Status() FounderStatus {
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	return supervisor.status
}

// Supervise runs until founding completes or ctx ends. It reports whether
// founding completed.
func (supervisor *FounderSupervisor) Supervise(ctx context.Context) bool {
	logger := supervisor.Logger
	if logger == nil {
		logger = slog.Default()
	}
	minimum, maximum := supervisor.MinBackoff, supervisor.MaxBackoff
	if minimum <= 0 {
		minimum = defaultFounderMinBackoff
	}
	if maximum < minimum {
		maximum = max(defaultFounderMaxBackoff, minimum)
	}
	after := supervisor.After
	if after == nil {
		after = time.After
	}
	if supervisor.Found == nil {
		supervisor.set(FounderStatus{Phase: FounderPhaseOperatorAction, LastError: "founder is not configured"})
		logger.Error("seed founder worker is not configured")
		return false
	}
	backoff := minimum
	for attempt := 1; ; attempt++ {
		if ctx.Err() != nil {
			supervisor.set(FounderStatus{Phase: FounderPhaseStopped, Attempt: attempt - 1})
			return false
		}
		supervisor.set(FounderStatus{Phase: FounderPhaseRunning, Attempt: attempt})
		err := supervisor.Found(ctx)
		if err == nil {
			supervisor.set(FounderStatus{Phase: FounderPhaseComplete, Attempt: attempt})
			logger.Info("seed founder completed every planned peer", "attempt", attempt)
			return true
		}
		if ctx.Err() != nil {
			supervisor.set(FounderStatus{Phase: FounderPhaseStopped, Attempt: attempt})
			return false
		}
		phase, delay := FounderPhaseRetrying, backoff
		if founderNeedsOperator(err) {
			phase, delay = FounderPhaseOperatorAction, maximum
		}
		// Up to 20% jitter keeps restarted seeds from retrying OCI in lockstep.
		delay += time.Duration(rand.Int64N(int64(delay)/5 + 1))
		next := supervisor.now().Add(delay)
		supervisor.set(FounderStatus{Phase: phase, Attempt: attempt, LastError: err.Error(), NextRetry: next})
		level := slog.LevelWarn
		if phase == FounderPhaseOperatorAction {
			level = slog.LevelError
		}
		logger.Log(ctx, level, "seed founder attempt failed; embedded NATS stays up",
			"phase", string(phase), "attempt", attempt, "retry_in", delay.Round(time.Second), "error", err)
		backoff = min(backoff*2, maximum)
		select {
		case <-ctx.Done():
			supervisor.set(FounderStatus{Phase: FounderPhaseStopped, Attempt: attempt, LastError: err.Error()})
			return false
		case <-after(delay):
		}
	}
}

// founderNeedsOperator classifies errors that a plain retry cannot fix.
func founderNeedsOperator(err error) bool {
	return errors.Is(err, bootstrap.ErrFounderPlanExpired) || errors.Is(err, ErrFounderSelectionFloor) ||
		errors.Is(err, ErrFounderSigner) || errors.Is(err, bootstrap.ErrControllerAntiAffinity)
}

func (supervisor *FounderSupervisor) now() time.Time {
	if supervisor.Now != nil {
		return supervisor.Now().UTC()
	}
	return time.Now().UTC()
}

func (supervisor *FounderSupervisor) set(status FounderStatus) {
	status.UpdatedAt = supervisor.now()
	supervisor.mu.Lock()
	supervisor.status = status
	supervisor.mu.Unlock()
}
