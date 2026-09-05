// Package lifecycle owns bounded cancellation and joining of scheduled services.
package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Service adapts a periodic operation to the command lifecycle.
// A zero interval means the operation owns its own cadence (the restore
// drill's daily SchedulerPort); all services still share cancellation.
type Service struct {
	name       string
	interval   time.Duration
	run        func(context.Context, time.Time) error
	completion chan struct{}
	cancel     context.CancelFunc
	mu         sync.Mutex
	started    bool
	closed     bool
	runError   error
}

func NewScheduledService(name string, interval time.Duration, run func(context.Context, time.Time) error) *Service {
	return &Service{name: name, interval: interval, run: run, completion: make(chan struct{})}
}

func (s *Service) Start(ctx context.Context) error {
	if s == nil || s.run == nil || ctx == nil {
		return errors.New("orchestrator: scheduled service is invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started || s.closed {
		return fmt.Errorf("orchestrator: %s cannot be started again", s.name)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	loopCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.started = true
	go func() {
		defer close(s.completion)
		if s.interval <= 0 {
			err := s.run(loopCtx, time.Time{})
			if err == nil && loopCtx.Err() == nil {
				err = errors.New("service stopped unexpectedly")
			}
			s.recordError(loopCtx, err)
			return
		}
		// Reconcile persisted work on every start. Waiting for the first daily
		// tick leaves interrupted rotations and reaping asleep after a restart.
		if err := loopCtx.Err(); err != nil {
			return
		}
		if err := s.run(loopCtx, time.Now().UTC()); err != nil {
			s.recordError(loopCtx, err)
			return
		}
		ticker := time.NewTicker(s.interval)
		defer ticker.Stop()
		for {
			select {
			case <-loopCtx.Done():
				return
			case at := <-ticker.C:
				if err := s.run(loopCtx, at); err != nil {
					s.recordError(loopCtx, err)
					return
				}
			}
		}
	}()
	return nil
}

func (s *Service) recordError(ctx context.Context, err error) {
	if err == nil || (ctx.Err() != nil && errors.Is(err, ctx.Err())) {
		return
	}
	s.mu.Lock()
	s.runError = fmt.Errorf("orchestrator: %s failed: %w", s.name, err)
	s.mu.Unlock()
}

func (s *Service) Completion() <-chan struct{} {
	if s == nil {
		return nil
	}
	return s.completion
}

func (s *Service) Shutdown() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	s.closed = true
	if s.cancel != nil {
		s.cancel()
	}
	started := s.started
	s.mu.Unlock()
	if !started {
		return nil
	}
	select {
	case <-s.completion:
		return nil
	case <-time.After(10 * time.Second):
		return fmt.Errorf("orchestrator: %s shutdown timed out", s.name)
	}
}

// Close joins the service and reports its execution failure. Shutdown joins
// without treating a canceled session's completed operation as disposal failure.
func (s *Service) Close() error {
	if err := s.Shutdown(); err != nil {
		return err
	}
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.runError
}
func (s *Service) Name() string { return s.name }
