package main

import (
	"context"
	"errors"
	"fmt"
	"time"
)

type reconcileBackgroundService interface {
	component
	Start(context.Context) error
}

// Required automation and provider reconciliation share one cancellation
// boundary. Stopped dependencies end provider work before shutdown reports the
// original failure; missing automation never permits a standalone mutation loop.
func runSupervisedReconcile(ctx context.Context, run func(context.Context) error, production, kv reconcileBackgroundService) (result error) {
	if ctx == nil || run == nil || isNilProductionValue(production) || isNilProductionValue(kv) {
		return errors.New("reconcile: complete runtime supervision is required")
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer func() {
		cancel()
		result = errors.Join(result, kv.Close(), production.Close())
	}()
	if err := production.Start(runCtx); err != nil {
		return fmt.Errorf("reconcile: production runtime startup: %w", err)
	}
	if err := kv.Start(runCtx); err != nil {
		return fmt.Errorf("reconcile: KV writer startup: %w", err)
	}
	if production.Completion() == nil || kv.Completion() == nil {
		return errors.New("reconcile: required service has no completion observation")
	}
	for _, service := range []reconcileBackgroundService{production, kv} {
		select {
		case <-service.Completion():
			return errors.New("reconcile: required service stopped before provider reconciliation")
		default:
		}
	}
	if err := runCtx.Err(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- run(runCtx) }()
	var runErr error
	completed := false
	select {
	case <-ctx.Done():
		result = ctx.Err()
	case <-production.Completion():
		result = errors.New("reconcile: production automation stopped unexpectedly")
	case <-kv.Completion():
		result = errors.New("reconcile: KV writer stopped unexpectedly")
	case runErr = <-done:
		completed = true
	}
	cancel()
	if !completed {
		select {
		case runErr = <-done:
		case <-time.After(10 * time.Second):
			return errors.Join(result, errors.New("reconcile: provider loop shutdown timed out"))
		}
	}
	// A cancelled provider request is the consequence of a failed dependency,
	// not a replacement for that failure (or a reason to exit as user cancellation).
	if runErr != nil && !(runCtx.Err() != nil && errors.Is(runErr, runCtx.Err())) {
		result = errors.Join(result, runErr)
	}
	if result == nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if result == nil {
		return errors.New("reconcile: provider loop stopped unexpectedly")
	}
	return result
}
