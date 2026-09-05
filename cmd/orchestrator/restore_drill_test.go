package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/restoredrill"
)

func TestProductionRestoreSchedulerCadenceAndCancellation(t *testing.T) {
	config := (productionRestoreConfig{}).resolve(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	const interval = 20 * time.Millisecond
	started := time.Now()
	ticks := make(chan time.Time, 4)
	finished := make(chan error, 1)
	go func() {
		finished <- config.Scheduler.Every(ctx, interval, func(_ context.Context, at time.Time) error {
			ticks <- at
			return nil
		})
	}()
	var prior time.Time
	for i := 0; i < 3; i++ {
		select {
		case at := <-ticks:
			if at.Before(started.Add(interval)) || !prior.IsZero() && at.Sub(prior) < interval/2 {
				t.Fatalf("restore tick escaped declared cadence: started=%v prior=%v at=%v", started, prior, at)
			}
			prior = at
		case <-ctx.Done():
			t.Fatal("production restore scheduler stopped before completing its cadence")
		}
	}
	cancel()
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("scheduler cancellation=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("restore scheduler did not stop with its runtime")
	}
}

func TestProductionRestoreSchedulerFailureReachesSupervision(t *testing.T) {
	failure := errors.New("restore journal unavailable")
	config := (productionRestoreConfig{}).resolve(nil)
	service := newScheduledService("restore drill", 0, func(ctx context.Context, _ time.Time) error {
		return config.Scheduler.Every(ctx, time.Millisecond, func(context.Context, time.Time) error {
			return failure
		})
	})
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	select {
	case <-service.Completion():
	case <-time.After(time.Second):
		t.Fatal("restore scheduler hid its failed callback from supervision")
	}
	if err := service.Close(); !errors.Is(err, failure) {
		t.Fatalf("restore shutdown lost the callback failure: %v", err)
	}
}

func TestProductionRestoreSchedulerCannotMaskMissingAuthorities(t *testing.T) {
	config := (productionRestoreConfig{}).resolve(nil)
	if config.Scheduler == nil {
		t.Fatal("command omitted its production scheduler")
	}
	if _, err := restoredrill.NewProductionComposition(config); err == nil {
		t.Fatal("owned scheduler bypassed required restore authorities")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := config.Scheduler.Every(ctx, 24*time.Hour, func(context.Context, time.Time) error {
		t.Fatal("cancelled daily scheduler invoked a drill")
		return nil
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled daily scheduler=%v", err)
	}
}
