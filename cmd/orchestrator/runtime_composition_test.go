package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestProductionRuntimeRequiresOwnershipReread(t *testing.T) {
	_, err := newProductionRuntime(productionRuntimeConfig{})
	if err == nil || err.Error() != "runtime delivery mirror: ownership reread callback is required" {
		t.Fatalf("runtime composition error = %v", err)
	}
}

func TestScheduledServiceReconcilesImmediatelyAndStopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	called := make(chan time.Time, 2)
	service := newScheduledService("test", 24*time.Hour, func(_ context.Context, at time.Time) error {
		called <- at
		return nil
	})
	before := time.Now()
	if err := service.Start(ctx); err != nil {
		t.Fatalf("start scheduled service: %v", err)
	}
	select {
	case at := <-called:
		if at.Before(before) || at.After(time.Now()) || at.Location() != time.UTC {
			t.Fatalf("startup reconciliation time = %v", at)
		}
	case <-time.After(time.Second):
		t.Fatal("daily service postponed startup reconciliation")
	}
	cancel()
	if err := service.Close(); err != nil {
		t.Fatalf("close scheduled service: %v", err)
	}
	select {
	case <-called:
		t.Fatal("scheduled service ran again before its interval")
	default:
	}
}

func TestScheduledServiceFailureSurvivesShutdown(t *testing.T) {
	failure := errors.New("durable journal unavailable")
	for _, interval := range []time.Duration{0, time.Millisecond} {
		t.Run(interval.String(), func(t *testing.T) {
			service := newScheduledService("restore", interval, func(context.Context, time.Time) error {
				return failure
			})
			if err := service.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			select {
			case <-service.Completion():
			case <-time.After(time.Second):
				t.Fatal("failed worker did not stop")
			}
			for range 2 {
				runtime := &productionRuntime{workers: []*scheduledService{service}}
				if err := closeRuntime(runtime, nil, nil); !errors.Is(err, failure) {
					t.Fatalf("shutdown lost service failure: %v", err)
				}
			}
		})
	}
}

func TestScheduledServiceRejectsUnexpectedExitAndRestart(t *testing.T) {
	service := newScheduledService("restore", 0, func(context.Context, time.Time) error { return nil })
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-service.Completion():
	case <-time.After(time.Second):
		t.Fatal("worker did not exit")
	}
	if err := service.Close(); err == nil {
		t.Fatal("unscheduled service exited successfully while runtime was active")
	}
	if err := service.Start(context.Background()); err == nil {
		t.Fatal("completed service restarted")
	}
}

func TestScheduledServiceCancellationIsClean(t *testing.T) {
	started := make(chan struct{})
	service := newScheduledService("restore", 0, func(ctx context.Context, _ time.Time) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	})
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	<-started
	if err := service.Start(context.Background()); err == nil {
		t.Fatal("running service started twice")
	}
	if err := service.Close(); err != nil {
		t.Fatalf("cancellation was reported as a worker failure: %v", err)
	}
}

func TestScheduledServiceCloseBeforeStart(t *testing.T) {
	service := newScheduledService("restore", 0, func(context.Context, time.Time) error {
		t.Fatal("closed service ran")
		return nil
	})
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	if err := service.Start(context.Background()); err == nil {
		t.Fatal("closed service started")
	}
}

func TestCloseRuntimeUsesProductionBeforeControlRuntimes(t *testing.T) {
	order := []string{}
	production := &fakeComponent{done: make(chan struct{}), name: "production", order: &order}
	global := &fakeComponent{done: make(chan struct{}), name: "global", order: &order}
	regional := &fakeComponent{done: make(chan struct{}), name: "regional", order: &order}
	close(production.done)
	close(global.done)
	close(regional.done)
	if err := closeRuntime(production, global, regional); err != nil {
		t.Fatalf("close runtime: %v", err)
	}
	if got, want := order, []string{"production", "global", "regional"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("close order = %v, want %v", got, want)
	}
}
