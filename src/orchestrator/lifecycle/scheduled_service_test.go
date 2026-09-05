package lifecycle

import (
	"context"
	"testing"
	"time"
)

func TestScheduledServiceReconcilesImmediatelyAndStopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	called := make(chan time.Time, 2)
	service := NewScheduledService("test", 24*time.Hour, func(_ context.Context, at time.Time) error {
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

func TestScheduledServiceRejectsUnexpectedExitAndRestart(t *testing.T) {
	service := NewScheduledService("restore", 0, func(context.Context, time.Time) error { return nil })
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
	service := NewScheduledService("restore", 0, func(ctx context.Context, _ time.Time) error {
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
	service := NewScheduledService("restore", 0, func(context.Context, time.Time) error {
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

func TestShutdownSeparatesExecutionFromDisposal(t *testing.T) {
	service := NewScheduledService("failed", 0, func(context.Context, time.Time) error { return context.DeadlineExceeded })
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	<-service.Completion()
	if err := service.Shutdown(); err != nil {
		t.Fatalf("joined operation classified as disposal failure: %v", err)
	}
	if err := service.Close(); err == nil {
		t.Fatal("execution failure lost")
	}
}
