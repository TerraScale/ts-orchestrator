package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

type supervisedTestService struct {
	done       chan struct{}
	context    context.Context
	startError error
	closeError error
	closed     bool
}

func (s *supervisedTestService) Start(ctx context.Context) error {
	s.context = ctx
	return s.startError
}
func (s *supervisedTestService) Completion() <-chan struct{} { return s.done }
func (s *supervisedTestService) Close() error                { s.closed = true; return s.closeError }

func TestReconcileDependencyFailureCancelsInflightProviderAndPreservesCause(t *testing.T) {
	for _, failed := range []string{"production", "kv"} {
		t.Run(failed, func(t *testing.T) {
			failure := errors.New("durable required worker failed")
			production := &supervisedTestService{done: make(chan struct{})}
			kv := &supervisedTestService{done: make(chan struct{})}
			service := production
			if failed == "kv" {
				service = kv
			}
			service.closeError = failure
			stopped := make(chan struct{})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err := runSupervisedReconcile(ctx, func(operation context.Context) error {
				close(service.done)
				<-operation.Done()
				close(stopped)
				return operation.Err()
			}, production, kv)
			if !errors.Is(err, failure) || errors.Is(err, context.Canceled) {
				t.Fatalf("worker cause replaced by cancellation: %v", err)
			}
			select {
			case <-stopped:
			default:
				t.Fatal("in-flight provider operation was not cancelled")
			}
			if !production.closed || !kv.closed || production.context.Err() == nil || kv.context.Err() == nil {
				t.Fatal("required services did not share shutdown")
			}
		})
	}
}

func TestReconcileStartupFailureDoesNotMutateProviders(t *testing.T) {
	for _, stage := range []string{"production", "kv", "already-stopped"} {
		t.Run(stage, func(t *testing.T) {
			failure := errors.New("startup failed")
			production := &supervisedTestService{done: make(chan struct{})}
			kv := &supervisedTestService{done: make(chan struct{})}
			switch stage {
			case "production":
				production.startError = failure
			case "kv":
				kv.startError = failure
			case "already-stopped":
				close(production.done)
			}
			err := runSupervisedReconcile(context.Background(), func(context.Context) error { t.Fatal("provider loop ran without required services"); return nil }, production, kv)
			if err == nil {
				t.Fatal("startup failure accepted")
			}
			if !production.closed || !kv.closed {
				t.Fatal("partial startup was not cleaned up")
			}
		})
	}
}

func TestReconcileCancellationAndUnexpectedLoopExit(t *testing.T) {
	production := &supervisedTestService{done: make(chan struct{})}
	kv := &supervisedTestService{done: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	err := runSupervisedReconcile(ctx, func(operation context.Context) error { cancel(); <-operation.Done(); return operation.Err() }, production, kv)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
	production = &supervisedTestService{done: make(chan struct{})}
	kv = &supervisedTestService{done: make(chan struct{})}
	if err := runSupervisedReconcile(context.Background(), func(context.Context) error { return nil }, production, kv); err == nil {
		t.Fatal("unexpected provider loop exit accepted")
	}
}

func TestAllRuntimeDependenciesAreSupervised(t *testing.T) {
	regional := &supervisedTestService{done: make(chan struct{})}
	production := &supervisedTestService{done: make(chan struct{})}
	global := &supervisedTestService{done: make(chan struct{})}
	close(global.done)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := waitForComponents(ctx, regional, production, global); err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second dependency stop was ignored: %v", err)
	}
}
