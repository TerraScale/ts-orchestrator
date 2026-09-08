package main

import (
	"context"
	"errors"
	"terrascale.tech/orchestrator/src/orchestrator/lifecycle"
	"testing"
	"time"
)

func TestProductionRuntimeRequiresOwnershipReread(t *testing.T) {
	_, err := newProductionRuntime(productionRuntimeConfig{})
	if err == nil || err.Error() != "runtime delivery mirror: ownership reread callback is required" {
		t.Fatalf("runtime composition error = %v", err)
	}
}

func TestScheduledServiceFailureSurvivesShutdown(t *testing.T) {
	failure := errors.New("durable journal unavailable")
	for _, interval := range []time.Duration{0, time.Millisecond} {
		t.Run(interval.String(), func(t *testing.T) {
			service := lifecycle.NewScheduledService("restore", interval, func(context.Context, time.Time) error {
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
				runtime := &productionRuntime{active: &productionGlobalWorkers{workers: []*lifecycle.Service{service}}}
				if err := closeRuntime(runtime, nil, nil); !errors.Is(err, failure) {
					t.Fatalf("shutdown lost service failure: %v", err)
				}
			}
		})
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

func TestGlobalClientOwnershipSurvivesPartialConstruction(t *testing.T) {
	for _, stage := range []string{"factory", "proof", "validation"} {
		t.Run(stage, func(t *testing.T) {
			failure := errors.New("client cleanup failed")
			calls := 0
			config := productionGlobalWorkerConfig{Close: func() error { calls++; return failure }}
			factoryFailure := errors.New("provider construction failed")
			runtime := &productionRuntime{plan: &productionGlobalWorkerPlan{Construct: func(context.Context, globalWorkerSession) (productionGlobalWorkerConfig, error) {
				if stage == "factory" {
					return config, factoryFailure
				}
				return config, nil
			}}}
			session := globalWorkerSession{}
			if stage == "validation" {
				session.check = func(context.Context) error { return nil }
			}
			group, err := runtime.constructGlobalWorkers(context.Background(), session)
			if err == nil || group == nil {
				t.Fatal("partial construction lost cleanup owner")
			}
			if stage == "factory" && !errors.Is(err, factoryFailure) {
				t.Fatal(err)
			}
			for range 2 {
				if err := joinGlobalWorker(group); !errors.Is(err, failure) {
					t.Fatalf("client cleanup error lost: %v", err)
				}
			}
			if calls != 1 {
				t.Fatalf("client cleanup called %d times", calls)
			}
		})
	}
}

func TestGlobalWorkerCloseStopsWorkersBeforeDatabase(t *testing.T) {
	order := make(chan string, 1)
	workerStarted := make(chan struct{})
	worker := lifecycle.NewScheduledService("worker", time.Hour, func(ctx context.Context, _ time.Time) error {
		close(workerStarted)
		<-ctx.Done()
		order <- "worker"
		return nil
	})
	if err := worker.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	<-workerStarted

	group := &productionGlobalWorkers{workers: []*lifecycle.Service{worker}, database: &productionDatabase{}, completion: make(chan struct{})}
	if err := group.Close(); err != nil {
		t.Fatal(err)
	}
	if got := <-order; got != "worker" {
		t.Fatalf("close order = %v, want worker before database", got)
	}
}
