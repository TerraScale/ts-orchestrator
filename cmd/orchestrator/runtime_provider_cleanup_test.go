package main

import (
	"errors"
	"testing"
)

func TestProductionRuntimeClosesWorkersBeforeProviderClientsOnce(t *testing.T) {
	workerFailure := errors.New("worker cleanup")
	providerFailure := errors.New("provider cleanup")
	var order []string
	runtime := &productionRuntime{
		active: &productionGlobalWorkers{release: func() error {
			order = append(order, "workers")
			return workerFailure
		}},
		release: func() error {
			order = append(order, "providers")
			return providerFailure
		},
	}
	for range 2 {
		err := runtime.Close()
		if !errors.Is(err, workerFailure) || !errors.Is(err, providerFailure) {
			t.Fatalf("cleanup lost an error: %v", err)
		}
	}
	if len(order) != 2 || order[0] != "workers" || order[1] != "providers" {
		t.Fatalf("cleanup order = %v", order)
	}
}
