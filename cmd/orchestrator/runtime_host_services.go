package main

import (
	"context"
	"errors"
	"sync"

	"terrascale.tech/orchestrator/src/orchestrator/control"
	"terrascale.tech/orchestrator/src/orchestrator/keylease"
)

type hostServices interface {
	Completion() <-chan struct{}
	Close() error
}
type configuredHostServices struct {
	lease     *keylease.Server
	placement *productionPlacementHost
	database  *productionDatabaseHostServices
	done      chan struct{}
	cancel    context.CancelFunc
	once      sync.Once
}

func (h *configuredHostServices) Completion() <-chan struct{} { return h.done }
func (h *configuredHostServices) Close() error {
	var err error
	h.once.Do(func() { h.cancel(); err = errors.Join(h.database.Close(), h.placement.Close(), h.lease.Close()) })
	return err
}
func startConfiguredHostServices(ctx context.Context, options *control.OrchestratorOptions, lookup envLookup) (hostServices, error) {
	if options.Cell == "local" {
		return nil, nil
	}
	local, cancel := context.WithCancel(ctx)
	lease, err := startKeyLease(local, options, lookup)
	if err != nil {
		cancel()
		return nil, err
	}
	placement, err := startProductionPlacementHost(local, options, lookup)
	if err != nil {
		cancel()
		lease.Close()
		return nil, err
	}
	database, err := startProductionDatabaseHost(local, options, lookup)
	if err != nil {
		cancel()
		_ = placement.Close()
		_ = lease.Close()
		return nil, err
	}
	hosts := &configuredHostServices{database: database, lease: lease, placement: placement, done: make(chan struct{}), cancel: cancel}
	go func() {
		defer close(hosts.done)
		select {
		case <-lease.Completion():
		case <-placement.Completion():
		case <-database.Completion():
		case <-local.Done():
		}
		cancel()
	}()
	return hosts, nil
}
