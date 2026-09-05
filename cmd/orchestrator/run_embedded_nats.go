package main

import (
	"context"
	"errors"
	"fmt"

	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
)

// A selected replica owns one linked broker. Other hosts have no server
// configuration and open only their authenticated regional client connection.
type embeddedNatsRuntime interface {
	component
	Ready() bool
	Err() error
}

var startEmbeddedNatsRuntime = func(ctx context.Context, config bootstrap.NatsServerConfig) (embeddedNatsRuntime, error) {
	runtime, err := bootstrap.StartNatsServer(ctx, config)
	if runtime == nil {
		return nil, err
	}
	return runtime, err
}

func selectedNatsConfiguration(lookup envLookup) (*bootstrap.NatsServerConfig, error) {
	_, selected := lookup(natsServerConfigEnvironment)
	_, timeoutPresent := lookup(natsServerReadinessEnvironment)
	if !selected {
		if timeoutPresent {
			return nil, errors.New("embedded NATS readiness requires an explicitly selected server configuration")
		}
		return nil, nil
	}
	config, err := natsServerConfiguration(lookup)
	if err != nil {
		return nil, err
	}
	// Static reference admission performs no listener or JetStream startup.
	if _, err := bootstrap.NewNatsServerRunner(config); err != nil {
		return nil, err
	}
	return &config, nil
}

// Keep the broker alive while clients tear down. Parent cancellation applies
// during bounded broker startup, then runCommand owns the shutdown order.
func startSelectedNatsRuntime(ctx, serverCtx context.Context, stopServer context.CancelFunc, config bootstrap.NatsServerConfig) (embeddedNatsRuntime, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	startupDone := make(chan struct{})
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-ctx.Done():
			stopServer()
		case <-startupDone:
		}
	}()
	runtime, err := startEmbeddedNatsRuntime(serverCtx, config)
	close(startupDone)
	<-watcherDone
	if err != nil {
		return runtime, fmt.Errorf("embedded NATS startup: %w", err)
	}
	if isNilProductionValue(runtime) {
		return nil, errors.New("embedded NATS starter returned nil")
	}
	if !runtime.Ready() {
		return runtime, errors.New("embedded NATS starter returned before readiness")
	}
	return runtime, nil
}

func closeRunRuntime(production component, global, regional component, server embeddedNatsRuntime) error {
	result := closeRuntime(production, global, regional)
	if !isNilProductionValue(server) {
		result = combineErrors(result, server.Close())
		result = combineErrors(result, server.Err())
	}
	return result
}
