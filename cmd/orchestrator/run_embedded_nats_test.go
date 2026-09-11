package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"terrascale.tech/orchestrator/src/orchestrator/lifecycle"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/control"
)

type fakeEmbeddedNats struct {
	done    chan struct{}
	ready   bool
	failure error
	closed  bool
	close   func()
}

func (s *fakeEmbeddedNats) Ready() bool                 { return s.ready }
func (s *fakeEmbeddedNats) Completion() <-chan struct{} { return s.done }
func (s *fakeEmbeddedNats) Err() error                  { return s.failure }
func (s *fakeEmbeddedNats) Close() error {
	s.closed = true
	if s.close != nil {
		s.close()
	}
	return nil
}

func TestRunEmbeddedNatsRequiresExplicitSelection(t *testing.T) {
	lookup := func(values map[string]string) envLookup {
		return func(key string) (string, bool) { value, present := values[key]; return value, present }
	}
	if config, err := selectedNatsConfiguration(lookup(nil)); err != nil || config != nil {
		t.Fatalf("unselected host: %v %v", config, err)
	}
	for _, values := range []map[string]string{
		{natsServerReadinessEnvironment: "1s"}, {natsServerConfigEnvironment: ""},
	} {
		if _, err := selectedNatsConfiguration(lookup(values)); err == nil {
			t.Fatal("ambiguous selection accepted")
		}
	}
	path := filepath.Join(t.TempDir(), "server.conf")
	if err := os.WriteFile(path, []byte("port: 4222\n"), 0400); err != nil {
		t.Fatal(err)
	}
	config, err := selectedNatsConfiguration(lookup(map[string]string{natsServerConfigEnvironment: path}))
	if err != nil || config.ConfigPath != path {
		t.Fatalf("selected configuration: %v", err)
	}
}

func TestProductionAdmissionFailureStartsNoEmbeddedListener(t *testing.T) {
	restoreHostSeams(t)
	rejected := errors.New("production configuration missing")
	admitProductionRuntime = func(context.Context, *control.OrchestratorOptions, envLookup) (*admittedProductionRuntime, error) {
		return nil, rejected
	}
	startEmbeddedNatsRuntime = func(context.Context, bootstrap.NatsServerConfig) (embeddedNatsRuntime, error) {
		t.Fatal("listener started before required production admission")
		return nil, nil
	}
	startRegionalRuntime = func(context.Context, *control.OrchestratorOptions) (component, error) {
		t.Fatal("regional client started before production admission")
		return nil, nil
	}
	options := fakeOptions(control.OrchestratorCommandRun)
	options.Cell = "gru"
	if err := runCommand(context.Background(), options, &bootstrap.NatsServerConfig{}, nil); !errors.Is(err, rejected) {
		t.Fatalf("admission result: %v", err)
	}
}

func TestEmbeddedNatsPrecedesRegionalAndClosesAfterClients(t *testing.T) {
	restoreHostSeams(t)
	var order []string
	worker := lifecycle.NewScheduledService("cleanup probe", 0, func(context.Context, time.Time) error { return nil })
	admitProductionRuntime = func(context.Context, *control.OrchestratorOptions, envLookup) (*admittedProductionRuntime, error) {
		order = append(order, "admit")
		return &admittedProductionRuntime{construct: func(context.Context) (*productionRuntime, error) {
			order = append(order, "compose")
			return &productionRuntime{delivery: &control.SignedDeliveryRuntimeConfig{}, active: &productionGlobalWorkers{workers: []*lifecycle.Service{worker}}}, nil
		}}, nil
	}
	regional := &fakeComponent{done: make(chan struct{}), name: "regional-close", order: &order}
	broker := &fakeEmbeddedNats{done: make(chan struct{}), ready: true, close: func() {
		if !regional.closed || worker.Start(context.Background()) == nil {
			t.Error("broker closed before dependent resources")
		}
		order = append(order, "broker-close")
	}}
	startEmbeddedNatsRuntime = func(context.Context, bootstrap.NatsServerConfig) (embeddedNatsRuntime, error) {
		order = append(order, "broker-ready")
		return broker, nil
	}
	failed := errors.New("regional startup failed")
	startRegionalRuntime = func(context.Context, *control.OrchestratorOptions) (component, error) {
		order = append(order, "regional-start")
		return regional, failed
	}
	options := fakeOptions(control.OrchestratorCommandRun)
	options.Cell = "gru"
	err := runCommand(context.Background(), options, &bootstrap.NatsServerConfig{}, nil)
	if !errors.Is(err, failed) || !reflect.DeepEqual(order, []string{"admit", "broker-ready", "compose", "regional-start", "regional-close", "broker-close"}) {
		t.Fatalf("error=%v order=%v", err, order)
	}
}

func TestEmbeddedNatsFailureCancelsRegionalStartupAndPreservesCause(t *testing.T) {
	restoreHostSeams(t)
	failed := errors.New("broker storage failure")
	broker := &fakeEmbeddedNats{done: make(chan struct{}), ready: true, failure: failed}
	startEmbeddedNatsRuntime = func(context.Context, bootstrap.NatsServerConfig) (embeddedNatsRuntime, error) { return broker, nil }
	startRegionalRuntime = func(ctx context.Context, _ *control.OrchestratorOptions) (component, error) {
		close(broker.done)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
			t.Fatal("broker failure did not cancel regional startup")
			return nil, nil
		}
	}
	err := runCommand(context.Background(), fakeOptions(control.OrchestratorCommandRun), &bootstrap.NatsServerConfig{}, nil)
	if !errors.Is(err, failed) || !broker.closed || exitCode(err) != 1 {
		t.Fatalf("broker failure=%v closed=%v", err, broker.closed)
	}
}

func TestRunCancellationKeepsEmbeddedNatsUntilClientCleanup(t *testing.T) {
	restoreHostSeams(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	regional := &fakeComponent{done: make(chan struct{})}
	var brokerContext context.Context
	broker := &fakeEmbeddedNats{done: make(chan struct{}), ready: true, close: func() {
		if !regional.closed || brokerContext.Err() != nil {
			t.Error("broker cancelled before client teardown")
		}
	}}
	startEmbeddedNatsRuntime = func(ctx context.Context, _ bootstrap.NatsServerConfig) (embeddedNatsRuntime, error) {
		brokerContext = ctx
		return broker, nil
	}
	startRegionalRuntime = func(context.Context, *control.OrchestratorOptions) (component, error) { cancel(); return regional, nil }
	if err := runCommand(ctx, fakeOptions(control.OrchestratorCommandRun), &bootstrap.NatsServerConfig{}, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
	if !broker.closed {
		t.Fatal("broker leaked on cancellation")
	}
}

func TestProductionConstructionFailureClosesStartedBrokerWithoutSubscriptions(t *testing.T) {
	restoreHostSeams(t)
	failed := errors.New("durable production store unavailable")
	broker := &fakeEmbeddedNats{done: make(chan struct{}), ready: true}
	admitted := false
	admitProductionRuntime = func(context.Context, *control.OrchestratorOptions, envLookup) (*admittedProductionRuntime, error) {
		admitted = true
		return &admittedProductionRuntime{construct: func(context.Context) (*productionRuntime, error) {
			if !broker.ready {
				t.Fatal("live construction ran before broker readiness")
			}
			return nil, failed
		}}, nil
	}
	startEmbeddedNatsRuntime = func(context.Context, bootstrap.NatsServerConfig) (embeddedNatsRuntime, error) {
		if !admitted {
			t.Fatal("broker started before static admission")
		}
		return broker, nil
	}
	startRegionalRuntime = func(context.Context, *control.OrchestratorOptions) (component, error) {
		t.Fatal("regional subscriptions started after live composition failure")
		return nil, nil
	}
	options := fakeOptions(control.OrchestratorCommandRun)
	options.Cell = "gru"
	if err := runCommand(context.Background(), options, &bootstrap.NatsServerConfig{}, nil); !errors.Is(err, failed) || !broker.closed {
		t.Fatalf("composition failure=%v broker closed=%v", err, broker.closed)
	}
}

func TestHostServicesStartAfterBrokerAndStopOnRuntimeExit(t *testing.T) {
	restoreHostSeams(t)
	var order []string
	broker := &fakeEmbeddedNats{done: make(chan struct{}), ready: true, close: func() { order = append(order, "broker-close") }}
	startEmbeddedNatsRuntime = func(context.Context, bootstrap.NatsServerConfig) (embeddedNatsRuntime, error) {
		order = append(order, "broker-ready")
		return broker, nil
	}
	hosts := &fakeComponent{done: make(chan struct{}), name: "hosts-close", order: &order}
	failed := errors.New("regional startup failed")
	startRegionalRuntime = func(context.Context, *control.OrchestratorOptions) (component, error) {
		order = append(order, "regional-start")
		return nil, failed
	}
	err := runCommand(t.Context(), fakeOptions(control.OrchestratorCommandRun), &bootstrap.NatsServerConfig{}, func(context.Context) (hostServices, error) { order = append(order, "hosts-start"); return hosts, nil })
	if !errors.Is(err, failed) || !reflect.DeepEqual(order, []string{"broker-ready", "hosts-start", "regional-start", "hosts-close", "broker-close"}) {
		t.Fatalf("host lifetime: %v %v", err, order)
	}
}
func TestHostServiceFailureIsNotReportedAsOperatorCancellation(t *testing.T) {
	restoreHostSeams(t)
	hosts := &fakeComponent{done: make(chan struct{})}
	startRegionalRuntime = func(ctx context.Context, _ *control.OrchestratorOptions) (component, error) {
		close(hosts.done)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
			t.Fatal("host failure did not cancel runtime")
			return nil, nil
		}
	}
	err := runCommand(t.Context(), fakeOptions(control.OrchestratorCommandRun), nil, func(context.Context) (hostServices, error) { return hosts, nil })
	if err == nil || errors.Is(err, context.Canceled) || exitCode(err) != 1 || !hosts.closed {
		t.Fatalf("wrong host failure outcome: %v", err)
	}
}
