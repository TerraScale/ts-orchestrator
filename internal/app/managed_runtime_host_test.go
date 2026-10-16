package app

import (
	"context"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/containerd/v2/core/remotes/docker"
	"github.com/moby/swarmkit/v2/api"
)

func TestManagedRuntimeRegistryRejectsEndedSession(t *testing.T) {
	session, cancel := context.WithCancel(t.Context())
	source := &managedRuntimeHost{}
	called := false
	source.bind(session, new(host.Agent), hostenroll.WorkerTransport{}, func(context.Context, *api.Task, *api.Node) (remotes.Resolver, error) {
		called = true
		return docker.NewResolver(docker.ResolverOptions{}), nil
	}, "manager")
	cancel()
	resolver, err := source.registryResolver(t.Context(), nil, nil)
	if err == nil || resolver != nil || called {
		t.Fatalf("ended session reached registry provider: resolver=%v error=%v called=%v", resolver, err, called)
	}
}

func TestManagedRuntimeRegistryCancelsInFlightSession(t *testing.T) {
	ctx, stop := context.WithTimeout(t.Context(), 5*time.Second)
	defer stop()
	session, cancel := context.WithCancel(ctx)
	defer cancel()
	source := &managedRuntimeHost{}
	entered := make(chan struct{})
	source.bind(session, new(host.Agent), hostenroll.WorkerTransport{}, func(ctx context.Context, _ *api.Task, _ *api.Node) (remotes.Resolver, error) {
		close(entered)
		<-ctx.Done()
		return docker.NewResolver(docker.ResolverOptions{}), nil
	}, "manager")
	type result struct {
		resolver remotes.Resolver
		err      error
	}
	done := make(chan result, 1)
	go func() {
		resolver, err := source.registryResolver(ctx, nil, nil)
		done <- result{resolver: resolver, err: err}
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("registry provider did not start")
	}
	cancel()
	select {
	case got := <-done:
		if got.err == nil || got.resolver != nil {
			t.Fatalf("ended session returned registry credentials: resolver=%v error=%v", got.resolver, got.err)
		}
	case <-ctx.Done():
		t.Fatal("session cancellation did not cancel the registry provider")
	}
	source.clear()
}
