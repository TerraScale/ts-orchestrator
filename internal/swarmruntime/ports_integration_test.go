package swarmruntime

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/moby/swarmkit/v2/api"
)

func TestContainerdHostPortReservationRecovery(t *testing.T) {
	if *integrationSocket == "" {
		t.Fatal("provide -containerd-socket for a disposable real runtime")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	state := t.TempDir()
	e, err := NewExecutor(*integrationSocket, state)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	runtime, err := ContainerRuntime(&api.ContainerSpec{Image: integrationImage, User: "65532:65532", Command: []string{"/bin/sh", "-c", "trap 'exit 0' TERM; while :; do sleep 1; done"}})
	if err != nil {
		t.Fatal(err)
	}
	first := &api.Task{
		ID: fmt.Sprintf("portfirst%d", time.Now().UnixNano()), ServiceID: "portintegration",
		Spec:     api.TaskSpec{Runtime: runtime, Resources: &api.ResourceRequirements{Limits: &api.Resources{NanoCPUs: 250_000_000, MemoryBytes: 64 << 20}}},
		Endpoint: &api.Endpoint{Spec: &api.EndpointSpec{Ports: []*api.PortConfig{{Protocol: api.ProtocolTCP, PublishMode: api.PublishModeHost, PublishedPort: 35001, TargetPort: 35001}}}},
	}
	c, err := e.Controller(first)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		_ = c.Remove(cleanup)
	})
	if err := c.Prepare(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	// A separate executor and state directory must recover the existing runtime
	// reservation rather than treating its empty supervisor memory as authority.
	e, err = NewExecutor(*integrationSocket, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c, err = e.Controller(first)
	if err != nil {
		t.Fatal(err)
	}
	second := first.Copy()
	second.ID = fmt.Sprintf("portsecond%d", time.Now().UnixNano())
	conflicting, err := e.Controller(second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		_ = conflicting.Remove(cleanup)
	})
	if err := conflicting.Prepare(ctx); err == nil {
		t.Fatal("second task acquired a running container's reserved host port")
	}
	if err := c.Remove(ctx); err != nil {
		t.Fatal(err)
	}
	if err := conflicting.Prepare(ctx); err != nil {
		t.Fatalf("removed container retained its host-port reservation: %v", err)
	}
	if err := conflicting.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := conflicting.Remove(ctx); err != nil {
		t.Fatal(err)
	}
}
