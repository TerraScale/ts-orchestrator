package swarmruntime

import (
	"context"
	"fmt"
	"testing"
	"time"

	swarmexec "github.com/moby/swarmkit/v2/agent/exec"
	"github.com/moby/swarmkit/v2/api"
)

// A task whose runtime create fails keeps its container until SwarmKit reaps
// it; its replacement must still get the host port.
func TestContainerdFailedStartReleasesHostPort(t *testing.T) {
	if *integrationSocket == "" {
		t.Skip("runs in the containerd workflow, which passes -containerd-socket")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	e, err := newIntegrationExecutor(*integrationSocket, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	controller := func(name string, command ...string) swarmexec.Controller {
		t.Helper()
		runtime, err := ContainerRuntime(&api.ContainerSpec{Image: integrationImage, User: "65532:65532", Command: command})
		if err != nil {
			t.Fatal(err)
		}
		task := &api.Task{ID: fmt.Sprintf("%s%d", name, time.Now().UnixNano()), ServiceID: "portrelease",
			Spec:     api.TaskSpec{Runtime: runtime, Resources: containerTestResources(250_000_000, 64<<20)},
			Endpoint: &api.Endpoint{Spec: &api.EndpointSpec{Ports: []*api.PortConfig{{Protocol: api.ProtocolTCP, PublishMode: api.PublishModeHost, PublishedPort: 35002, TargetPort: 35002}}}},
		}
		c, err := integrationContainerController(e, task)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
			defer stop()
			_ = c.Remove(cleanup)
		})
		return c
	}
	failed := controller("portfailed", "/does-not-exist")
	if err := failed.Prepare(ctx); err != nil {
		t.Fatal(err)
	}
	if err := failed.Start(ctx); err == nil {
		t.Fatal("task with a missing executable started")
	}
	replacement := controller("portreplacement", "/bin/sh", "-c", "trap 'exit 0' TERM; while :; do sleep 1; done")
	if err := replacement.Prepare(ctx); err != nil {
		t.Fatalf("failed task's container kept its host port: %v", err)
	}
	if err := replacement.Start(ctx); err != nil {
		t.Fatal(err)
	}
}
