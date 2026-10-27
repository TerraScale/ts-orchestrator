package swarmruntime

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/containerd/errdefs"
	"github.com/moby/swarmkit/v2/api"
)

// An exited task's shim and runtime logger lived until SwarmKit dropped the
// task from history; the reaper deletes the exited runtime task, and the
// retained container then holds neither its port nor its disk budget.
func TestContainerdReapExitedTask(t *testing.T) {
	if *integrationSocket == "" {
		t.Skip("runs in the containerd workflow, which passes -containerd-socket")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	e, err := newIntegrationExecutor(*integrationSocket, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	runtime, err := ContainerRuntime(&api.ContainerSpec{Image: integrationImage, User: "65532:65532", Command: []string{"/bin/sh", "-c", "exit 3"}})
	if err != nil {
		t.Fatal(err)
	}
	exited := &api.Task{
		ID: fmt.Sprintf("reapexited%d", time.Now().UnixNano()), ServiceID: "reapintegration",
		Spec:     api.TaskSpec{Runtime: runtime, Resources: containerTestResources(250_000_000, 64<<20)},
		Endpoint: &api.Endpoint{Spec: &api.EndpointSpec{Ports: []*api.PortConfig{{Protocol: api.ProtocolTCP, PublishMode: api.PublishModeHost, PublishedPort: 35011, TargetPort: 35011}}}},
	}
	generic, err := integrationContainerController(e, exited)
	if err != nil {
		t.Fatal(err)
	}
	c := generic.(*controller)
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
	if err := c.Wait(ctx); err == nil {
		t.Fatal("exit 3 reported success")
	}
	// Too recent: Wait may still be reading the exit.
	if reaped, err := e.reapExited(ctx, time.Now()); err != nil || reaped != 0 {
		t.Fatalf("reaped a fresh exit: %d, %v", reaped, err)
	}
	if reaped, err := e.reapExited(ctx, time.Now().Add(2*reapExitedAfter)); err != nil || reaped != 1 {
		t.Fatalf("reaped = %d, %v; want the exited task", reaped, err)
	}
	ctr, err := c.container(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ctr.Task(runtimeContext(ctx), nil); !errdefs.IsNotFound(err) {
		t.Fatalf("exited runtime task survived the reaper: %v", err)
	}
	labels, err := ctr.Labels(runtimeContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	if holder, err := portHolderState(runtimeContext(ctx), ctr, labels); err != nil || holder != holderExited {
		t.Fatalf("reaped container reads as %v, %v; want exited", holder, err)
	}
	if status, err := c.ContainerStatus(ctx); err != nil || status.ContainerID != c.id {
		t.Fatalf("container status after reaping = %+v, %v", status, err)
	}
	// Another service takes the port at once.
	other := exited.Copy()
	other.ID, other.ServiceID = fmt.Sprintf("reapother%d", time.Now().UnixNano()), "reapintegrationother"
	next, err := integrationContainerController(e, other)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		_ = next.Remove(cleanup)
	})
	if err := next.Prepare(ctx); err != nil {
		t.Fatalf("reaped container kept its port: %v", err)
	}
	if err := c.Remove(ctx); err != nil {
		t.Fatal(err)
	}
}
