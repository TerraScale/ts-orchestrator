package swarmruntime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	introspectionapi "github.com/containerd/containerd/api/services/introspection/v1"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/introspection"
	"github.com/containerd/errdefs"
	swarmexec "github.com/moby/swarmkit/v2/agent/exec"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/api/genericresource"
)

type missingDiskTelemetry struct{ introspection.Service }

func (missingDiskTelemetry) Plugins(context.Context, ...string) (*introspectionapi.PluginsResponse, error) {
	return nil, errors.New("fixture cannot observe storage roots")
}

func TestContainerdDiskBudgetAndRecovery(t *testing.T) {
	if *integrationSocket == "" {
		t.Skip("runs in the containerd workflow, which passes -containerd-socket")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	state := t.TempDir()
	e, err := newIntegrationExecutor(*integrationSocket, state)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	runtime, err := ContainerRuntime(&api.ContainerSpec{Image: integrationImage, User: "65532:65532", Command: []string{"/bin/sh", "-c",
		"head -c 3145728 /dev/zero; head -c 3145728 /dev/zero >&2; echo disk-ready; exec sleep 300"}})
	if err != nil {
		t.Fatal(err)
	}
	limits := &api.Resources{NanoCPUs: 250_000_000, MemoryBytes: 64 << 20, Generic: []*api.GenericResource{genericresource.NewDiscrete(DiskResource, 64<<20)}}
	task := &api.Task{ID: fmt.Sprintf("disk%d", time.Now().UnixNano()), ServiceID: "diskintegration", NodeID: "integrationnode",
		Spec: api.TaskSpec{Runtime: runtime, Resources: &api.ResourceRequirements{Limits: limits, Reservations: limits.Copy()}}}
	var current *controller
	t.Cleanup(func() {
		if current != nil {
			cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
			defer stop()
			if err := current.Remove(cleanup); err != nil {
				t.Error(err)
			}
		}
	})
	handle, err := integrationContainerController(e, task)
	if err != nil {
		t.Fatal(err)
	}
	current = handle.(*controller)
	if err := current.Prepare(ctx); err != nil {
		t.Fatal(err)
	}
	witness, err := readDiskWitness(e.logRoot, current.id)
	if err != nil || witness.ImageBytes <= 0 || witness.DiskBytes != 64<<20 {
		t.Fatalf("actual retained image accounting absent: %+v, %v", witness, err)
	}
	tooSmall := task.Copy()
	tooSmall.ID += "small"
	tooSmall.Spec.Resources.Limits.Generic[0].GetDiscreteResourceSpec().Value = witness.ImageBytes + witness.LogBytes - 1
	tooSmall.Spec.Resources.Reservations = tooSmall.Spec.Resources.Limits.Copy()
	denied, err := integrationContainerController(e, tooSmall)
	if err != nil {
		t.Fatal(err)
	}
	if err := denied.Prepare(ctx); !errors.Is(err, ErrDiskPending) {
		t.Fatalf("image and bounded logs exceeded signed disk bytes: %v", err)
	}
	if _, err := e.client.LoadContainer(runtimeContext(ctx), "ts-"+tooSmall.ID); !errdefs.IsNotFound(err) {
		t.Fatalf("undersized disk budget published a container: %v", err)
	}
	if err := denied.Remove(ctx); err != nil {
		t.Fatal(err)
	}
	if err := current.Start(ctx); err != nil {
		t.Fatal(err)
	}
	running, err := current.runtimeTask(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pid := running.Pid()
	for {
		stdout, err := os.ReadFile(filepath.Join(e.logRoot, current.id, "stdout"))
		if err == nil && bytes.Contains(stdout, []byte("disk-ready")) {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("bounded logger did not drain sustained stdout/stderr before deadline")
		case <-time.After(20 * time.Millisecond):
		}
	}
	for _, stream := range []string{"stdout", "stderr"} {
		info, err := os.Stat(filepath.Join(e.logRoot, current.id, stream))
		if err != nil || info.Size() <= 0 || info.Size() > logSegmentBytes {
			t.Fatalf("sustained %s exceeded fixed disk allowance: %v, %v", stream, info, err)
		}
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := newIntegrationExecutor(*integrationSocket, state)
	if err != nil {
		t.Fatal(err)
	}
	e = reopened
	// Only capacity discovery is lost; all container/snapshot metadata still
	// comes from the same real daemon and the shim-owned task keeps running.
	previousClient := e.client
	t.Cleanup(func() { _ = previousClient.Close() })
	e.client, err = containerd.New(*integrationSocket, containerd.WithServices(containerd.WithIntrospectionService(missingDiskTelemetry{previousClient.IntrospectionService()})))
	if err != nil {
		t.Fatal(err)
	}
	description, err := e.Describe(ctx)
	if err != nil || description.Resources == nil {
		t.Fatalf("lost disk telemetry failed healthy node description: %v", err)
	}
	if len(genericresource.GetResource(DiskResource, description.Resources.Generic)) != 0 {
		t.Fatal("unknown free space advertised new disk capacity")
	}
	handle, err = integrationContainerController(e, task)
	if err != nil {
		t.Fatal(err)
	}
	current = handle.(*controller)
	if err := current.Prepare(ctx); err != nil {
		t.Fatalf("lost free-space telemetry rejected owned running task: %v", err)
	}
	if err := current.Start(ctx); !errors.Is(err, swarmexec.ErrTaskStarted) {
		t.Fatalf("recovery replaced or rejected healthy task: %v", err)
	}
	recovered, err := current.runtimeTask(ctx)
	if err != nil || recovered.Pid() != pid {
		t.Fatalf("restart/telemetry loss changed actual PID: %v", err)
	}
	fresh := task.Copy()
	fresh.ID += "unknown"
	newController, err := integrationContainerController(e, fresh)
	if err != nil {
		t.Fatal(err)
	}
	if err := newController.Prepare(ctx); !errors.Is(err, ErrDiskPending) {
		t.Fatalf("unknown free space admitted a new task: %v", err)
	}
	if err := newController.Remove(ctx); err != nil {
		t.Fatal(err)
	}
	ctr, err := current.container(runtimeContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ctr.SetLabels(runtimeContext(ctx), map[string]string{diskImageBytesLabel: "0"}); err != nil {
		t.Fatal(err)
	}
	if err := current.verifyDisk(runtimeContext(ctx), ctr); !errors.Is(err, ErrDiskPending) {
		t.Fatalf("foreign image accounting passed restart readback: %v", err)
	}
	if _, err := ctr.SetLabels(runtimeContext(ctx), map[string]string{diskImageBytesLabel: fmt.Sprint(witness.ImageBytes)}); err != nil {
		t.Fatal(err)
	}
}
