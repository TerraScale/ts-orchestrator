package containermaterial

import (
	"errors"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/api/genericresource"
)

func TestAllocatedTaskRetainsShutdownAndPendingReservations(t *testing.T) {
	runtime, err := swarmruntime.ContainerRuntime(&api.ContainerSpec{Image: "registry.example/auth@sha256:" + strings.Repeat("a", 64), User: "65532:65532"})
	if err != nil {
		t.Fatal(err)
	}
	limits := &api.Resources{NanoCPUs: 1_000_000_000, MemoryBytes: 32 << 20, Generic: []*api.GenericResource{genericresource.NewDiscrete(swarmruntime.DiskResource, 64<<20)}}
	task := &api.Task{ID: "task1", ServiceID: "service1", NodeID: "node1", DesiredState: api.TaskStateRunning,
		Status: api.TaskStatus{State: api.TaskStateRunning}, Spec: api.TaskSpec{Runtime: runtime,
			Resources: &api.ResourceRequirements{Limits: limits, Reservations: limits.Copy()}}}
	fingerprint, err := swarmruntime.ContainerTaskFingerprint(task)
	if err != nil {
		t.Fatal(err)
	}
	binding := host.ContainerMaterialBinding{TaskID: task.ID, ServiceID: task.ServiceID, NodeID: task.NodeID, Fingerprint: fingerprint}
	for _, state := range []api.TaskState{api.TaskStateNew, api.TaskStatePending, api.TaskStateAssigned, api.TaskStateAccepted, api.TaskStatePreparing, api.TaskStateReady, api.TaskStateStarting, api.TaskStateRunning} {
		for _, desired := range []api.TaskState{api.TaskStateRunning, api.TaskStateShutdown, api.TaskStateRemove} {
			current := task.Copy()
			current.Status.State, current.DesiredState = state, desired
			if err := verifyAllocatedTask(current, binding); err != nil {
				t.Fatalf("allocated task %s desired %s: %v", state, desired, err)
			}
			if desired != api.TaskStateRunning || state < api.TaskStateAssigned {
				if err := verifyTaskAssignment(current, binding); !errors.Is(err, ErrPending) {
					t.Fatal("allocation lifecycle widened credential admission")
				}
			}
		}
	}
	for _, mutate := range []func(*api.Task){
		func(task *api.Task) { task.NodeID = "" },
		func(task *api.Task) { task.NodeID = "replacement" },
		func(task *api.Task) { task.ServiceID = "replacement" },
		func(task *api.Task) { task.Status.State = api.TaskStateCompleted },
		func(task *api.Task) { task.Status.State = api.TaskStateShutdown },
		func(task *api.Task) { task.Status.State = api.TaskStateFailed },
		func(task *api.Task) { task.Status.State = api.TaskState(-1) },
		func(task *api.Task) { task.DesiredState = api.TaskState(-1) },
		func(task *api.Task) { task.Spec.Resources.Reservations.MemoryBytes++ },
	} {
		invalid := task.Copy()
		mutate(invalid)
		if err := verifyAllocatedTask(invalid, binding); !errors.Is(err, ErrPending) {
			t.Fatal("changed or terminal allocation accepted")
		}
	}
	if err := verifyAllocatedTask(nil, binding); !errors.Is(err, ErrPending) {
		t.Fatal("missing allocation accepted")
	}
}
