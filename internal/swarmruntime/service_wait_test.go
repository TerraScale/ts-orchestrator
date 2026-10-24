package swarmruntime

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/moby/swarmkit/v2/api"
	"google.golang.org/grpc"
)

// rolloutControl advances the replacement one phase per ListTasks poll.
type rolloutControl struct {
	api.ControlClient
	service *api.Service
	states  []api.TaskState
	polls   int
}

func (c *rolloutControl) GetService(context.Context, *api.GetServiceRequest, ...grpc.CallOption) (*api.GetServiceResponse, error) {
	return &api.GetServiceResponse{Service: c.service}, nil
}

func (c *rolloutControl) ListTasks(_ context.Context, request *api.ListTasksRequest, _ ...grpc.CallOption) (*api.ListTasksResponse, error) {
	if !request.Filters.UpToDate {
		return nil, errors.New("rollout must ignore predecessors")
	}
	state := c.states[min(c.polls, len(c.states)-1)]
	c.polls++
	return &api.ListTasksResponse{Tasks: []*api.Task{{ID: "new", DesiredState: api.TaskStateRunning, Status: api.TaskStatus{State: state}}}}, nil
}

func TestWaitServiceSpecPhases(t *testing.T) {
	service := &api.Service{ID: "s", SpecVersion: &api.Version{Index: 7},
		Spec: api.ServiceSpec{Annotations: api.Annotations{Name: "web"}, Mode: &api.ServiceSpec_Replicated{Replicated: &api.ReplicatedService{Replicas: 1}}}}
	control := &rolloutControl{service: service, states: []api.TaskState{api.TaskStatePreparing, api.TaskStateRunning}}
	probes := 0
	rollout, err := WaitServiceSpec(t.Context(), control, service, func(context.Context, *api.Task) error {
		if probes++; probes < 3 {
			return errors.New("not ready")
		}
		return nil
	})
	if err != nil || rollout.Running == 0 || rollout.Ready < rollout.Running+2*servicePoll {
		t.Fatalf("rollout %+v, %v", rollout, err)
	}

	rolledBack := service.Copy()
	rolledBack.SpecVersion = &api.Version{Index: 6}
	rolledBack.UpdateStatus = &api.UpdateStatus{State: api.UpdateStatus_ROLLBACK_COMPLETED, Message: "update rolled back due to failure"}
	control = &rolloutControl{service: rolledBack, states: []api.TaskState{api.TaskStateRunning}}
	var rollback *RollbackError
	if _, err := WaitServiceSpec(t.Context(), control, service, nil); !errors.As(err, &rollback) || rollback.Reason != "update rolled back due to failure" {
		t.Fatalf("rollback reported as %v", err)
	}
	// Re-applying the spec a rollback restored is a completed no-op, not a new failure.
	if _, err := WaitServiceSpec(t.Context(), control, rolledBack, nil); err != nil {
		t.Fatalf("restored spec: %v", err)
	}

	// A concurrent re-apply of the same workload (new generation label, force-update) is followed, not a failure.
	reapplied := service.Copy()
	reapplied.SpecVersion = &api.Version{Index: 8}
	reapplied.Spec.Annotations.Labels = map[string]string{LabelGeneration: "2"}
	reapplied.Spec.Task.ForceUpdate = 1
	reapplied.UpdateStatus = &api.UpdateStatus{State: api.UpdateStatus_UPDATING, Message: "update in progress"}
	control = &rolloutControl{service: reapplied, states: []api.TaskState{api.TaskStateRunning}}
	if _, err := WaitServiceSpec(t.Context(), control, service, nil); err != nil {
		t.Fatalf("same-workload re-apply: %v", err)
	}
	// A different workload written meanwhile still supersedes the rollout.
	superseded := reapplied.Copy()
	superseded.Spec.Task.Restart = &api.RestartPolicy{Condition: api.RestartOnNone}
	control = &rolloutControl{service: superseded, states: []api.TaskState{api.TaskStateRunning}}
	if _, err := WaitServiceSpec(t.Context(), control, service, nil); err == nil || !strings.Contains(err.Error(), "did not complete") {
		t.Fatalf("different workload reported as %v", err)
	}

	paused := service.Copy()
	paused.UpdateStatus = &api.UpdateStatus{State: api.UpdateStatus_ROLLBACK_PAUSED, Message: "rollback paused"}
	control = &rolloutControl{service: paused, states: []api.TaskState{api.TaskStateRunning}}
	if _, err := WaitServiceSpec(t.Context(), control, service, nil); err == nil || !strings.Contains(err.Error(), "ROLLBACK_PAUSED") {
		t.Fatalf("paused rollback reported as %v", err)
	}
}

func TestServiceSpecReadyGate(t *testing.T) {
	base := ServiceSpec{Name: "web", Image: "docker.io/library/alpine@sha256:3e9b4b680bfc9fb5269227cffbd6d42be39fbf7c0b908123913864aa4447e764", Port: 8099, Replicas: 1}
	ungated, err := base.SwarmSpec()
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := containerOf(*ungated); len(c.Labels) != 0 || ReadyTimeout(ungated.Annotations.Labels) != DefaultReadyTimeout {
		t.Fatalf("spec without readyPath is gated: %v", c.Labels)
	}
	gated := base
	gated.ReadyPath, gated.ReadyTimeoutSeconds = "/health", 7
	swarm, err := gated.SwarmSpec()
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := containerOf(*swarm); c.Labels[LabelReadyPath] != "/health" || ReadyTimeout(swarm.Annotations.Labels) != 7*time.Second {
		t.Fatalf("gate labels %v %v", c.Labels, swarm.Annotations.Labels)
	}
	// A snapshot import may hold a task in its window for up to 30 minutes.
	long := base
	long.ReadyPath, long.ReadyTimeoutSeconds = "/health", 1800
	if swarm, err := long.SwarmSpec(); err != nil || ReadyTimeout(swarm.Annotations.Labels) != 30*time.Minute {
		t.Fatalf("1800 s window: %v", err)
	}
	for _, bad := range []ServiceSpec{{ReadyTimeoutSeconds: 5}, {ReadyPath: "/health", ReadyTimeoutSeconds: maxReadyTimeoutSeconds + 1}} {
		spec := base
		spec.ReadyPath, spec.ReadyTimeoutSeconds = bad.ReadyPath, bad.ReadyTimeoutSeconds
		if _, err := spec.SwarmSpec(); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
}
