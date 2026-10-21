package swarmruntime

import (
	"context"
	"errors"
	"strings"
	"testing"

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
	rolledBack.SpecVersion = &api.Version{Index: 9}
	rolledBack.UpdateStatus = &api.UpdateStatus{State: api.UpdateStatus_ROLLBACK_STARTED, Message: "update rolled back due to failure"}
	control = &rolloutControl{service: rolledBack, states: []api.TaskState{api.TaskStateRunning}}
	if _, err := WaitServiceSpec(t.Context(), control, service, func(context.Context, *api.Task) error { return nil }); err == nil || !strings.Contains(err.Error(), "ROLLBACK_STARTED") {
		t.Fatalf("rollback reported as %v", err)
	}
}
