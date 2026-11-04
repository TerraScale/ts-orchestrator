package swarmruntime

import (
	"context"
	"errors"

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
