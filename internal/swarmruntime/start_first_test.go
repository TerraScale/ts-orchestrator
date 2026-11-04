package swarmruntime

import (
	"context"
	"errors"

	"github.com/gogo/protobuf/types"
	"github.com/moby/swarmkit/v2/api"
	"google.golang.org/grpc"
)

// placementControl holds the candidate pending with reason until the update
// policy is rewritten or pendingPolls have passed.
type placementControl struct {
	api.ControlClient
	service      *api.Service
	reason       string
	pendingPolls int
	crash        bool
	polls        int
	writes       []*api.UpdateConfig
}

func (c *placementControl) GetService(context.Context, *api.GetServiceRequest, ...grpc.CallOption) (*api.GetServiceResponse, error) {
	return &api.GetServiceResponse{Service: c.service.Copy()}, nil
}

func (c *placementControl) ListTasks(context.Context, *api.ListTasksRequest, ...grpc.CallOption) (*api.ListTasksResponse, error) {
	c.polls++
	task := &api.Task{ID: "candidate", DesiredState: api.TaskStateRunning, Status: api.TaskStatus{State: api.TaskStatePending, Err: c.reason},
		Meta: api.Meta{CreatedAt: types.TimestampNow()}}
	task.Meta.CreatedAt.Seconds -= 10
	if len(c.writes) != 0 || c.polls > c.pendingPolls {
		task.NodeID, task.Status = "node", api.TaskStatus{State: api.TaskStateRunning}
		if c.crash {
			task.Status = api.TaskStatus{State: api.TaskStateFailed, Err: "task: non-zero exit (1)", Timestamp: types.TimestampNow()}
		}
	}
	return &api.ListTasksResponse{Tasks: []*api.Task{task}}, nil
}

func (c *placementControl) UpdateService(_ context.Context, request *api.UpdateServiceRequest, _ ...grpc.CallOption) (*api.UpdateServiceResponse, error) {
	if request.ServiceVersion.Index != c.service.Meta.Version.Index {
		return nil, errors.New("update out of sequence")
	}
	c.writes = append(c.writes, request.Spec.Update.Copy())
	c.service.Meta.Version.Index++
	c.service.Spec, c.service.SpecVersion, c.service.UpdateStatus = *request.Spec.Copy(), &api.Version{Index: c.service.Meta.Version.Index}, nil
	return &api.UpdateServiceResponse{Service: c.service.Copy()}, nil
}
