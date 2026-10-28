package swarmruntime

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gogo/protobuf/proto"
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

func placementService(order api.UpdateConfig_UpdateOrder) *api.Service {
	return &api.Service{ID: "s", Meta: api.Meta{Version: api.Version{Index: 7}}, SpecVersion: &api.Version{Index: 7},
		UpdateStatus: &api.UpdateStatus{State: api.UpdateStatus_UPDATING},
		Spec: api.ServiceSpec{Annotations: api.Annotations{Name: "ts-dashboard", Labels: map[string]string{LabelGeneration: "3"}},
			Mode:   &api.ServiceSpec_Replicated{Replicated: &api.ReplicatedService{Replicas: 1}},
			Update: &api.UpdateConfig{Parallelism: 1, FailureAction: api.UpdateConfig_ROLLBACK, Order: order}}}
}

const insufficientResources = "no suitable node (insufficient resources on 1 node)"

// E16: a 2-CPU node cannot hold the old task and the start-first candidate.
func TestStartFirstFallsBackWhenCandidateDoesNotFit(t *testing.T) {
	service := placementService(api.UpdateConfig_START_FIRST)
	control := &placementControl{service: service.Copy(), reason: insufficientResources, pendingPolls: 1 << 30}
	rollout, err := WaitServiceSpec(t.Context(), control, service, nil)
	if err != nil || !rollout.StopFirst {
		t.Fatalf("rollout %+v, %v", rollout, err)
	}
	if len(control.writes) != 2 || control.writes[0].Order != api.UpdateConfig_STOP_FIRST || control.writes[0].FailureAction != api.UpdateConfig_PAUSE {
		t.Fatalf("fallback writes %v", control.writes)
	}
	// Once ready, the service carries exactly the requested spec again.
	if live := control.service.Spec; !proto.Equal(live.Update, service.Spec.Update) || live.Annotations.Labels[LabelGeneration] != "3" {
		t.Fatalf("restored spec %+v", live)
	}
}

// The adopted candidate's failures are not SwarmKit's to count: the wait fails
// at once so the release rolls back, rather than at its deadline.
func TestStopFirstFallbackFailsFastOnCrash(t *testing.T) {
	service := placementService(api.UpdateConfig_START_FIRST)
	control := &placementControl{service: service.Copy(), reason: insufficientResources, pendingPolls: 1 << 30, crash: true}
	rollout, err := WaitServiceSpec(t.Context(), control, service, nil)
	if err == nil || !strings.Contains(err.Error(), "non-zero exit") || !rollout.StopFirst || len(control.writes) != 1 {
		t.Fatalf("rollout %+v, writes %v, %v", rollout, control.writes, err)
	}
}

func TestStartFirstKeepsOrderUnlessResourcesBlockPlacement(t *testing.T) {
	for name, control := range map[string]*placementControl{
		"placed":       {service: placementService(api.UpdateConfig_START_FIRST)},
		"other reason": {service: placementService(api.UpdateConfig_START_FIRST), reason: "no suitable node (scheduling constraints not satisfied on 1 node)", pendingPolls: 3},
		// TerraBase and other mounted services already stop first.
		"stop-first spec": {service: placementService(api.UpdateConfig_STOP_FIRST), reason: insufficientResources, pendingPolls: 3},
	} {
		t.Run(name, func(t *testing.T) {
			rollout, err := WaitServiceSpec(t.Context(), control, control.service.Copy(), nil)
			if err != nil || rollout.StopFirst || len(control.writes) != 0 {
				t.Fatalf("rollout %+v, writes %v, %v", rollout, control.writes, err)
			}
		})
	}
}

func TestUnplacedCandidateWaitsOutGrace(t *testing.T) {
	service := placementService(api.UpdateConfig_START_FIRST)
	created, _ := types.TimestampProto(time.Now().Add(-time.Second))
	task := &api.Task{Meta: api.Meta{CreatedAt: created}, Status: api.TaskStatus{State: api.TaskStatePending, Err: insufficientResources}}
	if unplacedCandidate(service, []*api.Task{task}, time.Now()) != nil || unplacedCandidate(service, []*api.Task{task}, time.Now().Add(startFirstPlacementGrace)) != task {
		t.Fatal("the fallback ignores the placement grace")
	}
}
