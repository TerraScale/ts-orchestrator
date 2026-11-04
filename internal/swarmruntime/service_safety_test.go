package swarmruntime

import (
	"context"

	"strings"
	"testing"

	"github.com/moby/swarmkit/v2/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type safetyControl struct {
	api.ControlClient
	service    *api.Service
	task       *api.Task
	conflict   bool
	onConflict func(*api.Service)
	writes     int
	machine    string
}

func (c *safetyControl) ListServices(context.Context, *api.ListServicesRequest, ...grpc.CallOption) (*api.ListServicesResponse, error) {
	return &api.ListServicesResponse{Services: []*api.Service{c.service.Copy()}}, nil
}

func (c *safetyControl) GetService(context.Context, *api.GetServiceRequest, ...grpc.CallOption) (*api.GetServiceResponse, error) {
	return &api.GetServiceResponse{Service: c.service.Copy()}, nil
}

func (c *safetyControl) ListTasks(context.Context, *api.ListTasksRequest, ...grpc.CallOption) (*api.ListTasksResponse, error) {
	return &api.ListTasksResponse{Tasks: []*api.Task{c.task.Copy()}}, nil
}

func (c *safetyControl) GetNode(context.Context, *api.GetNodeRequest, ...grpc.CallOption) (*api.GetNodeResponse, error) {
	return &api.GetNodeResponse{Node: &api.Node{Description: &api.NodeDescription{Hostname: c.machine}}}, nil
}

func (c *safetyControl) UpdateService(_ context.Context, request *api.UpdateServiceRequest, _ ...grpc.CallOption) (*api.UpdateServiceResponse, error) {
	c.writes++
	if c.conflict {
		c.conflict = false
		c.service.Meta.Version.Index++
		if c.onConflict != nil {
			c.onConflict(c.service)
		}
		return nil, status.Error(codes.Unknown, "update out of sequence")
	}
	if *request.ServiceVersion != c.service.Meta.Version {
		return nil, status.Error(codes.Unknown, "update out of sequence")
	}
	c.service.Spec = *request.Spec.Copy()
	return &api.UpdateServiceResponse{Service: c.service.Copy()}, nil
}

func safetyFixture(t *testing.T) (ServiceSpec, *safetyControl) {
	t.Helper()
	spec := ServiceSpec{Name: "web", Image: "ghcr.io/terrascale/web@sha256:" + strings.Repeat("a", 64), Port: 8080, Replicas: 1, Generation: 7, Region: "gru", Node: "gru-1"}
	swarm, err := spec.SwarmSpec()
	if err != nil {
		t.Fatal(err)
	}
	service := &api.Service{ID: "service", Spec: *swarm, SpecVersion: &api.Version{Index: 3}}
	task := &api.Task{ID: "task", ServiceID: service.ID, NodeID: "node", Spec: *swarm.Task.Copy(), SpecVersion: service.SpecVersion.Copy(),
		ServiceAnnotations: *swarm.Annotations.Copy(), DesiredState: api.TaskStateRunning, Status: api.TaskStatus{State: api.TaskStateRunning}}
	return spec, &safetyControl{service: service, task: task, machine: "gru-1"}
}

func swarmForTest(t *testing.T, spec ServiceSpec) api.ServiceSpec {
	t.Helper()
	swarm, err := spec.SwarmSpec()
	if err != nil {
		t.Fatal(err)
	}
	return *swarm
}

func TestDeploymentAttemptFencesRuntime(t *testing.T) {
	for _, rollback := range []int64{0, 10} {
		spec, control := safetyFixture(t)
		d := &Deployment{Repository: "TerraScale/terrascale", RunID: "100", RunAttempt: 1, Revision: strings.Repeat("b", 40), Image: spec.Image}
		spec.Generation, spec.RollbackOf, spec.Deployment, spec.DeploymentFloor = 11, rollback, d, d
		control.service.Spec = swarmForTest(t, spec)
		next := *d
		next.RunAttempt, next.Image = 2, "ghcr.io/terrascale/web@sha256:"+strings.Repeat("c", 64)
		spec.Generation, spec.RollbackOf, spec.Image, spec.Deployment, spec.DeploymentFloor = 12, 0, next.Image, &next, &next
		// A re-run's rebuilt image retries the run, serving or rolled back.
		if err := admitServiceSpec(control.service.Spec.Annotations.Labels, spec); err != nil {
			t.Fatalf("rollback=%d: %v", rollback, err)
		}
		if next.Accepts(d) == nil {
			t.Fatal("older attempt admitted")
		}
		changed := next
		changed.Revision = strings.Repeat("e", 40)
		changed.RunAttempt++
		if next.Accepts(&changed) == nil {
			t.Fatal("rerun changed commit")
		}
	}
}
