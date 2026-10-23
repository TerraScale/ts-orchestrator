package swarmruntime

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/moby/swarmkit/v2/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestServiceSpecLockSharedByRoot(t *testing.T) {
	state := t.TempDir()
	unlock, err := lockServiceSpecs(t.Context(), singleHostControl{state: state})
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	if release, err := lockServiceSpecs(ctx, singleHostControl{state: state}); err == nil {
		release()
		t.Fatal("another client acquired the same root's spec lock")
	}
	other, err := lockServiceSpecs(t.Context(), singleHostControl{state: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	other()
}

type safetyControl struct {
	api.ControlClient
	service  *api.Service
	task     *api.Task
	conflict bool
	writes   int
	machine  string
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

func TestServiceSpecRetriesMetadataConflictAndRejectsStaleGeneration(t *testing.T) {
	spec, control := safetyFixture(t)
	spec.Image = "ghcr.io/terrascale/web@sha256:" + strings.Repeat("b", 64)
	spec.Generation++
	control.conflict = true
	if _, err := ApplyServiceSpec(t.Context(), control, spec); err != nil || control.writes != 2 {
		t.Fatalf("metadata conflict: writes=%d, error=%v", control.writes, err)
	}
	spec.Generation--
	if _, err := ApplyServiceSpec(t.Context(), control, spec); err == nil || control.writes != 2 {
		t.Fatalf("stale generation wrote the service: writes=%d, error=%v", control.writes, err)
	}
}

func TestServiceSpecExactEvidenceRejectsUnrelatedArtifact(t *testing.T) {
	spec, control := safetyFixture(t)
	rollout, err := WaitServiceSpecExact(t.Context(), control, spec)
	if err != nil || len(rollout.Tasks) != 1 || rollout.Tasks[0].Machine != spec.Node || rollout.Tasks[0].Image != spec.Image || rollout.Tasks[0].Ready {
		t.Fatalf("runtime evidence: %+v, %v", rollout, err)
	}
	// An unchanged workload retains its original task metadata in SwarmKit.
	control.task.SpecVersion.Index--
	control.task.ServiceAnnotations.Labels[LabelGeneration] = "6"
	if same, err := WaitServiceSpecExact(t.Context(), control, spec); err != nil || len(same.Tasks) != 1 || same.Tasks[0].Generation != 6 {
		t.Fatalf("unchanged artifact's actual task generation: %+v, %v", same, err)
	}

	for _, change := range []func(*safetyControl){
		func(c *safetyControl) { c.task.Spec.ForceUpdate++ },
		func(c *safetyControl) { c.task.ServiceAnnotations.Labels[LabelGeneration] = "8" },
		func(c *safetyControl) { c.machine = "another-host" },
		func(c *safetyControl) { c.service.Spec.Task.ForceUpdate++ },
	} {
		spec, control := safetyFixture(t)
		change(control)
		if _, err := WaitServiceSpecExact(t.Context(), control, spec); err == nil {
			t.Fatal("unrelated task or service produced successful evidence")
		}
	}
}
