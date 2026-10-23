package swarmruntime

import (
	"context"
	"errors"
	"fmt"
	"maps"

	"github.com/gogo/protobuf/proto"
	"github.com/moby/swarmkit/v2/api"
)

// ServiceTaskEvidence contains runtime identity only, never task environments.
type ServiceTaskEvidence struct {
	ServiceID  string `json:"serviceId"`
	TaskID     string `json:"taskId"`
	NodeID     string `json:"nodeId"`
	Machine    string `json:"machine"`
	Image      string `json:"image"`
	Generation int64  `json:"generation"`
	Ready      bool   `json:"ready"`
}

// WaitServiceSpecExact binds readiness to the requested mesh spec, not whichever
// service happens to be present when an overlapping release starts waiting.
// A metadata-only reapply may keep an identical older task; report its actual generation.
func WaitServiceSpecExact(ctx context.Context, client api.ControlClient, requested ServiceSpec) (ServiceRollout, error) {
	var rollout ServiceRollout
	want, err := requested.SwarmSpec()
	if err != nil {
		return rollout, err
	}
	service, err := specService(ctx, client, requested.Name)
	if err != nil {
		return rollout, err
	}
	if service == nil || !proto.Equal(&service.Spec, want) {
		return rollout, errors.New("requested service spec was superseded before readiness")
	}
	var probe func(context.Context, *api.Task) error
	if requested.ReadyPath != "" {
		probe = ProbeLocalTask
	}
	rollout, err = WaitServiceSpec(ctx, client, service, probe)
	if err != nil {
		return rollout, err
	}
	tasks, err := client.ListTasks(ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{ServiceIDs: []string{service.ID}, DesiredStates: []api.TaskState{api.TaskStateRunning}, UpToDate: true}})
	if err != nil {
		return rollout, err
	}
	if uint64(len(tasks.Tasks)) != requested.Replicas || len(tasks.Tasks) == 0 {
		return rollout, errors.New("requested replica inventory changed after readiness")
	}
	for _, task := range tasks.Tasks {
		container, containerErr := containerOf(api.ServiceSpec{Task: task.Spec})
		generation, rollbackOf, err := serviceGeneration(task.ServiceAnnotations.Labels)
		if err != nil {
			return rollout, err
		}
		taskLabels, serviceLabels := maps.Clone(task.ServiceAnnotations.Labels), maps.Clone(service.Spec.Annotations.Labels)
		delete(taskLabels, LabelGeneration)
		delete(serviceLabels, LabelGeneration)
		delete(taskLabels, LabelRollbackOf)
		delete(serviceLabels, LabelRollbackOf)
		if task.ServiceID != service.ID || task.Status.State != api.TaskStateRunning || task.DesiredState != api.TaskStateRunning ||
			containerErr != nil || container.Image != requested.Image || !proto.Equal(&task.Spec, &service.Spec.Task) ||
			task.ServiceAnnotations.Name != service.Spec.Annotations.Name || !maps.Equal(taskLabels, serviceLabels) ||
			ServiceGenerationAfter(generation, rollbackOf, requested.Generation, requested.RollbackOf) {
			return rollout, errors.New("running task does not match the requested artifact and generation")
		}
		node, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: task.NodeID})
		if err != nil {
			return rollout, err
		}
		if node.Node == nil || node.Node.Description == nil || node.Node.Description.Hostname != requested.Node {
			return rollout, fmt.Errorf("task %s runs on an unexpected machine", task.ID)
		}
		if probe != nil {
			if err := probe(ctx, task); err != nil {
				return rollout, err
			}
		}
		rollout.Tasks = append(rollout.Tasks, ServiceTaskEvidence{ServiceID: service.ID, TaskID: task.ID, NodeID: task.NodeID,
			Machine: node.Node.Description.Hostname, Image: container.Image, Generation: generation, Ready: probe != nil})
	}
	latest, err := client.GetService(ctx, &api.GetServiceRequest{ServiceID: service.ID})
	if err != nil {
		return rollout, err
	}
	if !proto.Equal(&latest.Service.Spec, want) || !proto.Equal(latest.Service.SpecVersion, service.SpecVersion) {
		return rollout, errors.New("requested service spec changed during readiness verification")
	}
	return rollout, nil
}
