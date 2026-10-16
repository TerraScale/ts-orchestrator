package swarmruntime

import (
	"context"
	"errors"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/gogo/protobuf/proto"
	"github.com/moby/swarmkit/v2/api"
)

// FunctionCapacityDemand counts qualified worker slots waiting for placement.
// CAP derives host demand from the admitted host geometry and its spend authority.
type FunctionCapacityDemand struct {
	Architecture string
	Slots        uint64
}

// PendingCapacity observes actual manager tasks without changing replicas or
// placement. Assigned, starting and unhealthy workers require no additional slot.
func (i FunctionServiceIntent) PendingCapacity(ctx context.Context, client api.ControlClient, current CurrentFunctionIntent, worker release.VerifiedContainer) (FunctionCapacityDemand, error) {
	if current == nil {
		return FunctionCapacityDemand{}, errors.New("function capacity requires current signed intent authority")
	}
	function, err := current.CurrentFunction(ctx, i.TenantID, i.FunctionID)
	if err != nil {
		return FunctionCapacityDemand{}, err
	}
	spec, err := i.serviceSpec(function, worker)
	if err != nil {
		return FunctionCapacityDemand{}, err
	}
	if err := i.VerifyWorkerFloor(ctx, client, worker); err != nil {
		return FunctionCapacityDemand{}, err
	}
	listed, err := client.ListServices(ctx, &api.ListServicesRequest{Filters: &api.ListServicesRequest_Filters{Names: []string{spec.Annotations.Name}}})
	if err != nil {
		return FunctionCapacityDemand{}, err
	}
	if listed == nil || len(listed.Services) > 1 {
		return FunctionCapacityDemand{}, errors.New("function capacity requires an unambiguous service identity")
	}
	demand := FunctionCapacityDemand{Architecture: i.Architecture}
	if len(listed.Services) == 1 {
		service := listed.Services[0]
		if service == nil || service.PendingDelete || !proto.Equal(&service.Spec, spec) {
			return FunctionCapacityDemand{}, errors.New("function capacity service differs from current qualified intent")
		}
		tasks, err := client.ListTasks(ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{ServiceIDs: []string{service.ID}, DesiredStates: []api.TaskState{api.TaskStateRunning}}})
		if err != nil {
			return FunctionCapacityDemand{}, err
		}
		if tasks == nil {
			return FunctionCapacityDemand{}, errors.New("function capacity task observation is unavailable")
		}
		for _, task := range tasks.Tasks {
			if task == nil || task.DesiredState != api.TaskStateRunning || task.NodeID != "" || task.Status.State >= api.TaskStateAssigned {
				continue
			}
			if err := i.VerifyTask(task, service, function, worker); err != nil {
				return FunctionCapacityDemand{}, err
			}
			demand.Slots++
		}
	}
	latest, err := current.CurrentFunction(ctx, i.TenantID, i.FunctionID)
	if err != nil {
		return FunctionCapacityDemand{}, err
	}
	if !latest.Valid() || latest.EnvelopeSHA256() != function.EnvelopeSHA256() {
		return FunctionCapacityDemand{}, errors.New("function intent changed during capacity observation")
	}
	if err := i.VerifyWorkerFloor(ctx, client, worker); err != nil {
		return FunctionCapacityDemand{}, err
	}
	return demand, ctx.Err()
}
