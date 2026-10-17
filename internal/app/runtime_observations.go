package app

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/gogo/protobuf/proto"
	"github.com/moby/swarmkit/v2/api"
)

func managedServiceObservations(ctx context.Context, region, environment string, material *containerMaterialController) ([]swarmruntime.ServiceObservation, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	accepted, err := bootstrapstart.NewMarkerStore().ReadIdentity()
	if err != nil {
		return nil, err
	}
	client, _, connection, err := swarmruntime.DialManagement(ctx, accepted)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	if material == nil {
		return nil, errors.New("current managed readiness source is unavailable")
	}
	return observeManagedServices(ctx, client, region, environment, material.observeTaskReadiness)
}

func observeManagedServices(ctx context.Context, client api.ControlClient, region, environment string,
	readiness func(context.Context, *api.Task) (func(context.Context) error, error),
) ([]swarmruntime.ServiceObservation, error) {
	if client == nil || region == "" || environment == "" {
		return nil, errors.New("regional runtime observation source is unavailable")
	}
	listed, err := client.ListServices(ctx, &api.ListServicesRequest{})
	if err != nil {
		return nil, err
	}
	if listed == nil {
		return nil, errors.New("manager service list is unavailable")
	}
	services := make([]swarmruntime.ServiceObservation, 0, len(listed.Services))
	for _, service := range listed.Services {
		if service == nil {
			return nil, errors.New("manager service entry is unavailable")
		}
		labels := service.Spec.Annotations.Labels
		if labels[swarmruntime.LabelRegion] != region || labels[swarmruntime.LabelEnvironment] != environment || !entityid.Valid(labels[swarmruntime.LabelIntentID]) {
			continue
		}
		var probe func(context.Context, *api.Task) error
		var checks []func(context.Context) error
		var tasks []*api.Task
		unavailable := false
		// Native/stateful and function readiness have separate authenticated sources.
		if generic := service.Spec.Task.GetGeneric(); readiness != nil && generic != nil && generic.Kind == swarmruntime.ContainerKind &&
			labels[swarmruntime.LabelRole] != "terrabase" && labels[swarmruntime.LabelRole] != swarmruntime.FunctionWorkerRole {
			probe = func(ctx context.Context, task *api.Task) error {
				check, err := readiness(ctx, task)
				if err != nil || check == nil {
					unavailable = true
					return errors.New("current application readiness is unavailable")
				}
				checks, tasks = append(checks, check), append(tasks, task.Copy())
				return nil
			}
		}
		observed, err := swarmruntime.ObserveService(ctx, client, service.ID, probe)
		if err != nil {
			return nil, err
		}
		if observed.Region != region || observed.Environment != environment || observed.IntentID != labels[swarmruntime.LabelIntentID] {
			return nil, errors.New("managed service scope changed during observation")
		}
		for index, task := range tasks {
			current, err := client.GetTask(ctx, &api.GetTaskRequest{TaskID: task.ID})
			if err != nil || current == nil || !proto.Equal(task, current.Task) || checks[index](ctx) != nil {
				unavailable = true
			}
		}
		confirmed, err := client.GetService(ctx, &api.GetServiceRequest{ServiceID: service.ID})
		if err != nil || confirmed == nil || !proto.Equal(service, confirmed.Service) {
			return nil, errors.New("managed service changed during task readiness observation")
		}
		for _, check := range checks {
			if check(ctx) != nil {
				unavailable = true
			}
		}
		if unavailable {
			observed.Readiness, observed.ReadyReplicas = "unknown", 0
			for index := range observed.Tasks {
				observed.Tasks[index].Ready = false
			}
		}
		if observed.Readiness != "observed" {
			observed.ReadinessReason = "current authenticated task material and application readiness source is unavailable"
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		observed.ObservedAt = time.Now().UTC()
		services = append(services, observed)
	}
	slices.SortFunc(services, func(a, b swarmruntime.ServiceObservation) int { return strings.Compare(a.ServiceID, b.ServiceID) })
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return services, nil
}

// The final check retains the first recipient and material expiry across the probe.
func (controller *containerMaterialController) observeTaskReadiness(ctx context.Context, task *api.Task) (func(context.Context) error, error) {
	registration, binding, err := controller.taskRegistration(ctx, task)
	if err != nil {
		return nil, err
	}
	selected, err := controller.registryRecipient(ctx, registration, binding)
	if err != nil {
		return nil, err
	}
	if !proto.Equal(task, selected.Task) {
		return nil, errors.New("managed task changed before readiness probe")
	}
	deadline := selected.Verified.ExpiresAt()
	if selected.controllerProof != nil {
		if selected.controllerProof.Deadline().Before(deadline) {
			deadline = selected.controllerProof.Deadline()
		}
		if selected.enrollmentExpiresAt.Before(deadline) {
			deadline = selected.enrollmentExpiresAt
		}
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	if err := controller.currentMaterialTask(ctx, selected, registration, binding); err != nil {
		return nil, err
	}
	if err := controller.probe(ctx, task); err != nil {
		return nil, err
	}
	return func(ctx context.Context) error {
		return controller.currentMaterialTask(ctx, selected, registration, binding)
	}, nil
}
