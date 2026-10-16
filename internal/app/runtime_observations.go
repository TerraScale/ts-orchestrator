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
	"github.com/moby/swarmkit/v2/api"
)

func managedServiceObservations(ctx context.Context, region, environment string) ([]swarmruntime.ServiceObservation, error) {
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
	return observeManagedServices(ctx, client, region, environment)
}

func observeManagedServices(ctx context.Context, client api.ControlClient, region, environment string) ([]swarmruntime.ServiceObservation, error) {
	if client == nil || region == "" || environment == "" {
		return nil, errors.New("regional runtime observation source is unavailable")
	}
	listed, err := client.ListServices(ctx, &api.ListServicesRequest{})
	if err != nil {
		return nil, err
	}
	services := make([]swarmruntime.ServiceObservation, 0, len(listed.Services))
	for _, service := range listed.Services {
		labels := service.Spec.Annotations.Labels
		if labels[swarmruntime.LabelRegion] != region || labels[swarmruntime.LabelEnvironment] != environment || !entityid.Valid(labels[swarmruntime.LabelIntentID]) {
			continue
		}
		// Application readiness stays unknown until the current admission source
		// proves the task's OCI recipient; RUNNING alone cannot establish it.
		observed, err := swarmruntime.ObserveService(ctx, client, service.ID, nil)
		if err != nil {
			return nil, err
		}
		if observed.Region != region || observed.Environment != environment || observed.IntentID != labels[swarmruntime.LabelIntentID] {
			return nil, errors.New("managed service scope changed during observation")
		}
		services = append(services, observed)
	}
	slices.SortFunc(services, func(a, b swarmruntime.ServiceObservation) int { return strings.Compare(a.ServiceID, b.ServiceID) })
	return services, nil
}
