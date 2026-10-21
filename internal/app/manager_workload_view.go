package app

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/autoscale"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/workload"
	"github.com/moby/swarmkit/v2/api"
)

// workloadObservation keeps the existing history and insight presentation while
// manager services replace native per-host reconciliation.
type workloadObservation interface {
	Last() map[string]workload.Result
	Owns(string) (workload.ServiceSpec, bool)
	Leading() bool
}

type managerWorkloadView struct {
	client    api.ControlClient
	managerID string
	authority authority.Fencer
	scaler    *swarmruntime.Autoscaler
	specs     *specRegistry
	probe     func(context.Context, *api.Task) error
}

func newManagerWorkloadView(client api.ControlClient, managerID string, fencer authority.Fencer,
	scaler *swarmruntime.Autoscaler, specs *specRegistry, probe func(context.Context, *api.Task) error,
) (*managerWorkloadView, error) {
	if client == nil || managerID == "" || fencer == nil || scaler == nil || specs == nil || probe == nil {
		return nil, errors.New("manager workload observations require authority, signed services, scaler and current readiness")
	}
	return &managerWorkloadView{client: client, managerID: managerID, authority: fencer, scaler: scaler, specs: specs, probe: probe}, nil
}

func (view *managerWorkloadView) leader(ctx context.Context, epoch uint64) bool {
	if err := view.authority.Guard(ctx, epoch); err != nil {
		return false
	}
	current := view.authority.Current()
	if !current.CanMutate() || current.Epoch != epoch {
		return false
	}
	response, err := view.client.GetNode(ctx, &api.GetNodeRequest{NodeID: view.managerID})
	return err == nil && response != nil && response.Node != nil && response.Node.ID == view.managerID &&
		response.Node.ManagerStatus != nil && response.Node.ManagerStatus.Leader
}

func (view *managerWorkloadView) Leading() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return view.leader(ctx, view.authority.Current().Epoch)
}

func (view *managerWorkloadView) Owns(role string) (workload.ServiceSpec, bool) {
	_, specs := view.specs.effective()
	for _, spec := range specs {
		if spec.Role == role && spec.Kind == workload.KindStateless {
			return spec, true
		}
	}
	return workload.ServiceSpec{}, false
}

// Last never substitutes retained results for unavailable manager state.
func (view *managerWorkloadView) Last() map[string]workload.Result {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	epoch := view.authority.Current().Epoch
	if !view.leader(ctx, epoch) {
		return nil
	}
	_, specs := view.specs.effective()
	last := view.scaler.Last()
	results := make(map[string]workload.Result)
	region := catalog.OCIRegion(strings.ToUpper(view.specs.cell))
	for _, spec := range specs {
		if spec.Kind != workload.KindStateless {
			continue
		}
		response, err := view.client.ListServices(ctx, &api.ListServicesRequest{Filters: &api.ListServicesRequest_Filters{Labels: map[string]string{
			swarmruntime.LabelRegion: region, swarmruntime.LabelEnvironment: spec.Environment, swarmruntime.LabelRole: spec.Role,
		}}})
		if err != nil || response == nil {
			continue
		}
		if len(response.Services) == 0 {
			results[spec.Role] = workload.Result{Role: spec.Role, Reason: "awaiting-release"}
			continue
		}
		if len(response.Services) != 1 {
			continue
		}
		service := response.Services[0]
		if service == nil {
			continue
		}
		labels := service.Spec.Annotations.Labels
		if service.PendingDelete || labels[swarmruntime.LabelRole] != spec.Role || labels[swarmruntime.LabelRegion] != region ||
			labels[swarmruntime.LabelEnvironment] != spec.Environment || service.Spec.GetReplicated() == nil || service.Spec.GetReplicated().Replicas > autoscale.MaxReplicas {
			continue
		}
		observed, err := swarmruntime.ObserveService(ctx, view.client, service.ID, view.probe)
		if err != nil {
			continue
		}
		confirmed, err := view.client.GetService(ctx, &api.GetServiceRequest{ServiceID: service.ID})
		if err != nil || confirmed == nil || confirmed.Service == nil || confirmed.Service.Meta.Version.Index != service.Meta.Version.Index {
			continue
		}
		replicas := int(observed.RequestedReplicas)
		result := workload.Result{Role: spec.Role, Replicas: replicas, Target: replicas, Reason: "awaiting-autoscale"}
		target := autoscale.Target{Cell: view.specs.cell, Environment: spec.Environment, Role: spec.Role}
		if scaled, exists := last[target]; exists && scaled.Reason != "awaiting-release" && (scaled.Replicas == replicas || scaled.Target == replicas) {
			result.Target, result.Reason = scaled.Target, scaled.Reason
			result.Readings = slices.Clone(scaled.Readings)
			decision := scaled.Decision
			decision.History.Recommendations = slices.Clone(decision.History.Recommendations)
			result.Decision = &decision
		}
		if observed.UpdateState != "" && observed.UpdateState != api.UpdateStatus_COMPLETED.String() && observed.UpdateState != api.UpdateStatus_ROLLBACK_COMPLETED.String() {
			result.Target, result.Reason, result.Readings, result.Decision = replicas, "release-in-progress", nil, nil
		} else if observed.Readiness != "observed" || observed.ReadyReplicas != observed.RequestedReplicas || observed.RunningReplicas != observed.RequestedReplicas {
			result.Target, result.Reason, result.Readings, result.Decision = replicas, "unready-replicas", nil, nil
		}
		results[spec.Role] = result
	}
	_, currentSpecs := view.specs.effective()
	if !reflect.DeepEqual(specs, currentSpecs) || !view.leader(ctx, epoch) {
		return nil
	}
	return results
}
