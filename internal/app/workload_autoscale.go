package app

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/capacity"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/workload"
)

// AutoscaleConfig enables continuous reconciliation of generic services. It
// is part of the signed controller config and is off unless Enabled is set:
// without it every role keeps the fixed, one-shot delivery placement.
type AutoscaleConfig struct {
	Enabled         bool                   `json:"enabled"`
	IntervalSeconds int                    `json:"interval_seconds,omitzero"`
	Services        []workload.ServiceSpec `json:"services,omitempty"`
	// NodePools are planned in recommend-only mode until a generic host
	// provisioner exists; plans are logged, never applied.
	NodePools []capacity.NodePool `json:"node_pools,omitempty"`
}

func validateAutoscaleConfig(config *AutoscaleConfig, profiles map[string]WorkloadProfile) error {
	if config == nil {
		return nil
	}
	if config.IntervalSeconds < 0 || config.IntervalSeconds > 3600 {
		return errors.New("autoscale interval_seconds must be within 0..3600")
	}
	if err := workload.ValidateSpecs(config.Services); err != nil {
		return fmt.Errorf("autoscale services: %w", err)
	}
	for _, spec := range config.Services {
		if spec.Kind != workload.KindStateless {
			continue
		}
		profile, exists := profiles[spec.Role]
		if !exists {
			return fmt.Errorf("autoscale service %q has no workload profile", spec.Role)
		}
		if spec.Resources != (placement.Resources{}) && spec.Resources != profile.Resources {
			return fmt.Errorf("autoscale service %q resources differ from its workload profile", spec.Role)
		}
	}
	if err := capacity.ValidatePools(config.NodePools); err != nil {
		return fmt.Errorf("autoscale node pools: %w", err)
	}
	return nil
}

// startWorkloadAutoscale builds the reconciler and capacity scaler when the
// signed config enables them. Both act only on the regional authority leader.
func startWorkloadAutoscale(cell string, config *AutoscaleConfig, profiles map[string]WorkloadProfile,
	hosts *host.Controller, fencer authority.Fencer,
) (*workload.Reconciler, *capacity.Scaler, error) {
	if config == nil || !config.Enabled {
		return nil, nil, nil
	}
	interval := time.Duration(config.IntervalSeconds) * time.Second
	resources := make(map[string]placement.Resources, len(profiles))
	for role, profile := range profiles {
		resources[role] = profile.Resources
	}
	var scaler *capacity.Scaler
	var requester workload.CapacityRequester
	if len(config.NodePools) > 0 {
		var err error
		scaler, err = capacity.NewScaler(capacity.Config{Cell: cell, Pools: config.NodePools, Hosts: hosts,
			Fencer: fencer, Logf: log.Printf})
		if err != nil {
			return nil, nil, fmt.Errorf("start host pool scaler: %w", err)
		}
		requester = scaler
	}
	reconciler, err := workload.New(workload.Config{Cell: cell, Specs: config.Services, Profiles: resources,
		Hosts: hosts, Writer: hosts, Fencer: fencer, Capacity: requester, Interval: interval, Logf: log.Printf})
	if err != nil {
		return nil, nil, fmt.Errorf("start workload reconciler: %w", err)
	}
	return reconciler, scaler, nil
}

// PlanShaped plans a release. Roles owned by the workload reconciler get a
// release-scoped generation and keep their current scale; every other role
// keeps the intent's own generation and replica count.
func (p *regionalDeliveryPlanner) PlanShaped(ctx context.Context, intent delivery.Intent) (delivery.PlanShape, []host.Desired, error) {
	shape := delivery.PlanShape{Generation: intent.Generation, Replicas: intent.DesiredReplicas}
	spec, owned := p.workloads.Owns(intent.Role)
	if !owned || spec.Environment != intent.Environment {
		plan, err := p.Plan(ctx, intent)
		return shape, plan, err
	}
	plan, err := p.plan(ctx, intent, func(observation workload.Observation) (delivery.PlanShape, error) {
		generation, replicas, err := workload.ReleaseShape(spec, intent.Generation, intent.DesiredReplicas, observation)
		return delivery.PlanShape{Generation: generation, Replicas: replicas}, err
	}, &shape)
	return shape, plan, err
}
