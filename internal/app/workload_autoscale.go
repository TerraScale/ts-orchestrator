package app

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/autoscale"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostload"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostpool"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/tsauth"
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
	NodePools []hostpool.NodePool `json:"node_pools,omitempty"`
	// HostTelemetry makes the authority leader accept host load reports
	// (the "load" host operation) and feed them to the autoscaler as its
	// signal source. It is a trust decision: an authenticated host's
	// self-reported load can then move a service within its signed replica
	// bounds. Off by default; scaling policies are refused without it.
	HostTelemetry bool `json:"host_telemetry,omitzero"`
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
			// Nothing reconciles stateful services yet (TerraBase is sized
			// by placement); refuse signed config that would silently do
			// nothing.
			return fmt.Errorf("autoscale service %q: stateful services are not reconciled yet", spec.Role)
		}
		if spec.Scaling != nil && !config.HostTelemetry {
			// Host telemetry is the only signal source. Without it a
			// scaling policy would only ever hold with no-signal-data;
			// bounds and self-healing work without one.
			return fmt.Errorf("autoscale service %q: signal-driven scaling needs host_telemetry; set replicas bounds only", spec.Role)
		}
		if spec.Scaling != nil {
			for _, signal := range spec.Scaling.Signals {
				if !hostload.StatelessSignal(signal.Name) {
					// Request rates and TerraBase signals have no producer
					// for the stateless services this reconciler owns.
					return fmt.Errorf("autoscale service %q: signal %q has no producer for stateless services", spec.Role, signal.Name)
				}
			}
		}
		if spec.Role == "terrabase" {
			// TerraBase members are owned by placement, never by the
			// stateless reconciler or release shaping.
			return fmt.Errorf("autoscale service %q is a managed TerraBase role", spec.Role)
		}
		// ts-auth runs exactly its replica count, or none while a cell spec
		// drains it before removing it.
		if spec.Role == tsauth.Role && (spec.Replicas != workload.ReplicaBounds{Min: tsauth.Replicas, Max: tsauth.Replicas} &&
			spec.Replicas != workload.ReplicaBounds{} || spec.Placement.MaxPerFailureDomain != 1) {
			return fmt.Errorf("autoscale service %q must keep exactly %d replicas (or 0 to drain it) with one per failure domain",
				spec.Role, tsauth.Replicas)
		}
		profile, exists := profiles[spec.Role]
		if !exists {
			return fmt.Errorf("autoscale service %q has no workload profile", spec.Role)
		}
		if spec.Resources != (placement.Resources{}) && spec.Resources != profile.Resources {
			return fmt.Errorf("autoscale service %q resources differ from its workload profile", spec.Role)
		}
	}
	if err := hostpool.ValidatePools(config.NodePools); err != nil {
		return fmt.Errorf("autoscale node pools: %w", err)
	}
	return nil
}

// startWorkloadAutoscale builds the reconciler, which owns the cell spec's
// reconciled roles, and, when the signed config enables autoscaling, its
// host telemetry and host pool scaler. All act only on the regional
// authority leader. The returned aggregator is nil without host telemetry.
func startWorkloadAutoscale(cell string, config *AutoscaleConfig, profiles map[string]WorkloadProfile,
	specs []workload.ServiceSpec, hosts *host.Controller, fencer authority.Fencer,
) (*workload.Reconciler, *hostpool.Scaler, *hostload.Aggregator, error) {
	var settings AutoscaleConfig
	if config != nil && config.Enabled {
		settings = *config
	}
	interval := time.Duration(settings.IntervalSeconds) * time.Second
	resources := profileResources(profiles)
	var scaler *hostpool.Scaler
	var requester workload.CapacityRequester
	if len(settings.NodePools) > 0 {
		var err error
		scaler, err = hostpool.NewScaler(hostpool.Config{Cell: cell, Pools: settings.NodePools, Hosts: hosts,
			Fencer: fencer, Logf: log.Printf})
		if err != nil {
			return nil, nil, nil, fmt.Errorf("start host pool scaler: %w", err)
		}
		requester = scaler
	}
	var signals autoscale.Source
	var load *hostload.Aggregator
	if settings.HostTelemetry {
		load = hostload.NewAggregator(hostload.AggregatorConfig{Requests: loadRequests(resources)})
		signals = load
	}
	reconciler, err := workload.New(workload.Config{Cell: cell, Specs: specs, Profiles: resources,
		Hosts: hosts, Writer: hosts, Fencer: fencer, Signals: signals, Capacity: requester, Interval: interval,
		Logf: log.Printf})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("start workload reconciler: %w", err)
	}
	if load != nil {
		// Only the authority leader serves host requests, so only its
		// aggregator fills; a new leader starts empty and its reconciler
		// holds with no-signal-data until a full window arrives.
		hosts.SetLoadSink(load.Record)
	}
	return reconciler, scaler, load, nil
}

func loadRequests(resources map[string]placement.Resources) map[string]hostload.Request {
	requests := make(map[string]hostload.Request, len(resources))
	for role, request := range resources {
		requests[role] = hostload.Request{CPUCores: float64(request.CPU), MemoryBytes: request.MemoryBytes}
	}
	return requests
}

// PlanShaped plans a release. Roles owned by the workload reconciler get a
// release-scoped generation and keep their current scale; every other role
// keeps the intent's own generation and replica count.
func (p *regionalDeliveryPlanner) PlanShaped(ctx context.Context, intent delivery.Intent) (delivery.PlanShape, []host.Desired, error) {
	shape := delivery.PlanShape{Generation: intent.Generation, Replicas: intent.DesiredReplicas}
	spec, owned := p.workloads.Owns(intent.Role)
	if !owned || spec.Environment != intent.Environment {
		// A role the reconciler once owned carries release-scoped host
		// generations (intent << ReleaseShift). Planning it at the plain
		// intent generation would move every host backwards and hold
		// every later release, so it stays in that generation space.
		plan, err := p.plan(ctx, intent, func(observation workload.Observation) (delivery.PlanShape, error) {
			return unownedShape(intent, observation)
		}, &shape)
		return shape, plan, err
	}
	plan, err := p.plan(ctx, intent, func(observation workload.Observation) (delivery.PlanShape, error) {
		generation, replicas, err := workload.ReleaseShape(spec, intent.Generation, intent.DesiredReplicas, observation)
		return delivery.PlanShape{Generation: generation, Replicas: replicas}, err
	}, &shape)
	return shape, plan, err
}

// unownedShape is the shape of a release for a role the reconciler does not
// own: the intent's own generation and replicas, except that a role once
// committed with release-scoped generations keeps that generation space.
func unownedShape(intent delivery.Intent, observation workload.Observation) (delivery.PlanShape, error) {
	if !observation.Shaped() {
		return delivery.PlanShape{Generation: intent.Generation, Replicas: intent.DesiredReplicas}, nil
	}
	generation, err := workload.ReleaseGeneration(intent.Generation)
	return delivery.PlanShape{Generation: generation, Replicas: intent.DesiredReplicas}, err
}
