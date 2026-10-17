package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/hostload"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/tsauth"
	"github.com/TerraScale/ts-orchestrator/internal/workload"
)

// AutoscaleConfig carries the signed desired service policies.
type AutoscaleConfig struct {
	Services []workload.ServiceSpec `json:"services,omitempty"`
}

func validateAutoscaleConfig(config *AutoscaleConfig, profiles map[string]WorkloadProfile) error {
	if config == nil {
		return nil
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
	return nil
}

// PlanShaped plans a release. Roles with a signed stateless service policy get a
// release-scoped generation and keep their current scale; every other role
// keeps the intent's own generation and replica count.
func (p *regionalDeliveryPlanner) PlanShaped(ctx context.Context, intent delivery.Intent) (delivery.PlanShape, []host.Desired, error) {
	if p.migrated != nil && p.migrated(intent.Role) {
		return delivery.PlanShape{}, nil, errors.New("stateless native release planning is retired; signed container intent required")
	}
	shape := delivery.PlanShape{Generation: intent.Generation, Replicas: intent.DesiredReplicas}
	spec, owned := p.nativeServiceSpec(intent.Role)
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

func (p *regionalDeliveryPlanner) nativeServiceSpec(role string) (workload.ServiceSpec, bool) {
	if p.services != nil {
		_, specs := p.services.effective()
		for _, spec := range specs {
			if spec.Role == role && spec.Kind == workload.KindStateless {
				return spec, true
			}
		}
	}
	return workload.ServiceSpec{}, false
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
