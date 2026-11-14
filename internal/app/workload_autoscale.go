package app

import (
	"fmt"

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
