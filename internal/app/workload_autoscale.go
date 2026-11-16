package app

import (
	"github.com/TerraScale/ts-orchestrator/internal/workload"
)

// AutoscaleConfig carries the signed desired service policies.
type AutoscaleConfig struct {
	Services []workload.ServiceSpec `json:"services,omitempty"`
}
