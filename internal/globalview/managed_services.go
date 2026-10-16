package globalview

import (
	"encoding/json/v2"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

// Keep the management observation within the existing regional rollup budget.
func boundedManagedServices(source []swarmruntime.ServiceObservation, truncated *bool) []swarmruntime.ServiceObservation {
	services := slices.Clone(source)
	slices.SortFunc(services, func(a, b swarmruntime.ServiceObservation) int { return strings.Compare(a.ServiceID, b.ServiceID) })
	services = keep(services, 32, truncated)
	var bytes int
	var result []swarmruntime.ServiceObservation
	for _, service := range services {
		service.Tasks = keep(slices.Clone(service.Tasks), 16, truncated)
		data, err := json.Marshal(service)
		if err != nil || bytes+len(data) > 64<<10 {
			*truncated = true
			continue
		}
		bytes += len(data)
		result = append(result, service)
	}
	return result
}

// ManagedServiceState includes the source's own age, independently of a fresh rollup.
func (region Region) ManagedServiceState(found bool, observed time.Time) string {
	if region.Rollup != nil && region.Rollup.ServicesObservedAt.IsZero() {
		return "unavailable"
	}
	state := region.ResourceState(found)
	if state != "current" && state != "not_found" {
		return state
	}
	if observed.IsZero() || region.Rollup.ObservedAt.Sub(observed) > StaleAfter {
		return "stale"
	}
	return state
}
