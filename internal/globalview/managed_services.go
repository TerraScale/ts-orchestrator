package globalview

import (
	"time"
)

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
