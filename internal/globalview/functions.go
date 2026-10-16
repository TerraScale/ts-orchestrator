package globalview

import (
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/functions"
)

// FunctionObservation keeps desired identity separate from actual worker data.
// An unavailable snapshot never becomes a zero counter or a ready worker.
type FunctionObservation struct {
	TenantID   string              `json:"tenant_id"`
	FunctionID string              `json:"function_id"`
	Revision   string              `json:"revision"`
	Digest     string              `json:"digest"`
	TaskID     string              `json:"task_id,omitempty"`
	NodeID     string              `json:"node_id,omitempty"`
	State      string              `json:"state"`
	Snapshot   *functions.Snapshot `json:"snapshot,omitempty"`
	ObservedAt time.Time           `json:"observed_at,omitzero"`
}

func (region Region) FunctionState(observation *FunctionObservation, found bool) string {
	if region.Rollup != nil && region.Rollup.FunctionsObservedAt.IsZero() {
		return "unavailable"
	}
	state := region.ResourceState(found)
	if state != "current" && state != "not_found" {
		return state
	}
	observed := region.Rollup.FunctionsObservedAt
	if observation != nil {
		if observation.State != "observed" && observation.State != "unplaced" || observation.State == "observed" && observation.Snapshot == nil {
			return "unavailable"
		}
		observed = observation.ObservedAt
	}
	if observed.IsZero() || region.Rollup.ObservedAt.Sub(observed) > StaleAfter {
		return "stale"
	}
	return state
}
