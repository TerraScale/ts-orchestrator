package dashboard

import (
	"maps"
	"slices"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
)

// fleetViews lists the newest OCI fleet inventory of each region any
// member reported, by region.
func (current view) fleetViews() []observability.OCIFleetView {
	newest := map[string]observability.OCIFleetView{}
	for _, member := range current.members() {
		if member.OCI == nil {
			continue
		}
		for _, fleet := range member.OCI.Fleet {
			if known, ok := newest[fleet.Region]; !ok || fleet.ObservedAt.After(known.ObservedAt) {
				newest[fleet.Region] = fleet
			}
		}
	}
	out := make([]observability.OCIFleetView, 0, len(newest))
	for _, region := range slices.Sorted(maps.Keys(newest)) {
		out = append(out, newest[region])
	}
	return out
}

// fleetKinds are the inventory rows, in order.
var fleetKinds = []string{"instances", "volumes", "attachments"}

func fleetCounts(fleet observability.OCIFleetView, kind string) map[string]int {
	switch kind {
	case "instances":
		return fleet.Instances
	case "volumes":
		return fleet.Volumes
	default:
		return fleet.Attachments
	}
}

func sortedStates(counts map[string]int) []string { return slices.Sorted(maps.Keys(counts)) }

// lifecycleStatus colors an OCI lifecycle state.
func lifecycleStatus(state string) string {
	switch state {
	case "RUNNING", "AVAILABLE", "ATTACHED":
		return "ok"
	case "PROVISIONING", "STARTING", "ATTACHING", "RESTORING", "CREATING_IMAGE", "MOVING":
		return "run"
	case "STOPPING", "STOPPED", "DETACHING", "DETACHED", "TERMINATING":
		return "warn"
	case "FAULTY", "TERMINATED", "UNKNOWN":
		return "bad"
	default:
		return "idle"
	}
}

// fleetChart stacks one region's resources by lifecycle state.
func fleetChart(fleet observability.OCIFleetView) chartSpec {
	spec := chartSpec{Kind: "hbar", Unit: "count", Categories: fleetKinds}
	states := map[string]bool{}
	for _, kind := range fleetKinds {
		for state := range fleetCounts(fleet, kind) {
			states[state] = true
		}
	}
	for _, state := range slices.Sorted(maps.Keys(states)) {
		bar := barSeries{Name: state, Status: lifecycleStatus(state)}
		for _, kind := range fleetKinds {
			bar.Values = append(bar.Values, float64(fleetCounts(fleet, kind)[state]))
		}
		spec.Bars = append(spec.Bars, bar)
	}
	if len(spec.Bars) == 0 {
		spec.Empty = "The latest sweep found no managed instance."
	}
	return spec
}
