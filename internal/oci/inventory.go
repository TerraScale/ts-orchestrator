package oci

import (
	"cmp"
	"context"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

// Fleet inventory: how many of this region's managed instances, their
// retained data volumes and volume attachments are in each OCI lifecycle
// state, as of the latest complete Observe sweep. It is read-only telemetry
// for the dashboard and /metrics; nothing in the control plane reads it.

// maxInventoryStates bounds the lifecycle states one kind may report.
const maxInventoryStates = 16

// inventoryTally counts one Observe sweep. Only a complete sweep (Observe,
// not ObserveSelected) replaces the published inventory.
type inventoryTally struct {
	mu          sync.Mutex
	instances   map[string]int
	volumes     map[string]int
	attachments map[string]int
}

func newInventoryTally() *inventoryTally {
	return &inventoryTally{instances: map[string]int{}, volumes: map[string]int{}, attachments: map[string]int{}}
}

// The counting methods are nil-safe: paths outside a complete sweep carry
// no tally.
func (tally *inventoryTally) instance(state string) {
	if tally != nil {
		tally.add(tally.instances, state)
	}
}

func (tally *inventoryTally) volume(state string) {
	if tally != nil {
		tally.add(tally.volumes, state)
	}
}

func (tally *inventoryTally) attachment(state string) {
	if tally != nil {
		tally.add(tally.attachments, state)
	}
}

func (tally *inventoryTally) add(counts map[string]int, state string) {
	state = cmp.Or(state, "UNKNOWN")
	tally.mu.Lock()
	defer tally.mu.Unlock()
	if _, known := counts[state]; !known && len(counts) >= maxInventoryStates {
		state = "OTHER"
	}
	counts[state]++
}

type inventoryTallyKey struct{}

func withInventoryTally(ctx context.Context, tally *inventoryTally) context.Context {
	return context.WithValue(ctx, inventoryTallyKey{}, tally)
}

func inventoryTallyFrom(ctx context.Context) *inventoryTally {
	tally, _ := ctx.Value(inventoryTallyKey{}).(*inventoryTally)
	return tally
}

var fleetInventory = struct {
	mu      sync.Mutex
	regions map[Region]observability.OCIFleetView
	// gauges are the published gauge series, so a state that emptied is
	// reported as zero instead of keeping its last count.
	gauges map[Region]map[string]bool
}{regions: map[Region]observability.OCIFleetView{}, gauges: map[Region]map[string]bool{}}

// publishInventory replaces a region's inventory with a complete sweep.
func publishInventory(region Region, tally *inventoryTally, now time.Time) {
	tally.mu.Lock()
	view := observability.OCIFleetView{Region: string(region), ObservedAt: now.UTC(),
		Instances: maps.Clone(tally.instances), Volumes: maps.Clone(tally.volumes),
		Attachments: maps.Clone(tally.attachments)}
	tally.mu.Unlock()
	fleetInventory.mu.Lock()
	defer fleetInventory.mu.Unlock()
	fleetInventory.regions[region] = view
	current := map[string]float64{}
	for kind, counts := range map[string]map[string]int{"instance": view.Instances, "volume": view.Volumes,
		"attachment": view.Attachments} {
		for state, count := range counts {
			current[observability.Series(observability.MetricPrefix+"oci_fleet_resources",
				"region", string(region), "kind", kind, "state", state)] = float64(count)
		}
	}
	published := fleetInventory.gauges[region]
	if published == nil {
		published = map[string]bool{}
		fleetInventory.gauges[region] = published
	}
	for name := range published {
		if _, still := current[name]; !still {
			current[name] = 0
		}
	}
	for name, value := range current {
		published[name] = true
		Metrics.GetOrCreateGauge(name, nil).Set(value)
	}
}

// FleetInventory lists the latest complete inventory of every region this
// process observes, by region.
func FleetInventory() []observability.OCIFleetView {
	fleetInventory.mu.Lock()
	defer fleetInventory.mu.Unlock()
	views := make([]observability.OCIFleetView, 0, len(fleetInventory.regions))
	for _, region := range slices.Sorted(maps.Keys(fleetInventory.regions)) {
		views = append(views, fleetInventory.regions[region])
	}
	return views
}
