package globalview

import (
	"context"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/hostload"
	"github.com/TerraScale/ts-orchestrator/internal/insights"
	"github.com/TerraScale/ts-orchestrator/internal/nodescale"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/regionview"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/workload"
)

// Sources are the region's local providers a rollup is collected from. A
// nil source contributes nothing. The section functions of other tickets
// return their latest cached value without I/O; nil means not reported.
type Sources struct {
	Cell      string
	Cluster   observability.ClusterSource
	Grants    func(context.Context) []regionview.Node
	Reports   func() []hostload.NodeLoad
	Volumes   insights.VolumeProvider
	Services  func(context.Context) ([]swarmruntime.ServiceObservation, error)
	Links     func() []regionview.LinkProbe
	Autoscale func() map[string]workload.Result
	Events    func(limit int) []observability.Event
	Cost      func() *Cost             // TS-807
	Scale     func() *nodescale.Status // TS-804
	Databases func() []Database        // TS-806
	Errors    func() []Error           // TS-808; replaces Events when set
	Now       func() time.Time
}

// Inputs is one collection of the sources, the pure input of Build.
type Inputs struct {
	Cell string
	Now  time.Time
	// Cluster is the cell-wide controller snapshot; ClusterOK is false
	// when it could not be collected.
	Cluster            observability.ClusterSnapshot
	ClusterOK          bool
	Grants             []regionview.Node
	Reports            []hostload.NodeLoad
	Volumes            []insights.Volume
	Services           []swarmruntime.ServiceObservation
	ServicesObservedAt time.Time
	// VolumesUnavailable is true when the volume source failed, so an empty
	// list is not mistaken for a region without volumes.
	VolumesUnavailable bool
	Links              []regionview.LinkProbe
	Autoscale          map[string]workload.Result
	Events             []observability.Event
	Cost               *Cost
	Scale              *nodescale.Status
	Databases          []Database
	Errors             []Error
}
