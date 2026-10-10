package globalview

import (
	"context"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostload"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/insights"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionview"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/workload"
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
	Links     func() []regionview.LinkProbe
	Autoscale func() map[string]workload.Result
	Events    func(limit int) []observability.Event
	Cost      func() *Cost      // TS-807
	Databases func() []Database // TS-806
	Errors    func() []Error    // TS-808; replaces Events when set
	Now       func() time.Time
}

// Inputs is one collection of the sources, the pure input of Build.
type Inputs struct {
	Cell string
	Now  time.Time
	// Cluster is the cell-wide controller snapshot; ClusterOK is false
	// when it could not be collected.
	Cluster   observability.ClusterSnapshot
	ClusterOK bool
	Grants    []regionview.Node
	Reports   []hostload.NodeLoad
	Volumes   []insights.Volume
	Links     []regionview.LinkProbe
	Autoscale map[string]workload.Result
	Events    []observability.Event
	Cost      *Cost
	Databases []Database
	Errors    []Error
}
