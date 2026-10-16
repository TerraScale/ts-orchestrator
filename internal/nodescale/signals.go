package nodescale

import (
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/hostload"
)

type Signal string

const (
	SignalCPU      Signal = "cpu"
	SignalMemory   Signal = "memory"
	SignalDisk     Signal = "disk"
	SignalRequests Signal = "requests"
)

// Signals lists every signal in a fixed order.
var Signals = []Signal{SignalCPU, SignalMemory, SignalDisk, SignalRequests}

// Per-OCPU request capacity of a node. shortcut: conservative until TS-806
// measures TerraBase per-node capacity, replace both numbers then.
const (
	WriteQPSPerCore    = 500
	ConnectionsPerCore = 1000
)

// NodeLoad is one node's load: host fractions in [0,1] and TerraBase request totals.
type NodeLoad struct {
	Node              string
	At                time.Time
	CPU, Memory, Disk float64 // fractions
	Cores             int     // OCPUs; 0 counts as 1
	WriteQPS          float64
	Connections       uint64
}

// FromHostLoad converts one host load report. ok is false when CPU, memory or disk is missing.
// WriteQPS/Connections are summed over roles whose TerraBase load is present.
func FromHostLoad(load hostload.NodeLoad) (NodeLoad, bool) {
	host := load.Report.Host
	if host.CPU == nil || host.Memory == nil || host.Disk == nil {
		return NodeLoad{}, false
	}
	out := NodeLoad{
		Node:   load.Origin.Node,
		At:     load.At,
		CPU:    *host.CPU,
		Memory: *host.Memory,
		Disk:   *host.Disk,
		Cores:  host.CPUCores,
	}
	for _, role := range load.Report.Roles {
		if terrabase := role.TerraBase; terrabase != nil {
			out.WriteQPS += terrabase.WriteQPS
			out.Connections += terrabase.Connections
		}
	}
	return out, true
}

// Measure returns the region's sample at now: nodes is how many nodes the region has (from OCI),
// loads are the latest per-node loads. Loads older than SampleMaxAge are ignored. Reporting counts the fresh loads.
// Utilization: CPU/Memory/Disk = mean over fresh loads; Requests = max(sumWriteQPS/(sumCores*WriteQPSPerCore), sumConnections/(sumCores*ConnectionsPerCore)).
// With no fresh load, Utilization is nil.
func Measure(nodes int, loads []NodeLoad, now time.Time) Sample {
	sample := Sample{At: now, Nodes: nodes}
	var cpu, memory, disk, writeQPS float64
	var cores int
	var connections uint64
	for _, load := range loads {
		if now.Sub(load.At) > SampleMaxAge {
			continue
		}
		sample.Reporting++
		cpu += load.CPU
		memory += load.Memory
		disk += load.Disk
		cores += max(load.Cores, 1)
		writeQPS += load.WriteQPS
		connections += load.Connections
	}
	if sample.Reporting == 0 {
		return sample
	}
	n := float64(sample.Reporting)
	sample.Utilization = map[Signal]float64{
		SignalCPU:      cpu / n,
		SignalMemory:   memory / n,
		SignalDisk:     disk / n,
		SignalRequests: max(writeQPS/float64(cores*WriteQPSPerCore), float64(connections)/float64(cores*ConnectionsPerCore)),
	}
	return sample
}
