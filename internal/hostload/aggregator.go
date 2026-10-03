package hostload

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/autoscale"
)

const (
	// DefaultMinInterval is the shortest spacing of two accepted reports of
	// one node. Every accepted report is one sample per role, so without it
	// a single chatty host could dominate a windowed average.
	DefaultMinInterval = 5 * time.Second
	// DefaultStaleAfter is how long a node's latest report stays listed.
	DefaultStaleAfter = 5 * time.Minute
	maxNodes          = 4096
)

var (
	ErrTooFrequent  = errors.New("host load report arrived before the minimum interval")
	ErrTooManyNodes = errors.New("host load aggregator is tracking its maximum number of nodes")
)

// Request is a role's signed per-replica resource request. Utilization
// signals are usage divided by it, like a Kubernetes HPA's resource target.
type Request struct {
	CPUCores    float64
	MemoryBytes int64
}

// Origin is the authenticated registration a report arrived under. The
// controller fills it from its own registration state, never from the
// report.
type Origin struct {
	Cell        string
	Environment string
	Node        string
}

// NodeLoad is a node's latest accepted report.
type NodeLoad struct {
	Origin Origin    `json:"origin"`
	At     time.Time `json:"at"`
	Report Report    `json:"report"`
}

type AggregatorConfig struct {
	// Store receives the samples; nil creates one with default bounds.
	Store       *autoscale.WindowStore
	Requests    map[string]Request
	MinInterval time.Duration
	StaleAfter  time.Duration
	Now         func() time.Time
}

// Aggregator turns accepted host reports into autoscale samples. It is an
// autoscale.Source: the workload reconciler reads windowed aggregates of the
// per-replica samples it recorded. Samples are stamped with the
// controller's receive time, so a host clock can never place a sample in
// the future or keep it inside a window.
type Aggregator struct {
	config AggregatorConfig

	mu    sync.Mutex
	nodes map[string]NodeLoad
}

func NewAggregator(config AggregatorConfig) *Aggregator {
	if config.Store == nil {
		config.Store = autoscale.NewWindowStore(0, 0)
	}
	if config.MinInterval <= 0 {
		config.MinInterval = DefaultMinInterval
	}
	if config.StaleAfter <= 0 {
		config.StaleAfter = DefaultStaleAfter
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	config.Requests = maps.Clone(config.Requests)
	return &Aggregator{config: config, nodes: make(map[string]NodeLoad)}
}

// Read implements autoscale.Source.
func (a *Aggregator) Read(ctx context.Context, target autoscale.Target, signal autoscale.Signal, now time.Time) (autoscale.Reading, error) {
	return a.config.Store.Read(ctx, target, signal, now)
}

// Record accepts one validated report. The caller must already have
// authenticated the host and filtered Roles to roles it currently runs.
func (a *Aggregator) Record(origin Origin, report Report) error {
	if err := report.Validate(); err != nil {
		return err
	}
	now := a.config.Now()
	a.mu.Lock()
	previous, known := a.nodes[origin.Node]
	if known && now.Sub(previous.At) < a.config.MinInterval {
		a.mu.Unlock()
		return ErrTooFrequent
	}
	if !known && len(a.nodes) >= maxNodes {
		a.pruneLocked(now)
		if len(a.nodes) >= maxNodes {
			a.mu.Unlock()
			return ErrTooManyNodes
		}
	}
	a.nodes[origin.Node] = NodeLoad{Origin: origin, At: now, Report: report}
	a.mu.Unlock()
	for _, role := range report.Roles {
		target := autoscale.Target{Cell: origin.Cell, Environment: origin.Environment, Role: role.Role}
		for name, value := range roleSignals(role, report.Host, a.config.Requests[role.Role]) {
			a.config.Store.Record(target, name, autoscale.Sample{At: now, Value: value})
		}
	}
	return nil
}

// roleSignals maps one role's usage onto the autoscale signal vocabulary.
// A signal whose input or request is missing is not recorded at all, so
// the autoscaler sees it as unavailable rather than as zero load.
func roleSignals(role RoleUsage, host HostUsage, request Request) map[autoscale.SignalName]float64 {
	signals := make(map[autoscale.SignalName]float64, 7)
	if role.CPUCores != nil && request.CPUCores > 0 {
		signals[autoscale.SignalCPUUtilization] = *role.CPUCores / request.CPUCores
	}
	if role.MemoryBytes != nil && request.MemoryBytes > 0 {
		signals[autoscale.SignalMemoryUtilization] = float64(*role.MemoryBytes) / float64(request.MemoryBytes)
	}
	if host.Disk != nil && (role.CPUCores != nil || role.MemoryBytes != nil) {
		// Disk is shared by every role of the host; it is attributed to the
		// roles that actually run there.
		signals[autoscale.SignalDiskUtilization] = *host.Disk
	}
	if load := role.TerraBase; load != nil {
		signals[autoscale.SignalTerraBaseConnectionsPerMember] = float64(load.Connections)
		signals[autoscale.SignalTerraBaseStorageBytes] = float64(load.StorageBytes)
		signals[autoscale.SignalTerraBaseReplicationLag] = float64(load.ReplicationLagSeq)
		signals[autoscale.SignalTerraBaseWriteQPS] = load.WriteQPS
	}
	return signals
}

// Nodes lists every node's latest report that is not stale, by node name.
func (a *Aggregator) Nodes() []NodeLoad {
	now := a.config.Now()
	a.mu.Lock()
	a.pruneLocked(now)
	out := slices.Collect(maps.Values(a.nodes))
	a.mu.Unlock()
	slices.SortFunc(out, func(x, y NodeLoad) int { return strings.Compare(x.Origin.Node, y.Origin.Node) })
	return out
}

func (a *Aggregator) pruneLocked(now time.Time) {
	for node, load := range a.nodes {
		if now.Sub(load.At) > a.config.StaleAfter {
			delete(a.nodes, node)
		}
	}
}
