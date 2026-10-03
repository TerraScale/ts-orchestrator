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
	Requests    map[string]Request
	MinInterval time.Duration
	StaleAfter  time.Duration
	Now         func() time.Time
}

// nodeRetention is how long a silent node's samples are kept: the longest
// window a valid scaling policy may configure.
const nodeRetention = time.Hour

// nodeState is one node's latest report and its own sample window. Each
// node keeps a separate autoscale.WindowStore, so every node's series is
// bounded by its own report rate (at most one sample per MinInterval) and
// a busy cell can never truncate a configured window.
type nodeState struct {
	latest NodeLoad
	store  *autoscale.WindowStore
}

// Aggregator turns accepted host reports into autoscale samples. It is an
// autoscale.Source: the workload reconciler reads a windowed aggregate per
// node and then combines nodes with equal weight, so a host that reports
// every 5s does not outweigh a replica that reports every minute. Samples
// are stamped with the controller's receive time, so a host clock can never
// place a sample in the future or keep it inside a window.
type Aggregator struct {
	config AggregatorConfig

	mu    sync.Mutex
	nodes map[string]*nodeState
	runs  map[seriesKey]run
}

type seriesKey struct {
	target autoscale.Target
	signal autoscale.SignalName
}

// run is one series' current unbroken run of samples: since starts it, last
// is its latest sample from any node. A gap longer than StaleAfter (for
// example while another member led) ends the run; the next sample starts a
// new one.
type run struct{ since, last time.Time }

// Reset forgets every report and sample, for example when the authority
// term changes: a new term must observe a fresh window before scaling.
func (a *Aggregator) Reset() {
	a.mu.Lock()
	clear(a.nodes)
	clear(a.runs)
	a.mu.Unlock()
}

func NewAggregator(config AggregatorConfig) *Aggregator {
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
	return &Aggregator{config: config, nodes: make(map[string]*nodeState), runs: make(map[seriesKey]run)}
}

// nodePoints bounds one node's series: one accepted sample per MinInterval
// over the retention, plus slack.
func (a *Aggregator) nodePoints() int {
	return int(min(nodeRetention/a.config.MinInterval+16, 4096))
}

// Read implements autoscale.Source. Each node's samples inside the window
// are reduced with the signal's aggregation first; the per-node values are
// then reduced with the same aggregation, so every reporting replica counts
// once whatever its report interval. Samples is the total sample count.
//
// Until this series' samples have arrived without a break for the whole
// signal window, and while its latest sample is older than StaleAfter, the
// reading has no samples, so the autoscaler holds with no-signal-data: a
// new leader, a first enablement, a newly reporting service or a cell whose
// hosts went silent never scales on a partial or stale window.
func (a *Aggregator) Read(ctx context.Context, target autoscale.Target, signal autoscale.Signal, now time.Time) (autoscale.Reading, error) {
	reading := autoscale.Reading{Signal: signal.Name}
	a.mu.Lock()
	// Warm once the run started within one minimum report interval of the
	// window's start, so a window is covered even if its first sample
	// landed a moment after the window opened.
	current, ok := a.runs[seriesKey{target: target, signal: signal.Name}]
	if !ok || now.Sub(current.last) > a.config.StaleAfter || now.Sub(current.since) < signal.Window()-a.config.MinInterval {
		a.mu.Unlock()
		return reading, nil
	}
	a.pruneLocked(a.config.Now(), nodeRetention)
	stores := make([]*autoscale.WindowStore, 0, len(a.nodes))
	for _, node := range a.nodes {
		stores = append(stores, node.store)
	}
	a.mu.Unlock()
	values := make([]float64, 0, len(stores))
	for _, store := range stores {
		node, err := store.Read(ctx, target, signal, now)
		if err != nil {
			return autoscale.Reading{}, err
		}
		if node.Samples > 0 {
			values = append(values, node.Value)
			reading.Samples += node.Samples
		}
	}
	reading.Value = autoscale.Aggregate(signal.AggregationOrDefault(), values)
	return reading, nil
}

// Record accepts one validated report. The caller must already have
// authenticated the host and filtered Roles to roles it currently runs.
func (a *Aggregator) Record(origin Origin, report Report) error {
	if err := report.Validate(); err != nil {
		return err
	}
	now := a.config.Now()
	a.mu.Lock()
	node, known := a.nodes[origin.Node]
	if known && now.Sub(node.latest.At) < a.config.MinInterval {
		a.mu.Unlock()
		return ErrTooFrequent
	}
	if !known {
		if len(a.nodes) >= maxNodes {
			// Full: forget every node that is no longer reporting, even if
			// a long window could still use its older samples.
			a.pruneLocked(now, a.config.StaleAfter)
		}
		if len(a.nodes) >= maxNodes {
			a.mu.Unlock()
			return ErrTooManyNodes
		}
		node = &nodeState{store: autoscale.NewWindowStore(nodeRetention, a.nodePoints())}
		a.nodes[origin.Node] = node
	}
	node.latest = NodeLoad{Origin: origin, At: now, Report: report}
	// Recording under the aggregator lock keeps one node's samples in
	// receive order and its store from being pruned mid-record.
	for _, role := range report.Roles {
		target := autoscale.Target{Cell: origin.Cell, Environment: origin.Environment, Role: role.Role}
		for name, value := range roleSignals(role, report.Host, a.config.Requests[role.Role]) {
			node.store.Record(target, name, autoscale.Sample{At: now, Value: value})
			key := seriesKey{target: target, signal: name}
			current := a.runs[key]
			if current.last.IsZero() || now.Sub(current.last) > a.config.StaleAfter {
				current.since = now
			}
			current.last = now
			a.runs[key] = current
		}
	}
	a.mu.Unlock()
	return nil
}

// StatelessSignal reports whether host telemetry produces the signal for a
// generic (non-TerraBase) role.
func StatelessSignal(name autoscale.SignalName) bool {
	switch name {
	case autoscale.SignalCPUUtilization, autoscale.SignalMemoryUtilization, autoscale.SignalDiskUtilization:
		return true
	default:
		return false
	}
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
	a.pruneLocked(now, nodeRetention)
	out := make([]NodeLoad, 0, len(a.nodes))
	for _, node := range a.nodes {
		if now.Sub(node.latest.At) <= a.config.StaleAfter {
			out = append(out, node.latest)
		}
	}
	a.mu.Unlock()
	slices.SortFunc(out, func(x, y NodeLoad) int { return strings.Compare(x.Origin.Node, y.Origin.Node) })
	return out
}

// pruneLocked forgets nodes silent for longer than retention; none of their
// samples can fall inside a window any more.
func (a *Aggregator) pruneLocked(now time.Time, retention time.Duration) {
	for name, node := range a.nodes {
		if now.Sub(node.latest.At) > retention {
			delete(a.nodes, name)
		}
	}
	for key, current := range a.runs {
		if now.Sub(current.last) > nodeRetention {
			delete(a.runs, key)
		}
	}
}
