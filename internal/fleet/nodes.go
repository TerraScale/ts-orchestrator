package fleet

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/oracle/oci-go-sdk/v65/core"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/compute"
)

const (
	NodeLeaderSettle = 5 * time.Minute
	NodeUpWindow     = 3 * time.Minute
	NodeDownWindow   = 15 * time.Minute
	NodeCooldown     = 10 * time.Minute
	NodeDrainTimeout = 10 * time.Minute
)

type SwarmNode struct {
	ID, Hostname, InstanceID string
	Manager, ManagerReady    bool
	Leader, Ready, Active    bool
	DrainSince               time.Time
	Tasks                    int
	LastCopy                 string
	Relocatable              bool
}

type Demand struct {
	Known   bool
	Blocked []string
	Growing []string
}

type SwarmView struct {
	Term    uint64
	Nodes   []SwarmNode
	Pending int
	Demand  Demand
}

type Cluster interface {
	SwarmView(ctx context.Context) (SwarmView, error)
	Cordon(ctx context.Context, nodeID string, since time.Time) error
	Remove(ctx context.Context, hostname string, guard func(context.Context) error) error
}

type NodeDecision struct {
	At       time.Time      `json:"at"`
	Action   string         `json:"action"`
	Actual   int            `json:"actual"`
	Desired  int            `json:"desired"`
	Min      int            `json:"min"`
	Max      int            `json:"max"`
	Code     string         `json:"code"`
	Reason   string         `json:"reason"`
	Node     string         `json:"node,omitempty"`
	Refused  bool           `json:"refused,omitempty"`
	Stuck    bool           `json:"stuck,omitempty"`
	Refusals map[string]int `json:"refusals,omitempty"`

	nodeID, instanceID string
	size               int
}

func (d NodeDecision) line(pool string) string {
	switch d.Action {
	case "grow":
		return fmt.Sprintf("grow      instance pool %s %d -> %d nodes: %s", pool, d.size-1, d.size, d.Code)
	case "cordon":
		return fmt.Sprintf("cordon    node %s (%s) to remove it: %s", d.Node, d.instanceID, d.Code)
	default:
		return fmt.Sprintf("remove    node %s (%s): detach it from the pool, terminate it keeping its data volume, remove it from the swarm", d.Node, d.instanceID)
	}
}

func (d NodeDecision) String() string {
	text := fmt.Sprintf("%s %d", d.Action, d.Actual)
	if d.Desired != d.Actual {
		text += fmt.Sprintf(" -> %d", d.Desired)
	}
	text += fmt.Sprintf(" (bounds %d..%d): %s", d.Min, d.Max, d.Reason)
	if d.Refused {
		text += "; refused: " + d.Code
	}
	return text
}

type NodeScaler struct {
	mu           sync.Mutex
	term         uint64
	since        time.Time
	lastChange   time.Time
	blockedSince time.Time
	quietSince   time.Time
	last         NodeDecision
	refusals     map[string]int
}

var nodeScalers sync.Map

func scalerFor(label string) *NodeScaler {
	value, _ := nodeScalers.LoadOrStore(label, &NodeScaler{})
	return value.(*NodeScaler)
}

func LastNodeDecision(label string) (NodeDecision, bool) {
	value, ok := nodeScalers.Load(label)
	if !ok {
		return NodeDecision{}, false
	}
	s := value.(*NodeScaler)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last, !s.last.At.IsZero()
}

func applyNodes(ctx context.Context, _ Fleet, region Region, f *ociclient.Factory, cluster Cluster, out ociresource.Out) error {
	if cluster == nil {
		return errors.New("the nodes kind runs only on the region's Raft leader inside ts-orch node")
	}
	var err error
	pass := compute.Pass{Ownership: ociresource.Ownership{Owner: Owner}, Out: out,
		Nodes: compute.Nodes{Label: region.Label, Compartment: region.CompartmentID, Key: region.Key}}
	if pass.Compute, err = f.Compute(); err != nil {
		return err
	}
	if pass.Management, err = f.ComputeManagement(); err != nil {
		return err
	}
	view, err := cluster.SwarmView(ctx)
	if err != nil {
		return err
	}
	pool, pooled, err := pass.Pool(ctx)
	if err != nil {
		return err
	}
	s := scalerFor(region.Label)
	now := time.Now()
	s.mu.Lock()
	decision := s.Decide(now, region.Nodes, view, pool, pooled)
	if !out.Apply {
		s.record(region.Label, decision)
	}
	s.mu.Unlock()
	if decision.Action == "hold" {
		return nil
	}
	if _, err := fmt.Fprintln(out.Changed, decision.line(deref(pool.Id))); err != nil || !out.Apply {
		return err
	}
	if err := ociclient.Authorize(ctx); err != nil {
		return err
	}
	switch decision.Action {
	case "grow":
		err = pass.Resize(ctx, pool, decision.size)
	case "cordon":
		err = cluster.Cordon(ctx, decision.nodeID, now)
	case "remove":
		if err = pass.Retire(ctx, pool, decision.instanceID); err == nil {
			err = cluster.Remove(ctx, decision.Node, ociclient.Authorize)
		}
	}
	if err != nil {
		return fmt.Errorf("%s node %s: %w", decision.Action, cmp.Or(decision.Node, region.Label), err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blockedSince, s.quietSince = time.Time{}, time.Time{}
	if decision.Action != "cordon" {
		s.lastChange = time.Now()
	}
	slog.InfoContext(ctx, "node scaler acted", "region", region.Label, "action", decision.Action, "node", decision.Node,
		"actual", decision.Actual, "desired", decision.Desired, "reason", decision.Reason)
	return nil
}

func (s *NodeScaler) record(label string, d NodeDecision) {
	log := slog.With("region", label, "action", d.Action, "actual", d.Actual, "desired", d.Desired, "min", d.Min, "max", d.Max,
		"code", d.Code, "reason", d.Reason, "node", d.Node)
	if d.Refused {
		if s.refusals == nil {
			s.refusals = map[string]int{}
		}
		s.refusals[d.Code]++
	}
	switch {
	case d.Action == s.last.Action && d.Code == s.last.Code && d.Actual == s.last.Actual && d.Desired == s.last.Desired:
	case d.Refused:
		log.Warn("node scaler refused a change")
	default:
		log.Info("node scaler decision")
	}
	d.Refusals = maps.Clone(s.refusals)
	s.last = d
}

func since(start time.Time, holds bool, now time.Time) time.Time {
	switch {
	case !holds:
		return time.Time{}
	case start.IsZero():
		return now
	}
	return start
}

func (s *NodeScaler) Decide(now time.Time, bounds Nodes, view SwarmView, pool compute.Pool, pooled bool) NodeDecision {
	if view.Term != s.term {
		s.term, s.since, s.lastChange = view.Term, now, now
		s.blockedSince, s.quietSince = time.Time{}, time.Time{}
	}
	actual := len(view.Nodes)
	d := NodeDecision{At: now, Action: "hold", Actual: actual, Desired: actual, Min: bounds.Min, Max: bounds.Max}
	hold := func(code, reason string, args ...any) NodeDecision {
		d.Code, d.Reason = code, fmt.Sprintf(reason, args...)
		return d
	}
	refuse := func(code, reason string, args ...any) NodeDecision {
		d.Refused = true
		return hold(code, reason, args...)
	}
	members := map[string]bool{}
	for _, member := range pool.Members {
		members[deref(member.Id)] = true
	}
	joined, managers := 0, 0
	var draining *SwarmNode
	var unhealthy []string
	for i, node := range view.Nodes {
		if node.ManagerReady {
			managers++
		}
		switch {
		case !node.DrainSince.IsZero():
			draining = &view.Nodes[i]
		case !node.Ready || !node.Active:
			unhealthy = append(unhealthy, cmp.Or(node.Hostname, node.ID))
		case members[node.InstanceID]:
			joined++
		}
	}
	health := func() (NodeDecision, bool) {
		switch {
		case now.Sub(s.since) < NodeLeaderSettle:
			return refuse("unhealthy", "this leader took over at %s and waits %s before a node change", s.since.UTC().Format(time.RFC3339), NodeLeaderSettle), false
		case len(unhealthy) > 0:
			return refuse("unhealthy", "%s not ready or not active", strings.Join(unhealthy, ", ")), false
		case managers < MinNodes:
			return refuse("quorum", "%d of the %d managers are ready", managers, MinNodes), false
		}
		return d, true
	}
	if node := draining; node != nil {
		d.Desired, d.Node, d.nodeID, d.instanceID = actual-1, cmp.Or(node.Hostname, node.ID), node.ID, node.InstanceID
		switch {
		case node.Tasks > 0 || view.Pending > 0:
			if now.Sub(node.DrainSince) > NodeDrainTimeout {
				d.Stuck = true
				return refuse("drain-stuck", "%s still runs %d tasks and %d tasks wait for a node %s after its drain began; it stays cordoned", d.Node, node.Tasks, view.Pending, NodeDrainTimeout)
			}
			return refuse("in-flight", "draining %s: %d tasks left on it, %d tasks not yet running elsewhere", d.Node, node.Tasks, view.Pending)
		case node.Manager:
			return refuse("quorum", "%s became a manager while drained; it is never removed", d.Node)
		}
		if refused, ok := health(); !ok {
			return refused
		}
		d.Action = "remove"
		return hold("drained", "%s is drained and its tasks run elsewhere", d.Node)
	}
	if pooled && deref(pool.Size) > joined {
		d.Desired = actual + deref(pool.Size) - joined
		return refuse("in-flight", "waiting for %d of %d pool nodes to join and be ready", deref(pool.Size)-joined, deref(pool.Size))
	}
	if refused, ok := health(); !ok {
		return refused
	}
	if actual == bounds.Min && actual == bounds.Max {
		return hold("at-bounds", "nodes.min = nodes.max = %d", actual)
	}
	if !view.Demand.Known {
		return hold("no-demand", "the replica autoscaler has no result on this leader yet")
	}
	blocked := len(view.Demand.Blocked) > 0
	quiet := !blocked && len(view.Demand.Growing) == 0 && view.Pending == 0
	s.blockedSince, s.quietSince = since(s.blockedSince, blocked, now), since(s.quietSince, quiet, now)
	cooldown := s.lastChange.Add(NodeCooldown).Sub(now)
	switch {
	case actual < bounds.Min:
		return hold("below-min", "below nodes.min %d; the compute kind raises the pool", bounds.Min)
	case actual <= bounds.Max && blocked && now.Sub(s.blockedSince) >= NodeUpWindow:
		d.Desired = actual + 1
		switch {
		case actual == bounds.Max:
			return refuse("bounds", "%s cannot place more replicas, and %d nodes is nodes.max", strings.Join(view.Demand.Blocked, ", "), actual)
		case !pooled:
			return refuse("no-pool", "no document-made instance pool to grow; the compute kind makes it")
		case pool.LifecycleState != core.InstancePoolLifecycleStateRunning:
			return refuse("in-flight", "the instance pool is %s", pool.LifecycleState)
		case cooldown > 0:
			return hold("cooldown", "%s cannot place more replicas; the last change was less than %s ago", strings.Join(view.Demand.Blocked, ", "), NodeCooldown)
		}
		d.Action, d.size = "grow", deref(pool.Size)+1
		return hold("demand", "%s cannot place more replicas for %s", strings.Join(view.Demand.Blocked, ", "), NodeUpWindow)
	case actual <= bounds.Max && !(quiet && now.Sub(s.quietSince) >= NodeDownWindow):
		return hold("steady", "demand fits %d nodes", actual)
	}
	d.Desired = actual - 1
	code := "low-demand"
	if actual > bounds.Max {
		code = "above-max"
	}
	switch {
	case actual <= bounds.Min:
		d.Desired = actual
		return hold("at-min", "demand is low and %d nodes is nodes.min", actual)
	case cooldown > 0:
		return hold("cooldown", "the last change was less than %s ago", NodeCooldown)
	}
	var candidates []SwarmNode
	for _, node := range view.Nodes {
		if members[node.InstanceID] && !node.Leader {
			candidates = append(candidates, node)
		}
	}
	if len(candidates) == 0 {
		return refuse("no-pool-node", "no pool node to remove; hand-made hosts are never removed")
	}
	slices.SortFunc(candidates, func(a, b SwarmNode) int {
		return cmp.Or(cmp.Compare(a.Tasks, b.Tasks), strings.Compare(b.Hostname, a.Hostname))
	})
	var refusals []NodeDecision
	for _, node := range candidates {
		name := cmp.Or(node.Hostname, node.ID)
		switch {
		case node.Manager:
			refusals = append(refusals, refuseWith(d, "quorum", fmt.Sprintf("%s is a manager; removing it would leave fewer than %d", name, MinNodes)))
		case node.LastCopy != "":
			refusals = append(refusals, refuseWith(d, "last-copy", fmt.Sprintf("%s holds the last running copy of %s", name, node.LastCopy)))
		case !node.Relocatable:
			refusals = append(refusals, refuseWith(d, "no-room", fmt.Sprintf("the other nodes cannot take %s's tasks", name)))
		default:
			d.Action, d.Node, d.nodeID, d.instanceID = "cordon", name, node.ID, node.InstanceID
			return hold(code, "demand fits %d nodes; drain %s", actual-1, name)
		}
	}
	return refusals[0]
}

func refuseWith(d NodeDecision, code, reason string) NodeDecision {
	d.Code, d.Reason, d.Refused = code, reason, true
	return d
}

func WriteNodeMetrics(w io.Writer) {
	nodeScalers.Range(func(key, value any) bool {
		region := key.(string)
		d, ok := LastNodeDecision(region)
		if !ok {
			return true
		}
		series := func(name string, labels ...string) string {
			return observability.Series(name, append([]string{"region", region}, labels...)...)
		}
		observability.WriteGauge(w, series("ts_orch_node_scale_desired"), float64(d.Desired))
		observability.WriteGauge(w, series("ts_orch_node_scale_actual"), float64(d.Actual))
		observability.WriteGauge(w, series("ts_orch_node_scale_decision", "action", d.Action, "reason", d.Code), 1)
		observability.WriteGauge(w, series("ts_orch_node_scale_decision_timestamp_seconds"), float64(d.At.Unix()))
		observability.WriteGauge(w, series("ts_orch_node_scale_drain_stuck"), observability.Bool(d.Stuck))
		for _, code := range slices.Sorted(maps.Keys(d.Refusals)) {
			observability.WriteCounter(w, series("ts_orch_node_scale_refusals_total", "reason", code), float64(d.Refusals[code]))
		}
		return true
	})
}
