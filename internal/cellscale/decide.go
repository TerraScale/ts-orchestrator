package cellscale

import (
	"cmp"
	"math"
	"slices"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/autoscale"
)

// Kind is what an action does to the cell.
type Kind string

const (
	KindHold      Kind = "hold"
	KindScaleOut  Kind = "scale_out"
	KindScaleIn   Kind = "scale_in"
	KindResize    Kind = "resize"
	KindRebalance Kind = "rebalance"
)

// Reasons explain every action and every hold.
const (
	ReasonPaused        = "paused"
	ReasonRollout       = "rollout-in-flight"
	ReasonLag           = "replication-lag"
	ReasonNotSettled    = "cell-not-settled"
	ReasonBelowMin      = "below-min"
	ReasonAboveMax      = "above-max"
	ReasonConvergeShape = "converge-shape"
	ReasonHighPressure  = "high-pressure"
	ReasonLowPressure   = "low-pressure"
	ReasonHotspot       = "hotspot"
	ReasonAtCapacity    = "at-capacity"
	ReasonWithinBand    = "within-band"
	ReasonSustaining    = "sustaining"
	ReasonQuorum        = "quorum"
	ReasonAtMin         = "at-min"
	ReasonCooldown      = "cooldown"
	ReasonRateLimit     = "rate-limit"
	ReasonBudget        = "budget-cap"
	ReasonRecoverJoin   = "recover-join"
	ReasonRecoverDrain  = "recover-drain"
)

// Signals, in the order of Action.Pressure and the journal.
const (
	sigCPU = iota
	sigMemory
	sigDisk
	sigIOPS
	sigRequests
	sigQueue
	sigLatency
	signalCount
)

// The cell signals reuse the autoscale names where the host telemetry
// already reports the same measure.
const (
	SignalDiskIOPS     autoscale.SignalName = "disk_iops"
	SignalRequestRate  autoscale.SignalName = "request_rate"
	SignalIOQueueDepth autoscale.SignalName = "io_queue_depth"
	SignalP95Latency   autoscale.SignalName = "p95_latency_ms"
)

var signalNames = [signalCount]autoscale.SignalName{autoscale.SignalCPUUtilization, autoscale.SignalMemoryUtilization,
	autoscale.SignalDiskUtilization, SignalDiskIOPS, SignalRequestRate, SignalIOQueueDepth, SignalP95Latency}

// Node is one observed db node of a cell.
type Node struct {
	Name        string
	Ordinal     int
	ID          string
	Incarnation string
	Shape       Shape
	// Pressure is nil when the instance is not running or its pressure
	// could not be read.
	Pressure *NodePressure
}

func (n Node) ready() bool {
	return n.Pressure != nil && n.Pressure.Identity() == n.Identity() && n.Pressure.State == StateReady
}

func (n Node) Identity() NodeIdentity {
	return NodeIdentity{Name: n.Name, InstanceID: n.ID, Incarnation: n.Incarnation}
}

// State is one observation of a cell, its nodes ordered by ordinal.
type State struct {
	Cell  string
	Nodes []Node
	// Replicas is nil when the complete placement inventory is unavailable.
	Replicas *ReplicaSnapshot
	// Reserved are the ordinals of foreign instances: their names are taken
	// but the autoscaler neither counts nor manages them.
	Reserved        []int
	RolloutInFlight bool
	Now             time.Time
}

// Action is one decision. A hold carries only its reason and context.
type Action struct {
	Kind   Kind   `json:"kind"`
	Reason string `json:"reason"`
	// Node is the node added or removed, or a rebalance's source node.
	Node string `json:"node,omitempty"`
	From Shape  `json:"from,omitzero"`
	To   Shape  `json:"to,omitzero"`
	// Tenant and Target describe a rebalance of a ts-auth project to node
	// Target.
	Tenant string `json:"tenant,omitempty"`
	Target string `json:"target,omitempty"`
	// Pressure is the cell's mean pressure per signal.
	Pressure map[string]float64 `json:"pressure,omitempty"`
	// Held is the action a rail refused, on a hold.
	Held        *Action `json:"held,omitempty"`
	MonthlyCost float64 `json:"monthly_cost"`
	// Recovery finishes membership work on an already owned instance.
	Recovery bool `json:"recovery,omitempty"`
}

// up reports whether the action adds capacity or moves load, as opposed to
// removing capacity.
func (a Action) up() bool {
	return a.Kind == KindScaleOut || a.Kind == KindRebalance || a.Kind == KindResize && (a.To.OCPUs > a.From.OCPUs || a.To.MemoryGB > a.From.MemoryGB)
}

// key identifies what an action does, without why, so a sustained want
// survives a change of its dominant signal.
func (a Action) key() string {
	return string(a.Kind) + "|" + a.Node + "|" + a.To.String() + "|" + a.Tenant + "|" + a.Target
}

// Undo returns the action that reverses a. A scale-in cannot be undone: its
// node's data was drained away, so the cell scales out a fresh node instead.
func (a Action) Undo() (Action, bool) {
	switch a.Kind {
	case KindScaleOut:
		return Action{Kind: KindScaleIn, Node: a.Node, Reason: "undo"}, true
	case KindResize:
		return Action{Kind: KindResize, From: a.To, To: a.From, Reason: "undo"}, true
	case KindRebalance:
		return Action{Kind: KindRebalance, Node: a.Target, Target: a.Node, Tenant: a.Tenant, Reason: "undo"}, true
	default:
		return Action{}, false
	}
}

// History is the decision memory of one cell.
type History struct {
	// Want is the key of the action wanted on every evaluation since
	// WantSince; it must stay wanted for the sustain window to act.
	Want       string      `json:"want,omitempty"`
	WantSince  time.Time   `json:"want_since,omitzero"`
	LastAction time.Time   `json:"last_action,omitzero"`
	Actions    []time.Time `json:"actions,omitempty"`
	Failures   int         `json:"failures,omitzero"`
	Paused     bool        `json:"paused,omitempty"`
}

// Recorded returns the history after an applied action, pausing it after
// maxFailures consecutive failures.
func (h History) Recorded(now time.Time, ok bool, maxFailures int) History {
	h.Actions = append(recent(h.Actions, now), now)
	h.LastAction, h.Want, h.WantSince = now, "", time.Time{}
	if ok {
		h.Failures = 0
	} else if h.Failures++; h.Failures >= maxFailures {
		h.Paused = true
	}
	return h
}

func recent(times []time.Time, now time.Time) []time.Time {
	return slices.DeleteFunc(slices.Clone(times), func(at time.Time) bool { return now.Sub(at) >= time.Hour })
}

// Decide returns one action for the cell. It is pure and deterministic; the
// policy must be valid. Bounds and shape corrections skip the sustain window,
// load-driven actions need it, and every action passes the rails.
func Decide(policy Policy, state State, history History) (Action, History) {
	nodes := state.Nodes
	n := len(nodes)
	shape := cellShape(policy.Shape, nodes)
	current := 0.0
	for _, node := range nodes {
		current += policy.MonthlyCost(1, node.Shape)
	}
	hold := func(reason string, pressure map[string]float64) (Action, History) {
		history.Want, history.WantSince = "", time.Time{}
		return Action{Kind: KindHold, Reason: reason, Pressure: pressure, MonthlyCost: current}, history
	}
	if history.Paused {
		return hold(ReasonPaused, nil)
	}
	if state.RolloutInFlight {
		return hold(ReasonRollout, nil)
	}
	var recovery *Node
	for _, node := range nodes {
		if node.Pressure == nil || !node.Pressure.Fresh(state.Now) {
			return hold(ReasonNotSettled, nil)
		}
		if node.Pressure.Release != nodes[0].Pressure.Release {
			return hold(ReasonRollout, nil)
		}
		if !node.ready() {
			if recovery != nil {
				return hold(ReasonNotSettled, nil)
			}
			recovery = &node
		} else if node.Pressure.Load.ReplicationLagSeq > policy.MaxReplicationLagSeq {
			return hold(ReasonLag, nil)
		}
	}
	act := func(action Action) (Action, History) { return rails(policy, state, history, action, current) }
	// Owned nodes expose the unfinished membership step, including after a
	// restart. Finish one before deciding on fresh capacity or load changes.
	if recovery != nil {
		switch recovery.Pressure.State {
		case StateJoining:
			return act(Action{Kind: KindScaleOut, Node: recovery.Name, To: recovery.Shape, Reason: ReasonRecoverJoin, Recovery: true})
		case StateDraining, StateDrained:
			return act(Action{Kind: KindScaleIn, Node: recovery.Name, Reason: ReasonRecoverDrain, Recovery: true})
		default:
			return hold(ReasonNotSettled, nil)
		}
	}
	switch {
	case n < policy.Nodes.Min:
		minimum := policy.Shape.at(policy.Shape.MinOCPUs)
		missing := policy.Nodes.Min - n
		reserve := policy.MonthlyCost(missing, minimum)
		if current+reserve > policy.MonthlyBudget && policy.canRestart(n) {
			// Repair an already stranded cell at the largest ladder shape
			// that leaves room for every missing minimum-sized node.
			smaller := minimum
			floor := policy.MonthlyCost(n, minimum)
			stepCost := policy.MonthlyCost(n, policy.Shape.at(minimum.OCPUs+policy.Shape.StepOCPUs)) - floor
			if stepCost > 0 {
				steps := math.Max(0, math.Floor((policy.MonthlyBudget-reserve-floor)/stepCost))
				smaller = policy.Shape.at(math.Min(shape.OCPUs, minimum.OCPUs+steps*policy.Shape.StepOCPUs))
				if policy.MonthlyCost(n, smaller)+reserve > policy.MonthlyBudget {
					smaller = policy.Shape.at(math.Max(minimum.OCPUs, smaller.OCPUs-policy.Shape.StepOCPUs))
				}
			}
			if resizeFits(policy, nodes, smaller) && slices.ContainsFunc(nodes, func(node Node) bool { return !sameShape(node.Shape, smaller) }) {
				return act(Action{Kind: KindResize, From: shape, To: smaller, Reason: ReasonBelowMin})
			}
		}
		if current+reserve > policy.MonthlyBudget {
			return hold(ReasonBudget, nil)
		}
		if current+policy.MonthlyCost(1, shape)+policy.MonthlyCost(missing-1, minimum) > policy.MonthlyBudget {
			shape = minimum
		}
		return act(Action{Kind: KindScaleOut, Node: nextNode(state), To: shape, Reason: ReasonBelowMin})
	case n > policy.Nodes.Max:
		return act(Action{Kind: KindScaleIn, Node: nodes[n-1].Name, Reason: ReasonAboveMax})
	}
	// Budget-limited recovery may leave mixed shapes. Continue load decisions
	// when making every node match the largest shape would exceed the budget.
	canConverge := policy.MonthlyCost(n, shape) <= math.Max(current, policy.MonthlyBudget)
	for _, node := range nodes {
		if canConverge && !sameShape(node.Shape, shape) {
			return act(Action{Kind: KindResize, From: node.Shape, To: shape, Reason: ReasonConvergeShape})
		}
	}

	mean, hottest := cellPressure(policy.Targets, nodes)
	pressure := make(map[string]float64, signalCount)
	for index, value := range mean {
		pressure[string(signalNames[index])] = math.Round(value*1000) / 1000
	}
	want, reason := wanted(policy, state, mean, hottest, shape)
	if want.Kind == KindHold {
		return hold(reason, pressure)
	}
	want.Reason, want.Pressure = reason, pressure
	if key := want.key(); history.Want != key {
		history.Want, history.WantSince = key, state.Now
	}
	sustain := policy.sustainDown()
	if want.up() {
		sustain = policy.sustainUp()
	}
	if state.Now.Sub(history.WantSince) < sustain {
		return Action{Kind: KindHold, Reason: ReasonSustaining, Pressure: pressure, MonthlyCost: current}, history
	}
	return act(want)
}

// wanted picks the lever for the cell's pressure. CPU and memory pressure
// resize first, since a bigger shape relieves every node at once while new
// nodes only help once tenants move to them; everything else, and CPU or
// memory at the largest shape, adds nodes. Storage pressure never resizes.
func wanted(policy Policy, state State, mean [signalCount]float64, hottest float64, shape Shape) (Action, string) {
	nodes := state.Nodes
	n := len(nodes)
	top := 0
	for index := range mean {
		if mean[index] > mean[top] {
			top = index
		}
	}
	bounds := policy.Shape
	canResize := policy.canRestart(n) && !slices.ContainsFunc(nodes, func(node Node) bool {
		return replicasSafe(policy, state, node.Name, policy.quorum()) != nil
	})
	if mean[top] >= 1 {
		resize := Action{Kind: KindResize, From: shape, To: bounds.at(math.Min(shape.OCPUs+bounds.StepOCPUs, bounds.MaxOCPUs))}
		grow := shape.OCPUs < bounds.MaxOCPUs && !sameShape(shape, resize.To) && canResize && resizeHelps(top)
		reason := ReasonHighPressure + ":" + string(signalNames[top])
		switch {
		case (top == sigCPU || top == sigMemory) && grow:
			return resize, reason
		case n < policy.Nodes.Max:
			return Action{Kind: KindScaleOut, Node: nextNode(state), To: shape}, reason
		case grow:
			return resize, reason
		default:
			return Action{Kind: KindHold}, ReasonAtCapacity
		}
	}
	if hottest >= 1 {
		return relieve(policy, state, shape, canResize)
	}
	if n > max(policy.Nodes.Min, policy.ReplicationFactor) && scaleInFits(policy, nodes) {
		return Action{Kind: KindScaleIn, Node: nodes[n-1].Name}, ReasonLowPressure
	}
	if shape.OCPUs > bounds.MinOCPUs && canResize {
		smaller := bounds.at(math.Max(shape.OCPUs-bounds.StepOCPUs, bounds.MinOCPUs))
		if !sameShape(shape, smaller) && resizeFits(policy, nodes, smaller) {
			return Action{Kind: KindResize, From: shape, To: smaller}, ReasonLowPressure
		}
	}
	return Action{Kind: KindHold}, ReasonWithinBand
}

// relieve answers a hot node in a cell that is not hot on average, such as
// one noisy tenant or a node that has just joined empty. It moves a tenant of
// the hot node to the coolest other node that fits it, busiest first. When
// none fits it adds an empty node for one that would fit
// there, and when no node, new or existing, could take one it grows the
// shape, unless the node is hot on storage, which a shape cannot relieve.
func relieve(policy Policy, state State, shape Shape, canResize bool) (Action, string) {
	targets, nodes := policy.Targets, state.Nodes
	byPeak := func(a, b Node) int { return cmp.Compare(peak(*a.Pressure, targets), peak(*b.Pressure, targets)) }
	hot := slices.MaxFunc(nodes, byPeak)
	destinations := slices.Clone(nodes)
	slices.SortStableFunc(destinations, byPeak)
	tenants := slices.Clone(hot.Pressure.TopTenants)
	slices.SortStableFunc(tenants, func(a, b TenantLoad) int { return cmp.Compare(b.RequestRate, a.RequestRate) })
	fitsEmpty := false
	for _, tenant := range tenants {
		if !tenantRelievesHotspot(targets, *hot.Pressure, tenant) {
			continue
		}
		cpu := tenant.CPUShare * hot.Pressure.CPUUtil * hot.Shape.OCPUs / shape.OCPUs
		for _, cool := range destinations {
			if moveFits(targets, hot, cool, tenant) {
				return Action{Kind: KindRebalance, Node: hot.Name, Target: cool.Name, Tenant: tenant.Project}, ReasonHotspot
			}
		}
		fitsEmpty = fitsEmpty || fits(targets, cpu, tenant.RequestRate)
	}
	r := ratios(*hot.Pressure, targets)
	bounds := policy.Shape
	larger := bounds.at(math.Min(shape.OCPUs+bounds.StepOCPUs, bounds.MaxOCPUs))
	switch {
	case fitsEmpty && len(nodes) < policy.Nodes.Max:
		return Action{Kind: KindScaleOut, Node: nextNode(state), To: shape}, ReasonHotspot
	case shape.OCPUs < bounds.MaxOCPUs && !sameShape(shape, larger) && canResize && resizeHelps(slices.Index(r[:], slices.Max(r[:]))):
		return Action{Kind: KindResize, From: shape, To: larger}, ReasonHotspot
	default:
		return Action{Kind: KindHold}, ReasonAtCapacity
	}
}

// resizeHelps reports whether a bigger shape relieves a signal. Disk space,
// IOPS and I/O queue depth belong to the node's volume, not its shape.
func resizeHelps(signal int) bool {
	return signal != sigDisk && signal != sigIOPS && signal != sigQueue
}

// fits reports whether a node would stay below full CPU and request
// pressure, the two loads the contract attributes to tenants.
func fits(targets Targets, cpuUtil, requestRate float64) bool {
	return cpuUtil/targets.CPUUtil < 1 && requestRate/targets.RequestRate < 1
}

// scaleInFits is shared by the load decision and the last pre-drain check.
func scaleInFits(policy Policy, nodes []Node) bool {
	if len(nodes) < 2 {
		return false
	}
	var total [signalCount]float64
	for _, node := range nodes {
		if !node.ready() || !sameShape(node.Shape, nodes[0].Shape) {
			return false
		}
		readings := ratios(*node.Pressure, policy.Targets)
		if slices.Max(readings[:]) >= 1 {
			return false
		}
		for signal, value := range readings {
			total[signal] += value
		}
	}
	for _, value := range total {
		if value/float64(len(nodes)-1) > policy.ScaleDownBelow {
			return false
		}
	}
	return true
}

func moveFits(targets Targets, from, to Node, tenant TenantLoad) bool {
	if !from.ready() || !to.ready() || from.Name == to.Name || to.Shape.OCPUs <= 0 || !tenantRelievesHotspot(targets, *from.Pressure, tenant) {
		return false
	}
	cpu := tenant.CPUShare * from.Pressure.CPUUtil * from.Shape.OCPUs / to.Shape.OCPUs
	return fits(targets, to.Pressure.CPUUtil+cpu, to.Pressure.RequestRate+tenant.RequestRate)
}

// Tenant demand is attributed only to CPU and requests; destination fit alone
// cannot establish that moving a tenant relieves a hot resource.
func tenantRelievesHotspot(targets Targets, pressure NodePressure, tenant TenantLoad) bool {
	return pressure.CPUUtil >= targets.CPUUtil && tenant.CPUShare > 0 ||
		pressure.RequestRate >= targets.RequestRate && tenant.RequestRate > 0
}

// rails refuses an action that would break quorum, a cooldown, the hourly
// action limit or the monthly budget. A refused action keeps the history's
// want, so it acts as soon as the rail clears.
func rails(policy Policy, state State, history History, action Action, current float64) (Action, History) {
	n := len(state.Nodes)
	held := func(reason string) (Action, History) {
		refused := action
		return Action{Kind: KindHold, Reason: reason, Pressure: action.Pressure, Held: &refused, MonthlyCost: current}, history
	}
	after := current
	switch action.Kind {
	case KindScaleIn:
		if n-1 < policy.ReplicationFactor {
			return held(ReasonQuorum)
		}
		if n-1 < policy.Nodes.Min {
			return held(ReasonAtMin)
		}
		err := drainSafe(policy, state, action.Node)
		if action.Recovery {
			for _, node := range state.Nodes {
				if node.Name == action.Node && node.Pressure != nil {
					switch node.Pressure.State {
					case StateDraining:
						err = validReplicaInventory(state)
					case StateDrained:
						err = removalSafe(policy, state, action.Node)
					}
				}
			}
		}
		if err != nil {
			return held(ReasonQuorum)
		}
		for _, node := range state.Nodes {
			if node.Name == action.Node {
				after -= policy.MonthlyCost(1, node.Shape)
			}
		}
	case KindResize:
		// A rolling restart takes one node down at a time.
		if !policy.canRestart(n) {
			return held(ReasonQuorum)
		}
		if !resizeFits(policy, state.Nodes, action.To) {
			return held(ReasonWithinBand)
		}
		for _, node := range state.Nodes {
			if !sameShape(node.Shape, action.To) && replicasSafe(policy, state, node.Name, policy.quorum()) != nil {
				return held(ReasonQuorum)
			}
		}
		after = policy.MonthlyCost(n, action.To)
	case KindScaleOut:
		if action.Node == "" {
			return held(ReasonAtCapacity)
		}
		if !action.Recovery {
			after += policy.MonthlyCost(1, action.To)
		}
	}
	cooldown := policy.downCooldown()
	if action.up() {
		cooldown = policy.cooldown()
	}
	if !history.LastAction.IsZero() && state.Now.Sub(history.LastAction) < cooldown {
		return held(ReasonCooldown)
	}
	if len(recent(history.Actions, state.Now)) >= policy.MaxActionsPerHour {
		return held(ReasonRateLimit)
	}
	if after > current && after > policy.MonthlyBudget {
		return held(ReasonBudget)
	}
	action.MonthlyCost = after
	return action, history
}

// resizeFits checks each node's projected pressure for every resource that
// would shrink. A low cell mean cannot stand in for the busiest node.
func resizeFits(policy Policy, nodes []Node, to Shape) bool {
	return !slices.ContainsFunc(nodes, func(node Node) bool {
		p := node.Pressure
		return p == nil ||
			to.OCPUs < node.Shape.OCPUs && p.CPUUtil/policy.Targets.CPUUtil*node.Shape.OCPUs/to.OCPUs > policy.ScaleDownBelow ||
			to.MemoryGB < node.Shape.MemoryGB && p.MemoryUtil/policy.Targets.MemoryUtil*node.Shape.MemoryGB/to.MemoryGB > policy.ScaleDownBelow
	})
}

// cellShape is the cell's target shape: the largest node shape on the
// policy's ladder, or the smallest ladder shape for an empty cell.
func cellShape(bounds ShapeBounds, nodes []Node) Shape {
	ocpus := bounds.MinOCPUs
	for _, node := range nodes {
		ocpus = math.Max(ocpus, node.Shape.OCPUs)
	}
	return bounds.at(math.Min(ocpus, bounds.MaxOCPUs))
}

// sameShape compares shapes as OCI reports them, in float32.
func sameShape(a, b Shape) bool {
	return math.Abs(a.OCPUs-b.OCPUs) < 1e-3 && math.Abs(a.MemoryGB-b.MemoryGB) < 1e-3
}

// nextNode is the lowest static node name of the cell that neither a node
// nor a foreign instance holds, or empty when all supported names are taken.
func nextNode(state State) string {
	for n := 1; n <= maxOrdinal; n++ {
		if !slices.ContainsFunc(state.Nodes, func(node Node) bool { return node.Ordinal == n }) && !slices.Contains(state.Reserved, n) {
			return NodeName(state.Cell, n)
		}
	}
	return ""
}

// ratios is a node's pressure per signal.
func ratios(p NodePressure, t Targets) [signalCount]float64 {
	return [signalCount]float64{p.CPUUtil / t.CPUUtil, p.MemoryUtil / t.MemoryUtil, p.DiskUtil() / t.DiskUtil,
		p.DiskIOPS / t.DiskIOPS, p.RequestRate / t.RequestRate, p.IOQueueDepth / t.IOQueueDepth, p.P95LatencyMS / t.P95LatencyMS}
}

// peak is a node's largest pressure of any signal.
func peak(p NodePressure, t Targets) float64 {
	r := ratios(p, t)
	return slices.Max(r[:])
}

// cellPressure is the mean pressure per signal over the nodes and the
// largest single-node pressure of any signal.
func cellPressure(targets Targets, nodes []Node) (mean [signalCount]float64, hottest float64) {
	values := make([][]float64, signalCount)
	for _, node := range nodes {
		for index, value := range ratios(*node.Pressure, targets) {
			values[index] = append(values[index], value)
		}
		hottest = math.Max(hottest, peak(*node.Pressure, targets))
	}
	for index := range mean {
		mean[index] = autoscale.Aggregate(autoscale.AggregateAverage, values[index])
	}
	return mean, hottest
}
