// This file implements the autonomous autoscaler engine of the
// rootless-hosting and autoscaling lane: a pure decision function over
// validated cluster snapshots, carrying only explicit hysteresis state
// between ticks.
package autoscaling

import (
	"context"
	"fmt"
	"math"
	"math/big"
	"sort"

	"terrascale.tech/orchestrator/src/orchestrator/stateful"
)

// AutoscalerNodeClass is the node class carried by every node the autoscaler
// provisions; the greenfield estate of ADR 0024 is the provisioning target of
// this lane.
const AutoscalerNodeClass = "greenfield"

const (
	autoscalingMaximumNodesPerSnapshot  = 1024
	autoscalingMaximumDemandPerSnapshot = 4096

	// autoscalingInFlightTickTTL bounds how long a provision or cordon this
	// autoscaler remembers survives without being reflected by a snapshot:
	// once the bounded bridge expires, the snapshot is authoritative again.
	autoscalingInFlightTickTTL = 2
)

// AutoscalerSnapshot is one validated cluster observation of an autoscaler
// tick: the per-node observations plus the unsatisfied allocation demand.
type AutoscalerSnapshot struct {
	Nodes  []NodeObservation
	Demand []AllocationDemand
}

// NewAutoscalerSnapshot validates and snapshots one cluster observation.
// Nodes and demand are revalidated at this trust boundary, node identifiers
// and demand role identifiers must be unique, and both lists are stored in a
// canonical order (nodes by node id, demand by role id) so the same cluster
// yields byte-identical decisions regardless of input order.
func NewAutoscalerSnapshot(nodes []NodeObservation, demand []AllocationDemand) (AutoscalerSnapshot, error) {
	if len(nodes) > autoscalingMaximumNodesPerSnapshot {
		return AutoscalerSnapshot{}, &ArgumentError{
			Param: "nodes",
			Message: fmt.Sprintf("Node input exceeds the bound of %d entries.",
				autoscalingMaximumNodesPerSnapshot),
		}
	}
	if len(demand) > autoscalingMaximumDemandPerSnapshot {
		return AutoscalerSnapshot{}, &ArgumentError{
			Param: "demand",
			Message: fmt.Sprintf("Demand input exceeds the bound of %d entries.",
				autoscalingMaximumDemandPerSnapshot),
		}
	}
	nodeSnapshot := make([]NodeObservation, 0, len(nodes))
	seenNodes := make(map[string]struct{}, len(nodes))
	for _, node := range nodes {
		validated, err := NewNodeObservation(
			node.NodeId, node.NodeState, node.Capacity, node.Usage,
			node.PendingAllocations, node.StatefulReplicas)
		if err != nil {
			return AutoscalerSnapshot{}, err
		}
		if _, duplicate := seenNodes[validated.NodeId]; duplicate {
			return AutoscalerSnapshot{}, &ArgumentError{
				Param:   "nodes",
				Message: "A node may appear only once per snapshot.",
			}
		}
		seenNodes[validated.NodeId] = struct{}{}
		nodeSnapshot = append(nodeSnapshot, validated)
	}
	sort.Slice(nodeSnapshot, func(left, right int) bool {
		return nodeSnapshot[left].NodeId < nodeSnapshot[right].NodeId
	})
	demandSnapshot := make([]AllocationDemand, 0, len(demand))
	seenRoles := make(map[string]struct{}, len(demand))
	for _, entry := range demand {
		validated, err := NewAllocationDemand(entry.RoleId, entry.RoleKind, entry.Stateful, entry.Resources)
		if err != nil {
			return AutoscalerSnapshot{}, err
		}
		if _, duplicate := seenRoles[validated.RoleId]; duplicate {
			return AutoscalerSnapshot{}, &ArgumentError{
				Param:   "demand",
				Message: "A role may appear only once per snapshot.",
			}
		}
		seenRoles[validated.RoleId] = struct{}{}
		demandSnapshot = append(demandSnapshot, validated)
	}
	sort.Slice(demandSnapshot, func(left, right int) bool {
		return demandSnapshot[left].RoleId < demandSnapshot[right].RoleId
	})
	return AutoscalerSnapshot{Nodes: nodeSnapshot, Demand: demandSnapshot}, nil
}

// DrainSafetyEvaluator decides whether the stateful replicas of one node may
// be disturbed by a drain. The seam is declared here, consumer-side, because
// the stateful package landed the data contracts (NodeDrainCandidate and
// DrainDecision); any implementation in any package satisfies it structurally.
// Every drain decision is fail-closed: an error verdict blocks the drain.
type DrainSafetyEvaluator interface {
	// EvaluateDrainSafety returns the drain verdict for one candidate node.
	EvaluateDrainSafety(ctx context.Context, candidate stateful.NodeDrainCandidate) (stateful.DrainDecision, error)
}

// inFlightProvision is one provision action this autoscaler still remembers:
// the reserved capacity of the node and the tick the action was emitted on.
type inFlightProvision struct {
	resources NodeResources
	tick      int64
}

// Autoscaler is the autonomous node autoscaler engine: a deterministic
// decision function over validated cluster snapshots. Between ticks it carries
// only hysteresis state (confirmation counters, the remembered in-flight
// provisions and cordons a snapshot has not reflected yet, and the recently
// retired node ids of the flap suppression window); identical snapshots fed
// to identically constructed autoscalers produce byte-identical actions.
type Autoscaler struct {
	config              AutoscalerConfig
	drainSafety         DrainSafetyEvaluator
	tick                int64
	scaleUpBreachTicks  int
	scaleDownIdleTicks  int
	provisionSequence   int
	inFlightProvisions  map[string]inFlightProvision
	cordonedInFlight    map[string]int64
	recentlyRetiredNode map[string]int64
}

// NewAutoscaler composes the autoscaler from a validated scaling policy and
// the drain safety evaluator consulted before any node is cordoned. The
// evaluator is required, not optional: drain safety is a hard constraint of
// this lane, so there is no nil-evaluator mode.
func NewAutoscaler(config AutoscalerConfig, drainSafety DrainSafetyEvaluator) (*Autoscaler, error) {
	validated, err := NewAutoscalerConfig(
		config.MinNodes,
		config.MaxNodes,
		config.ScaleUpHeadroomPercent,
		config.ScaleDownHeadroomPercent,
		config.ScaleUpConfirmTicks,
		config.ScaleDownConfirmTicks,
		config.MaxConcurrentProvisions,
		config.FlapSuppressionTicks)
	if err != nil {
		return nil, err
	}
	if drainSafety == nil {
		return nil, &ArgumentError{
			Param:   "drainSafety",
			Message: "A drain safety evaluator is required.",
		}
	}
	return &Autoscaler{
		config:              validated,
		drainSafety:         drainSafety,
		inFlightProvisions:  make(map[string]inFlightProvision),
		cordonedInFlight:    make(map[string]int64),
		recentlyRetiredNode: make(map[string]int64),
	}, nil
}

// Tick applies the scaling policy to one snapshot. It updates the hysteresis
// counters and returns the actions of this tick in canonical order: retire
// actions for drained nodes first (by node id), then the cordon and drain
// pair of at most one scale-down victim, then the provision actions (by node
// id). A nil context or an invalid snapshot changes no state and returns an
// error.
func (a *Autoscaler) Tick(ctx context.Context, snapshot AutoscalerSnapshot) ([]AutoscalerAction, error) {
	if ctx == nil {
		return nil, &ArgumentError{Param: "ctx", Message: "The autoscaler context must not be nil."}
	}
	if a == nil || a.drainSafety == nil {
		return nil, &InvalidOperationError{Message: "The autoscaler is unavailable."}
	}
	validated, err := NewAutoscalerSnapshot(snapshot.Nodes, snapshot.Demand)
	if err != nil {
		return nil, err
	}
	a.tick++
	a.reconcileInFlight(validated)
	actions := a.planRetireActions(validated)
	pressure := computeClusterPressure(validated, a.config, a.inFlightProvisions)
	if pressure.scaleUpBreach {
		a.scaleUpBreachTicks++
	} else {
		a.scaleUpBreachTicks = 0
	}
	if !pressure.scaleUpBreach && pressure.headroomExceeds(a.config.ScaleDownHeadroomPercent) {
		a.scaleDownIdleTicks++
	} else {
		a.scaleDownIdleTicks = 0
	}
	actions = append(actions, a.planScaleDown(ctx, validated, pressure)...)
	actions = append(actions, a.planScaleUp(validated, pressure)...)
	return actions, nil
}

// reconcileInFlight drops the remembered in-flight provisions and cordons
// once a snapshot reflects them, so snapshot state always wins once it is
// visible, and expires bridge entries the snapshots never confirmed.
func (a *Autoscaler) reconcileInFlight(snapshot AutoscalerSnapshot) {
	states := make(map[string]NodeState, len(snapshot.Nodes))
	for _, node := range snapshot.Nodes {
		states[node.NodeId] = node.NodeState
	}
	for nodeId, provision := range a.inFlightProvisions {
		if _, present := states[nodeId]; present {
			delete(a.inFlightProvisions, nodeId)
			continue
		}
		if a.tick-provision.tick > autoscalingInFlightTickTTL {
			delete(a.inFlightProvisions, nodeId)
		}
	}
	for nodeId, cordonedTick := range a.cordonedInFlight {
		state, present := states[nodeId]
		cordonApplied := present &&
			(state == NodeStateCordoned || state == NodeStateDraining || state == NodeStateRetired)
		if cordonApplied || a.tick-cordonedTick > autoscalingInFlightTickTTL {
			delete(a.cordonedInFlight, nodeId)
		}
	}
	for nodeId, retiredTick := range a.recentlyRetiredNode {
		if a.tick-retiredTick > int64(a.config.FlapSuppressionTicks) {
			delete(a.recentlyRetiredNode, nodeId)
		}
	}
}

// planRetireActions retires every Draining node that reports zero running
// allocations: Usage.Tasks is the running-allocation gauge and
// PendingAllocations the queued count, so both must be zero before the drain
// is considered complete. A node that was never drained never reaches this
// path, so retiring an undrained node is not expressible here.
func (a *Autoscaler) planRetireActions(snapshot AutoscalerSnapshot) []AutoscalerAction {
	var actions []AutoscalerAction
	for _, node := range snapshot.Nodes {
		if node.NodeState != NodeStateDraining {
			continue
		}
		if _, alreadyRetired := a.recentlyRetiredNode[node.NodeId]; alreadyRetired {
			// The snapshot may continue to report a draining node until the
			// control-plane mutation is observed. Do not emit duplicate retire
			// actions while that first mutation is still in flight.
			continue
		}
		if node.Usage.Tasks > 0 || node.PendingAllocations > 0 {
			continue
		}
		action, err := NewRetireNodeAction(node.NodeId)
		if err != nil {
			// Unreachable for a snapshot-validated node id; skip fail-closed.
			continue
		}
		actions = append(actions, action)
		a.recentlyRetiredNode[node.NodeId] = a.tick
	}
	return actions
}

// planScaleDown cordons and drains at most one node per tick: the
// lowest-utilization Ready node the drain safety evaluator allows, once the
// sustained-headroom counter is confirmed, while no other drain is in flight
// and the fleet stays at or above MinNodes. The victim emits a cordon action
// followed by a drain action; when every candidate is blocked the autoscaler
// defers (no action) and re-evaluates next tick.
func (a *Autoscaler) planScaleDown(
	ctx context.Context,
	snapshot AutoscalerSnapshot,
	pressure clusterPressure,
) []AutoscalerAction {
	if a.scaleDownIdleTicks < a.config.ScaleDownConfirmTicks {
		return nil
	}
	if a.drainInFlight(snapshot) || len(a.cordonedInFlight) > 0 {
		return nil
	}
	fleetSize := activeFleetSize(snapshot) + len(a.inFlightProvisions)
	if fleetSize-1 < a.config.MinNodes {
		return nil
	}
	candidates := readyNodesByUtilization(snapshot)
	for _, node := range candidates {
		if !a.drainAllowed(ctx, node) {
			continue
		}
		cordon, cordonErr := NewCordonNodeAction(node.NodeId)
		drain, drainErr := NewDrainNodeAction(node.NodeId)
		if cordonErr != nil || drainErr != nil {
			// Unreachable for a snapshot-validated node id; defer.
			return nil
		}
		a.cordonedInFlight[node.NodeId] = a.tick
		a.scaleDownIdleTicks = 0
		return []AutoscalerAction{cordon, drain}
	}
	return nil
}

// drainAllowed reports whether the drain safety evaluator allows draining one
// node. Every drain candidate is evaluated, replica-free nodes included, and
// an evaluator error blocks the drain: the seam is fail-closed by contract.
func (a *Autoscaler) drainAllowed(ctx context.Context, node NodeObservation) bool {
	candidate, err := stateful.NewNodeDrainCandidate(node.NodeId, node.StatefulReplicas)
	if err != nil {
		// Unreachable for a snapshot-validated observation; block.
		return false
	}
	decision, err := a.drainSafety.EvaluateDrainSafety(ctx, candidate)
	if err != nil {
		return false
	}
	return decision.Allowed
}

// planScaleUp provisions nodes once the sustained-pressure counter is
// confirmed, no retirement is inside the flap suppression window, and demand
// exists to size the nodes: the sizing is the largest unschedulable demand
// (falling back to the largest demand overall when every demand still fits
// some Ready node), each new node carries that exact envelope, and the
// provision count is the per-dimension deficit after the capacity of nodes
// already Provisioning is counted against it, capped by MaxNodes and
// MaxConcurrentProvisions.
func (a *Autoscaler) planScaleUp(
	snapshot AutoscalerSnapshot,
	pressure clusterPressure,
) []AutoscalerAction {
	if a.scaleUpBreachTicks < a.config.ScaleUpConfirmTicks {
		return nil
	}
	if len(a.recentlyRetiredNode) > 0 {
		return nil
	}
	sizing, hasSizing := largestProvisionSizing(snapshot)
	if !hasSizing {
		// Pressure without demand cannot size a node; the breach counter
		// keeps running and the next demand-bearing snapshot decides.
		return nil
	}
	provisioningCount := provisioningNodeCount(snapshot) + len(a.inFlightProvisions)
	fleetSize := activeFleetSize(snapshot) + len(a.inFlightProvisions)
	needed := requiredProvisionCount(pressure, sizing, provisioningCount)
	allowed := needed
	if headroom := a.config.MaxNodes - fleetSize; allowed > headroom {
		allowed = headroom
	}
	if free := a.config.MaxConcurrentProvisions - provisioningCount; allowed > free {
		allowed = free
	}
	if allowed <= 0 {
		return nil
	}
	actions := make([]AutoscalerAction, 0, allowed)
	reservedIds := make(map[string]struct{}, len(snapshot.Nodes)+len(a.inFlightProvisions))
	for _, node := range snapshot.Nodes {
		reservedIds[node.NodeId] = struct{}{}
	}
	for nodeId := range a.inFlightProvisions {
		reservedIds[nodeId] = struct{}{}
	}
	for count := 0; count < allowed; count++ {
		nodeId := a.nextProvisionNodeId(reservedIds)
		request, err := NewNodeProvisionRequest(nodeId, AutoscalerNodeClass, sizing, a.scaleUpReason())
		if err != nil {
			// Unreachable: the sizing envelope is validated and the ids and
			// reason are generated inside their bounds; defer fail-closed.
			return nil
		}
		action, err := NewProvisionNodeAction(request)
		if err != nil {
			return nil
		}
		reservedIds[nodeId] = struct{}{}
		a.inFlightProvisions[nodeId] = inFlightProvision{resources: sizing, tick: a.tick}
		actions = append(actions, action)
	}
	a.scaleUpBreachTicks = 0
	return actions
}

// nextProvisionNodeId advances the provision sequence to the next
// deterministic node id the cluster does not use yet, so a fleet that already
// contains an as-node-* id never receives a colliding provision.
func (a *Autoscaler) nextProvisionNodeId(reserved map[string]struct{}) string {
	for {
		a.provisionSequence++
		nodeId := fmt.Sprintf("as-node-%d", a.provisionSequence)
		if _, taken := reserved[nodeId]; !taken {
			return nodeId
		}
	}
}

// scaleUpReason is the deterministic, bounded provision reason of this lane.
func (a *Autoscaler) scaleUpReason() string {
	return fmt.Sprintf("cluster pressure breached the scale-up headroom for %d consecutive ticks.",
		a.config.ScaleUpConfirmTicks)
}

// clusterPressure is the derived cluster pressure of one snapshot: projected
// demand (cluster usage plus the demand set), the capacity of nodes serving
// work, the reserved capacity of Provisioning nodes, whether the scale-up
// threshold is breached on any dimension, and the minimum headroom fraction
// across dimensions. All ratio arithmetic is exact rational arithmetic, so
// the derived values are deterministic for identical inputs.
type clusterPressure struct {
	projected            NodeResources
	activeCapacity       NodeResources
	provisioningCapacity NodeResources
	scaleUpBreach        bool
	minimumHeadroom      *big.Rat
}

// headroomExceeds reports whether the minimum headroom across dimensions
// exceeds the given percentage of capacity.
func (p clusterPressure) headroomExceeds(scaleDownHeadroomPercent int) bool {
	if p.minimumHeadroom == nil {
		return false
	}
	threshold := new(big.Rat).SetFrac(big.NewInt(int64(scaleDownHeadroomPercent)), big.NewInt(100))
	return p.minimumHeadroom.Cmp(threshold) > 0
}

// computeClusterPressure projects demand against capacity per dimension:
// usage is summed over the nodes still serving work (Ready, Cordoned, and
// Draining nodes keep their capacity until they are retired), the demand set
// is added on top, and Provisioning nodes contribute their reserved capacity
// to the in-flight reserve counted against the scale-up deficit. The
// remembered in-flight provisions of this autoscaler join that reserve until
// a snapshot reflects them. The scale-up threshold is breached when projected
// demand exceeds capacity scaled by (1 - ScaleUpHeadroomPercent/100) on any
// dimension; the scale-down headroom is the minimum over dimensions of
// (capacity - projected) / capacity, clamped at zero, and is nil when no
// dimension reports capacity, so a degenerate snapshot never shrinks the
// fleet.
func computeClusterPressure(
	snapshot AutoscalerSnapshot,
	config AutoscalerConfig,
	inFlight map[string]inFlightProvision,
) clusterPressure {
	pressure := clusterPressure{}
	for _, node := range snapshot.Nodes {
		switch node.NodeState {
		case NodeStateReady, NodeStateCordoned, NodeStateDraining:
			pressure.activeCapacity.add(node.Capacity)
			pressure.projected.add(node.Usage)
		case NodeStateProvisioning:
			pressure.provisioningCapacity.add(node.Capacity)
		case NodeStateRetired:
		}
	}
	for _, entry := range snapshot.Demand {
		pressure.projected.add(entry.Resources)
	}
	for _, provision := range inFlight {
		pressure.provisioningCapacity.add(provision.resources)
	}
	breachThreshold := new(big.Rat).SetFrac(
		big.NewInt(int64(100-config.ScaleUpHeadroomPercent)), big.NewInt(100))
	dimensions := []struct {
		projected int64
		capacity  int64
	}{
		{pressure.projected.MemoryBytes, pressure.activeCapacity.MemoryBytes},
		{int64(pressure.projected.CpuPercent), int64(pressure.activeCapacity.CpuPercent)},
		{int64(pressure.projected.Tasks), int64(pressure.activeCapacity.Tasks)},
	}
	for _, dimension := range dimensions {
		if dimension.capacity <= 0 {
			if dimension.projected > 0 {
				// Demand against zero capacity can never be served: breach.
				pressure.scaleUpBreach = true
			}
			continue
		}
		usageRatio := new(big.Rat).SetFrac(
			big.NewInt(dimension.projected), big.NewInt(dimension.capacity))
		if usageRatio.Cmp(breachThreshold) > 0 {
			pressure.scaleUpBreach = true
		}
		headroomRatio := new(big.Rat).Sub(big.NewRat(1, 1), usageRatio)
		if headroomRatio.Sign() < 0 {
			headroomRatio = new(big.Rat)
		}
		if pressure.minimumHeadroom == nil || headroomRatio.Cmp(pressure.minimumHeadroom) < 0 {
			pressure.minimumHeadroom = headroomRatio
		}
	}
	return pressure
}

// add accumulates one envelope into this envelope with saturation, so
// absurdly large validated inputs can never wrap into negative aggregates.
func (r *NodeResources) add(other NodeResources) {
	r.MemoryBytes = saturatingAddInt64(r.MemoryBytes, other.MemoryBytes)
	r.CpuPercent = int(saturatingAddInt64(int64(r.CpuPercent), int64(other.CpuPercent)))
	r.Tasks = int(saturatingAddInt64(int64(r.Tasks), int64(other.Tasks)))
}

// saturatingAddInt64 adds two non-negative values clamping at the maximum.
func saturatingAddInt64(left, right int64) int64 {
	if left > math.MaxInt64-right {
		return math.MaxInt64
	}
	return left + right
}

// activeFleetSize counts every node the fleet still owns: all states except
// Retired.
func activeFleetSize(snapshot AutoscalerSnapshot) int {
	count := 0
	for _, node := range snapshot.Nodes {
		if node.NodeState != NodeStateRetired {
			count++
		}
	}
	return count
}

// provisioningNodeCount counts the nodes a snapshot reports as Provisioning.
func provisioningNodeCount(snapshot AutoscalerSnapshot) int {
	count := 0
	for _, node := range snapshot.Nodes {
		if node.NodeState == NodeStateProvisioning {
			count++
		}
	}
	return count
}

// drainInFlight reports whether any node is Cordoned or Draining: this lane
// drains one node at a time so the fleet never drains in waves. A node for
// which a retire action was already emitted is no longer an in-flight drain,
// even if its stale pre-retirement state remains in the next snapshot.
func (a *Autoscaler) drainInFlight(snapshot AutoscalerSnapshot) bool {
	for _, node := range snapshot.Nodes {
		if _, alreadyRetired := a.recentlyRetiredNode[node.NodeId]; alreadyRetired {
			continue
		}
		if node.NodeState == NodeStateCordoned || node.NodeState == NodeStateDraining {
			return true
		}
	}
	return false
}

// readyNodesByUtilization returns the Ready nodes ordered by (utilization,
// node id), where utilization is the exact maximum usage-to-capacity ratio
// over dimensions: a node loaded in any dimension is a loaded node, and the
// node id breaks exact ties so the order is total.
func readyNodesByUtilization(snapshot AutoscalerSnapshot) []NodeObservation {
	type utilizationEntry struct {
		node        NodeObservation
		utilization *big.Rat
	}
	entries := make([]utilizationEntry, 0, len(snapshot.Nodes))
	for _, node := range snapshot.Nodes {
		if node.NodeState != NodeStateReady {
			continue
		}
		entries = append(entries, utilizationEntry{node: node, utilization: nodeUtilizationRatio(node)})
	}
	sort.Slice(entries, func(left, right int) bool {
		if comparison := entries[left].utilization.Cmp(entries[right].utilization); comparison != 0 {
			return comparison < 0
		}
		return entries[left].node.NodeId < entries[right].node.NodeId
	})
	candidates := make([]NodeObservation, 0, len(entries))
	for _, entry := range entries {
		candidates = append(candidates, entry.node)
	}
	return candidates
}

// nodeUtilizationRatio derives the exact utilization of one node: the maximum
// usage-to-capacity ratio over the dimensions with positive capacity, and
// zero when every dimension is degenerate.
func nodeUtilizationRatio(node NodeObservation) *big.Rat {
	utilization := new(big.Rat)
	dimensions := []struct {
		usage    int64
		capacity int64
	}{
		{node.Usage.MemoryBytes, node.Capacity.MemoryBytes},
		{int64(node.Usage.CpuPercent), int64(node.Capacity.CpuPercent)},
		{int64(node.Usage.Tasks), int64(node.Capacity.Tasks)},
	}
	for _, dimension := range dimensions {
		if dimension.capacity <= 0 {
			continue
		}
		ratio := new(big.Rat).SetFrac(big.NewInt(dimension.usage), big.NewInt(dimension.capacity))
		if ratio.Cmp(utilization) > 0 {
			utilization = ratio
		}
	}
	return utilization
}

// largestProvisionSizing sizes provisioned nodes: the largest unschedulable
// demand, a workload no Ready node has the free capacity to host, with the
// largest demand overall as the fallback when every demand still fits. The
// demand list is role-ordered and envelopes compare by memory, then CPU
// percent, then tasks, so the choice is deterministic; the second return is
// false when the snapshot carries no demand at all, in which case there is
// nothing to size a node for.
func largestProvisionSizing(snapshot AutoscalerSnapshot) (NodeResources, bool) {
	if len(snapshot.Demand) == 0 {
		return NodeResources{}, false
	}
	pool := make([]AllocationDemand, 0, len(snapshot.Demand))
	for _, entry := range snapshot.Demand {
		if !demandFitsAnyReadyNode(entry, snapshot) {
			pool = append(pool, entry)
		}
	}
	if len(pool) == 0 {
		pool = snapshot.Demand
	}
	best := pool[0]
	for _, entry := range pool[1:] {
		if envelopeLarger(entry.Resources, best.Resources) {
			best = entry
		}
	}
	return best.Resources, true
}

// envelopeLarger orders two resource envelopes by memory, then CPU percent,
// then tasks.
func envelopeLarger(left, right NodeResources) bool {
	if left.MemoryBytes != right.MemoryBytes {
		return left.MemoryBytes > right.MemoryBytes
	}
	if left.CpuPercent != right.CpuPercent {
		return left.CpuPercent > right.CpuPercent
	}
	return left.Tasks > right.Tasks
}

// demandFitsAnyReadyNode reports whether any Ready node has the free capacity
// to host one demand unit.
func demandFitsAnyReadyNode(entry AllocationDemand, snapshot AutoscalerSnapshot) bool {
	for _, node := range snapshot.Nodes {
		if node.NodeState == NodeStateReady && entry.Resources.fits(freeResources(node)) {
			return true
		}
	}
	return false
}

// freeResources derives the free envelope of one node; usage fits capacity by
// contract, so every dimension is non-negative.
func freeResources(node NodeObservation) NodeResources {
	return NodeResources{
		MemoryBytes: node.Capacity.MemoryBytes - node.Usage.MemoryBytes,
		CpuPercent:  node.Capacity.CpuPercent - node.Usage.CpuPercent,
		Tasks:       node.Capacity.Tasks - node.Usage.Tasks,
	}
}

// requiredProvisionCount derives how many nodes of the given sizing close the
// scale-up deficit: per dimension, the hard shortfall of projected demand
// against active capacity plus the in-flight reserve, divided by the sizing
// and rounded up. When no dimension reports a shortfall but nothing is in
// flight, one node still relieves the breached headroom; when the in-flight
// reserve already covers the deficit, zero nodes are needed, so the
// autoscaler never double-provisions the same shortfall.
func requiredProvisionCount(pressure clusterPressure, sizing NodeResources, provisioningCount int) int {
	needed := 0
	dimensions := []struct {
		projected    int64
		capacity     int64
		provisioning int64
		sizing       int64
	}{
		{pressure.projected.MemoryBytes, pressure.activeCapacity.MemoryBytes,
			pressure.provisioningCapacity.MemoryBytes, sizing.MemoryBytes},
		{int64(pressure.projected.CpuPercent), int64(pressure.activeCapacity.CpuPercent),
			int64(pressure.provisioningCapacity.CpuPercent), int64(sizing.CpuPercent)},
		{int64(pressure.projected.Tasks), int64(pressure.activeCapacity.Tasks),
			int64(pressure.provisioningCapacity.Tasks), int64(sizing.Tasks)},
	}
	for _, dimension := range dimensions {
		served := saturatingAddInt64(dimension.capacity, dimension.provisioning)
		if dimension.projected <= served {
			continue
		}
		deficit := dimension.projected - served
		if dimension.sizing <= 0 {
			continue
		}
		if count := ceilDivPositive(deficit, dimension.sizing); count > needed {
			needed = count
		}
	}
	if needed == 0 && provisioningCount == 0 {
		return 1
	}
	return needed
}

// ceilDivPositive divides two positive values rounding up, without overflow.
func ceilDivPositive(value, divisor int64) int {
	return int((value-1)/divisor) + 1
}
