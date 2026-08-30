package autoscaling

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/stateful"
)

// fakeDrainSafetyEvaluator is the deterministic stand-in for the control-plane
// drain safety evaluator: it records every consult, blocks the configured
// node ids, and fails for the configured node ids.
type fakeDrainSafetyEvaluator struct {
	defaultAllowed bool
	blockedIds     map[string]bool
	errorsFor      map[string]error
	calls          []string
}

func (e *fakeDrainSafetyEvaluator) EvaluateDrainSafety(
	ctx context.Context,
	candidate stateful.NodeDrainCandidate,
) (stateful.DrainDecision, error) {
	e.calls = append(e.calls, candidate.NodeId)
	if err, present := e.errorsFor[candidate.NodeId]; present {
		return stateful.DrainDecision{}, err
	}
	if e.blockedIds[candidate.NodeId] {
		return stateful.NewDrainDecision(false,
			"The replica set is below the minimum on peers.",
			[]string{"terrabase-blocking-1"})
	}
	return stateful.NewDrainDecision(e.defaultAllowed,
		"Peer replica sets are healthy.", nil)
}

func allowAllDrains() *fakeDrainSafetyEvaluator {
	return &fakeDrainSafetyEvaluator{defaultAllowed: true}
}

func mustNode(
	t *testing.T,
	nodeId string,
	nodeState NodeState,
	capacity NodeResources,
	usage NodeResources,
	pending int,
	replicas ...stateful.ReplicaHealth,
) NodeObservation {
	t.Helper()
	observation, err := NewNodeObservation(nodeId, nodeState, capacity, usage, pending, replicas)
	if err != nil {
		t.Fatalf("node observation %s: %v", nodeId, err)
	}
	return observation
}

func mustDemand(
	t *testing.T,
	roleId string,
	roleKind string,
	statefulRole bool,
	resources NodeResources,
) AllocationDemand {
	t.Helper()
	demand, err := NewAllocationDemand(roleId, roleKind, statefulRole, resources)
	if err != nil {
		t.Fatalf("demand %s: %v", roleId, err)
	}
	return demand
}

func mustReplica(t *testing.T, allocationId string, up bool) stateful.ReplicaHealth {
	t.Helper()
	replica, err := stateful.NewReplicaHealth("terrabase", allocationId, up, 2, 3, 0)
	if err != nil {
		t.Fatalf("replica %s: %v", allocationId, err)
	}
	return replica
}

func mustConfig(
	t *testing.T,
	minNodes int,
	maxNodes int,
	scaleUpHeadroomPercent int,
	scaleDownHeadroomPercent int,
	scaleUpConfirmTicks int,
	scaleDownConfirmTicks int,
	maxConcurrentProvisions int,
	flapSuppressionTicks int,
) AutoscalerConfig {
	t.Helper()
	config, err := NewAutoscalerConfig(
		minNodes, maxNodes, scaleUpHeadroomPercent, scaleDownHeadroomPercent,
		scaleUpConfirmTicks, scaleDownConfirmTicks, maxConcurrentProvisions,
		flapSuppressionTicks)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	return config
}

func mustAutoscaler(t *testing.T, config AutoscalerConfig, drainSafety DrainSafetyEvaluator) *Autoscaler {
	t.Helper()
	autoscaler, err := NewAutoscaler(config, drainSafety)
	if err != nil {
		t.Fatalf("autoscaler: %v", err)
	}
	return autoscaler
}

func mustTick(t *testing.T, autoscaler *Autoscaler, snapshot AutoscalerSnapshot) []AutoscalerAction {
	t.Helper()
	actions, err := autoscaler.Tick(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("tick: %v", err)
	}
	return actions
}

// actionSignature renders the canonical decision of one tick so whole action
// streams compare byte-for-byte.
func actionSignature(actions []AutoscalerAction) string {
	var builder strings.Builder
	for _, action := range actions {
		switch action.Kind() {
		case AutoscalerActionProvisionNode:
			request := action.ProvisionRequest()
			fmt.Fprintf(&builder, "provision|%s|%s|%d/%d/%d|%s;",
				request.NodeId, request.NodeClass,
				request.Resources.MemoryBytes, request.Resources.CpuPercent,
				request.Resources.Tasks, request.Reason)
		default:
			fmt.Fprintf(&builder, "%s|%s;", action.Kind(), action.NodeId())
		}
	}
	return builder.String()
}

var engineTestCapacity = NodeResources{MemoryBytes: 1000, CpuPercent: 100, Tasks: 100}

func TestNewAutoscalerRequiresAValidPolicyAndAnEvaluator(t *testing.T) {
	config := mustConfig(t, 1, 4, 20, 30, 2, 2, 2, 3)
	if _, err := NewAutoscaler(config, nil); !errorsAsParam(err, "drainSafety") {
		t.Fatalf("a nil evaluator must be refused, got %v", err)
	}
	invalid := config
	invalid.MinNodes = 0
	if _, err := NewAutoscaler(invalid, allowAllDrains()); !errorsAsParam(err, "minNodes") {
		t.Fatalf("an invalid policy must be refused, got %v", err)
	}
}

func TestNewAutoscalerSnapshotOrdersAndRejectsDuplicates(t *testing.T) {
	first := mustNode(t, "gru-node-2", NodeStateReady, engineTestCapacity, NodeResources{}, 0)
	second := mustNode(t, "gru-node-1", NodeStateReady, engineTestCapacity, NodeResources{}, 0)
	demand := mustDemand(t, "terrabase-b", "terrabase", true, engineTestCapacity)
	otherDemand := mustDemand(t, "terrabase-a", "terrabase", true, engineTestCapacity)

	snapshot, err := NewAutoscalerSnapshot(
		[]NodeObservation{first, second},
		[]AllocationDemand{demand, otherDemand})
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if snapshot.Nodes[0].NodeId != "gru-node-1" || snapshot.Nodes[1].NodeId != "gru-node-2" {
		t.Fatalf("nodes must be stored in node-id order, got %v", snapshot.Nodes)
	}
	if snapshot.Demand[0].RoleId != "terrabase-a" || snapshot.Demand[1].RoleId != "terrabase-b" {
		t.Fatalf("demand must be stored in role-id order, got %v", snapshot.Demand)
	}

	duplicate := mustNode(t, "gru-node-1", NodeStateReady, engineTestCapacity, NodeResources{}, 0)
	if _, err := NewAutoscalerSnapshot(
		[]NodeObservation{second, duplicate}, nil); !errorsAsParam(err, "nodes") {
		t.Fatalf("a duplicate node must be refused, got %v", err)
	}
	if _, err := NewAutoscalerSnapshot(nil,
		[]AllocationDemand{otherDemand, otherDemand}); !errorsAsParam(err, "demand") {
		t.Fatalf("a duplicate role must be refused, got %v", err)
	}
}

func TestTickRequiresAContextAndAValidSnapshot(t *testing.T) {
	autoscaler := mustAutoscaler(t,
		mustConfig(t, 1, 4, 20, 30, 2, 2, 2, 3), allowAllDrains())
	if _, err := autoscaler.Tick(nil, AutoscalerSnapshot{}); !errorsAsParam(err, "ctx") {
		t.Fatalf("a nil context must be refused, got %v", err)
	}
	first := mustNode(t, "gru-node-1", NodeStateReady, engineTestCapacity, NodeResources{}, 0)
	duplicate := mustNode(t, "gru-node-1", NodeStateReady, engineTestCapacity, NodeResources{}, 0)
	if _, err := autoscaler.Tick(context.Background(),
		AutoscalerSnapshot{Nodes: []NodeObservation{first, duplicate}}); !errorsAsParam(err, "nodes") {
		t.Fatalf("an invalid snapshot must be refused, got %v", err)
	}
}

func TestTickScaleUpProvisionsAfterConsecutiveBreachTicks(t *testing.T) {
	config := mustConfig(t, 1, 8, 20, 30, 2, 50, 4, 3)
	loaded := mustNode(t, "gru-node-1", NodeStateReady, engineTestCapacity,
		NodeResources{MemoryBytes: 700, CpuPercent: 70, Tasks: 70}, 0)
 peer := mustNode(t, "gru-node-2", NodeStateReady, engineTestCapacity,
		NodeResources{MemoryBytes: 700, CpuPercent: 70, Tasks: 70}, 0)
	large := mustDemand(t, "terrabase-gru", "terrabase", true,
		NodeResources{MemoryBytes: 400, CpuPercent: 40, Tasks: 40})
	small := mustDemand(t, "web-gru", "web", false,
		NodeResources{MemoryBytes: 100, CpuPercent: 10, Tasks: 10})
	snapshot := AutoscalerSnapshot{
		Nodes:  []NodeObservation{loaded, peer},
		Demand: []AllocationDemand{large, small},
	}
	autoscaler := mustAutoscaler(t, config, allowAllDrains())

	if actions := mustTick(t, autoscaler, snapshot); len(actions) != 0 {
		t.Fatalf("one breach tick must not provision, got %v", actionSignature(actions))
	}
	actions := mustTick(t, autoscaler, snapshot)
	expected := "provision|as-node-1|greenfield|400/40/40|" +
		"cluster pressure breached the scale-up headroom for 2 consecutive ticks.;"
	if signature := actionSignature(actions); signature != expected {
		t.Fatalf("signature = %q, want %q", signature, expected)
	}

	// The confirmation counter resets with the action, so a calm tick stays
	// calm and the next breach needs a fresh confirmation window.
	calm := AutoscalerSnapshot{Nodes: []NodeObservation{loaded, peer}}
	if actions := mustTick(t, autoscaler, calm); len(actions) != 0 {
		t.Fatalf("a calm tick must not act, got %v", actionSignature(actions))
	}
	if actions := mustTick(t, autoscaler, snapshot); len(actions) != 0 {
		t.Fatalf("a fresh breach must restart the window, got %v", actionSignature(actions))
	}
}

func TestTickAlternatingPressureNeverScalesUp(t *testing.T) {
	config := mustConfig(t, 1, 8, 20, 30, 2, 50, 4, 3)
	loaded := mustNode(t, "gru-node-1", NodeStateReady, engineTestCapacity,
		NodeResources{MemoryBytes: 700, CpuPercent: 70, Tasks: 70}, 0)
	peer := mustNode(t, "gru-node-2", NodeStateReady, engineTestCapacity,
		NodeResources{MemoryBytes: 700, CpuPercent: 70, Tasks: 70}, 0)
	breach := AutoscalerSnapshot{
		Nodes: []NodeObservation{loaded, peer},
		Demand: []AllocationDemand{mustDemand(t, "terrabase-gru", "terrabase", true,
			NodeResources{MemoryBytes: 400, CpuPercent: 40, Tasks: 40})},
	}
	calm := AutoscalerSnapshot{Nodes: []NodeObservation{loaded, peer}}
	autoscaler := mustAutoscaler(t, config, allowAllDrains())

	for tick := 0; tick < 8; tick++ {
		snapshot := calm
		if tick%2 == 0 {
			snapshot = breach
		}
		if actions := mustTick(t, autoscaler, snapshot); len(actions) != 0 {
			t.Fatalf("alternating pressure must never confirm scale-up, got %v at tick %d",
				actionSignature(actions), tick)
		}
	}
}

func TestTickDoesNotDoubleProvisionWhileAProvisioningNodeCoversTheDeficit(t *testing.T) {
	config := mustConfig(t, 1, 8, 20, 30, 1, 50, 4, 3)
	loaded := mustNode(t, "gru-node-1", NodeStateReady, engineTestCapacity,
		NodeResources{MemoryBytes: 700, CpuPercent: 70, Tasks: 70}, 0)
	peer := mustNode(t, "gru-node-2", NodeStateReady, engineTestCapacity,
		NodeResources{MemoryBytes: 700, CpuPercent: 70, Tasks: 70}, 0)
	large := mustDemand(t, "terrabase-gru", "terrabase", true,
		NodeResources{MemoryBytes: 400, CpuPercent: 40, Tasks: 40})
	breach := AutoscalerSnapshot{
		Nodes:  []NodeObservation{loaded, peer},
		Demand: []AllocationDemand{large},
	}
	autoscaler := mustAutoscaler(t, config, allowAllDrains())

	if actions := mustTick(t, autoscaler, breach); actionSignature(actions) == "" {
		t.Fatal("the first confirmed breach tick must provision")
	}

	// The next snapshot reports the new node as Provisioning: its reserved
	// capacity counts against the same deficit, so nothing else is ordered.
	provisioning := mustNode(t, "as-node-1", NodeStateProvisioning,
		NodeResources{MemoryBytes: 400, CpuPercent: 40, Tasks: 40}, NodeResources{}, 0)
	withProvisioning := breach
	withProvisioning.Nodes = append([]NodeObservation{}, breach.Nodes...)
	withProvisioning.Nodes = append(withProvisioning.Nodes, provisioning)
	if actions := mustTick(t, autoscaler, withProvisioning); len(actions) != 0 {
		t.Fatalf("a provisioning node must absorb the deficit, got %v", actionSignature(actions))
	}

	// The same holds while the snapshot has not reflected the provision at
	// all: the autoscaler remembers its own in-flight reservation.
	blind := mustAutoscaler(t, config, allowAllDrains())
	if actions := mustTick(t, blind, breach); actionSignature(actions) == "" {
		t.Fatal("the blind sequence must provision on its first tick")
	}
	if actions := mustTick(t, blind, breach); len(actions) != 0 {
		t.Fatalf("an unreflected provision must still be counted, got %v", actionSignature(actions))
	}
	if actions := mustTick(t, blind, breach); len(actions) != 0 {
		t.Fatalf("the bridge window must hold while unreflected, got %v", actionSignature(actions))
	}
	// Once the bridge expires without the node ever appearing, the deficit is
	// open again and the autoscaler orders a replacement node.
	actions := mustTick(t, blind, breach)
	if signature := actionSignature(actions); !strings.Contains(signature, "as-node-2") {
		t.Fatalf("the expired bridge must reprovision, got %q", signature)
	}
}

func TestTickScaleUpHonorsMaxNodesAndMaxConcurrentProvisions(t *testing.T) {
	full := mustNode(t, "gru-node-1", NodeStateReady, engineTestCapacity, engineTestCapacity, 0)
	peer := mustNode(t, "gru-node-2", NodeStateReady, engineTestCapacity, engineTestCapacity, 0)
	demand := func() []AllocationDemand {
		return []AllocationDemand{
			mustDemand(t, "terrabase-a", "terrabase", true,
				NodeResources{MemoryBytes: 4000, CpuPercent: 40, Tasks: 40}),
			mustDemand(t, "terrabase-b", "terrabase", true,
				NodeResources{MemoryBytes: 4000, CpuPercent: 40, Tasks: 40}),
		}
	}

	atMaxNodes := mustAutoscaler(t,
		mustConfig(t, 1, 2, 20, 30, 1, 50, 4, 3), allowAllDrains())
	if actions := mustTick(t, atMaxNodes, AutoscalerSnapshot{
		Nodes: []NodeObservation{full, peer}, Demand: demand()}); len(actions) != 0 {
		t.Fatalf("a fleet at MaxNodes must not provision, got %v", actionSignature(actions))
	}

	withHeadroom := mustAutoscaler(t,
		mustConfig(t, 1, 4, 20, 30, 1, 50, 4, 3), allowAllDrains())
	actions := mustTick(t, withHeadroom, AutoscalerSnapshot{
		Nodes: []NodeObservation{full, peer}, Demand: demand()})
	if signature := actionSignature(actions); signature !=
		"provision|as-node-1|greenfield|4000/40/40|"+
			"cluster pressure breached the scale-up headroom for 1 consecutive ticks.;"+
			"provision|as-node-2|greenfield|4000/40/40|"+
			"cluster pressure breached the scale-up headroom for 1 consecutive ticks.;" {
		t.Fatalf("signature = %q", signature)
	}

	atConcurrency := mustAutoscaler(t,
		mustConfig(t, 1, 8, 20, 30, 1, 50, 1, 3), allowAllDrains())
	first := mustTick(t, atConcurrency, AutoscalerSnapshot{
		Nodes: []NodeObservation{full, peer}, Demand: demand()})
	if len(first) != 1 {
		t.Fatalf("MaxConcurrentProvisions bounds one tick, got %v", actionSignature(first))
	}
	provisioning := mustNode(t, "as-node-1", NodeStateProvisioning,
		NodeResources{MemoryBytes: 4000, CpuPercent: 40, Tasks: 40}, NodeResources{}, 0)
	if actions := mustTick(t, atConcurrency, AutoscalerSnapshot{
		Nodes:  []NodeObservation{full, peer, provisioning},
		Demand: demand()}); len(actions) != 0 {
		t.Fatalf("an in-flight provision consumes the concurrency budget, got %v",
			actionSignature(actions))
	}
}

func TestTickScaleUpWithoutDemandSizesNothing(t *testing.T) {
	loaded := mustNode(t, "gru-node-1", NodeStateReady, engineTestCapacity,
		NodeResources{MemoryBytes: 950, CpuPercent: 95, Tasks: 95}, 0)
	autoscaler := mustAutoscaler(t,
		mustConfig(t, 1, 8, 20, 30, 1, 50, 4, 3), allowAllDrains())
	for tick := 0; tick < 3; tick++ {
		if actions := mustTick(t, autoscaler,
			AutoscalerSnapshot{Nodes: []NodeObservation{loaded}}); len(actions) != 0 {
			t.Fatalf("pressure without demand must not provision, got %v",
				actionSignature(actions))
		}
	}
}

func TestTickScaleUpSizingFallsBackToTheLargestDemand(t *testing.T) {
	loaded := mustNode(t, "gru-node-1", NodeStateReady, engineTestCapacity,
		NodeResources{MemoryBytes: 850, CpuPercent: 85, Tasks: 85}, 0)
	peer := mustNode(t, "gru-node-2", NodeStateReady, engineTestCapacity,
		NodeResources{MemoryBytes: 850, CpuPercent: 85, Tasks: 85}, 0)
	// Every demand still fits the free envelope of a Ready node, so the
	// sizing falls back to the largest overall demand.
	fits := mustDemand(t, "web-gru", "web", false,
		NodeResources{MemoryBytes: 100, CpuPercent: 10, Tasks: 10})
	larger := mustDemand(t, "web-eu", "web", false,
		NodeResources{MemoryBytes: 150, CpuPercent: 10, Tasks: 10})
	autoscaler := mustAutoscaler(t,
		mustConfig(t, 1, 8, 20, 30, 1, 50, 4, 3), allowAllDrains())

	actions := mustTick(t, autoscaler, AutoscalerSnapshot{
		Nodes:  []NodeObservation{loaded, peer},
		Demand: []AllocationDemand{fits, larger}})
	if len(actions) != 1 || actions[0].Kind() != AutoscalerActionProvisionNode {
		t.Fatalf("actions = %v", actionSignature(actions))
	}
	sized := actions[0].ProvisionRequest().Resources
	if sized.MemoryBytes != 150 || sized.CpuPercent != 10 || sized.Tasks != 10 {
		t.Fatalf("sizing = %+v, want the largest overall demand", sized)
	}
}

func scaleDownCluster(t *testing.T, replicas ...stateful.ReplicaHealth) ([]NodeObservation, AutoscalerSnapshot) {
	t.Helper()
	nodes := []NodeObservation{
		mustNode(t, "gru-node-1", NodeStateReady, engineTestCapacity,
			NodeResources{MemoryBytes: 100, CpuPercent: 10, Tasks: 10}, 0),
		mustNode(t, "gru-node-2", NodeStateReady, engineTestCapacity,
			NodeResources{MemoryBytes: 300, CpuPercent: 30, Tasks: 30}, 0),
		mustNode(t, "gru-node-3", NodeStateReady, engineTestCapacity,
			NodeResources{MemoryBytes: 200, CpuPercent: 20, Tasks: 20}, 0),
	}
	idle := mustNode(t, "gru-node-4", NodeStateReady, engineTestCapacity,
		NodeResources{MemoryBytes: 50, CpuPercent: 5, Tasks: 5}, 0, replicas...)
	nodes = append(nodes, idle)
	return nodes, AutoscalerSnapshot{Nodes: nodes}
}

func TestTickScaleDownCordonsAndDrainsTheLowestUtilizationReadyNode(t *testing.T) {
	nodes, snapshot := scaleDownCluster(t)
	config := mustConfig(t, 3, 8, 20, 30, 1, 2, 4, 3)
	evaluator := allowAllDrains()
	autoscaler := mustAutoscaler(t, config, evaluator)

	if actions := mustTick(t, autoscaler, snapshot); len(actions) != 0 {
		t.Fatalf("one idle tick must not scale down, got %v", actionSignature(actions))
	}
	actions := mustTick(t, autoscaler, snapshot)
	if signature := actionSignature(actions); signature != "CordonNode|gru-node-4;DrainNode|gru-node-4;" {
		t.Fatalf("signature = %q", signature)
	}
	if len(evaluator.calls) == 0 || evaluator.calls[len(evaluator.calls)-1] != "gru-node-4" {
		t.Fatalf("the drained node must be drain-safety evaluated, calls = %v", evaluator.calls)
	}

	// Exactly one drain is in flight at a time, so sustained headroom with a
	// cordoned node defers instead of draining in waves.
	cordoned := mustNode(t, "gru-node-4", NodeStateCordoned, engineTestCapacity,
		NodeResources{MemoryBytes: 50, CpuPercent: 5, Tasks: 5}, 0)
	withCordoned := snapshot
	withCordoned.Nodes = append([]NodeObservation{}, nodes[:3]...)
	withCordoned.Nodes = append(withCordoned.Nodes, cordoned)
	for tick := 0; tick < 3; tick++ {
		if actions := mustTick(t, autoscaler, withCordoned); len(actions) != 0 {
			t.Fatalf("a drain in flight defers further scale-down, got %v",
				actionSignature(actions))
		}
	}
}

func TestTickScaleDownNeverShrinksBelowMinNodes(t *testing.T) {
	_, snapshot := scaleDownCluster(t)
	autoscaler := mustAutoscaler(t,
		mustConfig(t, 4, 8, 20, 30, 1, 1, 4, 3), allowAllDrains())
	for tick := 0; tick < 3; tick++ {
		if actions := mustTick(t, autoscaler, snapshot); len(actions) != 0 {
			t.Fatalf("a fleet at MinNodes must never drain, got %v at tick %d",
				actionSignature(actions), tick)
		}
	}
}

func TestTickScaleDownDefersWhenDrainSafetyBlocksEveryCandidate(t *testing.T) {
	_, snapshot := scaleDownCluster(t, mustReplica(t, "terrascale-gru-terrabase-4", true))
	evaluator := &fakeDrainSafetyEvaluator{
		defaultAllowed: true,
		blockedIds:     map[string]bool{"gru-node-4": true},
	}
	autoscaler := mustAutoscaler(t,
		mustConfig(t, 3, 8, 20, 30, 1, 1, 4, 3), evaluator)

	actions := mustTick(t, autoscaler, snapshot)
	if signature := actionSignature(actions); signature != "CordonNode|gru-node-1;DrainNode|gru-node-1;" {
		t.Fatalf("a blocked victim must defer to the next-lowest node, signature = %q", signature)
	}
	if len(evaluator.calls) != 2 ||
		evaluator.calls[0] != "gru-node-4" || evaluator.calls[1] != "gru-node-1" {
		t.Fatalf("candidates must be evaluated in utilization order, calls = %v", evaluator.calls)
	}

	allBlocked := &fakeDrainSafetyEvaluator{
		defaultAllowed: true,
		blockedIds: map[string]bool{
			"gru-node-1": true, "gru-node-2": true, "gru-node-3": true, "gru-node-4": true,
		},
	}
	deferred := mustAutoscaler(t,
		mustConfig(t, 3, 8, 20, 30, 1, 1, 4, 3), allBlocked)
	if actions := mustTick(t, deferred, snapshot); len(actions) != 0 {
		t.Fatalf("a fully blocked cluster must defer, got %v", actionSignature(actions))
	}

	failing := &fakeDrainSafetyEvaluator{
		defaultAllowed: true,
		errorsFor:      map[string]error{"gru-node-4": context.DeadlineExceeded},
	}
	withFailure := mustAutoscaler(t,
		mustConfig(t, 3, 8, 20, 30, 1, 1, 4, 3), failing)
	actions = mustTick(t, withFailure, snapshot)
	if signature := actionSignature(actions); signature != "CordonNode|gru-node-1;DrainNode|gru-node-1;" {
		t.Fatalf("an evaluator failure must block only its candidate, signature = %q", signature)
	}
}

func TestTickRetiresOnlyDrainedNodesWithZeroRunningAllocations(t *testing.T) {
	draining := mustNode(t, "gru-node-4", NodeStateDraining, engineTestCapacity,
		NodeResources{MemoryBytes: 20, CpuPercent: 2, Tasks: 2}, 0)
	ready := mustNode(t, "gru-node-1", NodeStateReady, engineTestCapacity, NodeResources{}, 0)
	autoscaler := mustAutoscaler(t,
		mustConfig(t, 1, 8, 20, 30, 1, 50, 4, 3), allowAllDrains())

	if actions := mustTick(t, autoscaler,
		AutoscalerSnapshot{Nodes: []NodeObservation{draining, ready}}); len(actions) != 0 {
		t.Fatalf("a draining node with running allocations must not retire, got %v",
			actionSignature(actions))
	}
	empty := mustNode(t, "gru-node-4", NodeStateDraining, engineTestCapacity, NodeResources{}, 0)
	actions := mustTick(t, autoscaler, AutoscalerSnapshot{
		Nodes: []NodeObservation{empty, ready}})
	if signature := actionSignature(actions); signature != "RetireNode|gru-node-4;" {
		t.Fatalf("signature = %q", signature)
	}
	if actions := mustTick(t, autoscaler,
		AutoscalerSnapshot{Nodes: []NodeObservation{ready}}); len(actions) != 0 {
		t.Fatalf("a Ready node is never retired, got %v", actionSignature(actions))
	}
}

func TestTickRetireThenImmediateBreachHonorsTheFlapSuppressionWindow(t *testing.T) {
	config := mustConfig(t, 1, 8, 20, 30, 1, 50, 4, 2)
	drained := mustNode(t, "gru-node-1", NodeStateDraining, engineTestCapacity, NodeResources{}, 0)
	loaded := mustNode(t, "gru-node-2", NodeStateReady, engineTestCapacity,
		NodeResources{MemoryBytes: 950, CpuPercent: 95, Tasks: 95}, 0)
	breach := AutoscalerSnapshot{
		Nodes: []NodeObservation{loaded},
		Demand: []AllocationDemand{mustDemand(t, "terrabase-gru", "terrabase", true,
			NodeResources{MemoryBytes: 100, CpuPercent: 10, Tasks: 10})},
	}
	autoscaler := mustAutoscaler(t, config, allowAllDrains())

	// Tick 1 retires the drained node; the just-retired id is remembered, so
	// the confirmed breach in the same tick must not provision.
	actions := mustTick(t, autoscaler, AutoscalerSnapshot{
		Nodes: append([]NodeObservation{loaded}, drained)})
	if signature := actionSignature(actions); signature != "RetireNode|gru-node-1;" {
		t.Fatalf("signature = %q", signature)
	}

	// Ticks 2 and 3 stay inside the two-tick window.
	for tick := 0; tick < 2; tick++ {
		if actions := mustTick(t, autoscaler, breach); len(actions) != 0 {
			t.Fatalf("the flap suppression window must hold, got %v at offset %d",
				actionSignature(actions), tick)
		}
	}

	// The window expires and the sustained breach provisions.
	actions = mustTick(t, autoscaler, breach)
	if signature := actionSignature(actions); !strings.Contains(signature, "as-node-1") {
		t.Fatalf("the expired window must provision, got %q", signature)
	}
}

func TestTickDecisionsAreDeterministicUnderPermutedNodeInput(t *testing.T) {
	config := mustConfig(t, 3, 8, 20, 30, 1, 1, 4, 3)
	draining := mustNode(t, "gru-node-9", NodeStateDraining, engineTestCapacity, NodeResources{}, 0)
	nodes := []NodeObservation{
		mustNode(t, "gru-node-1", NodeStateReady, engineTestCapacity,
			NodeResources{MemoryBytes: 100, CpuPercent: 10, Tasks: 10}, 0),
		mustNode(t, "gru-node-2", NodeStateReady, engineTestCapacity,
			NodeResources{MemoryBytes: 300, CpuPercent: 30, Tasks: 30}, 0),
		mustNode(t, "gru-node-3", NodeStateReady, engineTestCapacity,
			NodeResources{MemoryBytes: 200, CpuPercent: 20, Tasks: 20}, 0),
	}
	demand := []AllocationDemand{
		mustDemand(t, "terrabase-gru", "terrabase", true,
			NodeResources{MemoryBytes: 400, CpuPercent: 40, Tasks: 40}),
	}

	run := func() string {
		autoscaler := mustAutoscaler(t, config, allowAllDrains())
		var builder strings.Builder
		first := append([]NodeObservation{draining}, nodes...)
		reversed := append([]NodeObservation{draining}, nodes[2], nodes[1], nodes[0])
		for _, tickNodes := range [][]NodeObservation{first, reversed, first, reversed} {
			fmt.Fprintf(&builder, "%s\n", actionSignature(mustTick(t, autoscaler,
				AutoscalerSnapshot{Nodes: tickNodes, Demand: demand})))
		}
		return builder.String()
	}

	reference := run()
	for attempt := 0; attempt < 3; attempt++ {
		if replay := run(); replay != reference {
			t.Fatalf("decisions are not reproducible:\nreference:\n%s\nreplay:\n%s",
				reference, replay)
		}
	}
	if !strings.Contains(reference, "RetireNode|gru-node-9;") ||
		!strings.Contains(reference, "CordonNode|gru-node-1;DrainNode|gru-node-1;") {
		t.Fatalf("the permuted sequence must still retire and drain, got:\n%s", reference)
	}
}
