package stateful

import (
	"errors"
	"reflect"
	"testing"
)

// drainTestInvalidData reports whether err is one of the package
// invalid-data errors.
func drainTestInvalidData(err error) bool {
	var invalidData *InvalidDataError
	return errors.As(err, &invalidData)
}

// drainTestInvalidOperation reports whether err is one of the package
// invalid-operation errors.
func drainTestInvalidOperation(err error) bool {
	var invalidOperation *InvalidOperationError
	return errors.As(err, &invalidOperation)
}

// drainTestReplica builds one validated replica observation.
func drainTestReplica(
	t *testing.T,
	roleKind string,
	allocationId string,
	up bool,
	minReplicas int,
	lagBytes int64,
) ReplicaHealth {
	t.Helper()
	replica, err := NewReplicaHealth(roleKind, allocationId, up, 0, minReplicas, lagBytes)
	if err != nil {
		t.Fatalf("replica %s/%s: %v", roleKind, allocationId, err)
	}
	return replica
}

// drainTestCandidate builds one validated drain candidate.
func drainTestCandidate(t *testing.T, nodeId string, replicas ...ReplicaHealth) NodeDrainCandidate {
	t.Helper()
	candidate, err := NewNodeDrainCandidate(nodeId, replicas)
	if err != nil {
		t.Fatalf("candidate %s: %v", nodeId, err)
	}
	return candidate
}

// drainTestEvaluator builds one validated replica drain evaluator.
func drainTestEvaluator(t *testing.T, maxLagBytes int64) *ReplicaDrainSafetyEvaluator {
	t.Helper()
	evaluator, err := NewReplicaDrainSafetyEvaluator(DrainPolicy{MaxLagBytes: maxLagBytes})
	if err != nil {
		t.Fatalf("evaluator: %v", err)
	}
	return evaluator
}

func TestNewDrainPolicy(t *testing.T) {
	tests := []struct {
		name        string
		maxLagBytes int64
		expectValid bool
	}{
		{name: "positive bound", maxLagBytes: 1, expectValid: true},
		{name: "zero bound", maxLagBytes: 0},
		{name: "negative bound", maxLagBytes: -1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy, err := NewDrainPolicy(test.maxLagBytes)
			if test.expectValid {
				if err != nil {
					t.Fatalf("policy: %v", err)
				}
				if policy.MaxLagBytes != test.maxLagBytes {
					t.Fatalf("MaxLagBytes = %d", policy.MaxLagBytes)
				}
				return
			}
			if !errorsAsParam(err, "maxLagBytes") {
				t.Fatalf("error %v does not reference param maxLagBytes", err)
			}
		})
	}

	if _, err := NewReplicaDrainSafetyEvaluator(DrainPolicy{}); !errorsAsParam(err, "maxLagBytes") {
		t.Fatalf("evaluator error %v does not reference param maxLagBytes", err)
	}
}

func TestEvaluateDrainSafetyMatrix(t *testing.T) {
	evaluator := drainTestEvaluator(t, 1024)

	tests := []struct {
		name           string
		candidate      NodeDrainCandidate
		peers          []NodeDrainCandidate
		expectAllowed  bool
		expectBlocking []string
	}{
		{
			name: "healthy cluster allows the drain",
			candidate: drainTestCandidate(t, "node-a",
				drainTestReplica(t, "terrabase", "tb-1", true, 2, 0)),
			peers: []NodeDrainCandidate{
				drainTestCandidate(t, "node-b",
					drainTestReplica(t, "terrabase", "tb-2", true, 2, 0)),
				drainTestCandidate(t, "node-c",
					drainTestReplica(t, "terrabase", "tb-3", true, 2, 0)),
			},
			expectAllowed: true,
		},
		{
			name: "short replica sets elsewhere defer the drain",
			candidate: drainTestCandidate(t, "node-a",
				drainTestReplica(t, "terrabase", "tb-1", true, 2, 0)),
			peers: []NodeDrainCandidate{
				drainTestCandidate(t, "node-b",
					drainTestReplica(t, "terrabase", "tb-2", true, 2, 0)),
			},
			expectBlocking: []string{"tb-1"},
		},
		{
			name: "lag at the bound defers the drain",
			candidate: drainTestCandidate(t, "node-a",
				drainTestReplica(t, "terrabase", "tb-1", true, 2, 1024)),
			peers: []NodeDrainCandidate{
				drainTestCandidate(t, "node-b",
					drainTestReplica(t, "terrabase", "tb-2", true, 2, 0)),
				drainTestCandidate(t, "node-c",
					drainTestReplica(t, "terrabase", "tb-3", true, 2, 0)),
			},
			expectBlocking: []string{"tb-1"},
		},
		{
			name: "lag just below the bound allows the drain",
			candidate: drainTestCandidate(t, "node-a",
				drainTestReplica(t, "terrabase", "tb-1", true, 2, 1023)),
			peers: []NodeDrainCandidate{
				drainTestCandidate(t, "node-b",
					drainTestReplica(t, "terrabase", "tb-2", true, 2, 0)),
				drainTestCandidate(t, "node-c",
					drainTestReplica(t, "terrabase", "tb-3", true, 2, 0)),
			},
			expectAllowed: true,
		},
		{
			name: "a down replica on the node defers the drain",
			candidate: drainTestCandidate(t, "node-a",
				drainTestReplica(t, "terrabase", "tb-1", true, 2, 0),
				drainTestReplica(t, "backup", "bk-1", false, 1, 0)),
			peers: []NodeDrainCandidate{
				drainTestCandidate(t, "node-b",
					drainTestReplica(t, "terrabase", "tb-2", true, 2, 0),
					drainTestReplica(t, "backup", "bk-2", true, 1, 0)),
				drainTestCandidate(t, "node-c",
					drainTestReplica(t, "terrabase", "tb-3", true, 2, 0)),
			},
			expectBlocking: []string{"bk-1"},
		},
		{
			name: "down replicas elsewhere do not count as survivors",
			candidate: drainTestCandidate(t, "node-a",
				drainTestReplica(t, "terrabase", "tb-1", true, 2, 0)),
			peers: []NodeDrainCandidate{
				drainTestCandidate(t, "node-b",
					drainTestReplica(t, "terrabase", "tb-2", false, 2, 0)),
				drainTestCandidate(t, "node-c",
					drainTestReplica(t, "terrabase", "tb-3", true, 2, 0)),
			},
			expectBlocking: []string{"tb-1"},
		},
		{
			name:          "a node without stateful replicas drains freely",
			candidate:     drainTestCandidate(t, "node-a"),
			peers:         nil,
			expectAllowed: true,
		},
		{
			name: "replicas of other role kinds do not count as survivors",
			candidate: drainTestCandidate(t, "node-a",
				drainTestReplica(t, "terrabase", "tb-1", true, 1, 0)),
			peers: []NodeDrainCandidate{
				drainTestCandidate(t, "node-b",
					drainTestReplica(t, "backup", "bk-2", true, 1, 0)),
			},
			expectBlocking: []string{"tb-1"},
		},
		{
			name: "the candidate's own allocations do not count as survivors",
			candidate: drainTestCandidate(t, "node-a",
				drainTestReplica(t, "terrabase", "tb-1", true, 2, 0),
				drainTestReplica(t, "terrabase", "tb-2", true, 2, 0)),
			peers: []NodeDrainCandidate{
				drainTestCandidate(t, "node-b",
					drainTestReplica(t, "terrabase", "tb-1", true, 2, 0),
					drainTestReplica(t, "terrabase", "tb-3", true, 2, 0)),
			},
			expectBlocking: []string{"tb-1", "tb-2"},
		},
		{
			name: "blocking allocation ids are sorted",
			candidate: drainTestCandidate(t, "node-a",
				drainTestReplica(t, "terrabase", "tb-c", true, 2, 0),
				drainTestReplica(t, "terrabase", "tb-a", true, 2, 0),
				drainTestReplica(t, "terrabase", "tb-b", true, 2, 0)),
			expectBlocking: []string{"tb-a", "tb-b", "tb-c"},
		},
		{
			name: "one allocation id under two role kinds blocks once",
			candidate: drainTestCandidate(t, "node-a",
				drainTestReplica(t, "terrabase", "dup-1", false, 1, 0),
				drainTestReplica(t, "backup", "dup-1", false, 1, 0)),
			expectBlocking: []string{"dup-1"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision, err := evaluator.EvaluateDrainSafety(test.candidate, test.peers)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if decision.Allowed != test.expectAllowed {
				t.Fatalf("allowed = %v, want %v (reason %q)",
					decision.Allowed, test.expectAllowed, decision.Reason)
			}
			if test.expectAllowed {
				if len(decision.BlockingAllocationIds) != 0 {
					t.Fatalf("allowed drain named blockers %v", decision.BlockingAllocationIds)
				}
				return
			}
			if !reflect.DeepEqual(decision.BlockingAllocationIds, test.expectBlocking) {
				t.Fatalf("blocking = %v, want %v",
					decision.BlockingAllocationIds, test.expectBlocking)
			}
		})
	}
}

func TestEvaluateDrainSafetyIsInputOrderIndependent(t *testing.T) {
	evaluator := drainTestEvaluator(t, 1024)
	forward := drainTestCandidate(t, "node-a",
		drainTestReplica(t, "terrabase", "tb-1", false, 1, 0),
		drainTestReplica(t, "backup", "bk-1", true, 2, 4096))
	reverse := drainTestCandidate(t, "node-a",
		drainTestReplica(t, "backup", "bk-1", true, 2, 4096),
		drainTestReplica(t, "terrabase", "tb-1", false, 1, 0))

	forwardDecision, err := evaluator.EvaluateDrainSafety(forward, nil)
	if err != nil {
		t.Fatalf("forward: %v", err)
	}
	reverseDecision, err := evaluator.EvaluateDrainSafety(reverse, nil)
	if err != nil {
		t.Fatalf("reverse: %v", err)
	}
	if !reflect.DeepEqual(forwardDecision, reverseDecision) {
		t.Fatalf("decisions differ by replica input order: %v vs %v",
			forwardDecision, reverseDecision)
	}
	if !reflect.DeepEqual(forwardDecision.BlockingAllocationIds, []string{"bk-1", "tb-1"}) {
		t.Fatalf("blocking = %v", forwardDecision.BlockingAllocationIds)
	}
}

func TestEvaluateDrainSafetyRejectsBadPeers(t *testing.T) {
	evaluator := drainTestEvaluator(t, 1024)
	candidate := drainTestCandidate(t, "node-a",
		drainTestReplica(t, "terrabase", "tb-1", true, 1, 0))

	peer := drainTestCandidate(t, "node-b",
		drainTestReplica(t, "terrabase", "tb-2", true, 1, 0))
	if _, err := evaluator.EvaluateDrainSafety(candidate,
		[]NodeDrainCandidate{candidate, peer}); !drainTestInvalidData(err) {
		t.Fatalf("candidate among peers error = %v, want an invalid-data error", err)
	}
	if _, err := evaluator.EvaluateDrainSafety(candidate,
		[]NodeDrainCandidate{peer, peer}); !drainTestInvalidData(err) {
		t.Fatalf("duplicate peer error = %v, want an invalid-data error", err)
	}
	tooManyReplicas := make([]ReplicaHealth, statefulMaximumReplicaCount+1)
	if _, err := evaluator.EvaluateDrainSafety(candidate,
		[]NodeDrainCandidate{{NodeId: "node-c", Replicas: tooManyReplicas}}); !errorsAsParam(err, "replicas") {
		t.Fatalf("unvalidated peer error %v does not reference param replicas", err)
	}
}

func TestNewDrainingAllocation(t *testing.T) {
	replica := drainTestReplica(t, "terrabase", "tb-1", true, 2, 0)

	tests := []struct {
		name         string
		allocationId string
		roleKind     string
		stateful     bool
		replica      *ReplicaHealth
		expectParam  string
	}{
		{
			name:         "stateful allocation with matching replica",
			allocationId: "tb-1",
			roleKind:     "terrabase",
			stateful:     true,
			replica:      &replica,
		},
		{
			name:         "stateless allocation",
			allocationId: "web-1",
			roleKind:     "web",
		},
		{
			name:         "stateful allocation without replica",
			allocationId: "tb-1",
			roleKind:     "terrabase",
			stateful:     true,
			expectParam:  "replica",
		},
		{
			name:         "stateless allocation with replica",
			allocationId: "web-1",
			roleKind:     "web",
			replica:      &replica,
			expectParam:  "replica",
		},
		{
			name:         "replica identity mismatch",
			allocationId: "tb-2",
			roleKind:     "terrabase",
			stateful:     true,
			replica:      &replica,
			expectParam:  "replica",
		},
		{
			name:         "malformed allocation id",
			allocationId: "TB-1",
			roleKind:     "terrabase",
			stateful:     true,
			replica:      &replica,
			expectParam:  "allocationId",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			allocation, err := NewDrainingAllocation(
				test.allocationId, test.roleKind, test.stateful, test.replica)
			if test.expectParam != "" {
				if !errorsAsParam(err, test.expectParam) {
					t.Fatalf("error %v does not reference param %s", err, test.expectParam)
				}
				return
			}
			if err != nil {
				t.Fatalf("allocation: %v", err)
			}
			if allocation.Stateful != (allocation.Replica != nil) {
				t.Fatalf("stateful = %v with replica %v", allocation.Stateful, allocation.Replica)
			}
		})
	}
}

func TestNewCordonedNodeObservationRejectsDuplicates(t *testing.T) {
	replica := drainTestReplica(t, "terrabase", "tb-1", true, 2, 0)
	stateful, err := NewDrainingAllocation("tb-1", "terrabase", true, &replica)
	if err != nil {
		t.Fatalf("stateful: %v", err)
	}
	stateless, err := NewDrainingAllocation("tb-1", "web", false, nil)
	if err != nil {
		t.Fatalf("stateless: %v", err)
	}

	if _, err := NewCordonedNodeObservation("node-a",
		[]DrainingAllocation{stateful, stateless}); !errorsAsParam(err, "allocations") {
		t.Fatalf("error %v does not reference param allocations", err)
	}
	if _, err := NewCordonedNodeObservation("Node-A",
		[]DrainingAllocation{stateful}); !errorsAsParam(err, "nodeId") {
		t.Fatalf("error %v does not reference param nodeId", err)
	}
}

func TestNewNodeDrainPlanEnforcesOrderingInvariants(t *testing.T) {
	allowed, err := NewDrainDecision(true, "Safe to drain.", nil)
	if err != nil {
		t.Fatalf("allowed: %v", err)
	}
	blocked, err := NewDrainDecision(false, "Not safe to drain.", []string{"tb-1"})
	if err != nil {
		t.Fatalf("blocked: %v", err)
	}
	stateless, err := NewDrainStep(DrainStepStopStateless, "web-1", "web")
	if err != nil {
		t.Fatalf("stateless: %v", err)
	}
	stateful, err := NewDrainStep(DrainStepStopStateful, "tb-1", "terrabase")
	if err != nil {
		t.Fatalf("stateful: %v", err)
	}

	tests := []struct {
		name     string
		steps    []DrainStep
		decision DrainDecision
	}{
		{
			name:     "stateful step with a blocked decision",
			steps:    []DrainStep{stateless, stateful},
			decision: blocked,
		},
		{
			name:     "stateless step after a stateful step",
			steps:    []DrainStep{stateful, stateless},
			decision: allowed,
		},
		{
			name:     "duplicate allocation step",
			steps:    []DrainStep{stateless, stateless},
			decision: allowed,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewNodeDrainPlan("node-a", test.steps, test.decision); !drainTestInvalidOperation(err) {
				t.Fatalf("error = %v, want an invalid operation", err)
			}
		})
	}

	plan, err := NewNodeDrainPlan("node-a", []DrainStep{stateless, stateful}, allowed)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if plan.NodeId != "node-a" || len(plan.Steps) != 2 {
		t.Fatalf("plan = %+v", plan)
	}
	if _, err := NewDrainStep(DrainStepKind(7), "web-1", "web"); !errorsAsParam(err, "kind") {
		t.Fatalf("error %v does not reference param kind", err)
	}
	if DrainStepStopStateless.String() != "StopStateless" || DrainStepStopStateful.String() != "StopStateful" {
		t.Fatal("drain step kind names must be stable")
	}
	if DrainStepKind(7).String() != "DrainStepKind(7)" {
		t.Fatal("out-of-range drain step kind name must be stable")
	}
}

func TestNewNodeDrainCoordinatorRequiresEvaluator(t *testing.T) {
	if _, err := NewNodeDrainCoordinator(nil); !errorsAsParam(err, "evaluator") {
		t.Fatalf("error %v does not reference param evaluator", err)
	}
}

func drainTestCordonedNode(t *testing.T, nodeId string) CordonedNodeObservation {
	t.Helper()
	web1, err := NewDrainingAllocation("web-1", "web", false, nil)
	if err != nil {
		t.Fatalf("web-1: %v", err)
	}
	web2, err := NewDrainingAllocation("web-2", "web", false, nil)
	if err != nil {
		t.Fatalf("web-2: %v", err)
	}
	api, err := NewDrainingAllocation("api-1", "api", false, nil)
	if err != nil {
		t.Fatalf("api-1: %v", err)
	}
	terrabase1Replica := drainTestReplica(t, "terrabase", "terrabase-1", true, 2, 0)
	terrabase1, err := NewDrainingAllocation("terrabase-1", "terrabase", true, &terrabase1Replica)
	if err != nil {
		t.Fatalf("terrabase-1: %v", err)
	}
	terrabase2Replica := drainTestReplica(t, "terrabase", "terrabase-2", true, 2, 0)
	terrabase2, err := NewDrainingAllocation("terrabase-2", "terrabase", true, &terrabase2Replica)
	if err != nil {
		t.Fatalf("terrabase-2: %v", err)
	}
	observation, err := NewCordonedNodeObservation(nodeId, []DrainingAllocation{
		web2, terrabase2, web1, api, terrabase1,
	})
	if err != nil {
		t.Fatalf("observation: %v", err)
	}
	return observation
}

func TestPlanDrainStopsStatelessFirstAndStatefulLast(t *testing.T) {
	evaluator := drainTestEvaluator(t, 1024)
	coordinator, err := NewNodeDrainCoordinator(evaluator)
	if err != nil {
		t.Fatalf("coordinator: %v", err)
	}
	peers := []NodeDrainCandidate{
		drainTestCandidate(t, "node-b",
			drainTestReplica(t, "terrabase", "terrabase-8", true, 2, 0)),
		drainTestCandidate(t, "node-c",
			drainTestReplica(t, "terrabase", "terrabase-9", true, 2, 0)),
	}

	plan, err := coordinator.PlanDrain(drainTestCordonedNode(t, "node-a"), peers)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if !plan.Decision.Allowed {
		t.Fatalf("decision = %v", plan.Decision)
	}
	expected := []struct {
		kind         DrainStepKind
		allocationId string
		roleKind     string
	}{
		{DrainStepStopStateless, "api-1", "api"},
		{DrainStepStopStateless, "web-1", "web"},
		{DrainStepStopStateless, "web-2", "web"},
		{DrainStepStopStateful, "terrabase-1", "terrabase"},
		{DrainStepStopStateful, "terrabase-2", "terrabase"},
	}
	if len(plan.Steps) != len(expected) {
		t.Fatalf("step count = %d, want %d", len(plan.Steps), len(expected))
	}
	for index, want := range expected {
		step := plan.Steps[index]
		if step.Kind != want.kind || step.AllocationId != want.allocationId ||
			step.RoleKind != want.roleKind {
			t.Fatalf("step[%d] = %+v, want %+v", index, step, want)
		}
	}
}

func TestPlanDrainDefersStatefulStepsWhenUnsafe(t *testing.T) {
	evaluator := drainTestEvaluator(t, 1024)
	coordinator, err := NewNodeDrainCoordinator(evaluator)
	if err != nil {
		t.Fatalf("coordinator: %v", err)
	}
	peers := []NodeDrainCandidate{
		drainTestCandidate(t, "node-b",
			drainTestReplica(t, "terrabase", "terrabase-8", true, 2, 0)),
	}

	plan, err := coordinator.PlanDrain(drainTestCordonedNode(t, "node-a"), peers)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if plan.Decision.Allowed {
		t.Fatal("a short replica set must defer the drain")
	}
	if !reflect.DeepEqual(plan.Decision.BlockingAllocationIds,
		[]string{"terrabase-1", "terrabase-2"}) {
		t.Fatalf("blocking = %v", plan.Decision.BlockingAllocationIds)
	}
	for _, step := range plan.Steps {
		if step.Kind != DrainStepStopStateless {
			t.Fatalf("deferred plan contains stateful step %+v", step)
		}
	}
	if len(plan.Steps) != 3 {
		t.Fatalf("step count = %d, want the three stateless steps", len(plan.Steps))
	}
}

func TestPlanDrainIsAllocationOrderIndependent(t *testing.T) {
	evaluator := drainTestEvaluator(t, 1024)
	coordinator, err := NewNodeDrainCoordinator(evaluator)
	if err != nil {
		t.Fatalf("coordinator: %v", err)
	}
	peers := []NodeDrainCandidate{
		drainTestCandidate(t, "node-b",
			drainTestReplica(t, "terrabase", "terrabase-8", true, 2, 0)),
		drainTestCandidate(t, "node-c",
			drainTestReplica(t, "terrabase", "terrabase-9", true, 2, 0)),
	}

	node := drainTestCordonedNode(t, "node-a")
	first, err := coordinator.PlanDrain(node, peers)
	if err != nil {
		t.Fatalf("first plan: %v", err)
	}
	reversedNode := node
	reversedNode.Allocations = append([]DrainingAllocation(nil), node.Allocations...)
	for left, right := 0, len(reversedNode.Allocations)-1; left < right; left, right = left+1, right-1 {
		reversedNode.Allocations[left], reversedNode.Allocations[right] =
			reversedNode.Allocations[right], reversedNode.Allocations[left]
	}
	second, err := coordinator.PlanDrain(reversedNode, peers)
	if err != nil {
		t.Fatalf("second plan: %v", err)
	}
	if !reflect.DeepEqual(first.Steps, second.Steps) {
		t.Fatalf("plans differ: %v vs %v", first.Steps, second.Steps)
	}
}

func TestPlanDrainPropagatesEvaluatorErrors(t *testing.T) {
	evaluator := drainTestEvaluator(t, 1024)
	coordinator, err := NewNodeDrainCoordinator(evaluator)
	if err != nil {
		t.Fatalf("coordinator: %v", err)
	}
	node := drainTestCordonedNode(t, "node-a")
	self := drainTestCandidate(t, "node-a",
		drainTestReplica(t, "terrabase", "terrabase-1", true, 2, 0))
	if _, err := coordinator.PlanDrain(node,
		[]NodeDrainCandidate{self}); !drainTestInvalidData(err) {
		t.Fatalf("error = %v, want an invalid-data error", err)
	}
}
