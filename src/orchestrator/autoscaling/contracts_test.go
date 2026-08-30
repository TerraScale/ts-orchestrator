package autoscaling

import (
	"errors"
	"strings"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/stateful"
)

// errorsAsParam reports whether err is one of the package argument errors
// naming the given parameter.
func errorsAsParam(err error, param string) bool {
	var argumentError *ArgumentError
	if errors.As(err, &argumentError) {
		return argumentError.Param == param
	}
	var outOfRange *ArgumentOutOfRangeError
	if errors.As(err, &outOfRange) {
		return outOfRange.Param == param
	}
	var statefulOutOfRange *stateful.ArgumentOutOfRangeError
	if errors.As(err, &statefulOutOfRange) {
		return statefulOutOfRange.Param == param
	}
	var statefulArgument *stateful.ArgumentError
	if errors.As(err, &statefulArgument) {
		return statefulArgument.Param == param
	}
	return false
}

func TestNodeStateStringIsAClosedVocabulary(t *testing.T) {
	expected := map[NodeState]string{
		NodeStateReady:        "Ready",
		NodeStateProvisioning: "Provisioning",
		NodeStateCordoned:     "Cordoned",
		NodeStateDraining:     "Draining",
		NodeStateRetired:      "Retired",
	}
	if len(expected) != len(AllNodeStates) {
		t.Fatalf("vocabulary size = %d, want %d", len(AllNodeStates), len(expected))
	}
	for state, name := range expected {
		if state.String() != name {
			t.Fatalf("state %d String() = %q, want %q", int(state), state.String(), name)
		}
	}
	if unknown := NodeState(42); unknown.String() != "NodeState(42)" {
		t.Fatalf("unknown state String() = %q", unknown.String())
	}
}

func TestNewNodeResources(t *testing.T) {
	tests := []struct {
		name        string
		memoryBytes int64
		cpuPercent  int
		tasks       int
		expectParam string
	}{
		{name: "valid envelope", memoryBytes: 16 << 30, cpuPercent: 800, tasks: 2048},
		{name: "zero envelope", memoryBytes: 0, cpuPercent: 0, tasks: 0},
		{name: "negative memory", memoryBytes: -1, cpuPercent: 100, tasks: 10, expectParam: "memoryBytes"},
		{name: "negative cpu", memoryBytes: 1, cpuPercent: -1, tasks: 10, expectParam: "cpuPercent"},
		{name: "cpu above bound", memoryBytes: 1, cpuPercent: 10001, tasks: 10, expectParam: "cpuPercent"},
		{name: "negative tasks", memoryBytes: 1, cpuPercent: 100, tasks: -1, expectParam: "tasks"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resources, err := NewNodeResources(test.memoryBytes, test.cpuPercent, test.tasks)
			if test.expectParam != "" {
				if err == nil {
					t.Fatal("expected an error, got a valid envelope")
				}
				if !errorsAsParam(err, test.expectParam) {
					t.Fatalf("error %v does not reference param %q", err, test.expectParam)
				}
				return
			}
			if err != nil {
				t.Fatalf("resources: %v", err)
			}
			if resources.MemoryBytes != test.memoryBytes || resources.CpuPercent != test.cpuPercent ||
				resources.Tasks != test.tasks {
				t.Fatalf("resources = %+v", resources)
			}
		})
	}
}

func validReplicaList() []stateful.ReplicaHealth {
	return []stateful.ReplicaHealth{
		{RoleKind: "terrabase", AllocationId: "terrascale-gru-terrabase-1", Up: true, MinReplicas: 3},
		{RoleKind: "terrabase", AllocationId: "terrascale-gru-terrabase-2", Up: true, MinReplicas: 3},
	}
}

func TestNewNodeObservation(t *testing.T) {
	capacity := NodeResources{MemoryBytes: 16 << 30, CpuPercent: 800, Tasks: 2048}

	tests := []struct {
		name                string
		nodeId              string
		nodeState           NodeState
		capacity            NodeResources
		usage               NodeResources
		pending             int
		replicas            []stateful.ReplicaHealth
		expectParam         string
		expectStatefulParam string
	}{
		{
			name:      "ready node observation",
			nodeId:    "gru-node-1",
			nodeState: NodeStateReady,
			capacity:  capacity,
			usage:     NodeResources{MemoryBytes: 8 << 30, CpuPercent: 400, Tasks: 1024},
			pending:   2,
			replicas:  validReplicaList(),
		},
		{
			name:        "invalid node id",
			nodeId:      "GRU-NODE-1",
			nodeState:   NodeStateReady,
			capacity:    capacity,
			usage:       NodeResources{},
			expectParam: "nodeId",
		},
		{
			name:        "undefined node state",
			nodeId:      "gru-node-1",
			nodeState:   NodeState(9),
			capacity:    capacity,
			usage:       NodeResources{},
			expectParam: "nodeState",
		},
		{
			name:        "usage above capacity",
			nodeId:      "gru-node-1",
			nodeState:   NodeStateReady,
			capacity:    capacity,
			usage:       NodeResources{MemoryBytes: 32 << 30, CpuPercent: 400, Tasks: 1024},
			expectParam: "usage",
		},
		{
			name:        "negative pending count",
			nodeId:      "gru-node-1",
			nodeState:   NodeStateReady,
			capacity:    capacity,
			usage:       NodeResources{},
			pending:     -1,
			expectParam: "pendingAllocations",
		},
		{
			name:      "duplicate replicas",
			nodeId:    "gru-node-1",
			nodeState: NodeStateReady,
			capacity:  capacity,
			usage:     NodeResources{},
			replicas: []stateful.ReplicaHealth{
				{RoleKind: "terrabase", AllocationId: "terrascale-gru-terrabase-1", MinReplicas: 3},
				{RoleKind: "terrabase", AllocationId: "terrascale-gru-terrabase-1", MinReplicas: 3},
			},
			expectParam: "statefulReplicas",
		},
		{
			name:      "invalid replica inside observation",
			nodeId:    "gru-node-1",
			nodeState: NodeStateReady,
			capacity:  capacity,
			usage:     NodeResources{},
			replicas: []stateful.ReplicaHealth{
				{RoleKind: "terrabase", AllocationId: "ok-1", MinReplicas: 0},
			},
			// The replica revalidation surfaces the stateful package's own
			// typed error, exactly like the containerd adapter surfaces
			// HostRuntimePlan.Create's errors without wrapping them.
			expectStatefulParam: "minReplicas",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observation, err := NewNodeObservation(
				test.nodeId, test.nodeState, test.capacity, test.usage, test.pending, test.replicas)
			if test.expectParam != "" {
				if err == nil {
					t.Fatal("expected an error, got a valid observation")
				}
				if !errorsAsParam(err, test.expectParam) {
					t.Fatalf("error %v does not reference param %q", err, test.expectParam)
				}
				return
			}
			if test.expectStatefulParam != "" {
				if err == nil {
					t.Fatal("expected an error, got a valid observation")
				}
				var statefulOutOfRange *stateful.ArgumentOutOfRangeError
				if !errors.As(err, &statefulOutOfRange) ||
					statefulOutOfRange.Param != test.expectStatefulParam {
					t.Fatalf("error %v does not reference stateful param %q", err, test.expectStatefulParam)
				}
				return
			}
			if err != nil {
				t.Fatalf("observation: %v", err)
			}
			if observation.NodeId != test.nodeId || observation.NodeState != test.nodeState ||
				observation.PendingAllocations != test.pending ||
				len(observation.StatefulReplicas) != len(test.replicas) {
				t.Fatalf("observation = %+v", observation)
			}
		})
	}
}

func TestNewAllocationDemand(t *testing.T) {
	tests := []struct {
		name        string
		roleId      string
		roleKind    string
		resources   NodeResources
		expectParam string
	}{
		{
			name:      "stateful demand",
			roleId:    "terrabase-gru",
			roleKind:  "terrabase",
			resources: NodeResources{MemoryBytes: 8 << 30, CpuPercent: 400, Tasks: 1024},
		},
		{
			name:        "invalid role id",
			roleId:      "TerraBase",
			roleKind:    "terrabase",
			expectParam: "roleId",
		},
		{
			name:        "invalid role kind",
			roleId:      "terrabase-gru",
			roleKind:    "role kind",
			expectParam: "roleKind",
		},
		{
			name:        "negative demand memory",
			roleId:      "terrabase-gru",
			roleKind:    "terrabase",
			resources:   NodeResources{MemoryBytes: -1},
			expectParam: "memoryBytes",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			demand, err := NewAllocationDemand(test.roleId, test.roleKind, false, test.resources)
			if test.expectParam != "" {
				if err == nil {
					t.Fatal("expected an error, got a valid demand")
				}
				if !errorsAsParam(err, test.expectParam) {
					t.Fatalf("error %v does not reference param %q", err, test.expectParam)
				}
				return
			}
			if err != nil {
				t.Fatalf("demand: %v", err)
			}
			if demand.RoleId != test.roleId || demand.RoleKind != test.roleKind || demand.Stateful {
				t.Fatalf("demand = %+v", demand)
			}
		})
	}
}

func TestNewAutoscalerConfig(t *testing.T) {
	tests := []struct {
		name                     string
		minNodes                 int
		maxNodes                 int
		scaleUpHeadroomPercent   int
		scaleDownHeadroomPercent int
		scaleUpConfirmTicks      int
		scaleDownConfirmTicks    int
		maxConcurrentProvisions  int
		flapSuppressionTicks     int
		expectParam              string
	}{
		{
			name:                     "sane policy",
			minNodes:                 3,
			maxNodes:                 12,
			scaleUpHeadroomPercent:   20,
			scaleDownHeadroomPercent: 30,
			scaleUpConfirmTicks:      3,
			scaleDownConfirmTicks:    5,
			maxConcurrentProvisions:  2,
			flapSuppressionTicks: 4,
		},
		{
			name:                     "zero min nodes",
			minNodes:                 0,
			maxNodes:                 12,
			scaleUpHeadroomPercent:   20,
			scaleDownHeadroomPercent: 30,
			scaleUpConfirmTicks:      3,
			scaleDownConfirmTicks:    5,
			maxConcurrentProvisions:  2,
			flapSuppressionTicks: 4,
			expectParam:              "minNodes",
		},
		{
			name:                     "max below min",
			minNodes:                 3,
			maxNodes:                 2,
			scaleUpHeadroomPercent:   20,
			scaleDownHeadroomPercent: 30,
			scaleUpConfirmTicks:      3,
			scaleDownConfirmTicks:    5,
			maxConcurrentProvisions:  2,
			flapSuppressionTicks: 4,
			expectParam:              "maxNodes",
		},
		{
			name:                     "zero scale up headroom",
			minNodes:                 3,
			maxNodes:                 12,
			scaleUpHeadroomPercent:   0,
			scaleDownHeadroomPercent: 30,
			scaleUpConfirmTicks:      3,
			scaleDownConfirmTicks:    5,
			maxConcurrentProvisions:  2,
			flapSuppressionTicks: 4,
			expectParam:              "scaleUpHeadroomPercent",
		},
		{
			name:                     "full scale down headroom",
			minNodes:                 3,
			maxNodes:                 12,
			scaleUpHeadroomPercent:   20,
			scaleDownHeadroomPercent: 100,
			scaleUpConfirmTicks:      3,
			scaleDownConfirmTicks:    5,
			maxConcurrentProvisions:  2,
			flapSuppressionTicks: 4,
			expectParam:              "scaleDownHeadroomPercent",
		},
		{
			name:                     "zero scale up ticks",
			minNodes:                 3,
			maxNodes:                 12,
			scaleUpHeadroomPercent:   20,
			scaleDownHeadroomPercent: 30,
			scaleUpConfirmTicks:      0,
			scaleDownConfirmTicks:    5,
			maxConcurrentProvisions:  2,
			flapSuppressionTicks: 4,
			expectParam:              "scaleUpConfirmTicks",
		},
		{
			name:                     "zero scale down ticks",
			minNodes:                 3,
			maxNodes:                 12,
			scaleUpHeadroomPercent:   20,
			scaleDownHeadroomPercent: 30,
			scaleUpConfirmTicks:      3,
			scaleDownConfirmTicks:    0,
			maxConcurrentProvisions:  2,
			flapSuppressionTicks: 4,
			expectParam:              "scaleDownConfirmTicks",
		},
		{
			name:                     "zero provision concurrency",
			minNodes:                 3,
			maxNodes:                 12,
			scaleUpHeadroomPercent:   20,
			scaleDownHeadroomPercent: 30,
			scaleUpConfirmTicks:      3,
			scaleDownConfirmTicks:    5,
			maxConcurrentProvisions:  0,
			flapSuppressionTicks: 4,
			expectParam:              "maxConcurrentProvisions",
		},
		{
			name:                     "provision concurrency above bound",
			minNodes:                 3,
			maxNodes:                 12,
			scaleUpHeadroomPercent:   20,
			scaleDownHeadroomPercent: 30,
			scaleUpConfirmTicks:      3,
			scaleDownConfirmTicks:    5,
			maxConcurrentProvisions:  65,
			flapSuppressionTicks:     4,
			expectParam:              "maxConcurrentProvisions",
		},
		{
			name:                     "negative flap suppression ticks",
			minNodes:                 3,
			maxNodes:                 12,
			scaleUpHeadroomPercent:   20,
			scaleDownHeadroomPercent: 30,
			scaleUpConfirmTicks:      3,
			scaleDownConfirmTicks:    5,
			maxConcurrentProvisions:  2,
			flapSuppressionTicks:     -1,
			expectParam:              "flapSuppressionTicks",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config, err := NewAutoscalerConfig(
				test.minNodes,
				test.maxNodes,
				test.scaleUpHeadroomPercent,
				test.scaleDownHeadroomPercent,
				test.scaleUpConfirmTicks,
				test.scaleDownConfirmTicks,
				test.maxConcurrentProvisions,
				test.flapSuppressionTicks)
			if test.expectParam != "" {
				if err == nil {
					t.Fatal("expected an error, got a valid config")
				}
				if !errorsAsParam(err, test.expectParam) {
					t.Fatalf("error %v does not reference param %q", err, test.expectParam)
				}
				return
			}
			if err != nil {
				t.Fatalf("config: %v", err)
			}
			if config.MinNodes != test.minNodes || config.MaxNodes != test.maxNodes ||
				config.ScaleUpHeadroomPercent != test.scaleUpHeadroomPercent ||
				config.ScaleDownHeadroomPercent != test.scaleDownHeadroomPercent ||
				config.ScaleUpConfirmTicks != test.scaleUpConfirmTicks ||
				config.ScaleDownConfirmTicks != test.scaleDownConfirmTicks ||
				config.MaxConcurrentProvisions != test.maxConcurrentProvisions ||
				config.FlapSuppressionTicks != test.flapSuppressionTicks {
				t.Fatalf("config = %+v", config)
			}
		})
	}
}

func TestAutoscalerActionClosedUnion(t *testing.T) {
	provision, err := NewProvisionNodeAction(NodeProvisionRequest{
		NodeId:    "gru-node-9",
		NodeClass: "worker-medium",
		Resources: NodeResources{MemoryBytes: 32 << 30, CpuPercent: 800, Tasks: 2048},
		Reason:    "unschedulable terrabase demand",
	})
	if err != nil {
		t.Fatalf("provision action: %v", err)
	}
	if provision.Kind() != AutoscalerActionProvisionNode {
		t.Fatalf("kind = %v", provision.Kind())
	}
	if provision.ProvisionRequest().NodeId != "gru-node-9" {
		t.Fatalf("request = %+v", provision.ProvisionRequest())
	}
	if provision.NodeId() != "" {
		t.Fatal("a provision action carries no target node id")
	}

	for name, constructor := range map[string]func(string) (AutoscalerAction, error){
		"cordon": NewCordonNodeAction,
		"drain":  NewDrainNodeAction,
		"retire": NewRetireNodeAction,
	} {
		action, err := constructor("gru-node-4")
		if err != nil {
			t.Fatalf("%s action: %v", name, err)
		}
		if action.NodeId() != "gru-node-4" {
			t.Fatalf("%s action node = %q", name, action.NodeId())
		}
		if _, err := constructor("Gru_Node"); err == nil {
			t.Fatalf("%s action must reject an invalid node id", name)
		}
	}

	invalidResources := NodeResources{Tasks: -1}
	if _, err := NewProvisionNodeAction(NodeProvisionRequest{
		NodeId: "gru-node-9", NodeClass: "worker", Resources: invalidResources, Reason: "r",
	}); !errorsAsParam(err, "tasks") {
		t.Fatalf("a provision action must revalidate its request, got %v", err)
	}

	// The zero AutoscalerAction is constructible (like the zero AdmittedRole);
	// only the New* constructors produce valid payloads, which the checks
	// above enforce, so nothing may be derived from a zero action's payload.
	var zero AutoscalerAction
	if zero.ProvisionRequest().NodeId != "" || zero.NodeId() != "" {
		t.Fatal("the zero action must carry an empty payload")
	}
}

func TestNewNodeProvisionRequest(t *testing.T) {
	tests := []struct {
		name        string
		nodeId      string
		nodeClass   string
		resources   NodeResources
		reason      string
		expectParam string
	}{
		{
			name:      "valid request",
			nodeId:    "gru-node-9",
			nodeClass: "worker-medium",
			resources: NodeResources{MemoryBytes: 32 << 30, CpuPercent: 800, Tasks: 2048},
			reason:    "unschedulable terrabase demand",
		},
		{
			name:        "invalid node id",
			nodeId:      "gru node 9",
			nodeClass:   "worker-medium",
			reason:      "unschedulable terrabase demand",
			expectParam: "nodeId",
		},
		{
			name:        "invalid node class",
			nodeId:      "gru-node-9",
			nodeClass:   "Worker/Medium",
			reason:      "unschedulable terrabase demand",
			expectParam: "nodeClass",
		},
		{
			name:        "invalid resources",
			nodeId:      "gru-node-9",
			nodeClass:   "worker-medium",
			resources:   NodeResources{Tasks: -1},
			reason:      "unschedulable terrabase demand",
			expectParam: "tasks",
		},
		{
			name:        "empty reason",
			nodeId:      "gru-node-9",
			nodeClass:   "worker-medium",
			reason:      "",
			expectParam: "reason",
		},
		{
			name:        "oversized reason",
			nodeId:      "gru-node-9",
			nodeClass:   "worker-medium",
			reason:      strings.Repeat("r", 257),
			expectParam: "reason",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, err := NewNodeProvisionRequest(
				test.nodeId, test.nodeClass, test.resources, test.reason)
			if test.expectParam != "" {
				if err == nil {
					t.Fatal("expected an error, got a valid request")
				}
				if !errorsAsParam(err, test.expectParam) {
					t.Fatalf("error %v does not reference param %q", err, test.expectParam)
				}
				return
			}
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			if request.NodeId != test.nodeId || request.NodeClass != test.nodeClass ||
				request.Reason != test.reason {
				t.Fatalf("request = %+v", request)
			}
		})
	}
}
