package hostagent

import (
	"errors"
	"strings"
	"testing"
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
	return false
}

func TestNewNodeId(t *testing.T) {
	tests := []struct {
		name        string
		value       string
		expectValid bool
	}{
		{name: "canonical node token", value: "gru-node-1", expectValid: true},
		{name: "uuid token", value: "550e8400-e29b-41d4-a716-446655440000", expectValid: true},
		{name: "uppercase", value: "GRU-NODE-1", expectValid: false},
		{name: "underscore", value: "gru_node_1", expectValid: false},
		{name: "leading dash", value: "-gru-node-1", expectValid: false},
		{name: "empty", value: "", expectValid: false},
		{name: "too long", value: strings.Repeat("n", 64), expectValid: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			id, err := NewNodeId(test.value)
			if test.expectValid {
				if err != nil {
					t.Fatalf("id: %v", err)
				}
				if id.String() != test.value {
					t.Fatalf("id = %q, want %q", id.String(), test.value)
				}
				return
			}
			if err == nil {
				t.Fatal("expected an error, got a valid id")
			}
			if !errorsAsParam(err, "value") {
				t.Fatalf("error %v does not reference param value", err)
			}
		})
	}
}

func TestNewNodeMetricsSample(t *testing.T) {
	tests := []struct {
		name        string
		memoryTotal int64
		memoryUsed  int64
		cpuQuota    int
		cpuUsed     int
		tasksMax    int
		tasksRun    int
		pending     int
		expectParam string
	}{
		{
			name:        "healthy sample",
			memoryTotal: 16 << 30,
			memoryUsed:  8 << 30,
			cpuQuota:    800,
			cpuUsed:     300,
			tasksMax:    2048,
			tasksRun:    512,
			pending:     1,
		},
		{
			name:        "idle sample",
			memoryTotal: 16 << 30,
			memoryUsed:  0,
			cpuQuota:    1,
			cpuUsed:     0,
			tasksMax:    0,
			tasksRun:    0,
		},
		{
			name:        "negative memory total",
			memoryTotal: -1,
			expectParam: "memoryTotalBytes",
		},
		{
			name:        "memory used above total",
			memoryTotal: 1024,
			memoryUsed:  2048,
			expectParam: "memoryUsedBytes",
		},
		{
			name:        "zero cpu quota",
			cpuQuota:    0,
			expectParam: "cpuQuotaPercent",
		},
		{
			name:        "cpu used above quota",
			cpuQuota:    100,
			cpuUsed:     101,
			expectParam: "cpuUsedPercent",
		},
		{
			name:        "negative running tasks",
			cpuQuota:    100,
			tasksMax:    10,
			tasksRun:    -1,
			expectParam: "tasksRunning",
		},
		{
			name:        "running tasks above ceiling",
			cpuQuota:    100,
			tasksMax:    10,
			tasksRun:    11,
			expectParam: "tasksRunning",
		},
		{
			name:        "negative pending allocations",
			cpuQuota:    100,
			pending:     -1,
			expectParam: "pendingAllocations",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sample, err := NewNodeMetricsSample(
				test.memoryTotal, test.memoryUsed, test.cpuQuota, test.cpuUsed,
				test.tasksMax, test.tasksRun, test.pending)
			if test.expectParam != "" {
				if err == nil {
					t.Fatal("expected an error, got a valid sample")
				}
				if !errorsAsParam(err, test.expectParam) {
					t.Fatalf("error %v does not reference param %q", err, test.expectParam)
				}
				return
			}
			if err != nil {
				t.Fatalf("sample: %v", err)
			}
			if sample.MemoryTotalBytes != test.memoryTotal ||
				sample.MemoryUsedBytes != test.memoryUsed ||
				sample.CpuQuotaPercent != test.cpuQuota ||
				sample.CpuUsedPercent != test.cpuUsed ||
				sample.TasksMax != test.tasksMax ||
				sample.TasksRunning != test.tasksRun ||
				sample.PendingAllocations != test.pending {
				t.Fatalf("sample = %+v", sample)
			}
		})
	}
}

func TestNewNodeHeartbeat(t *testing.T) {
	validMetrics, err := NewNodeMetricsSample(16<<30, 8<<30, 800, 300, 2048, 512, 1)
	if err != nil {
		t.Fatalf("metrics: %v", err)
	}
	nodeId, err := NewNodeId("gru-node-1")
	if err != nil {
		t.Fatalf("node: %v", err)
	}

	heartbeat, err := NewNodeHeartbeat(nodeId, 1770000000, validMetrics)
	if err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	if heartbeat.NodeId.Value != "gru-node-1" || heartbeat.UnixSeconds != 1770000000 {
		t.Fatalf("heartbeat = %+v", heartbeat)
	}

	if _, err := NewNodeHeartbeat(nodeId, 0, validMetrics); !errorsAsParam(err, "unixSeconds") {
		t.Fatalf("non-positive timestamp must be rejected with unixSeconds, got %v", err)
	}
	if _, err := NewNodeHeartbeat(NodeId{}, 1770000000, validMetrics); !errorsAsParam(err, "value") {
		t.Fatalf("zero node id must be rejected with value, got %v", err)
	}
	invalidMetrics := validMetrics
	invalidMetrics.PendingAllocations = -1
	if _, err := NewNodeHeartbeat(nodeId, 1770000000, invalidMetrics); !errorsAsParam(err, "pendingAllocations") {
		t.Fatalf("invalid metrics must surface their own error, got %v", err)
	}
}

func TestNodeSubjectBuildersProduceTheExactWireNames(t *testing.T) {
	nodeId, err := NewNodeId("gru-node-7")
	if err != nil {
		t.Fatalf("node: %v", err)
	}

	tests := []struct {
		name     string
		build    func(NodeId) (string, error)
		expected string
	}{
		{name: "converge", build: NodeConvergeSubject, expected: "terrascale.node.v1.gru-node-7.converge"},
		{name: "observe", build: NodeObserveSubject, expected: "terrascale.node.v1.gru-node-7.observe"},
		{name: "stop", build: NodeStopSubject, expected: "terrascale.node.v1.gru-node-7.stop"},
		{name: "delete", build: NodeDeleteSubject, expected: "terrascale.node.v1.gru-node-7.delete"},
		{name: "heartbeat", build: NodeHeartbeatSubject, expected: "terrascale.node.v1.gru-node-7.heartbeat"},
		{name: "cordon", build: NodeCordonSubject, expected: "terrascale.node.v1.gru-node-7.cordon"},
		{name: "drain-status", build: NodeDrainStatusSubject, expected: "terrascale.node.v1.gru-node-7.drain-status"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			subject, err := test.build(nodeId)
			if err != nil {
				t.Fatalf("subject: %v", err)
			}
			if subject != test.expected {
				t.Fatalf("subject = %q, want %q", subject, test.expected)
			}
		})
	}

	if _, err := NodeConvergeSubject(NodeId{}); err == nil {
		t.Fatal("a zero node id must fail closed")
	}
}

func TestNewWorkloadCommandRequest(t *testing.T) {
	validPlan := []byte(`{"schemaVersion":2,"role":"orchestrator"}`)

	request, err := NewWorkloadCommandRequest(validPlan, "cmd-0001")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if request.CommandId != "cmd-0001" || string(request.PlanJson) != string(validPlan) {
		t.Fatalf("request = %+v", request)
	}

	tests := []struct {
		name        string
		planJson    []byte
		commandId   string
		wantType    string
		expectParam string
	}{
		{name: "empty plan", planJson: nil, commandId: "cmd-0001", wantType: "ArgumentError", expectParam: "planJson"},
		{
			name:        "oversized plan",
			planJson:    append([]byte(`{"pad":"`), bytesOf('a', hostAgentMaximumPlanJsonBytes)...),
			commandId:   "cmd-0001",
			wantType:    "ArgumentError",
			expectParam: "planJson",
		},
		{name: "invalid json", planJson: []byte(`{"schemaVersion":`), commandId: "cmd-0001", wantType: "InvalidDataError"},
		{name: "invalid command id", planJson: validPlan, commandId: "CMD 1", wantType: "ArgumentError", expectParam: "commandId"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewWorkloadCommandRequest(test.planJson, test.commandId)
			if err == nil {
				t.Fatal("expected an error, got a valid request")
			}
			if !hostAgentErrorType(err, test.wantType) {
				t.Fatalf("expected %s, got %T: %v", test.wantType, err, err)
			}
			if test.expectParam != "" && !errorsAsParam(err, test.expectParam) {
				t.Fatalf("error %v does not reference param %q", err, test.expectParam)
			}
		})
	}
}

func bytesOf(fill byte, count int) []byte {
	value := make([]byte, count)
	for index := range value {
		value[index] = fill
	}
	return value
}

func TestReceiptConstructorsShareOneValidation(t *testing.T) {
	fingerprint := strings.Repeat("0123456789abcdef", 4)

	converge, err := NewConvergeReceipt("cmd-0001", true, "converged", fingerprint)
	if err != nil {
		t.Fatalf("converge: %v", err)
	}
	if !converge.Accepted || converge.PlanFingerprint != fingerprint {
		t.Fatalf("converge = %+v", converge)
	}

	rejected, err := NewStopReceipt("cmd-0002", false, "allocation not running", "")
	if err != nil {
		t.Fatalf("stop: %v", err)
	}
	if rejected.Accepted || rejected.PlanFingerprint != "" {
		t.Fatalf("stop = %+v", rejected)
	}

	invalidDetail := strings.Repeat("d", 513)
	if _, err := NewObserveReceipt("cmd-0003", true, invalidDetail, ""); !errorsAsParam(err, "detail") {
		t.Fatalf("oversized detail must be rejected with detail, got %v", err)
	}
	controlDetail := "observed\x00state"
	if _, err := NewDeleteReceipt("cmd-0004", true, controlDetail, ""); !errorsAsParam(err, "detail") {
		t.Fatalf("control-character detail must be rejected with detail, got %v", err)
	}
	uppercaseFingerprint := strings.ToUpper(fingerprint)
	if _, err := NewConvergeReceipt("cmd-0005", true, "ok", uppercaseFingerprint); !errorsAsParam(err, "planFingerprint") {
		t.Fatalf("uppercase fingerprint must be rejected with planFingerprint, got %v", err)
	}
	if _, err := NewConvergeReceipt("CMD-6", true, "ok", ""); !errorsAsParam(err, "commandId") {
		t.Fatalf("invalid command id must be rejected with commandId, got %v", err)
	}
}

// hostAgentErrorType reports whether err unwraps to the named package error.
func hostAgentErrorType(err error, name string) bool {
	switch name {
	case "ArgumentError":
		var target *ArgumentError
		return errors.As(err, &target)
	case "ArgumentOutOfRangeError":
		var target *ArgumentOutOfRangeError
		return errors.As(err, &target)
	case "InvalidOperationError":
		var target *InvalidOperationError
		return errors.As(err, &target)
	case "InvalidDataError":
		var target *InvalidDataError
		return errors.As(err, &target)
	default:
		return false
	}
}
