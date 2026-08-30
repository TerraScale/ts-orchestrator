// Package hostagent defines the per-node host agent contracts of the
// rootless-hosting and autoscaling lane: the node identity token, heartbeat
// metric samples, the NATS transport subjects that carry orchestrator-to-node
// workload commands, and the typed command receipts the agent returns.
package hostagent

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// ArgumentError reports an invalid argument passed to a constructor.
type ArgumentError struct {
	Param   string
	Message string
}

func (e *ArgumentError) Error() string { return e.Message }

// ArgumentOutOfRangeError reports an argument outside its closed range.
type ArgumentOutOfRangeError struct {
	Param   string
	Message string
}

func (e *ArgumentOutOfRangeError) Error() string { return e.Message }

// InvalidOperationError reports an operation invalid for the current state.
type InvalidOperationError struct {
	Message string
}

func (e *InvalidOperationError) Error() string { return e.Message }

// InvalidDataError reports malformed observed or received data.
type InvalidDataError struct {
	Message string
}

func (e *InvalidDataError) Error() string { return e.Message }

var hostAgentTokenPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)

var hostAgentFingerprintPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

const (
	hostAgentMaximumTokenLength   = 63
	hostAgentMaximumDetailLength  = 512
	hostAgentMaximumPlanJsonBytes = 256 * 1024
	hostAgentMaximumCpuPercent    = 10000
)

// requireHostAgentToken enforces the bounded canonical token vocabulary shared
// by node identifiers and command identifiers.
func requireHostAgentToken(value, param, message string) (string, error) {
	if len(value) < 1 || len(value) > hostAgentMaximumTokenLength ||
		!hostAgentTokenPattern.MatchString(value) {
		return "", &ArgumentError{Param: param, Message: message}
	}
	return value, nil
}

// requireHostAgentDetail enforces a bounded, control-character-free detail
// string so receipts stay log-safe.
func requireHostAgentDetail(value, param string) (string, error) {
	if len(value) > hostAgentMaximumDetailLength || strings.ContainsFunc(value, isControlRune) {
		return "", &ArgumentError{
			Param:   param,
			Message: "Detail must be bounded and free of control characters.",
		}
	}
	return value, nil
}

func isControlRune(r rune) bool { return r < 0x20 || r == 0x7f }

// requireHostAgentFingerprint accepts either the empty fingerprint or the
// canonical 64-character lowercase SHA-256 fingerprint of a runtime plan.
func requireHostAgentFingerprint(value, param string) (string, error) {
	if value == "" {
		return "", nil
	}
	if !hostAgentFingerprintPattern.MatchString(value) {
		return "", &ArgumentError{
			Param:   param,
			Message: "Plan fingerprint must be lowercase SHA-256 hex.",
		}
	}
	return value, nil
}

// NodeId is a bounded canonical node token.
type NodeId struct {
	Value string
}

// NewNodeId validates the DNS-style node token.
func NewNodeId(value string) (NodeId, error) {
	if _, err := requireHostAgentToken(value, "value",
		"Node ID must be a lowercase DNS-style token."); err != nil {
		return NodeId{}, err
	}
	return NodeId{Value: value}, nil
}

func (id NodeId) String() string { return id.Value }

// NodeMetricsSample is one heartbeat metric sample of a node.
type NodeMetricsSample struct {
	MemoryTotalBytes   int64
	MemoryUsedBytes    int64
	CpuQuotaPercent    int
	CpuUsedPercent     int
	TasksMax           int
	TasksRunning       int
	PendingAllocations int
}

// NewNodeMetricsSample validates one metric sample: every dimension is
// non-negative, memory usage stays inside the total, running tasks stay
// inside the task ceiling, CPU usage stays inside the cgroup quota, and the
// CPU envelope stays inside the closed percent bound.
func NewNodeMetricsSample(
	memoryTotalBytes int64,
	memoryUsedBytes int64,
	cpuQuotaPercent int,
	cpuUsedPercent int,
	tasksMax int,
	tasksRunning int,
	pendingAllocations int,
) (NodeMetricsSample, error) {
	if memoryTotalBytes < 0 {
		return NodeMetricsSample{}, &ArgumentOutOfRangeError{
			Param:   "memoryTotalBytes",
			Message: "Memory total must be non-negative.",
		}
	}
	if memoryUsedBytes < 0 || memoryUsedBytes > memoryTotalBytes {
		return NodeMetricsSample{}, &ArgumentOutOfRangeError{
			Param:   "memoryUsedBytes",
			Message: "Memory used must be between zero and the total.",
		}
	}
	if cpuQuotaPercent < 1 || cpuQuotaPercent > hostAgentMaximumCpuPercent {
		return NodeMetricsSample{}, &ArgumentOutOfRangeError{
			Param: "cpuQuotaPercent",
			Message: fmt.Sprintf("CPU quota must be between 1 and %d percent.",
				hostAgentMaximumCpuPercent),
		}
	}
	if cpuUsedPercent < 0 || cpuUsedPercent > cpuQuotaPercent {
		return NodeMetricsSample{}, &ArgumentOutOfRangeError{
			Param:   "cpuUsedPercent",
			Message: "CPU used must be between zero and the quota.",
		}
	}
	if tasksMax < 0 {
		return NodeMetricsSample{}, &ArgumentOutOfRangeError{
			Param:   "tasksMax",
			Message: "Task ceiling must be non-negative.",
		}
	}
	if tasksRunning < 0 || tasksRunning > tasksMax {
		return NodeMetricsSample{}, &ArgumentOutOfRangeError{
			Param:   "tasksRunning",
			Message: "Running tasks must be between zero and the ceiling.",
		}
	}
	if pendingAllocations < 0 {
		return NodeMetricsSample{}, &ArgumentOutOfRangeError{
			Param:   "pendingAllocations",
			Message: "Pending allocation count must be non-negative.",
		}
	}
	return NodeMetricsSample{
		MemoryTotalBytes:   memoryTotalBytes,
		MemoryUsedBytes:    memoryUsedBytes,
		CpuQuotaPercent:    cpuQuotaPercent,
		CpuUsedPercent:     cpuUsedPercent,
		TasksMax:           tasksMax,
		TasksRunning:       tasksRunning,
		PendingAllocations: pendingAllocations,
	}, nil
}

// NodeHeartbeat is one published heartbeat of a node agent.
type NodeHeartbeat struct {
	NodeId      NodeId
	UnixSeconds int64
	Metrics     NodeMetricsSample
}

// NewNodeHeartbeat validates one heartbeat. The node token is revalidated,
// the timestamp is a positive Unix epoch second, and the metrics sample is
// revalidated at this trust boundary.
func NewNodeHeartbeat(nodeId NodeId, unixSeconds int64, metrics NodeMetricsSample) (NodeHeartbeat, error) {
	validatedNode, err := NewNodeId(nodeId.Value)
	if err != nil {
		return NodeHeartbeat{}, err
	}
	if unixSeconds <= 0 {
		return NodeHeartbeat{}, &ArgumentOutOfRangeError{
			Param:   "unixSeconds",
			Message: "Heartbeat timestamp must be a positive Unix epoch second.",
		}
	}
	validatedMetrics, err := NewNodeMetricsSample(
		metrics.MemoryTotalBytes, metrics.MemoryUsedBytes, metrics.CpuQuotaPercent,
		metrics.CpuUsedPercent, metrics.TasksMax, metrics.TasksRunning,
		metrics.PendingAllocations)
	if err != nil {
		return NodeHeartbeat{}, err
	}
	return NodeHeartbeat{
		NodeId:      validatedNode,
		UnixSeconds: unixSeconds,
		Metrics:     validatedMetrics,
	}, nil
}

// NATS subject constants of the node transport. The converge, observe, stop,
// and delete leaves are request-reply; the heartbeat leaf is publish-only;
// the cordon and drain-status leaves carry node lifecycle state.
const (
	// NatsSubjectNodePrefix is the shared subject prefix of every node leaf.
	NatsSubjectNodePrefix = "terrascale.node.v1"
	// NatsSubjectLeafConverge requests plan convergence (request-reply).
	NatsSubjectLeafConverge = "converge"
	// NatsSubjectLeafObserve requests a plan observation (request-reply).
	NatsSubjectLeafObserve = "observe"
	// NatsSubjectLeafStop requests a running allocation stop (request-reply).
	NatsSubjectLeafStop = "stop"
	// NatsSubjectLeafDelete requests an allocation deletion (request-reply).
	NatsSubjectLeafDelete = "delete"
	// NatsSubjectLeafHeartbeat publishes periodic node metrics.
	NatsSubjectLeafHeartbeat = "heartbeat"
	// NatsSubjectLeafCordon marks a node unschedulable.
	NatsSubjectLeafCordon = "cordon"
	// NatsSubjectLeafDrainStatus reports the drain progress of a node.
	NatsSubjectLeafDrainStatus = "drain-status"
)

// nodeSubject builds one validated node subject leaf.
func nodeSubject(nodeId NodeId, leaf string) (string, error) {
	validated, err := NewNodeId(nodeId.Value)
	if err != nil {
		return "", err
	}
	return NatsSubjectNodePrefix + "." + validated.Value + "." + leaf, nil
}

// NodeConvergeSubject builds the request-reply converge subject of a node.
func NodeConvergeSubject(nodeId NodeId) (string, error) {
	return nodeSubject(nodeId, NatsSubjectLeafConverge)
}

// NodeObserveSubject builds the request-reply observe subject of a node.
func NodeObserveSubject(nodeId NodeId) (string, error) {
	return nodeSubject(nodeId, NatsSubjectLeafObserve)
}

// NodeStopSubject builds the request-reply stop subject of a node.
func NodeStopSubject(nodeId NodeId) (string, error) {
	return nodeSubject(nodeId, NatsSubjectLeafStop)
}

// NodeDeleteSubject builds the request-reply delete subject of a node.
func NodeDeleteSubject(nodeId NodeId) (string, error) {
	return nodeSubject(nodeId, NatsSubjectLeafDelete)
}

// NodeHeartbeatSubject builds the publish-only heartbeat subject of a node.
func NodeHeartbeatSubject(nodeId NodeId) (string, error) {
	return nodeSubject(nodeId, NatsSubjectLeafHeartbeat)
}

// NodeCordonSubject builds the cordon subject of a node.
func NodeCordonSubject(nodeId NodeId) (string, error) {
	return nodeSubject(nodeId, NatsSubjectLeafCordon)
}

// NodeDrainStatusSubject builds the drain-status subject of a node.
func NodeDrainStatusSubject(nodeId NodeId) (string, error) {
	return nodeSubject(nodeId, NatsSubjectLeafDrainStatus)
}

// WorkloadCommandRequest is one orchestrator command carrying a serialized
// canonical runtime plan to a node agent.
type WorkloadCommandRequest struct {
	PlanJson  []byte
	CommandId string
}

// NewWorkloadCommandRequest validates one command: the plan payload is
// nonempty, bounded, and syntactically valid JSON, and the command
// identifier is a bounded canonical token.
func NewWorkloadCommandRequest(planJson []byte, commandId string) (WorkloadCommandRequest, error) {
	if len(planJson) == 0 {
		return WorkloadCommandRequest{}, &ArgumentError{
			Param:   "planJson",
			Message: "A plan payload is required.",
		}
	}
	if len(planJson) > hostAgentMaximumPlanJsonBytes {
		return WorkloadCommandRequest{}, &ArgumentError{
			Param: "planJson",
			Message: fmt.Sprintf("Plan payload exceeds the bound of %d bytes.",
				hostAgentMaximumPlanJsonBytes),
		}
	}
	if !json.Valid(planJson) {
		return WorkloadCommandRequest{}, &InvalidDataError{
			Message: "Plan payload must be syntactically valid JSON.",
		}
	}
	validatedCommand, err := requireHostAgentToken(commandId, "commandId",
		"Command ID must be a lowercase DNS-style token.")
	if err != nil {
		return WorkloadCommandRequest{}, err
	}
	return WorkloadCommandRequest{
		PlanJson:  append([]byte(nil), planJson...),
		CommandId: validatedCommand,
	}, nil
}

// ConvergeReceipt is the agent receipt of one converge command.
type ConvergeReceipt struct {
	CommandId       string
	Accepted        bool
	Detail          string
	PlanFingerprint string
}

// NewConvergeReceipt validates one converge receipt.
func NewConvergeReceipt(commandId string, accepted bool, detail string, planFingerprint string) (ConvergeReceipt, error) {
	validated, err := validateReceiptFields(commandId, detail, planFingerprint)
	if err != nil {
		return ConvergeReceipt{}, err
	}
	return ConvergeReceipt{
		CommandId:       validated.commandId,
		Accepted:        accepted,
		Detail:          validated.detail,
		PlanFingerprint: validated.planFingerprint,
	}, nil
}

// ObserveReceipt is the agent receipt of one observe command.
type ObserveReceipt struct {
	CommandId       string
	Accepted        bool
	Detail          string
	PlanFingerprint string
}

// NewObserveReceipt validates one observe receipt.
func NewObserveReceipt(commandId string, accepted bool, detail string, planFingerprint string) (ObserveReceipt, error) {
	validated, err := validateReceiptFields(commandId, detail, planFingerprint)
	if err != nil {
		return ObserveReceipt{}, err
	}
	return ObserveReceipt{
		CommandId:       validated.commandId,
		Accepted:        accepted,
		Detail:          validated.detail,
		PlanFingerprint: validated.planFingerprint,
	}, nil
}

// StopReceipt is the agent receipt of one stop command.
type StopReceipt struct {
	CommandId       string
	Accepted        bool
	Detail          string
	PlanFingerprint string
}

// NewStopReceipt validates one stop receipt.
func NewStopReceipt(commandId string, accepted bool, detail string, planFingerprint string) (StopReceipt, error) {
	validated, err := validateReceiptFields(commandId, detail, planFingerprint)
	if err != nil {
		return StopReceipt{}, err
	}
	return StopReceipt{
		CommandId:       validated.commandId,
		Accepted:        accepted,
		Detail:          validated.detail,
		PlanFingerprint: validated.planFingerprint,
	}, nil
}

// DeleteReceipt is the agent receipt of one delete command.
type DeleteReceipt struct {
	CommandId       string
	Accepted        bool
	Detail          string
	PlanFingerprint string
}

// NewDeleteReceipt validates one delete receipt.
func NewDeleteReceipt(commandId string, accepted bool, detail string, planFingerprint string) (DeleteReceipt, error) {
	validated, err := validateReceiptFields(commandId, detail, planFingerprint)
	if err != nil {
		return DeleteReceipt{}, err
	}
	return DeleteReceipt{
		CommandId:       validated.commandId,
		Accepted:        accepted,
		Detail:          validated.detail,
		PlanFingerprint: validated.planFingerprint,
	}, nil
}

type receiptFields struct {
	commandId       string
	detail          string
	planFingerprint string
}

// validateReceiptFields applies the shared receipt validation: the command
// identifier is a bounded canonical token, the detail is bounded and
// control-character-free, and the fingerprint is either empty or canonical
// lowercase SHA-256 hex.
func validateReceiptFields(commandId, detail, planFingerprint string) (receiptFields, error) {
	validatedCommand, err := requireHostAgentToken(commandId, "commandId",
		"Command ID must be a lowercase DNS-style token.")
	if err != nil {
		return receiptFields{}, err
	}
	validatedDetail, err := requireHostAgentDetail(detail, "detail")
	if err != nil {
		return receiptFields{}, err
	}
	validatedFingerprint, err := requireHostAgentFingerprint(planFingerprint, "planFingerprint")
	if err != nil {
		return receiptFields{}, err
	}
	return receiptFields{
		commandId:       validatedCommand,
		detail:          validatedDetail,
		planFingerprint: validatedFingerprint,
	}, nil
}
