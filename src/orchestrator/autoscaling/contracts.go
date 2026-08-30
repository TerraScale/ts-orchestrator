// Package autoscaling defines the contracts of the autonomous node
// autoscaler: node capacity and demand observations, the bounded autoscaler
// configuration, the closed AutoscalerAction union, and the NodeProvisioner
// seam that creates and retires nodes.
package autoscaling

import (
	"context"
	"fmt"
	"regexp"

	"terrascale.tech/orchestrator/src/orchestrator/stateful"
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

// InvalidDataError reports malformed observed data.
type InvalidDataError struct {
	Message string
}

func (e *InvalidDataError) Error() string { return e.Message }

var autoscalingTokenPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)

const (
	autoscalingMaximumTokenLength          = 63
	autoscalingMaximumReasonLength         = 256
	autoscalingMaximumReplicaCount         = 1024
	autoscalingMaximumCpuPercent           = 10000
	autoscalingMaximumConcurrentProvisions = 64
)

// requireAutoscalingToken enforces the bounded canonical token vocabulary
// shared by node, role, and node-class identifiers.
func requireAutoscalingToken(value, param, message string) (string, error) {
	if len(value) < 1 || len(value) > autoscalingMaximumTokenLength ||
		!autoscalingTokenPattern.MatchString(value) {
		return "", &ArgumentError{Param: param, Message: message}
	}
	return value, nil
}

// NodeState is the closed node lifecycle vocabulary.
type NodeState int

const (
	NodeStateReady NodeState = iota
	NodeStateProvisioning
	NodeStateCordoned
	NodeStateDraining
	NodeStateRetired
)

func (s NodeState) defined() bool {
	return s >= NodeStateReady && s <= NodeStateRetired
}

func (s NodeState) String() string {
	names := [...]string{"Ready", "Provisioning", "Cordoned", "Draining", "Retired"}
	if s >= 0 && int(s) < len(names) {
		return names[s]
	}
	return fmt.Sprintf("NodeState(%d)", int(s))
}

// AllNodeStates lists every node state in declared order.
var AllNodeStates = []NodeState{
	NodeStateReady,
	NodeStateProvisioning,
	NodeStateCordoned,
	NodeStateDraining,
	NodeStateRetired,
}

// NodeResources is the closed per-node resource envelope of the autoscaler.
type NodeResources struct {
	MemoryBytes int64
	CpuPercent  int
	Tasks       int
}

// NewNodeResources validates one resource envelope; every dimension is
// non-negative and the CPU envelope stays inside the closed percent bound.
func NewNodeResources(memoryBytes int64, cpuPercent int, tasks int) (NodeResources, error) {
	if memoryBytes < 0 {
		return NodeResources{}, &ArgumentOutOfRangeError{
			Param:   "memoryBytes",
			Message: "Memory must be non-negative.",
		}
	}
	if cpuPercent < 0 || cpuPercent > autoscalingMaximumCpuPercent {
		return NodeResources{}, &ArgumentOutOfRangeError{
			Param: "cpuPercent",
			Message: fmt.Sprintf("CPU percent must be between 0 and %d.",
				autoscalingMaximumCpuPercent),
		}
	}
	if tasks < 0 {
		return NodeResources{}, &ArgumentOutOfRangeError{
			Param:   "tasks",
			Message: "Task count must be non-negative.",
		}
	}
	return NodeResources{MemoryBytes: memoryBytes, CpuPercent: cpuPercent, Tasks: tasks}, nil
}

// fits reports whether one envelope fits inside another envelope.
func (r NodeResources) fits(within NodeResources) bool {
	return r.MemoryBytes <= within.MemoryBytes &&
		r.CpuPercent <= within.CpuPercent &&
		r.Tasks <= within.Tasks
}

// NodeObservation is one autoscaler view of a node.
type NodeObservation struct {
	NodeId             string
	NodeState          NodeState
	Capacity           NodeResources
	Usage              NodeResources
	PendingAllocations int
	StatefulReplicas   []stateful.ReplicaHealth
}

// NewNodeObservation validates and snapshots one node observation. The node
// state comes from the closed vocabulary, usage fits inside capacity, the
// pending count is non-negative, and the replica list is bounded, validated,
// and duplicate-free.
func NewNodeObservation(
	nodeId string,
	nodeState NodeState,
	capacity NodeResources,
	usage NodeResources,
	pendingAllocations int,
	statefulReplicas []stateful.ReplicaHealth,
) (NodeObservation, error) {
	validatedNode, err := requireAutoscalingToken(nodeId, "nodeId",
		"Node ID must be a lowercase DNS-style token.")
	if err != nil {
		return NodeObservation{}, err
	}
	if !nodeState.defined() {
		return NodeObservation{}, &ArgumentOutOfRangeError{Param: "nodeState"}
	}
	validatedCapacity, err := NewNodeResources(capacity.MemoryBytes, capacity.CpuPercent, capacity.Tasks)
	if err != nil {
		return NodeObservation{}, err
	}
	validatedUsage, err := NewNodeResources(usage.MemoryBytes, usage.CpuPercent, usage.Tasks)
	if err != nil {
		return NodeObservation{}, err
	}
	if !validatedUsage.fits(validatedCapacity) {
		return NodeObservation{}, &ArgumentError{
			Param:   "usage",
			Message: "Usage cannot exceed capacity.",
		}
	}
	if pendingAllocations < 0 {
		return NodeObservation{}, &ArgumentOutOfRangeError{
			Param:   "pendingAllocations",
			Message: "Pending allocation count must be non-negative.",
		}
	}
	if len(statefulReplicas) > autoscalingMaximumReplicaCount {
		return NodeObservation{}, &ArgumentError{
			Param: "statefulReplicas",
			Message: fmt.Sprintf("Replica input exceeds the bound of %d entries.",
				autoscalingMaximumReplicaCount),
		}
	}
	snapshot := make([]stateful.ReplicaHealth, 0, len(statefulReplicas))
	seen := make(map[string]struct{}, len(statefulReplicas))
	for _, replica := range statefulReplicas {
		validated, err := stateful.NewReplicaHealth(
			replica.RoleKind, replica.AllocationId, replica.Up,
			replica.PeerAckCount, replica.MinReplicas, replica.LagBytes)
		if err != nil {
			return NodeObservation{}, err
		}
		key := validated.RoleKind + "/" + validated.AllocationId
		if _, duplicate := seen[key]; duplicate {
			return NodeObservation{}, &ArgumentError{
				Param:   "statefulReplicas",
				Message: "A role allocation may appear only once per node.",
			}
		}
		seen[key] = struct{}{}
		snapshot = append(snapshot, validated)
	}
	return NodeObservation{
		NodeId:             validatedNode,
		NodeState:          nodeState,
		Capacity:           validatedCapacity,
		Usage:              validatedUsage,
		PendingAllocations: pendingAllocations,
		StatefulReplicas:   snapshot,
	}, nil
}

// AllocationDemand is one unit of unsatisfied or projected workload demand.
type AllocationDemand struct {
	RoleId    string
	RoleKind  string
	Stateful  bool
	Resources NodeResources
}

// NewAllocationDemand validates one demand unit.
func NewAllocationDemand(roleId string, roleKind string, isStateful bool, resources NodeResources) (AllocationDemand, error) {
	validatedRoleId, err := requireAutoscalingToken(roleId, "roleId",
		"Role ID must be a lowercase DNS-style token.")
	if err != nil {
		return AllocationDemand{}, err
	}
	validatedRoleKind, err := requireAutoscalingToken(roleKind, "roleKind",
		"Role kind must be a lowercase DNS-style token.")
	if err != nil {
		return AllocationDemand{}, err
	}
	validatedResources, err := NewNodeResources(resources.MemoryBytes, resources.CpuPercent, resources.Tasks)
	if err != nil {
		return AllocationDemand{}, err
	}
	return AllocationDemand{
		RoleId:    validatedRoleId,
		RoleKind:  validatedRoleKind,
		Stateful:  isStateful,
		Resources: validatedResources,
	}, nil
}

// AutoscalerConfig is the bounded scaling policy of the autoscaler.
type AutoscalerConfig struct {
	MinNodes                 int
	MaxNodes                 int
	ScaleUpHeadroomPercent   int
	ScaleDownHeadroomPercent int
	ScaleUpConfirmTicks      int
	ScaleDownConfirmTicks    int
	MaxConcurrentProvisions  int
}

// NewAutoscalerConfig validates the scaling policy: MinNodes is at least one,
// MaxNodes is not below MinNodes, headroom percentages are inside (0, 100),
// confirmation ticks are at least one, and the provision concurrency is
// between one and the closed bound.
func NewAutoscalerConfig(
	minNodes int,
	maxNodes int,
	scaleUpHeadroomPercent int,
	scaleDownHeadroomPercent int,
	scaleUpConfirmTicks int,
	scaleDownConfirmTicks int,
	maxConcurrentProvisions int,
) (AutoscalerConfig, error) {
	if minNodes < 1 {
		return AutoscalerConfig{}, &ArgumentOutOfRangeError{
			Param:   "minNodes",
			Message: "MinNodes must be at least one.",
		}
	}
	if maxNodes < minNodes {
		return AutoscalerConfig{}, &ArgumentOutOfRangeError{
			Param:   "maxNodes",
			Message: "MaxNodes must be at least MinNodes.",
		}
	}
	if scaleUpHeadroomPercent <= 0 || scaleUpHeadroomPercent >= 100 {
		return AutoscalerConfig{}, &ArgumentOutOfRangeError{
			Param:   "scaleUpHeadroomPercent",
			Message: "Scale-up headroom must be between 0 and 100 exclusive.",
		}
	}
	if scaleDownHeadroomPercent <= 0 || scaleDownHeadroomPercent >= 100 {
		return AutoscalerConfig{}, &ArgumentOutOfRangeError{
			Param:   "scaleDownHeadroomPercent",
			Message: "Scale-down headroom must be between 0 and 100 exclusive.",
		}
	}
	if scaleUpConfirmTicks < 1 {
		return AutoscalerConfig{}, &ArgumentOutOfRangeError{
			Param:   "scaleUpConfirmTicks",
			Message: "Scale-up confirmation ticks must be at least one.",
		}
	}
	if scaleDownConfirmTicks < 1 {
		return AutoscalerConfig{}, &ArgumentOutOfRangeError{
			Param:   "scaleDownConfirmTicks",
			Message: "Scale-down confirmation ticks must be at least one.",
		}
	}
	if maxConcurrentProvisions < 1 || maxConcurrentProvisions > autoscalingMaximumConcurrentProvisions {
		return AutoscalerConfig{}, &ArgumentOutOfRangeError{
			Param: "maxConcurrentProvisions",
			Message: fmt.Sprintf("Provision concurrency must be between 1 and %d.",
				autoscalingMaximumConcurrentProvisions),
		}
	}
	return AutoscalerConfig{
		MinNodes:                 minNodes,
		MaxNodes:                 maxNodes,
		ScaleUpHeadroomPercent:   scaleUpHeadroomPercent,
		ScaleDownHeadroomPercent: scaleDownHeadroomPercent,
		ScaleUpConfirmTicks:      scaleUpConfirmTicks,
		ScaleDownConfirmTicks:    scaleDownConfirmTicks,
		MaxConcurrentProvisions:  maxConcurrentProvisions,
	}, nil
}

// AutoscalerActionKind is the closed action vocabulary of the autoscaler.
type AutoscalerActionKind int

const (
	AutoscalerActionProvisionNode AutoscalerActionKind = iota
	AutoscalerActionCordonNode
	AutoscalerActionDrainNode
	AutoscalerActionRetireNode
)

func (k AutoscalerActionKind) String() string {
	names := [...]string{"ProvisionNode", "CordonNode", "DrainNode", "RetireNode"}
	if k >= 0 && int(k) < len(names) {
		return names[k]
	}
	return fmt.Sprintf("AutoscalerActionKind(%d)", int(k))
}

func (k AutoscalerActionKind) defined() bool {
	return k >= AutoscalerActionProvisionNode && k <= AutoscalerActionRetireNode
}

// AutoscalerAction is the closed action union of the autoscaler, mirroring the
// discriminated-struct shape of AdmittedRole: one struct with an unexported
// kind, accessible only through the New*Action constructors.
type AutoscalerAction struct {
	kind             AutoscalerActionKind
	provisionRequest NodeProvisionRequest
	nodeId           string
}

// Kind returns the action kind of this autoscaler action.
func (a AutoscalerAction) Kind() AutoscalerActionKind { return a.kind }

// ProvisionRequest returns the provision request; it is meaningful only when
// Kind is AutoscalerActionProvisionNode.
func (a AutoscalerAction) ProvisionRequest() NodeProvisionRequest { return a.provisionRequest }

// NodeId returns the target node; it is meaningful only when Kind is
// AutoscalerActionCordonNode, AutoscalerActionDrainNode, or
// AutoscalerActionRetireNode.
func (a AutoscalerAction) NodeId() string { return a.nodeId }

// NewProvisionNodeAction creates a validated provision-node action.
func NewProvisionNodeAction(request NodeProvisionRequest) (AutoscalerAction, error) {
	validated, err := NewNodeProvisionRequest(
		request.NodeId, request.NodeClass, request.Resources, request.Reason)
	if err != nil {
		return AutoscalerAction{}, err
	}
	return AutoscalerAction{kind: AutoscalerActionProvisionNode, provisionRequest: validated}, nil
}

// NewCordonNodeAction creates a validated cordon-node action.
func NewCordonNodeAction(nodeId string) (AutoscalerAction, error) {
	validated, err := requireAutoscalingToken(nodeId, "nodeId",
		"Node ID must be a lowercase DNS-style token.")
	if err != nil {
		return AutoscalerAction{}, err
	}
	return AutoscalerAction{kind: AutoscalerActionCordonNode, nodeId: validated}, nil
}

// NewDrainNodeAction creates a validated drain-node action.
func NewDrainNodeAction(nodeId string) (AutoscalerAction, error) {
	validated, err := requireAutoscalingToken(nodeId, "nodeId",
		"Node ID must be a lowercase DNS-style token.")
	if err != nil {
		return AutoscalerAction{}, err
	}
	return AutoscalerAction{kind: AutoscalerActionDrainNode, nodeId: validated}, nil
}

// NewRetireNodeAction creates a validated retire-node action.
func NewRetireNodeAction(nodeId string) (AutoscalerAction, error) {
	validated, err := requireAutoscalingToken(nodeId, "nodeId",
		"Node ID must be a lowercase DNS-style token.")
	if err != nil {
		return AutoscalerAction{}, err
	}
	return AutoscalerAction{kind: AutoscalerActionRetireNode, nodeId: validated}, nil
}

// NodeProvisionRequest is one node creation request handed to a
// NodeProvisioner.
type NodeProvisionRequest struct {
	NodeId    string
	NodeClass string
	Resources NodeResources
	Reason    string
}

// NewNodeProvisionRequest validates one provision request.
func NewNodeProvisionRequest(
	nodeId string,
	nodeClass string,
	resources NodeResources,
	reason string,
) (NodeProvisionRequest, error) {
	validatedNode, err := requireAutoscalingToken(nodeId, "nodeId",
		"Node ID must be a lowercase DNS-style token.")
	if err != nil {
		return NodeProvisionRequest{}, err
	}
	validatedClass, err := requireAutoscalingToken(nodeClass, "nodeClass",
		"Node class must be a lowercase DNS-style token.")
	if err != nil {
		return NodeProvisionRequest{}, err
	}
	validatedResources, err := NewNodeResources(resources.MemoryBytes, resources.CpuPercent, resources.Tasks)
	if err != nil {
		return NodeProvisionRequest{}, err
	}
	if reason == "" || len(reason) > autoscalingMaximumReasonLength {
		return NodeProvisionRequest{}, &ArgumentError{
			Param:   "reason",
			Message: "A nonempty bounded reason is required.",
		}
	}
	return NodeProvisionRequest{
		NodeId:    validatedNode,
		NodeClass: validatedClass,
		Resources: validatedResources,
		Reason:    reason,
	}, nil
}

// NodeProvisioner is the seam that materializes and retires nodes for the
// autoscaler.
type NodeProvisioner interface {
	// Provision creates one node described by the request.
	Provision(ctx context.Context, request NodeProvisionRequest) error
	// Retire releases one node after it has been drained.
	Retire(ctx context.Context, nodeId string) error
}
