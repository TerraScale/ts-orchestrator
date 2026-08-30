// Package stateful defines the stateful-first hosting contracts of the
// rootless-hosting and autoscaling lane: persistent volume bindings, replica
// health observations, node drain candidates, drain decisions, and the
// DrainSafetyEvaluator seam every drain path must consult before a stateful
// node may be disturbed.
package stateful

import (
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

// InvalidDataError reports malformed observed data.
type InvalidDataError struct {
	Message string
}

func (e *InvalidDataError) Error() string { return e.Message }

var statefulTokenPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)

const (
	statefulMaximumTokenLength  = 63
	statefulMaximumPathLength   = 256
	statefulMaximumReasonLength = 256
	statefulMaximumReplicaCount = 1024
)

// requireStatefulToken enforces the bounded canonical token vocabulary shared
// by volume, allocation, role, and node identifiers.
func requireStatefulToken(value, param, message string) (string, error) {
	if len(value) < 1 || len(value) > statefulMaximumTokenLength || !statefulTokenPattern.MatchString(value) {
		return "", &ArgumentError{Param: param, Message: message}
	}
	return value, nil
}

// requireStatefulAbsolutePath enforces a bounded absolute container path with
// no empty, dot, or dot-dot segments; the filesystem root itself is rejected.
func requireStatefulAbsolutePath(value, param string) (string, error) {
	if len(value) < 2 || len(value) > statefulMaximumPathLength || !strings.HasPrefix(value, "/") {
		return "", &ArgumentError{
			Param:   param,
			Message: "A bounded absolute path is required.",
		}
	}
	for _, segment := range strings.Split(value[1:], "/") {
		if segment == "" || segment == "." || segment == ".." {
			return "", &ArgumentError{
				Param:   param,
				Message: "Path segments must be nonempty and cannot traverse upward.",
			}
		}
	}
	return value, nil
}

// requireStatefulReasonText enforces a bounded, control-character-free reason
// string so drain traces stay log-safe.
func requireStatefulReasonText(value, param string) (string, error) {
	if value == "" || len(value) > statefulMaximumReasonLength || strings.ContainsFunc(value, isControlRune) {
		return "", &ArgumentError{
			Param:   param,
			Message: "A nonempty bounded reason without control characters is required.",
		}
	}
	return value, nil
}

func isControlRune(r rune) bool { return r < 0x20 || r == 0x7f }

// PersistentVolumeId is a bounded canonical persistent volume token.
type PersistentVolumeId struct {
	Value string
}

// NewPersistentVolumeId validates the DNS-style volume token.
func NewPersistentVolumeId(value string) (PersistentVolumeId, error) {
	if _, err := requireStatefulToken(value, "value",
		"Persistent volume ID must be a lowercase DNS-style token."); err != nil {
		return PersistentVolumeId{}, err
	}
	return PersistentVolumeId{Value: value}, nil
}

func (id PersistentVolumeId) String() string { return id.Value }

// VolumeBinding binds one persistent volume to one allocation destination.
type VolumeBinding struct {
	VolumeId     PersistentVolumeId
	RoleKind     string
	AllocationId string
	Destination  string
	ReadOnly     bool
}

// NewVolumeBinding validates and snapshots one volume binding. VolumeId,
// RoleKind, and AllocationId must be bounded canonical tokens and Destination
// must be a bounded absolute container path.
func NewVolumeBinding(
	volumeId PersistentVolumeId,
	roleKind string,
	allocationId string,
	destination string,
	readOnly bool,
) (VolumeBinding, error) {
	validatedVolume, err := NewPersistentVolumeId(volumeId.Value)
	if err != nil {
		return VolumeBinding{}, err
	}
	validatedRole, err := requireStatefulToken(roleKind, "roleKind",
		"Role kind must be a lowercase DNS-style token.")
	if err != nil {
		return VolumeBinding{}, err
	}
	validatedAllocation, err := requireStatefulToken(allocationId, "allocationId",
		"Allocation ID must be a lowercase DNS-style token.")
	if err != nil {
		return VolumeBinding{}, err
	}
	validatedDestination, err := requireStatefulAbsolutePath(destination, "destination")
	if err != nil {
		return VolumeBinding{}, err
	}
	return VolumeBinding{
		VolumeId:     validatedVolume,
		RoleKind:     validatedRole,
		AllocationId: validatedAllocation,
		Destination:  validatedDestination,
		ReadOnly:     readOnly,
	}, nil
}

// ReplicaHealth is one observed stateful replica of a role on a node.
type ReplicaHealth struct {
	RoleKind     string
	AllocationId string
	Up           bool
	PeerAckCount int
	MinReplicas  int
	LagBytes     int64
}

// NewReplicaHealth validates one replica observation. PeerAckCount is
// non-negative, MinReplicas is at least one, and LagBytes is non-negative.
func NewReplicaHealth(
	roleKind string,
	allocationId string,
	up bool,
	peerAckCount int,
	minReplicas int,
	lagBytes int64,
) (ReplicaHealth, error) {
	validatedRole, err := requireStatefulToken(roleKind, "roleKind",
		"Role kind must be a lowercase DNS-style token.")
	if err != nil {
		return ReplicaHealth{}, err
	}
	validatedAllocation, err := requireStatefulToken(allocationId, "allocationId",
		"Allocation ID must be a lowercase DNS-style token.")
	if err != nil {
		return ReplicaHealth{}, err
	}
	if peerAckCount < 0 {
		return ReplicaHealth{}, &ArgumentOutOfRangeError{
			Param:   "peerAckCount",
			Message: "Peer acknowledgement count must be non-negative.",
		}
	}
	if minReplicas < 1 {
		return ReplicaHealth{}, &ArgumentOutOfRangeError{
			Param:   "minReplicas",
			Message: "Minimum replica count must be at least one.",
		}
	}
	if lagBytes < 0 {
		return ReplicaHealth{}, &ArgumentOutOfRangeError{
			Param:   "lagBytes",
			Message: "Replication lag must be non-negative.",
		}
	}
	return ReplicaHealth{
		RoleKind:     validatedRole,
		AllocationId: validatedAllocation,
		Up:           up,
		PeerAckCount: peerAckCount,
		MinReplicas:  minReplicas,
		LagBytes:     lagBytes,
	}, nil
}

// NodeDrainCandidate is one node under drain evaluation with the stateful
// replicas it currently hosts.
type NodeDrainCandidate struct {
	NodeId   string
	Replicas []ReplicaHealth
}

// NewNodeDrainCandidate validates the node token and snapshots a bounded,
// duplicate-free replica list.
func NewNodeDrainCandidate(nodeId string, replicas []ReplicaHealth) (NodeDrainCandidate, error) {
	validatedNode, err := requireStatefulToken(nodeId, "nodeId",
		"Node ID must be a lowercase DNS-style token.")
	if err != nil {
		return NodeDrainCandidate{}, err
	}
	if len(replicas) > statefulMaximumReplicaCount {
		return NodeDrainCandidate{}, &ArgumentError{
			Param:   "replicas",
			Message: fmt.Sprintf("Replica input exceeds the bound of %d entries.", statefulMaximumReplicaCount),
		}
	}
	snapshot := make([]ReplicaHealth, 0, len(replicas))
	seen := make(map[string]struct{}, len(replicas))
	for _, replica := range replicas {
		validated, err := NewReplicaHealth(
			replica.RoleKind, replica.AllocationId, replica.Up,
			replica.PeerAckCount, replica.MinReplicas, replica.LagBytes)
		if err != nil {
			return NodeDrainCandidate{}, err
		}
		key := validated.RoleKind + "/" + validated.AllocationId
		if _, duplicate := seen[key]; duplicate {
			return NodeDrainCandidate{}, &ArgumentError{
				Param:   "replicas",
				Message: "A role allocation may appear only once per node.",
			}
		}
		seen[key] = struct{}{}
		snapshot = append(snapshot, validated)
	}
	return NodeDrainCandidate{NodeId: validatedNode, Replicas: snapshot}, nil
}

// DrainDecision is the closed drain verdict of the DrainSafetyEvaluator.
type DrainDecision struct {
	Allowed               bool
	Reason                string
	BlockingAllocationIds []string
}

// NewDrainDecision validates one drain verdict. An allowed drain may not name
// blocking allocations; a blocked drain names each blocking allocation as a
// bounded canonical token without duplicates.
func NewDrainDecision(allowed bool, reason string, blockingAllocationIds []string) (DrainDecision, error) {
	validatedReason, err := requireStatefulReasonText(reason, "reason")
	if err != nil {
		return DrainDecision{}, err
	}
	if len(blockingAllocationIds) > statefulMaximumReplicaCount {
		return DrainDecision{}, &ArgumentError{
			Param:   "blockingAllocationIds",
			Message: fmt.Sprintf("Blocking allocation input exceeds the bound of %d entries.", statefulMaximumReplicaCount),
		}
	}
	snapshot := make([]string, 0, len(blockingAllocationIds))
	for _, allocationId := range blockingAllocationIds {
		validated, err := requireStatefulToken(allocationId, "blockingAllocationIds",
			"Blocking allocation IDs must be lowercase DNS-style tokens.")
		if err != nil {
			return DrainDecision{}, err
		}
		snapshot = append(snapshot, validated)
	}
	seen := make(map[string]struct{}, len(snapshot))
	for _, allocationId := range snapshot {
		if _, duplicate := seen[allocationId]; duplicate {
			return DrainDecision{}, &ArgumentError{
				Param:   "blockingAllocationIds",
				Message: "Blocking allocation IDs cannot contain duplicates.",
			}
		}
		seen[allocationId] = struct{}{}
	}
	if allowed && len(snapshot) > 0 {
		return DrainDecision{}, &ArgumentError{
			Param:   "blockingAllocationIds",
			Message: "An allowed drain cannot name blocking allocations.",
		}
	}
	return DrainDecision{
		Allowed:               allowed,
		Reason:                validatedReason,
		BlockingAllocationIds: snapshot,
	}, nil
}
