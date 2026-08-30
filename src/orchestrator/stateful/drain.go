// This file implements the drain safety layer of the stateful-first hosting
// lane: the DrainSafetyEvaluator seam, the explicit DrainPolicy, the
// ReplicaDrainSafetyEvaluator gate every drain path must consult before a
// stateful node may be disturbed, and the pure NodeDrainCoordinator that
// orders the drain steps of one cordoned node.
package stateful

import (
	"fmt"
	"sort"
)

// DrainSafetyEvaluator is the seam every drain path must consult before a
// stateful node may be disturbed: it decides whether one node may drain given
// its own replica health and the replica health observed on every other node.
type DrainSafetyEvaluator interface {
	// EvaluateDrainSafety returns the closed drain decision for one candidate
	// node; peers carry the replicas of every other node.
	EvaluateDrainSafety(candidate NodeDrainCandidate, peers []NodeDrainCandidate) (DrainDecision, error)
}

// DrainPolicy is the explicit drain-safety configuration of the replica drain
// evaluator. MaxLagBytes is an exclusive bound: a replica whose observed
// LagBytes is not strictly below MaxLagBytes is lagging and blocks the drain.
type DrainPolicy struct {
	MaxLagBytes int64
}

// NewDrainPolicy validates one drain policy: the lag bound is positive so a
// caught-up replica (LagBytes zero) can always pass it.
func NewDrainPolicy(maxLagBytes int64) (DrainPolicy, error) {
	if maxLagBytes < 1 {
		return DrainPolicy{}, &ArgumentOutOfRangeError{
			Param:   "maxLagBytes",
			Message: "The drain lag bound must be positive.",
		}
	}
	return DrainPolicy{MaxLagBytes: maxLagBytes}, nil
}

// ReplicaDrainSafetyEvaluator is the stateful drain gate. A node may drain
// iff every replica it hosts is up, every hosted replica's replication lag is
// strictly below the configured bound, and every hosted replica keeps at
// least MinReplicas acknowledgements plus up replicas of the same role kind
// on other nodes. PeerAckCount is the candidate replica's already-observed
// quorum contribution; peer acknowledgements are not summed again, avoiding
// double counting. Any
// failing replica defers the drain and is named in the blocking allocation
// IDs, sorted and deduplicated.
type ReplicaDrainSafetyEvaluator struct {
	policy DrainPolicy
}

// NewReplicaDrainSafetyEvaluator creates one evaluator with its explicit drain
// policy.
func NewReplicaDrainSafetyEvaluator(policy DrainPolicy) (*ReplicaDrainSafetyEvaluator, error) {
	validated, err := NewDrainPolicy(policy.MaxLagBytes)
	if err != nil {
		return nil, err
	}
	return &ReplicaDrainSafetyEvaluator{policy: validated}, nil
}

// EvaluateDrainSafety decides one drain. The candidate observation and every
// peer observation are revalidated at this trust boundary; the candidate node
// may not appear among its peers and peer nodes must be unique. Replicas the
// candidate node itself hosts never count toward another replica's survivors,
// because a drain stops every replica on the node.
func (e *ReplicaDrainSafetyEvaluator) EvaluateDrainSafety(
	candidate NodeDrainCandidate,
	peers []NodeDrainCandidate,
) (DrainDecision, error) {
	revalidated, err := NewNodeDrainCandidate(candidate.NodeId, candidate.Replicas)
	if err != nil {
		return DrainDecision{}, err
	}
	if len(peers) > statefulMaximumReplicaCount {
		return DrainDecision{}, &ArgumentError{
			Param:   "peers",
			Message: fmt.Sprintf("Peer input exceeds the bound of %d entries.", statefulMaximumReplicaCount),
		}
	}
	ownAllocations := make(map[string]struct{}, len(revalidated.Replicas))
	for _, replica := range revalidated.Replicas {
		ownAllocations[replica.RoleKind+"/"+replica.AllocationId] = struct{}{}
	}
	upElsewhereByRole := make(map[string]map[string]struct{})
	seenPeers := make(map[string]struct{}, len(peers))
	for _, peer := range peers {
		revalidatedPeer, err := NewNodeDrainCandidate(peer.NodeId, peer.Replicas)
		if err != nil {
			return DrainDecision{}, err
		}
		if revalidatedPeer.NodeId == revalidated.NodeId {
			return DrainDecision{}, &InvalidDataError{
				Message: "The candidate node may not appear among its drain peers.",
			}
		}
		if _, duplicate := seenPeers[revalidatedPeer.NodeId]; duplicate {
			return DrainDecision{}, &InvalidDataError{
				Message: "Peer nodes must be unique.",
			}
		}
		seenPeers[revalidatedPeer.NodeId] = struct{}{}
		for _, replica := range revalidatedPeer.Replicas {
			if _, own := ownAllocations[replica.RoleKind+"/"+replica.AllocationId]; own || !replica.Up {
				continue
			}
			upSet := upElsewhereByRole[replica.RoleKind]
			if upSet == nil {
				upSet = make(map[string]struct{}, 1)
				upElsewhereByRole[replica.RoleKind] = upSet
			}
			upSet[replica.AllocationId] = struct{}{}
		}
	}
	blocking := make(map[string]struct{}, len(revalidated.Replicas))
	for _, replica := range revalidated.Replicas {
		switch {
		case !replica.Up:
			blocking[replica.AllocationId] = struct{}{}
		case replica.LagBytes >= e.policy.MaxLagBytes:
			blocking[replica.AllocationId] = struct{}{}
		case int64(replica.PeerAckCount)+int64(len(upElsewhereByRole[replica.RoleKind])) < int64(replica.MinReplicas):
			blocking[replica.AllocationId] = struct{}{}
		}
	}
	if len(blocking) == 0 {
		return NewDrainDecision(true,
			"Every replica is up, caught up, and sufficiently replicated on other nodes.", nil)
	}
	blockingIds := make([]string, 0, len(blocking))
	for allocationId := range blocking {
		blockingIds = append(blockingIds, allocationId)
	}
	sort.Strings(blockingIds)
	return NewDrainDecision(false,
		"Replicas are down, lagging, or under-replicated on other nodes.", blockingIds)
}

// DrainingAllocation is one running allocation observed on a cordoned node. A
// stateful allocation carries its replica observation; a stateless allocation
// carries none.
type DrainingAllocation struct {
	AllocationId string
	RoleKind     string
	Stateful     bool
	Replica      *ReplicaHealth
}

// NewDrainingAllocation validates one draining allocation. Both tokens are
// bounded canonical tokens; a stateful allocation must carry a matching
// replica observation and a stateless allocation must carry none.
func NewDrainingAllocation(
	allocationId string,
	roleKind string,
	stateful bool,
	replica *ReplicaHealth,
) (DrainingAllocation, error) {
	validatedAllocation, err := requireStatefulToken(allocationId, "allocationId",
		"Allocation ID must be a lowercase DNS-style token.")
	if err != nil {
		return DrainingAllocation{}, err
	}
	validatedRole, err := requireStatefulToken(roleKind, "roleKind",
		"Role kind must be a lowercase DNS-style token.")
	if err != nil {
		return DrainingAllocation{}, err
	}
	if stateful {
		if replica == nil {
			return DrainingAllocation{}, &ArgumentError{
				Param:   "replica",
				Message: "A stateful allocation carries its replica observation.",
			}
		}
		if replica.RoleKind != validatedRole || replica.AllocationId != validatedAllocation {
			return DrainingAllocation{}, &ArgumentError{
				Param:   "replica",
				Message: "The replica observation must match the allocation identity.",
			}
		}
	} else if replica != nil {
		return DrainingAllocation{}, &ArgumentError{
			Param:   "replica",
			Message: "A stateless allocation carries no replica observation.",
		}
	}
	var snapshot *ReplicaHealth
	if replica != nil {
		revalidated, err := NewReplicaHealth(
			replica.RoleKind, replica.AllocationId, replica.Up,
			replica.PeerAckCount, replica.MinReplicas, replica.LagBytes)
		if err != nil {
			return DrainingAllocation{}, err
		}
		snapshot = &revalidated
	}
	return DrainingAllocation{
		AllocationId: validatedAllocation,
		RoleKind:     validatedRole,
		Stateful:     stateful,
		Replica:      snapshot,
	}, nil
}

// CordonedNodeObservation is the pure drain-planning view of one cordoned
// node: the running allocations and, for stateful ones, their replica health.
type CordonedNodeObservation struct {
	NodeId      string
	Allocations []DrainingAllocation
}

// NewCordonedNodeObservation validates and snapshots one cordoned node view.
// Allocations are bounded, revalidated, and unique per node.
func NewCordonedNodeObservation(nodeId string, allocations []DrainingAllocation) (CordonedNodeObservation, error) {
	validatedNode, err := requireStatefulToken(nodeId, "nodeId",
		"Node ID must be a lowercase DNS-style token.")
	if err != nil {
		return CordonedNodeObservation{}, err
	}
	if len(allocations) > statefulMaximumReplicaCount {
		return CordonedNodeObservation{}, &ArgumentError{
			Param: "allocations",
			Message: fmt.Sprintf("Allocation input exceeds the bound of %d entries.",
				statefulMaximumReplicaCount),
		}
	}
	snapshot := make([]DrainingAllocation, 0, len(allocations))
	seen := make(map[string]struct{}, len(allocations))
	for _, allocation := range allocations {
		revalidated, err := NewDrainingAllocation(
			allocation.AllocationId, allocation.RoleKind, allocation.Stateful, allocation.Replica)
		if err != nil {
			return CordonedNodeObservation{}, err
		}
		if _, duplicate := seen[revalidated.AllocationId]; duplicate {
			return CordonedNodeObservation{}, &ArgumentError{
				Param:   "allocations",
				Message: "An allocation may appear only once per node.",
			}
		}
		seen[revalidated.AllocationId] = struct{}{}
		snapshot = append(snapshot, revalidated)
	}
	return CordonedNodeObservation{NodeId: validatedNode, Allocations: snapshot}, nil
}

// DrainStepKind is the closed drain step vocabulary.
type DrainStepKind int

const (
	// DrainStepStopStateless stops one stateless allocation.
	DrainStepStopStateless DrainStepKind = iota
	// DrainStepStopStateful stops one stateful allocation after drain safety holds.
	DrainStepStopStateful
)

// defined reports whether the drain step kind is inside the closed vocabulary.
func (k DrainStepKind) defined() bool {
	return k >= DrainStepStopStateless && k <= DrainStepStopStateful
}

// String returns the declared name of the drain step kind.
func (k DrainStepKind) String() string {
	names := [...]string{"StopStateless", "StopStateful"}
	if k >= 0 && int(k) < len(names) {
		return names[k]
	}
	return fmt.Sprintf("DrainStepKind(%d)", int(k))
}

// DrainStep is one ordered stop step of a node drain plan.
type DrainStep struct {
	Kind         DrainStepKind
	AllocationId string
	RoleKind     string
}

// NewDrainStep validates one drain step.
func NewDrainStep(kind DrainStepKind, allocationId string, roleKind string) (DrainStep, error) {
	if !kind.defined() {
		return DrainStep{}, &ArgumentOutOfRangeError{Param: "kind"}
	}
	validatedAllocation, err := requireStatefulToken(allocationId, "allocationId",
		"Allocation ID must be a lowercase DNS-style token.")
	if err != nil {
		return DrainStep{}, err
	}
	validatedRole, err := requireStatefulToken(roleKind, "roleKind",
		"Role kind must be a lowercase DNS-style token.")
	if err != nil {
		return DrainStep{}, err
	}
	return DrainStep{
		Kind:         kind,
		AllocationId: validatedAllocation,
		RoleKind:     validatedRole,
	}, nil
}

// NodeDrainPlan is the ordered drain plan of one cordoned node: stateless
// stop steps first, stateful stop steps last, with stateful steps appearing
// only after the drain-safety evaluator allowed the node.
type NodeDrainPlan struct {
	NodeId   string
	Steps    []DrainStep
	Decision DrainDecision
}

// NewNodeDrainPlan validates one drain plan. Steps are bounded, revalidated,
// and unique per allocation; stateless steps strictly precede stateful steps;
// and stateful steps require an allowed drain decision.
func NewNodeDrainPlan(nodeId string, steps []DrainStep, decision DrainDecision) (NodeDrainPlan, error) {
	validatedNode, err := requireStatefulToken(nodeId, "nodeId",
		"Node ID must be a lowercase DNS-style token.")
	if err != nil {
		return NodeDrainPlan{}, err
	}
	revalidatedDecision, err := NewDrainDecision(
		decision.Allowed, decision.Reason, decision.BlockingAllocationIds)
	if err != nil {
		return NodeDrainPlan{}, err
	}
	if len(steps) > statefulMaximumReplicaCount {
		return NodeDrainPlan{}, &ArgumentError{
			Param: "steps",
			Message: fmt.Sprintf("Drain step input exceeds the bound of %d entries.",
				statefulMaximumReplicaCount),
		}
	}
	snapshot := make([]DrainStep, 0, len(steps))
	seen := make(map[string]struct{}, len(steps))
	statefulSeen := false
	for _, step := range steps {
		revalidated, err := NewDrainStep(step.Kind, step.AllocationId, step.RoleKind)
		if err != nil {
			return NodeDrainPlan{}, err
		}
		if _, duplicate := seen[revalidated.AllocationId]; duplicate {
			return NodeDrainPlan{}, &InvalidOperationError{
				Message: "An allocation may be stopped only once per drain plan.",
			}
		}
		if revalidated.Kind == DrainStepStopStateful {
			if !revalidatedDecision.Allowed {
				return NodeDrainPlan{}, &InvalidOperationError{
					Message: "Stateful drain steps require an allowed drain decision.",
				}
			}
			statefulSeen = true
		} else if statefulSeen {
			return NodeDrainPlan{}, &InvalidOperationError{
				Message: "Stateless drain steps must precede stateful drain steps.",
			}
		}
		seen[revalidated.AllocationId] = struct{}{}
		snapshot = append(snapshot, revalidated)
	}
	return NodeDrainPlan{
		NodeId:   validatedNode,
		Steps:    snapshot,
		Decision: revalidatedDecision,
	}, nil
}

// NodeDrainCoordinator plans the ordered drain of one cordoned node. Planning
// is pure: stateless allocations stop first in canonical order and stateful
// allocations stop last, and only after the injected drain-safety evaluator
// allows the node; a deferred decision yields the stateless prefix plus the
// blocking decision and never a stateful step.
type NodeDrainCoordinator struct {
	evaluator DrainSafetyEvaluator
}

// NewNodeDrainCoordinator creates one coordinator over one non-nil
// DrainSafetyEvaluator.
func NewNodeDrainCoordinator(evaluator DrainSafetyEvaluator) (*NodeDrainCoordinator, error) {
	if evaluator == nil {
		return nil, &ArgumentError{
			Param:   "evaluator",
			Message: "A drain safety evaluator is required.",
		}
	}
	return &NodeDrainCoordinator{evaluator: evaluator}, nil
}

// PlanDrain produces the ordered drain plan of one cordoned node. Peers carry
// the stateful replica health of every other node and must not include the
// cordoned node itself.
func (c *NodeDrainCoordinator) PlanDrain(
	node CordonedNodeObservation,
	peers []NodeDrainCandidate,
) (NodeDrainPlan, error) {
	revalidated, err := NewCordonedNodeObservation(node.NodeId, node.Allocations)
	if err != nil {
		return NodeDrainPlan{}, err
	}
	stateless := make([]DrainStep, 0, len(revalidated.Allocations))
	stateful := make([]DrainStep, 0, len(revalidated.Allocations))
	replicas := make([]ReplicaHealth, 0, len(revalidated.Allocations))
	for _, allocation := range revalidated.Allocations {
		kind := DrainStepStopStateless
		if allocation.Stateful {
			kind = DrainStepStopStateful
			replicas = append(replicas, *allocation.Replica)
		}
		step, err := NewDrainStep(kind, allocation.AllocationId, allocation.RoleKind)
		if err != nil {
			return NodeDrainPlan{}, err
		}
		if allocation.Stateful {
			stateful = append(stateful, step)
		} else {
			stateless = append(stateless, step)
		}
	}
	sortStatefulDrainSteps(stateless)
	sortStatefulDrainSteps(stateful)
	candidate, err := NewNodeDrainCandidate(revalidated.NodeId, replicas)
	if err != nil {
		return NodeDrainPlan{}, err
	}
	decision, err := c.evaluator.EvaluateDrainSafety(candidate, peers)
	if err != nil {
		return NodeDrainPlan{}, err
	}
	steps := append([]DrainStep(nil), stateless...)
	if decision.Allowed {
		steps = append(steps, stateful...)
	}
	return NewNodeDrainPlan(revalidated.NodeId, steps, decision)
}

// sortStatefulDrainSteps orders drain steps by role kind then allocation ID.
func sortStatefulDrainSteps(steps []DrainStep) {
	sort.Slice(steps, func(left, right int) bool {
		if steps[left].RoleKind != steps[right].RoleKind {
			return steps[left].RoleKind < steps[right].RoleKind
		}
		return steps[left].AllocationId < steps[right].AllocationId
	})
}
