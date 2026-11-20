package swarmruntime

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/gogo/protobuf/types"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/manager"
	"github.com/moby/swarmkit/v2/manager/state/store"
	"golang.org/x/sys/unix"
)

const (
	VotingManagers   = 3
	LabelPromotion   = "terrascale.promotion"
	managerJoinWait  = time.Minute
	membershipSample = 250 * time.Millisecond
)

var ErrNotRegionLeader = errors.New("membership changes run on the region's Raft leader")

type Promotion struct {
	Hostname string `json:"hostname"`
	NodeID   string `json:"node_id"`
	Voters   int    `json:"voters"`
}

type promotionStep struct {
	node     *api.Node
	rollback bool
	voters   int
}

func IsLeader(nodes []*api.Node, nodeID string) bool {
	return slices.ContainsFunc(nodes, func(node *api.Node) bool {
		return node.ID == nodeID && node.Role == api.NodeRoleManager && node.ManagerStatus != nil && node.ManagerStatus.Leader
	})
}

func LockMembership(state string) (func(), error) {
	lock, err := os.OpenFile(filepath.Join(state, "membership.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		return nil, fmt.Errorf("another membership change is in progress: %w", err)
	}
	return func() {
		_ = unix.Flock(int(lock.Fd()), unix.LOCK_UN)
		lock.Close()
	}, nil
}

func (n *Node) leaderManager() (*manager.Manager, *manager.Observation, error) {
	upstream := n.upstream.Manager()
	if upstream == nil {
		return nil, nil, ErrNotRegionLeader
	}
	observation, err := upstream.Observe(nil, func(store.ReadTx) error { return nil })
	if err != nil {
		return nil, nil, err
	}
	observation.Cancel()
	if err := upstream.ViewMembership(observation, func(store.ReadTx, []manager.Voter) error { return nil }); errors.Is(err, manager.ErrNotRaftLeader) {
		return nil, nil, ErrNotRegionLeader
	} else if err != nil {
		return nil, nil, err
	}
	return upstream, observation, nil
}

func (n *Node) PromoteManager(ctx context.Context, operation string) (Promotion, error) {
	if operation == "" || len(operation) > 63 {
		return Promotion{}, errors.New("promotion needs an operation identifier of at most 63 characters")
	}
	unlock, err := LockMembership(filepath.Dir(n.stateDir))
	if err != nil {
		return Promotion{}, err
	}
	defer unlock()
	upstream, observation, err := n.leaderManager()
	if err != nil {
		return Promotion{}, err
	}
	var step promotionStep
	err = upstream.UpdateMembership(observation, func(tx store.Tx, voters []manager.Voter) error {
		nodes, err := store.FindNodes(tx, store.All)
		if err != nil {
			return err
		}
		if step, err = planPromotion(nodes, voters, operation, time.Now()); err != nil {
			return err
		}
		changed := step.node.Copy()
		if step.rollback {
			changed.Spec.DesiredRole = api.NodeRoleWorker
		} else {
			changed.Spec.DesiredRole = api.NodeRoleManager
			changed.Spec.Annotations.Labels[LabelPromotion] = operation
		}
		return store.UpdateNode(tx, changed)
	})
	if errors.Is(err, manager.ErrNotRaftLeader) {
		return Promotion{}, ErrNotRegionLeader
	}
	if err != nil {
		return Promotion{}, err
	}
	name := memberName(step.node)
	if step.rollback {
		return Promotion{}, fmt.Errorf("rolled back the incomplete promotion of %s, which never became a Raft voter; nothing was promoted, run the promotion again", name)
	}
	promotion := Promotion{Hostname: name, NodeID: step.node.ID, Voters: step.voters + 1}
	if err := awaitVoter(ctx, upstream, observation, promotion.NodeID); err != nil {
		return Promotion{}, fmt.Errorf("committed the manager intent for %s, but %w", name, rollbackIntent(upstream, observation, promotion.NodeID, err))
	}
	return promotion, nil
}

func planPromotion(nodes []*api.Node, voters []manager.Voter, operation string, now time.Time) (promotionStep, error) {
	byID := map[string]*api.Node{}
	for _, node := range nodes {
		byID[node.ID] = node
		if node.Spec.Annotations.Labels[LabelPromotion] == operation {
			return promotionStep{}, fmt.Errorf("operation %s already promoted %s; a promotion token is used once", operation, memberName(node))
		}
	}
	voting := map[string]bool{}
	for _, voter := range voters {
		node := byID[voter.NodeID]
		switch {
		case node == nil:
			return promotionStep{}, fmt.Errorf("Raft voter %s has no node record; a membership change is pending", voter.NodeID)
		case !voter.Reachable || !voter.CaughtUp || !votingReady(node):
			return promotionStep{}, fmt.Errorf("voting manager %s is not ready, active, Raft-reachable and caught up; a membership change is pending", memberName(node))
		}
		voting[node.ID] = true
	}
	var eligible []*api.Node
	for _, node := range nodes {
		intent := node.Role == api.NodeRoleManager || node.Spec.DesiredRole == api.NodeRoleManager
		switch {
		case intent && !voting[node.ID]:
			updated, _ := types.TimestampFromProto(node.Meta.UpdatedAt)
			if now.Sub(updated) < managerJoinWait {
				return promotionStep{}, fmt.Errorf("%s is joining Raft as a manager; a membership change is pending", memberName(node))
			}
			return promotionStep{node: node, rollback: true}, nil
		case node.Role != node.Spec.DesiredRole:
			return promotionStep{}, fmt.Errorf("%s is changing role from %s to %s; a membership change is pending", memberName(node), strings.ToLower(node.Role.String()), strings.ToLower(node.Spec.DesiredRole.String()))
		case promotionEligible(node):
			eligible = append(eligible, node)
		}
	}
	if len(voters) >= VotingManagers {
		return promotionStep{}, fmt.Errorf("the region already has %d voting managers", len(voters))
	}
	if len(eligible) == 0 {
		return promotionStep{}, errors.New("no eligible worker: promotion needs an admitted container worker that is READY, active and not draining")
	}
	slices.SortFunc(eligible, func(a, b *api.Node) int {
		at, bt := a.Meta.CreatedAt, b.Meta.CreatedAt
		return cmp.Or(cmp.Compare(at.GetSeconds(), bt.GetSeconds()), cmp.Compare(at.GetNanos(), bt.GetNanos()), strings.Compare(a.ID, b.ID))
	})
	return promotionStep{node: eligible[0], voters: len(voters)}, nil
}

func awaitVoter(ctx context.Context, upstream *manager.Manager, observation *manager.Observation, nodeID string) error {
	ctx, cancel := context.WithTimeout(ctx, managerJoinWait)
	defer cancel()
	tick := time.NewTicker(membershipSample)
	defer tick.Stop()
	for {
		settled := false
		err := upstream.ViewMembership(observation, func(tx store.ReadTx, voters []manager.Voter) error {
			node := store.GetNode(tx, nodeID)
			if node == nil {
				return errors.New("it left the cluster")
			}
			if node.Spec.Availability != api.NodeAvailabilityActive {
				return fmt.Errorf("its availability became %s", strings.ToLower(node.Spec.Availability.String()))
			}
			at := slices.IndexFunc(voters, func(voter manager.Voter) bool { return voter.NodeID == nodeID })
			settled = at >= 0 && voters[at].Reachable && voters[at].CaughtUp && votingReady(node)
			return nil
		})
		if err != nil || settled {
			return err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("it is not a ready, Raft-reachable voter caught up to the leader's commit index after %s", managerJoinWait)
		case <-tick.C:
		}
	}
}

func rollbackIntent(upstream *manager.Manager, observation *manager.Observation, nodeID string, cause error) error {
	rolledBack := false
	err := upstream.UpdateMembership(observation, func(tx store.Tx, voters []manager.Voter) error {
		node := store.GetNode(tx, nodeID)
		if node == nil || slices.ContainsFunc(voters, func(voter manager.Voter) bool { return voter.NodeID == nodeID }) {
			return nil
		}
		changed := node.Copy()
		changed.Spec.DesiredRole = api.NodeRoleWorker
		rolledBack = true
		return store.UpdateNode(tx, changed)
	})
	switch {
	case err != nil:
		return fmt.Errorf("%w; rolling back its intent failed: %w", cause, err)
	case rolledBack:
		return fmt.Errorf("%w; it never became a Raft voter, so its manager intent was rolled back", cause)
	}
	return fmt.Errorf("%w; it is a Raft voter, so it keeps its manager role and promotions refuse until it settles", cause)
}

func (n *Node) MemberView() (MemberList, error) {
	upstream, observation, err := n.leaderManager()
	if err != nil {
		return MemberList{}, err
	}
	var list MemberList
	err = upstream.ViewMembership(observation, func(tx store.ReadTx, voters []manager.Voter) error {
		nodes, err := store.FindNodes(tx, store.All)
		if err != nil {
			return err
		}
		list = memberRows(nodes, voters)
		return nil
	})
	if errors.Is(err, manager.ErrNotRaftLeader) {
		return MemberList{}, ErrNotRegionLeader
	}
	return list, err
}

func memberName(node *api.Node) string {
	if node.Spec.Annotations.Name != "" {
		return node.Spec.Annotations.Name
	}
	if node.Description != nil && node.Description.Hostname != "" {
		return node.Description.Hostname
	}
	return node.ID
}

func promotionEligible(node *api.Node) bool {
	labels := node.Spec.Annotations.Labels
	return node.Role == api.NodeRoleWorker && node.Spec.DesiredRole == api.NodeRoleWorker &&
		node.Status.State == api.NodeStatus_READY && node.Spec.Availability == api.NodeAvailabilityActive &&
		node.Spec.Membership == api.NodeMembershipAccepted && node.Spec.Annotations.Name != "" &&
		labels[LabelHostRole] == "container" && labels[LabelInstanceID] != "" && labels[LabelDrainSince] == ""
}

func votingReady(node *api.Node) bool {
	return node.Role == api.NodeRoleManager && node.Spec.DesiredRole == api.NodeRoleManager &&
		node.Status.State == api.NodeStatus_READY && node.Spec.Availability == api.NodeAvailabilityActive
}

func managerReachable(node *api.Node) bool {
	return node.Role == api.NodeRoleManager && node.ManagerStatus != nil && node.ManagerStatus.Reachability == api.RaftMemberStatus_REACHABLE
}

func managerReady(node *api.Node) bool {
	return managerReachable(node) && node.Status.State == api.NodeStatus_READY && node.Spec.DesiredRole == api.NodeRoleManager
}
