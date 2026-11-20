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

	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/manager"
	"github.com/moby/swarmkit/v2/manager/state/store"
	"golang.org/x/sys/unix"
)

const (
	VotingManagers   = 3
	managerJoinWait  = 2 * time.Minute
	membershipSample = 250 * time.Millisecond
)

var ErrNotRegionLeader = errors.New("membership changes run on the region's Raft leader")

type Promotion struct {
	Hostname string `json:"hostname"`
	NodeID   string `json:"node_id"`
	Voters   int    `json:"voters"`
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

func (n *Node) RaftVoters() ([]manager.Voter, error) {
	upstream := n.upstream.Manager()
	if upstream == nil {
		return nil, ErrNotRegionLeader
	}
	observation, err := upstream.Observe(nil, func(store.ReadTx) error { return nil })
	if err != nil {
		return nil, err
	}
	observation.Cancel()
	var voters []manager.Voter
	err = upstream.ViewMembership(observation, func(_ store.ReadTx, current []manager.Voter) error {
		voters = current
		return nil
	})
	if errors.Is(err, manager.ErrNotRaftLeader) {
		return nil, ErrNotRegionLeader
	}
	return voters, err
}

func (n *Node) PromoteManager(ctx context.Context) (Promotion, error) {
	unlock, err := LockMembership(filepath.Dir(n.stateDir))
	if err != nil {
		return Promotion{}, err
	}
	defer unlock()
	upstream := n.upstream.Manager()
	if upstream == nil {
		return Promotion{}, ErrNotRegionLeader
	}
	observation, err := upstream.Observe(nil, func(store.ReadTx) error { return nil })
	if err != nil {
		return Promotion{}, err
	}
	observation.Cancel()
	var promotion Promotion
	err = upstream.UpdateMembership(observation, func(tx store.Tx, voters []manager.Voter) error {
		nodes, err := store.FindNodes(tx, store.All)
		if err != nil {
			return err
		}
		candidate, err := promotionCandidate(nodes, voters)
		if err != nil {
			return err
		}
		promoted := candidate.Copy()
		promoted.Spec.DesiredRole = api.NodeRoleManager
		if err := store.UpdateNode(tx, promoted); err != nil {
			return err
		}
		promotion = Promotion{Hostname: memberName(candidate), NodeID: candidate.ID, Voters: len(voters) + 1}
		return nil
	})
	if errors.Is(err, manager.ErrNotRaftLeader) {
		return Promotion{}, ErrNotRegionLeader
	}
	if err != nil {
		return Promotion{}, err
	}
	if err := awaitVoter(ctx, upstream, observation, promotion); err != nil {
		return promotion, fmt.Errorf("%s became voting manager %d of %d, but %w; it keeps its manager role and further promotions refuse until it settles", promotion.Hostname, promotion.Voters, VotingManagers, err)
	}
	return promotion, nil
}

func promotionCandidate(nodes []*api.Node, voters []manager.Voter) (*api.Node, error) {
	if len(voters) >= VotingManagers {
		return nil, fmt.Errorf("the region already has %d voting managers", len(voters))
	}
	byID := map[string]*api.Node{}
	for _, node := range nodes {
		byID[node.ID] = node
	}
	for _, voter := range voters {
		node := byID[voter.NodeID]
		switch {
		case node == nil:
			return nil, fmt.Errorf("Raft voter %s has no node record; a membership change is pending", voter.NodeID)
		case !voter.Reachable || !voter.CaughtUp || !managerReady(node):
			return nil, fmt.Errorf("voting manager %s is not ready, Raft-reachable and caught up; a membership change is pending", memberName(node))
		}
	}
	var eligible []*api.Node
	for _, node := range nodes {
		voting := slices.ContainsFunc(voters, func(voter manager.Voter) bool { return voter.NodeID == node.ID })
		switch {
		case node.Role != node.Spec.DesiredRole:
			return nil, fmt.Errorf("%s is changing role from %s to %s; a membership change is pending", memberName(node), strings.ToLower(node.Role.String()), strings.ToLower(node.Spec.DesiredRole.String()))
		case node.Role == api.NodeRoleManager && !voting:
			return nil, fmt.Errorf("%s holds the manager role but is not a Raft voter; a membership change is pending", memberName(node))
		case promotionEligible(node):
			eligible = append(eligible, node)
		}
	}
	if len(eligible) == 0 {
		return nil, errors.New("no eligible worker: promotion needs an admitted container worker that is READY, active and not draining")
	}
	slices.SortFunc(eligible, func(a, b *api.Node) int {
		at, bt := a.Meta.CreatedAt, b.Meta.CreatedAt
		return cmp.Or(cmp.Compare(at.GetSeconds(), bt.GetSeconds()), cmp.Compare(at.GetNanos(), bt.GetNanos()), strings.Compare(a.ID, b.ID))
	})
	return eligible[0], nil
}

func awaitVoter(ctx context.Context, upstream *manager.Manager, observation *manager.Observation, promotion Promotion) error {
	ctx, cancel := context.WithTimeout(ctx, managerJoinWait)
	defer cancel()
	tick := time.NewTicker(membershipSample)
	defer tick.Stop()
	for {
		settled := false
		err := upstream.ViewMembership(observation, func(tx store.ReadTx, voters []manager.Voter) error {
			node := store.GetNode(tx, promotion.NodeID)
			if node == nil {
				return errors.New("it left the cluster")
			}
			at := slices.IndexFunc(voters, func(voter manager.Voter) bool { return voter.NodeID == node.ID })
			settled = at >= 0 && voters[at].Reachable && voters[at].CaughtUp && managerReady(node)
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

func managerReachable(node *api.Node) bool {
	return node.Role == api.NodeRoleManager && node.ManagerStatus != nil && node.ManagerStatus.Reachability == api.RaftMemberStatus_REACHABLE
}

func managerReady(node *api.Node) bool {
	return managerReachable(node) && node.Status.State == api.NodeStatus_READY && node.Spec.DesiredRole == api.NodeRoleManager
}
