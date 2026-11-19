package swarmruntime

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
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
	VotingManagers      = 3
	ManagerReplaceAfter = 5 * time.Minute
	ManagerJoinWait     = 2 * time.Minute
	managerKeepEvery    = 10 * time.Second
	membershipPoll      = 200 * time.Millisecond
)

var errMembershipMoved = errors.New("voting membership changed between the decision and the write")

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
		unix.Flock(int(lock.Fd()), unix.LOCK_UN)
		lock.Close()
	}, nil
}

type ManagerKeeper struct {
	state            string
	node             *Node
	unreachableSince map[string]time.Time
	joiningSince     map[string]time.Time
}

type membershipStep struct {
	action string
	node   *api.Node
	reason string
}

func NewManagerKeeper(state string, node *Node) *ManagerKeeper {
	return &ManagerKeeper{state: state, node: node, unreachableSince: map[string]time.Time{}, joiningSince: map[string]time.Time{}}
}

func (k *ManagerKeeper) Run(ctx context.Context) {
	tick := time.NewTicker(managerKeepEvery)
	defer tick.Stop()
	for {
		change, err := k.Reconcile(ctx, time.Now())
		if change != "" {
			slog.InfoContext(ctx, "manager keeper changed voting membership", "change", change)
		}
		if err != nil && ctx.Err() == nil {
			slog.WarnContext(ctx, "manager keeper stopped a voting membership change", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (k *ManagerKeeper) Reconcile(ctx context.Context, now time.Time) (string, error) {
	upstream := k.node.upstream.Manager()
	if upstream == nil {
		k.forget()
		return "", nil
	}
	observation, err := upstream.Observe(nil, func(store.ReadTx) error { return nil })
	if err != nil {
		return "", err
	}
	observation.Cancel()
	if first, err := k.plan(upstream, observation, now); errors.Is(err, manager.ErrNotRaftLeader) {
		k.forget()
		return "", nil
	} else if err != nil || first.action == "" {
		return "", err
	}
	unlock, err := LockMembership(k.state)
	if err != nil {
		return "", err
	}
	defer unlock()
	var changes []string
	for range VotingManagers + 1 {
		step, err := k.plan(upstream, observation, now)
		if err != nil || step.action == "" {
			return strings.Join(changes, "; "), err
		}
		if err := k.apply(upstream, observation, step, now); err != nil {
			return strings.Join(changes, "; "), fmt.Errorf("%s: %w", step.reason, err)
		}
		changes = append(changes, step.reason)
		if err := k.settle(ctx, upstream, observation, step); err != nil {
			return strings.Join(changes, "; "), err
		}
	}
	return strings.Join(changes, "; "), nil
}

func (k *ManagerKeeper) forget() {
	clear(k.unreachableSince)
	clear(k.joiningSince)
}

func (k *ManagerKeeper) plan(upstream *manager.Manager, observation *manager.Observation, now time.Time) (membershipStep, error) {
	var step membershipStep
	err := upstream.ViewMembership(observation, func(tx store.ReadTx, voters []manager.Voter) error {
		nodes, err := store.FindNodes(tx, store.All)
		if err != nil {
			return err
		}
		step = k.decide(nodes, voters, now, true)
		return nil
	})
	return step, err
}

func (k *ManagerKeeper) decide(nodes []*api.Node, voters []manager.Voter, now time.Time, record bool) membershipStep {
	unreachable, joining := map[string]time.Time{}, map[string]time.Time{}
	if record {
		defer func() { k.unreachableSince, k.joiningSince = unreachable, joining }()
	}
	voting := map[string]manager.Voter{}
	for _, voter := range voters {
		voting[voter.NodeID] = voter
	}
	settled, reachable := true, 0
	var revert *api.Node
	var down, eligible []*api.Node
	for _, node := range nodes {
		voter, isVoter := voting[node.ID]
		switch {
		case isVoter && node.Spec.DesiredRole != api.NodeRoleManager:
			settled = false
		case isVoter && voter.Reachable:
			reachable++
			settled = settled && voter.CaughtUp
		case isVoter:
			since := cmp.Or(k.unreachableSince[node.ID], now)
			unreachable[node.ID] = since
			if now.Sub(since) < ManagerReplaceAfter {
				settled = false
			} else {
				down = append(down, node)
			}
		case node.Role == api.NodeRoleManager || node.Spec.DesiredRole == api.NodeRoleManager:
			since := cmp.Or(k.joiningSince[node.ID], now)
			joining[node.ID] = since
			if revert == nil && node.Spec.DesiredRole == api.NodeRoleManager && now.Sub(since) >= ManagerJoinWait {
				revert = node
			}
			settled = false
		case promotionEligible(node):
			eligible = append(eligible, node)
		}
	}
	if revert != nil {
		return membershipStep{action: "revert", node: revert, reason: fmt.Sprintf("returned %s to worker: it did not join Raft within %s", memberName(revert), ManagerJoinWait)}
	}
	if !settled {
		return membershipStep{}
	}
	slices.SortFunc(eligible, func(a, b *api.Node) int {
		at, bt := a.Meta.CreatedAt, b.Meta.CreatedAt
		return cmp.Or(cmp.Compare(at.GetSeconds(), bt.GetSeconds()), cmp.Compare(at.GetNanos(), bt.GetNanos()), strings.Compare(a.ID, b.ID))
	})
	total := len(voters)
	switch {
	case len(down) > 0:
		if total >= VotingManagers && len(eligible) > 0 && reachable >= total/2+1 {
			return membershipStep{action: "demote", node: down[0], reason: fmt.Sprintf("demoted %s: Raft-unreachable for %s", memberName(down[0]), ManagerReplaceAfter)}
		}
	case total == 1 && len(eligible) >= VotingManagers-1, total == VotingManagers-1 && len(eligible) >= 1:
		return membershipStep{action: "promote", node: eligible[0], reason: fmt.Sprintf("promoted %s to voting manager %d of %d", memberName(eligible[0]), total+1, VotingManagers)}
	}
	return membershipStep{}
}

func (k *ManagerKeeper) apply(upstream *manager.Manager, observation *manager.Observation, step membershipStep, now time.Time) error {
	return upstream.UpdateMembership(observation, func(tx store.Tx, voters []manager.Voter) error {
		nodes, err := store.FindNodes(tx, store.All)
		if err != nil {
			return err
		}
		current := k.decide(nodes, voters, now, false)
		if current.action != step.action || current.node.ID != step.node.ID {
			return errMembershipMoved
		}
		node := current.node.Copy()
		node.Spec.DesiredRole = api.NodeRoleWorker
		if step.action == "promote" {
			node.Spec.DesiredRole = api.NodeRoleManager
		}
		return store.UpdateNode(tx, node)
	})
}

func (k *ManagerKeeper) settle(ctx context.Context, upstream *manager.Manager, observation *manager.Observation, step membershipStep) error {
	ctx, cancel := context.WithTimeout(ctx, ManagerJoinWait)
	defer cancel()
	tick := time.NewTicker(membershipPoll)
	defer tick.Stop()
	for {
		done := false
		err := upstream.ViewMembership(observation, func(tx store.ReadTx, voters []manager.Voter) error {
			node := store.GetNode(tx, step.node.ID)
			if node == nil {
				return fmt.Errorf("%s left the cluster during its role change", memberName(step.node))
			}
			at := slices.IndexFunc(voters, func(voter manager.Voter) bool { return voter.NodeID == node.ID })
			if step.action == "promote" {
				done = node.Role == api.NodeRoleManager && at >= 0 && voters[at].Reachable && voters[at].CaughtUp
			} else {
				done = node.Role == api.NodeRoleWorker && at < 0
			}
			return nil
		})
		if err != nil || done {
			return err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%s: wait for Raft: %w", step.reason, ctx.Err())
		case <-tick.C:
		}
	}
}

func memberName(node *api.Node) string {
	if node.Description != nil && node.Description.Hostname != "" {
		return node.Description.Hostname
	}
	return node.ID
}

func promotionEligible(node *api.Node) bool {
	return node.Role == api.NodeRoleWorker && node.Spec.DesiredRole == api.NodeRoleWorker &&
		node.Status.State == api.NodeStatus_READY && node.Spec.Availability == api.NodeAvailabilityActive &&
		node.Spec.Membership == api.NodeMembershipAccepted && node.Spec.Annotations.Labels[LabelHostRole] == "container"
}

func managerReachable(node *api.Node) bool {
	return node.Role == api.NodeRoleManager && node.ManagerStatus != nil && node.ManagerStatus.Reachability == api.RaftMemberStatus_REACHABLE
}

func managerReady(node *api.Node) bool {
	return managerReachable(node) && node.Status.State == api.NodeStatus_READY && node.Spec.DesiredRole == api.NodeRoleManager
}
