package swarmruntime

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/moby/swarmkit/v2/api"
	"golang.org/x/sys/unix"
)

const (
	VotingManagers      = 3
	ManagerReplaceAfter = 5 * time.Minute
	managerKeepEvery    = 10 * time.Second
)

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
	state     string
	node      *Node
	downSince map[string]time.Time
}

func NewManagerKeeper(state string, node *Node) *ManagerKeeper {
	return &ManagerKeeper{state: state, node: node, downSince: map[string]time.Time{}}
}

func (k *ManagerKeeper) Run(ctx context.Context) {
	tick := time.NewTicker(managerKeepEvery)
	defer tick.Stop()
	for {
		change, err := k.Reconcile(ctx, time.Now())
		switch {
		case err != nil && ctx.Err() == nil:
			slog.WarnContext(ctx, "manager keeper left voting membership unchanged", "error", err)
		case change != "":
			slog.InfoContext(ctx, "manager keeper changed voting membership", "change", change)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (k *ManagerKeeper) Reconcile(ctx context.Context, now time.Time) (string, error) {
	if !k.node.IsManager() {
		return "", nil
	}
	client, conn, err := DialControl(k.state)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	listed, err := client.ListNodes(ctx, &api.ListNodesRequest{})
	if err != nil {
		return "", err
	}
	if !IsLeader(listed.Nodes, k.node.ID()) {
		clear(k.downSince)
		return "", nil
	}
	unlock, err := LockMembership(k.state)
	if err != nil {
		return "", err
	}
	defer unlock()
	_, guard, err := k.node.LeaderTerm(ctx)
	if err != nil {
		return "", err
	}
	voters, down, eligible, settled := k.observe(listed.Nodes, now)
	if !settled {
		return "", nil
	}
	var changes []string
	if len(down) > 0 && len(eligible) > 0 && voters >= VotingManagers {
		dead := down[0]
		if err := demoteDeadManager(ctx, client, dead, guard); err != nil {
			return "", err
		}
		delete(k.downSince, dead.ID)
		voters--
		down = down[1:]
		changes = append(changes, "demoted "+memberName(dead)+" after "+ManagerReplaceAfter.String()+" unreachable")
	}
	if len(down) > 0 || voters < 1 || voters >= VotingManagers || voters+len(eligible) < VotingManagers {
		return strings.Join(changes, "; "), nil
	}
	candidate := eligible[0]
	if err := guard(ctx); err != nil {
		return strings.Join(changes, "; "), err
	}
	if err := promoteManager(ctx, client, api.NewWatchClient(conn), candidate.ID); err != nil {
		return strings.Join(changes, "; "), err
	}
	return strings.Join(append(changes, fmt.Sprintf("promoted %s to manager %d of %d", memberName(candidate), voters+1, VotingManagers)), "; "), nil
}

func (k *ManagerKeeper) observe(nodes []*api.Node, now time.Time) (int, []*api.Node, []*api.Node, bool) {
	voters := 0
	var down, eligible []*api.Node
	downSince := map[string]time.Time{}
	for _, node := range nodes {
		if node.Role != node.Spec.DesiredRole {
			return 0, nil, nil, false
		}
		switch {
		case node.Role == api.NodeRoleManager:
			voters++
			if managerReady(node) {
				continue
			}
			since := cmp.Or(k.downSince[node.ID], now)
			downSince[node.ID] = since
			if now.Sub(since) >= ManagerReplaceAfter {
				down = append(down, node)
			}
		case promotionEligible(node):
			eligible = append(eligible, node)
		}
	}
	k.downSince = downSince
	if len(downSince) > len(down) {
		return voters, nil, nil, false
	}
	slices.SortFunc(eligible, func(a, b *api.Node) int {
		at, bt := a.Meta.CreatedAt, b.Meta.CreatedAt
		return cmp.Or(cmp.Compare(at.GetSeconds(), bt.GetSeconds()), cmp.Compare(at.GetNanos(), bt.GetNanos()), strings.Compare(a.ID, b.ID))
	})
	return voters, down, eligible, true
}

func demoteDeadManager(ctx context.Context, client api.ControlClient, dead *api.Node, guard func(context.Context) error) error {
	if err := CanDemoteManager(ctx, client, dead.ID); err != nil {
		return fmt.Errorf("keep unreachable manager %s: %w", memberName(dead), err)
	}
	if err := guard(ctx); err != nil {
		return err
	}
	spec := dead.Spec.Copy()
	spec.DesiredRole = api.NodeRoleWorker
	if _, err := client.UpdateNode(ctx, &api.UpdateNodeRequest{NodeID: dead.ID, NodeVersion: &dead.Meta.Version, Spec: spec}); err != nil {
		return fmt.Errorf("demote unreachable manager %s: %w", memberName(dead), err)
	}
	if _, err := awaitMember(ctx, client, memberName(dead), 2*time.Minute, func(node *api.Node, _ []*api.Task) bool {
		return node.Role == api.NodeRoleWorker
	}); err != nil {
		return fmt.Errorf("demote unreachable manager %s: %w", memberName(dead), err)
	}
	return nil
}

func memberName(node *api.Node) string {
	if node.Description != nil && node.Description.Hostname != "" {
		return node.Description.Hostname
	}
	return node.ID
}

func promotionEligible(node *api.Node) bool {
	return node.Role == api.NodeRoleWorker && node.Spec.DesiredRole != api.NodeRoleManager &&
		node.Status.State == api.NodeStatus_READY && node.Spec.Availability == api.NodeAvailabilityActive &&
		node.Spec.Membership == api.NodeMembershipAccepted && node.Spec.Annotations.Labels[LabelHostRole] == "container"
}

func managerReachable(node *api.Node) bool {
	return node.Role == api.NodeRoleManager && node.ManagerStatus != nil && node.ManagerStatus.Reachability == api.RaftMemberStatus_REACHABLE
}

func managerReady(node *api.Node) bool {
	return managerReachable(node) && node.Status.State == api.NodeStatus_READY && node.Spec.DesiredRole == api.NodeRoleManager
}
func promoteManager(ctx context.Context, client api.ControlClient, watcher api.WatchClient, nodeID string) error {
	watchCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	stream, err := watcher.Watch(watchCtx, &api.WatchRequest{Entries: []*api.WatchRequest_WatchEntry{{
		Kind: "node", Action: api.WatchActionKindUpdate,
		Filters: []*api.SelectBy{{By: &api.SelectBy_ID{ID: nodeID}}},
	}}})
	if err != nil {
		return err
	}
	if _, err := stream.Recv(); err != nil {
		return err
	}
	current, err := client.GetNode(watchCtx, &api.GetNodeRequest{NodeID: nodeID})
	if err != nil {
		return err
	}
	node := current.Node
	if node.Role != api.NodeRoleManager && node.Spec.DesiredRole != api.NodeRoleManager && !promotionEligible(node) {
		return fmt.Errorf("promotion candidate %s is no longer an eligible container worker", nodeID)
	}
	if managerReachable(node) {
		return nil
	}
	if node.Spec.DesiredRole != api.NodeRoleManager {
		spec := node.Spec.Copy()
		spec.DesiredRole = api.NodeRoleManager
		if _, err := client.UpdateNode(watchCtx, &api.UpdateNodeRequest{NodeID: node.ID, NodeVersion: &node.Meta.Version, Spec: spec}); err != nil {
			return fmt.Errorf("promote %s: %w", nodeID, err)
		}
	}
	for node.Role != api.NodeRoleManager {
		message, err := stream.Recv()
		if err != nil {
			return fmt.Errorf("wait for manager %s role: %w", nodeID, err)
		}
		for _, event := range message.Events {
			if updated := event.Object.GetNode(); updated != nil && updated.ID == nodeID {
				node = updated
			}
		}
	}
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		current, err := client.GetNode(watchCtx, &api.GetNodeRequest{NodeID: nodeID})
		if err != nil {
			return err
		}
		if managerReady(current.Node) {
			return nil
		}
		select {
		case <-watchCtx.Done():
			return fmt.Errorf("wait for manager %s Raft reachability: %w", nodeID, watchCtx.Err())
		case <-tick.C:
		}
	}
}
