package swarmruntime

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/moby/swarmkit/v2/api"
)

func IsLeader(nodes []*api.Node, nodeID string) bool {
	return slices.ContainsFunc(nodes, func(node *api.Node) bool {
		return node.ID == nodeID && node.Role == api.NodeRoleManager && node.ManagerStatus != nil && node.ManagerStatus.Leader
	})
}

func PromoteManagers(ctx context.Context, client api.ControlClient, watcher api.WatchClient, nodeID string) error {
	listed, err := client.ListNodes(ctx, &api.ListNodesRequest{})
	if err != nil {
		return err
	}
	if !IsLeader(listed.Nodes, nodeID) {
		return nil
	}
	managers := 0
	var eligible []*api.Node
	for _, node := range listed.Nodes {
		if node.Role == api.NodeRoleManager || node.Spec.DesiredRole == api.NodeRoleManager {
			managers++
		} else if promotionEligible(node) {
			eligible = append(eligible, node)
		}
	}
	needed := 3 - managers
	if managers < 1 || needed < 1 || len(eligible) < needed {
		return nil
	}
	slices.SortFunc(eligible, func(a, b *api.Node) int {
		at, bt := a.Meta.CreatedAt, b.Meta.CreatedAt
		return cmp.Or(cmp.Compare(at.GetSeconds(), bt.GetSeconds()), cmp.Compare(at.GetNanos(), bt.GetNanos()), strings.Compare(a.ID, b.ID))
	})
	for _, candidate := range eligible[:needed] {
		listed, err := client.ListNodes(ctx, &api.ListNodesRequest{})
		if err != nil {
			return err
		}
		if !IsLeader(listed.Nodes, nodeID) {
			return errors.New("manager promotion lost local Raft leadership")
		}
		managers := 0
		for _, node := range listed.Nodes {
			if node.Role == api.NodeRoleManager || node.Spec.DesiredRole == api.NodeRoleManager {
				managers++
			}
		}
		if managers >= 3 {
			return nil
		}
		if err := promoteManager(ctx, client, watcher, candidate.ID); err != nil {
			return err
		}
	}
	return nil
}

func promotionEligible(node *api.Node) bool {
	return node.Role == api.NodeRoleWorker && node.Spec.DesiredRole != api.NodeRoleManager &&
		node.Status.State == api.NodeStatus_READY && node.Spec.Availability == api.NodeAvailabilityActive &&
		node.Spec.Membership == api.NodeMembershipAccepted && node.Spec.Annotations.Labels[LabelHostRole] == "container"
}

func managerReachable(node *api.Node) bool {
	return node.Role == api.NodeRoleManager && node.ManagerStatus != nil && node.ManagerStatus.Reachability == api.RaftMemberStatus_REACHABLE
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
		if managerReachable(current.Node) {
			return nil
		}
		select {
		case <-watchCtx.Done():
			return fmt.Errorf("wait for manager %s Raft reachability: %w", nodeID, watchCtx.Err())
		case <-tick.C:
		}
	}
}
