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
	ready := 0
	var eligible []*api.Node
	for _, node := range listed.Nodes {
		if node.Status.State != api.NodeStatus_READY {
			continue
		}
		if node.Role == api.NodeRoleManager {
			ready++
		} else if node.Spec.Availability == api.NodeAvailabilityActive && node.Spec.Membership == api.NodeMembershipAccepted {
			eligible = append(eligible, node)
		}
	}
	needed := 3 - ready
	if ready < 1 || needed < 1 || len(eligible) < needed {
		return nil
	}
	slices.SortFunc(eligible, func(a, b *api.Node) int {
		at, bt := a.Meta.CreatedAt, b.Meta.CreatedAt
		return cmp.Or(cmp.Compare(at.GetSeconds(), bt.GetSeconds()), cmp.Compare(at.GetNanos(), bt.GetNanos()), strings.Compare(a.ID, b.ID))
	})
	promoteCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	for _, candidate := range eligible[:needed] {
		listed, err := client.ListNodes(promoteCtx, &api.ListNodesRequest{})
		if err != nil {
			return err
		}
		if !IsLeader(listed.Nodes, nodeID) {
			return errors.New("manager promotion lost local Raft leadership")
		}
		if err := promoteManager(promoteCtx, client, watcher, candidate.ID); err != nil {
			return err
		}
	}
	return nil
}

func promoteManager(ctx context.Context, client api.ControlClient, watcher api.WatchClient, nodeID string) error {
	watchCtx, cancel := context.WithCancel(ctx)
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
	current, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: nodeID})
	if err != nil {
		return err
	}
	node := current.Node
	if node.Status.State != api.NodeStatus_READY || node.Spec.Availability != api.NodeAvailabilityActive {
		return fmt.Errorf("promotion candidate %s is no longer READY and active", nodeID)
	}
	if node.Role == api.NodeRoleManager {
		return nil
	}
	if node.Spec.DesiredRole != api.NodeRoleManager {
		spec := node.Spec.Copy()
		spec.DesiredRole = api.NodeRoleManager
		if _, err := client.UpdateNode(ctx, &api.UpdateNodeRequest{NodeID: node.ID, NodeVersion: &node.Meta.Version, Spec: spec}); err != nil {
			return fmt.Errorf("promote %s: %w", nodeID, err)
		}
	}
	for {
		message, err := stream.Recv()
		if err != nil {
			return fmt.Errorf("wait for manager %s role: %w", nodeID, err)
		}
		for _, event := range message.Events {
			if node := event.Object.GetNode(); node != nil && node.ID == nodeID && node.Role == api.NodeRoleManager {
				return nil
			}
		}
	}
}
