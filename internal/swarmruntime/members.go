package swarmruntime

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/moby/swarmkit/v2/api"
)

// Member is one host of the region's cluster as its manager sees it.
type Member struct {
	Hostname, Role, State, Availability, Address string
}

// ListMembers lists the cluster's hosts by hostname.
func ListMembers(ctx context.Context, client api.ControlClient) ([]Member, error) {
	listed, err := client.ListNodes(ctx, &api.ListNodesRequest{})
	if err != nil {
		return nil, err
	}
	members := make([]Member, 0, len(listed.Nodes))
	for _, node := range listed.Nodes {
		member := Member{Role: strings.ToLower(node.Role.String()), State: node.Status.State.String(),
			Availability: node.Spec.Availability.String(), Address: node.Status.Addr}
		if node.Description != nil {
			member.Hostname = node.Description.Hostname
		}
		if node.ManagerStatus != nil {
			member.Address = node.ManagerStatus.Addr
		}
		members = append(members, member)
	}
	slices.SortFunc(members, func(a, b Member) int { return strings.Compare(a.Hostname, b.Hostname) })
	return members, nil
}

// LeaveMember drains the worker named hostname, waits until none of its tasks
// runs, then removes it from the cluster. The removed host cannot rejoin with
// its old identity; it is retired or rebuilt from empty state.
func LeaveMember(ctx context.Context, client api.ControlClient, hostname string) error {
	node, err := memberNode(ctx, client, hostname)
	if err != nil {
		return err
	}
	if node.Role == api.NodeRoleManager {
		return fmt.Errorf("%s is the region's manager; only workers leave", hostname)
	}
	if node.Spec.Availability != api.NodeAvailabilityDrain {
		spec := node.Spec.Copy()
		spec.Availability = api.NodeAvailabilityDrain
		if _, err := client.UpdateNode(ctx, &api.UpdateNodeRequest{NodeID: node.ID, NodeVersion: &node.Meta.Version, Spec: spec}); err != nil {
			return fmt.Errorf("drain %s: %w", hostname, err)
		}
	}
	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Minute) // bounds the tasks' stop grace periods
	defer cancel()
	for ; ; time.Sleep(time.Second) {
		tasks, err := client.ListTasks(waitCtx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{NodeIDs: []string{node.ID}}})
		if err != nil {
			return fmt.Errorf("%s still runs tasks: %w", hostname, err)
		}
		if !slices.ContainsFunc(tasks.Tasks, func(task *api.Task) bool { return task.Status.State <= api.TaskStateRunning }) {
			break
		}
	}
	// Force: the drained host is still up; SwarmKit revokes its certificate.
	if _, err := client.RemoveNode(ctx, &api.RemoveNodeRequest{NodeID: node.ID, Force: true}); err != nil {
		return fmt.Errorf("remove %s: %w", hostname, err)
	}
	return nil
}

func memberNode(ctx context.Context, client api.ControlClient, hostname string) (*api.Node, error) {
	listed, err := client.ListNodes(ctx, &api.ListNodesRequest{})
	if err != nil {
		return nil, err
	}
	var found *api.Node
	for _, node := range listed.Nodes {
		if node.Description != nil && node.Description.Hostname == hostname {
			if found != nil {
				return nil, fmt.Errorf("two cluster hosts are named %s", hostname)
			}
			found = node
		}
	}
	if found == nil {
		return nil, fmt.Errorf("no cluster host is named %s", hostname)
	}
	return found, nil
}
