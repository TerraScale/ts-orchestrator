package swarmruntime

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/moby/swarmkit/v2/api"
)

type Member struct {
	Hostname     string `json:"hostname"`
	Name         string `json:"name"`
	Role         string `json:"role"`
	HostRole     string `json:"host_role"`
	Reachability string `json:"reachability"`
	State        string `json:"state"`
	Availability string `json:"availability"`
	Address      string `json:"address"`
}

type MemberList struct {
	Members   []Member `json:"members"`
	Voters    int      `json:"voters"`
	Reachable int      `json:"reachable"`
}

func (l MemberList) Quorum() string {
	return fmt.Sprintf("voters: %d of %d, %d Raft-reachable; quorum needs %d", l.Voters, VotingManagers, l.Reachable, l.Voters/2+1)
}

func ListMembers(ctx context.Context, client api.ControlClient) (MemberList, error) {
	listed, err := client.ListNodes(ctx, &api.ListNodesRequest{})
	if err != nil {
		return MemberList{}, err
	}
	var list MemberList
	for _, node := range listed.Nodes {
		member := Member{Name: node.Spec.Annotations.Name, Role: strings.ToLower(node.Role.String()), HostRole: node.Spec.Annotations.Labels[LabelHostRole],
			Reachability: "-", State: node.Status.State.String(), Availability: node.Spec.Availability.String(), Address: node.Status.Addr}
		if node.Description != nil {
			member.Hostname = node.Description.Hostname
		}
		if node.ManagerStatus != nil {
			member.Address = node.ManagerStatus.Addr
			member.Reachability = strings.ToLower(node.ManagerStatus.Reachability.String())
			list.Voters++
			if node.ManagerStatus.Reachability == api.RaftMemberStatus_REACHABLE {
				list.Reachable++
			}
		}
		list.Members = append(list.Members, member)
	}
	slices.SortFunc(list.Members, func(a, b Member) int { return strings.Compare(a.Hostname, b.Hostname) })
	return list, nil
}

func (l MemberList) Write(output io.Writer) error {
	table := tabwriter.NewWriter(output, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "HOSTNAME\tNAME\tROLE\tHOST-ROLE\tRAFT\tSTATUS\tAVAILABILITY\tADDRESS")
	for _, m := range l.Members {
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", m.Hostname, cmp.Or(m.Name, "-"), m.Role, cmp.Or(m.HostRole, "-"), m.Reachability, m.State, m.Availability, m.Address)
	}
	if err := table.Flush(); err != nil {
		return err
	}
	_, err := fmt.Fprintln(output, l.Quorum())
	return err
}

func RemoveMember(ctx context.Context, client api.ControlClient, hostname string, guard func(context.Context) error) error {
	node, err := memberNode(ctx, client, hostname)
	if err != nil {
		return err
	}
	if node.Role == api.NodeRoleManager || node.Spec.DesiredRole == api.NodeRoleManager {
		if err := CanDemoteManager(ctx, client, node.ID); err != nil {
			return fmt.Errorf("cannot remove %s; promote replacement managers first: %w", hostname, err)
		}
		if err := updateMember(ctx, client, node, api.NodeRoleWorker, guard); err != nil {
			return fmt.Errorf("demote %s: %w", hostname, err)
		}
		if node, err = awaitMember(ctx, client, hostname, 2*time.Minute, func(node *api.Node, _ []*api.Task) bool {
			return node.Role == api.NodeRoleWorker && node.ManagerStatus == nil
		}); err != nil {
			return fmt.Errorf("demote %s: %w", hostname, err)
		}
	}
	if err := updateMember(ctx, client, node, node.Spec.DesiredRole, guard); err != nil {
		return fmt.Errorf("drain %s: %w", hostname, err)
	}
	if _, err := awaitMember(ctx, client, hostname, 5*time.Minute, drained); err != nil {
		return fmt.Errorf("%s still runs tasks: %w", hostname, err)
	}
	if err := guard(ctx); err != nil {
		return err
	}
	if _, err := client.RemoveNode(ctx, &api.RemoveNodeRequest{NodeID: node.ID, Force: true}); err != nil {
		return fmt.Errorf("remove %s: %w", hostname, err)
	}
	return nil
}

func updateMember(ctx context.Context, client api.ControlClient, node *api.Node, role api.NodeRole, guard func(context.Context) error) error {
	if node.Spec.DesiredRole == role && node.Spec.Availability == api.NodeAvailabilityDrain {
		return nil
	}
	if err := guard(ctx); err != nil {
		return err
	}
	spec := node.Spec.Copy()
	spec.DesiredRole, spec.Availability = role, api.NodeAvailabilityDrain
	_, err := client.UpdateNode(ctx, &api.UpdateNodeRequest{NodeID: node.ID, NodeVersion: &node.Meta.Version, Spec: spec})
	return err
}

func drained(node *api.Node, tasks []*api.Task) bool {
	return !slices.ContainsFunc(tasks, func(task *api.Task) bool {
		return task.DesiredState <= api.TaskStateRunning || node.Status.State == api.NodeStatus_READY && task.Status.State <= api.TaskStateRunning
	})
}

func awaitMember(ctx context.Context, client api.ControlClient, hostname string, within time.Duration, done func(*api.Node, []*api.Task) bool) (*api.Node, error) {
	ctx, cancel := context.WithTimeout(ctx, within)
	defer cancel()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		node, err := memberNode(ctx, client, hostname)
		if err != nil {
			return nil, err
		}
		tasks, err := client.ListTasks(ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{NodeIDs: []string{node.ID}}})
		if err != nil {
			return nil, err
		}
		if done(node, tasks.Tasks) {
			return node, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-tick.C:
		}
	}
}

// SetMemberAvailability drains (no tasks) or activates the worker named
// hostname. A drained worker stays in the cluster and the mesh, but counts
// as no node of its region's per-node services.
func SetMemberAvailability(ctx context.Context, client api.ControlClient, hostname string, availability api.NodeSpec_Availability) error {
	node, err := memberNode(ctx, client, hostname)
	if err != nil {
		return err
	}
	if node.Role == api.NodeRoleManager {
		return fmt.Errorf("%s is the region's manager; only workers drain", hostname)
	}
	if _, scaled := node.Spec.Annotations.Labels[LabelDrainSince]; node.Spec.Availability == availability && !scaled {
		return nil
	}
	spec := node.Spec.Copy()
	spec.Availability = availability
	delete(spec.Annotations.Labels, LabelDrainSince)
	_, err = client.UpdateNode(ctx, &api.UpdateNodeRequest{NodeID: node.ID, NodeVersion: &node.Meta.Version, Spec: spec})
	return err
}

func CanDemoteManager(ctx context.Context, client api.ControlClient, nodeID string) error {
	listed, err := client.ListNodes(ctx, &api.ListNodesRequest{})
	if err != nil {
		return err
	}
	managers, remaining := 0, 0
	for _, node := range listed.Nodes {
		if node.Role != node.Spec.DesiredRole {
			return fmt.Errorf("node %s has a pending role change", node.ID)
		}
		if node.Role == api.NodeRoleManager {
			managers++
			if node.ID == nodeID && node.ManagerStatus != nil && node.ManagerStatus.Leader {
				return fmt.Errorf("transfer Raft leadership before removing the leader")
			}
			if node.ID != nodeID && managerReady(node) {
				remaining++
			}
		}
	}
	if managers < 2 || remaining < managers/2+1 {
		return fmt.Errorf("%d reachable remaining managers cannot preserve the majority of %d", remaining, managers)
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
