package swarmruntime

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/manager/scheduler"

	"github.com/TerraScale/ts-orchestrator/internal/fleet"
	"github.com/TerraScale/ts-orchestrator/internal/storage/execution"
)

const LabelDrainSince = "terrascale.drain-since"

func (n *Node) SwarmView(ctx context.Context) (fleet.SwarmView, error) {
	term, _, err := n.LeaderTerm(ctx)
	if err != nil {
		return fleet.SwarmView{}, err
	}
	client, err := n.ControlClient(ctx)
	if err != nil {
		return fleet.SwarmView{}, err
	}
	nodes, err := client.ListNodes(ctx, &api.ListNodesRequest{})
	if err != nil {
		return fleet.SwarmView{}, err
	}
	tasks, err := client.ListTasks(ctx, &api.ListTasksRequest{})
	if err != nil {
		return fleet.SwarmView{}, err
	}
	services, err := client.ListServices(ctx, &api.ListServicesRequest{})
	if err != nil {
		return fleet.SwarmView{}, err
	}
	view := fleet.SwarmView{Term: term, Demand: replicaDemand()}
	for _, task := range tasks.Tasks {
		if task.DesiredState == api.TaskStateRunning && task.Status.State < api.TaskStateRunning {
			view.Pending++
		}
	}
	for _, node := range nodes.Nodes {
		member := fleet.SwarmNode{ID: node.ID, InstanceID: node.Spec.Annotations.Labels[LabelInstanceID],
			Manager: node.Role == api.NodeRoleManager || node.Spec.DesiredRole == api.NodeRoleManager, ManagerReady: managerReady(node),
			Leader: node.ManagerStatus != nil && node.ManagerStatus.Leader, Ready: node.Status.State == api.NodeStatus_READY,
			Active:      node.Spec.Availability == api.NodeAvailabilityActive,
			Relocatable: scheduler.Relocatable(services.Services, nodes.Nodes, tasks.Tasks, node.ID)}
		if node.Description != nil {
			member.Hostname = node.Description.Hostname
		}
		member.Address, member.Version = node.Status.Addr, node.Meta.Version.Index
		if since, ok := node.Spec.Annotations.Labels[LabelDrainSince]; ok && node.Spec.Availability == api.NodeAvailabilityDrain {
			if member.DrainSince, err = time.Parse(time.RFC3339, since); err != nil {
				return fleet.SwarmView{}, fmt.Errorf("node %s %s: %w", node.ID, LabelDrainSince, err)
			}
		}
		for _, task := range tasks.Tasks {
			if task.NodeID != node.ID || task.Status.State > api.TaskStateRunning {
				continue
			}
			member.Tasks++
			if member.Data == "" && execution.Stateful(task) {
				member.Data = task.ServiceAnnotations.Name
			}
		}
		view.Nodes = append(view.Nodes, member)
	}
	return view, nil
}

func replicaDemand() fleet.Demand {
	replicaMetrics.Lock()
	a := replicaMetrics.scaler
	replicaMetrics.Unlock()
	if a == nil {
		return fleet.Demand{}
	}
	results := a.Last()
	if results == nil {
		return fleet.Demand{}
	}
	demand := fleet.Demand{Known: true}
	for target, result := range results {
		switch {
		case result.Reason == "region-capacity":
			demand.Blocked = append(demand.Blocked, target.Role)
		case result.Decision.To > result.Decision.From:
			demand.Growing = append(demand.Growing, target.Role)
		}
	}
	slices.Sort(demand.Blocked)
	slices.Sort(demand.Growing)
	return demand
}

func (n *Node) Cordon(ctx context.Context, nodeID string, since time.Time) error {
	client, err := n.ControlClient(ctx)
	if err != nil {
		return err
	}
	got, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: nodeID})
	if err != nil {
		return err
	}
	node := got.Node
	if node.Role == api.NodeRoleManager || node.Spec.DesiredRole == api.NodeRoleManager {
		return fmt.Errorf("node %s is a manager; only workers are drained for removal", nodeID)
	}
	spec := node.Spec.Copy()
	spec.Availability = api.NodeAvailabilityDrain
	if spec.Annotations.Labels == nil {
		spec.Annotations.Labels = map[string]string{}
	}
	spec.Annotations.Labels[LabelDrainSince] = since.UTC().Format(time.RFC3339)
	_, err = client.UpdateNode(ctx, &api.UpdateNodeRequest{NodeID: node.ID, NodeVersion: &node.Meta.Version, Spec: spec})
	return err
}

func (n *Node) Remove(ctx context.Context, hostname string, guard func(context.Context) error) error {
	client, err := n.ControlClient(ctx)
	if err != nil {
		return err
	}
	return RemoveMember(ctx, client, hostname, guard)
}

func (n *Node) Admit(ctx context.Context, verified fleet.SwarmNode, instanceID, region string) error {
	client, err := n.ControlClient(ctx)
	if err != nil {
		return err
	}
	listed, err := client.ListNodes(ctx, &api.ListNodesRequest{})
	if err != nil {
		return err
	}
	var node *api.Node
	for _, current := range listed.Nodes {
		switch {
		case current.ID == verified.ID:
			node = current
		case current.Spec.Annotations.Labels[LabelInstanceID] == instanceID && current.Status.State == api.NodeStatus_READY:
			return fmt.Errorf("instance %s already has the live Swarm identity %s", instanceID, current.ID)
		}
	}
	switch {
	case node == nil:
		return errors.New("node left the cluster after verification")
	case node.Meta.Version.Index != verified.Version || node.Description == nil || node.Description.Hostname != verified.Hostname ||
		node.Status.Addr != verified.Address || node.Status.State != api.NodeStatus_READY:
		return fmt.Errorf("node changed after verification (version %d, verified %d)", node.Meta.Version.Index, verified.Version)
	}
	role := "container"
	if node.Role == api.NodeRoleManager {
		role = "manager"
	}
	_, err = admitNode(ctx, client, node, Admission{Region: region, HostID: verified.Hostname, InstanceID: instanceID, Role: role})
	return err
}
