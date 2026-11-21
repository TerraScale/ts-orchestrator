package swarmruntime

import (
	"context"
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
	nodes, err := readSwarmNodes(ctx, client)
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
	for i, node := range nodes.raw {
		member := nodes.members[i]
		member.Relocatable = scheduler.Relocatable(services.Services, nodes.raw, tasks.Tasks, node.ID)
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

type swarmNodes struct {
	raw     []*api.Node
	members []fleet.SwarmNode
}

func SwarmManagers(ctx context.Context, client api.ControlClient) fleet.QuorumObservation {
	nodes, err := readSwarmNodes(ctx, client)
	if err != nil {
		return fleet.QuorumObservation{Error: fmt.Sprintf("SwarmKit membership unavailable: %v", err)}
	}
	return fleet.QuorumObservation{Nodes: nodes.members}
}

func readSwarmNodes(ctx context.Context, client api.ControlClient) (swarmNodes, error) {
	listed, err := client.ListNodes(ctx, &api.ListNodesRequest{})
	if err != nil {
		return swarmNodes{}, err
	}
	result := swarmNodes{raw: listed.Nodes}
	for _, node := range listed.Nodes {
		member := fleet.SwarmNode{ID: node.ID, InstanceID: node.Spec.Annotations.Labels[LabelInstanceID], Region: node.Spec.Annotations.Labels[LabelRegion],
			Manager: node.Role == api.NodeRoleManager || node.Spec.DesiredRole == api.NodeRoleManager, ManagerReady: managerReady(node),
			Leader: node.ManagerStatus != nil && node.ManagerStatus.Leader, Ready: node.Status.State == api.NodeStatus_READY,
			Active: node.Spec.Availability == api.NodeAvailabilityActive}
		if node.Description != nil {
			member.Hostname = node.Description.Hostname
		}
		if since, ok := node.Spec.Annotations.Labels[LabelDrainSince]; ok && node.Spec.Availability == api.NodeAvailabilityDrain {
			if member.DrainSince, err = time.Parse(time.RFC3339, since); err != nil {
				return swarmNodes{}, fmt.Errorf("node %s %s: %w", node.ID, LabelDrainSince, err)
			}
		}
		result.members = append(result.members, member)
	}
	return result, nil
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
