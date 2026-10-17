package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
	"google.golang.org/grpc"
)

var edgeTestSessionExpiry = time.Now().Add(time.Hour)

type edgeTestManager struct {
	api.ControlClient
	hosts        *nodeHosts
	changed      bool
	probe        func(*api.Task)
	readinessErr bool
	names        []string
	roles        []string
	mismatch     bool
}

func bindEdgeTestManager(fence *releaseFence, hosts *nodeHosts) *edgeTestManager {
	client := &edgeTestManager{hosts: hosts}
	fence.recipient = func(_ context.Context, node *api.Node, registration host.Registration) (managerEdgeRecipient, error) {
		current := func(context.Context) error {
			if fence.manager == nil || fence.manager.specs.controllerNode(registration.Cell, node.Spec.Annotations.Name) != registration.Node {
				return errors.New("recipient mismatch")
			}
			return nil
		}
		return managerEdgeRecipient{deadline: edgeTestSessionExpiry, current: current}, current(context.Background())
	}
	specs := &specRegistry{cell: "gru"}
	for _, node := range []string{"ctl-1", "ctl-2", "ctl-3"} {
		specs.current.HostGrants = append(specs.current.HostGrants, cellspec.HostGrant{Node: node, Controller: node, PrivateIP: fenceAddresses[node]})
	}
	fence.manager = &managerWorkloadView{client: client, managerID: "ctl-1", authority: fence.fencer, specs: specs, probe: func(_ context.Context, task *api.Task) error {
		if client.probe != nil {
			client.probe(task)
		}
		hosts.mu.Lock()
		defer hosts.mu.Unlock()
		if client.readinessErr || hosts.down[task.NodeID] || hosts.states[task.NodeID+"/"+task.ServiceAnnotations.Labels[swarmruntime.LabelRole]] != "" {
			return errors.New("application is unready")
		}
		return nil
	}}
	return client
}

func (c *edgeTestManager) nodeNames() []string {
	if c.names != nil {
		return c.names
	}
	return []string{"ctl-1", "ctl-2", "ctl-3"}
}
func (c *edgeTestManager) serviceRoles() []string {
	if c.roles != nil {
		return c.roles
	}
	return []string{"terrabase", "ts-auth"}
}

func (c *edgeTestManager) GetNode(ctx context.Context, r *api.GetNodeRequest, _ ...grpc.CallOption) (*api.GetNodeResponse, error) {
	nodes, _ := c.ListNodes(ctx, &api.ListNodesRequest{})
	for _, node := range nodes.Nodes {
		if node.ID == r.NodeID {
			return &api.GetNodeResponse{Node: node}, nil
		}
	}
	return nil, errors.New("node missing")
}

func (c *edgeTestManager) ListNodes(context.Context, *api.ListNodesRequest, ...grpc.CallOption) (*api.ListNodesResponse, error) {
	response := &api.ListNodesResponse{}
	for _, name := range c.nodeNames() {
		response.Nodes = append(response.Nodes, &api.Node{ID: name, Role: api.NodeRoleManager, Spec: api.NodeSpec{Annotations: api.Annotations{Name: name, Labels: map[string]string{swarmruntime.LabelRegion: "sa-saopaulo-1"}}, Membership: api.NodeMembershipAccepted, DesiredRole: api.NodeRoleManager, Availability: api.NodeAvailabilityActive}, Status: api.NodeStatus{State: api.NodeStatus_READY}, ManagerStatus: &api.ManagerStatus{Leader: name == c.nodeNames()[0]}})
	}
	return response, nil
}

func (c *edgeTestManager) ListServices(context.Context, *api.ListServicesRequest, ...grpc.CallOption) (*api.ListServicesResponse, error) {
	response := &api.ListServicesResponse{}
	for _, role := range c.serviceRoles() {
		response.Services = append(response.Services, &api.Service{ID: role, Spec: api.ServiceSpec{Annotations: api.Annotations{Labels: edgeTestLabels(role)}, Mode: &api.ServiceSpec_Replicated{Replicated: &api.ReplicatedService{Replicas: 3}}}})
	}
	return response, nil
}

func edgeTestLabels(role string) map[string]string {
	return map[string]string{swarmruntime.LabelRole: role, swarmruntime.LabelRegion: "sa-saopaulo-1", swarmruntime.LabelEnvironment: "production"}
}

func (c *edgeTestManager) ListTasks(context.Context, *api.ListTasksRequest, ...grpc.CallOption) (*api.ListTasksResponse, error) {
	c.hosts.mu.Lock()
	defer c.hosts.mu.Unlock()
	response := &api.ListTasksResponse{}
	for _, node := range c.nodeNames() {
		if c.hosts.withdrawn[node] {
			continue
		}
		for _, role := range c.serviceRoles() {
			task := &api.Task{ID: node + "/" + role, NodeID: node, ServiceID: role, ServiceAnnotations: api.Annotations{Labels: edgeTestLabels(role)}, DesiredState: api.TaskStateRunning, Status: api.TaskStatus{State: api.TaskStateRunning}}
			if c.changed {
				task.Meta.Version.Index++
			}
			if c.mismatch {
				task.ServiceAnnotations.Labels[swarmruntime.LabelEnvironment] = "different"
			}
			response.Tasks = append(response.Tasks, task)
		}
	}
	return response, nil
}

func TestEdgeReadinessRejectsMissingManager(t *testing.T) {
	edge, _, balancer, _ := newEdgeTest(t)
	edge.fence.manager = nil
	if err := edge.pass(t.Context()); err == nil || !strings.Contains(err.Error(), "source is unavailable") {
		t.Fatalf("missing manager: %v", err)
	}
	if len(balancer.log) != 0 {
		t.Fatalf("missing manager changed traffic: %v", balancer.log)
	}
}

func TestEdgeReadinessRejectsAssignmentChangedDuringProbe(t *testing.T) {
	edge, _, balancer, _ := newEdgeTest(t)
	client := edge.fence.manager.client.(*edgeTestManager)
	client.probe = func(*api.Task) { client.changed = true }
	if err := edge.pass(t.Context()); err == nil || !strings.Contains(err.Error(), "changed during observation") {
		t.Fatalf("changed assignment: %v", err)
	}
	if len(balancer.log) != 0 {
		t.Fatalf("changed assignment changed traffic: %v", balancer.log)
	}
}

func TestEdgeReadinessIgnoresNativeReports(t *testing.T) {
	edge, _, _, _ := newEdgeTest(t)
	client := edge.fence.manager.client.(*edgeTestManager)
	client.readinessErr = true
	reason, err := edge.fence.nodeRolesServing(t.Context(), "ctl-2", time.Time{})
	if err != nil || reason == "" {
		t.Fatalf("native reports replaced task readiness: %q %v", reason, err)
	}
}

func TestEdgeReadinessVerifiesIdleManager(t *testing.T) {
	edge, _, _, _ := newEdgeTest(t)
	client := edge.fence.manager.client.(*edgeTestManager)
	client.hosts.withdrawn["ctl-2"] = true
	if reason, err := edge.fence.nodeRolesServing(t.Context(), "ctl-2", time.Time{}); err != nil || reason != "" {
		t.Fatalf("verified idle manager: %q %v", reason, err)
	}
	client.hosts.down["ctl-2"] = true
	if reason, err := edge.fence.nodeRolesServing(t.Context(), "ctl-2", time.Time{}); err != nil || reason == "" {
		t.Fatalf("unverified idle manager: %q %v", reason, err)
	}
}

func TestEdgeReadinessRejectsMismatchedAssignmentScope(t *testing.T) {
	edge, _, balancer, _ := newEdgeTest(t)
	edge.fence.manager.client.(*edgeTestManager).mismatch = true
	if err := edge.pass(t.Context()); err == nil || !strings.Contains(err.Error(), "scope differs") {
		t.Fatalf("mismatched assignment scope: %v", err)
	}
	if len(balancer.log) != 0 {
		t.Fatalf("mismatched assignment changed traffic: %v", balancer.log)
	}
}

func TestEdgeReadinessRetainsOriginalContext(t *testing.T) {
	edge, _, _, _ := newEdgeTest(t)
	view := edge.fence.manager
	source := managerEdgeSource{client: view.client, specs: view.specs, hosts: edge.fence.hosts, probe: view.probe, recipient: edge.fence.recipient, guard: func(ctx context.Context) error { return view.authority.Guard(ctx, 3) }}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	_, check, err := source.snapshot(ctx)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	cancel()
	if err := check(t.Context()); err == nil {
		t.Fatal("successor context refreshed original readiness lifetime")
	}
}
