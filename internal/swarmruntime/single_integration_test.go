package swarmruntime

import (
	"context"
	"testing"
	"time"

	"github.com/moby/swarmkit/v2/api"
)

func TestSingleHostIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	state := t.TempDir()
	start := func() (*Node, api.ControlClient) {
		node, err := StartSingleHost(ctx, state, nodeIdleExecutor{})
		if err != nil {
			t.Fatal(err)
		}
		client, conn, err := DialSingleHost(state)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return node, client
	}
	stop := func(node *Node) {
		if err := node.Stop(ctx); err != nil {
			t.Fatal(err)
		}
	}
	node, client := start()
	id := node.ID()
	services, err := client.ListServices(ctx, &api.ListServicesRequest{})
	if err != nil || len(services.Services) != 0 {
		t.Fatalf("fresh single host services: %v, %v", services, err)
	}
	created, err := client.CreateService(ctx, &api.CreateServiceRequest{Spec: &api.ServiceSpec{
		Annotations: api.Annotations{Name: "single-host-persistence"},
		Task:        api.TaskSpec{Runtime: &api.TaskSpec_Container{Container: &api.ContainerSpec{Image: "example.invalid/proof"}}},
		Mode:        &api.ServiceSpec_Replicated{Replicated: &api.ReplicatedService{Replicas: 0}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	stop(node)

	node, client = start()
	defer stop(node)
	if node.ID() != id {
		t.Fatalf("restart changed node identity: %s != %s", node.ID(), id)
	}
	nodes, err := client.ListNodes(ctx, &api.ListNodesRequest{})
	if err != nil || len(nodes.Nodes) != 1 || nodes.Nodes[0].Role != api.NodeRoleManager ||
		nodes.Nodes[0].Spec.Availability != api.NodeAvailabilityActive {
		t.Fatalf("single host must be one active manager: %v, %v", nodes, err)
	}
	if _, err := client.GetService(ctx, &api.GetServiceRequest{ServiceID: created.Service.ID}); err != nil {
		t.Fatalf("restart lost Raft state: %v", err)
	}
}
