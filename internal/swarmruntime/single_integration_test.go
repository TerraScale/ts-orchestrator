package swarmruntime

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/moby/swarmkit/v2/api"
)

func TestSingleHostIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	state := t.TempDir()
	start := func() (*Node, api.ControlClient) {
		node, err := StartSingleHost(ctx, state, nodeIdleExecutor{}, SingleHostAddress, SingleHostAddress, FounderAdmission())
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
	networks, err := client.ListNetworks(ctx, &api.ListNetworksRequest{})
	if err != nil {
		t.Fatal(err)
	}
	for _, network := range networks.Networks {
		if network.Spec.Ingress {
			t.Fatalf("single host kept the ingress network %s", network.ID)
		}
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

// TestSingleHostFounderMovesAddressIntegration is the live founders'
// migration: a founder created advertising one address restarts advertising
// its VCN address, keeps its cluster, Raft log and services, and a worker then
// joins it there, restarts from persisted identity and leaves.
func TestSingleHostFounderMovesAddressIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
	defer cancel()
	state := t.TempDir()
	start := func(dir, address string, admission Admission) (*Node, api.ControlClient) {
		t.Helper()
		node, err := StartSingleHost(ctx, dir, nodeIdleExecutor{}, address, address, admission)
		if err != nil {
			t.Fatal(err)
		}
		if admission.Role != "manager" {
			return node, nil
		}
		client, conn, err := DialSingleHost(dir)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return node, client
	}
	stop := func(node *Node) {
		t.Helper()
		if err := node.Stop(ctx); err != nil {
			t.Fatal(err)
		}
	}
	managerAddr := func(client api.ControlClient, id string) string {
		t.Helper()
		got, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: id})
		if err != nil || got.Node.ManagerStatus == nil {
			t.Fatalf("manager status: %v, %v", got, err)
		}
		return got.Node.ManagerStatus.Addr
	}
	loopback, private := freeAddress(t), freeAddress(t)

	founder, client := start(state, loopback, FounderAdmission())
	id := founder.ID()
	clusters, err := client.ListClusters(ctx, &api.ListClustersRequest{})
	if err != nil || len(clusters.Clusters) != 1 {
		t.Fatalf("clusters: %v, %v", clusters, err)
	}
	created, err := client.CreateService(ctx, &api.CreateServiceRequest{Spec: &api.ServiceSpec{
		Annotations: api.Annotations{Name: "survives-address-move"},
		Task:        api.TaskSpec{Runtime: &api.TaskSpec_Container{Container: &api.ContainerSpec{Image: "example.invalid/proof"}}},
		Mode:        &api.ServiceSpec_Replicated{Replicated: &api.ReplicatedService{Replicas: 0}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if got := managerAddr(client, id); got != loopback {
		t.Fatalf("founder advertised %s, want %s", got, loopback)
	}
	stop(founder)

	founder, client = start(state, private, FounderAdmission())
	if founder.ID() != id {
		t.Fatalf("restart changed node identity: %s != %s", founder.ID(), id)
	}
	if got := managerAddr(client, id); got != private {
		t.Fatalf("Raft member address %s, want %s", got, private)
	}
	moved, err := client.ListClusters(ctx, &api.ListClustersRequest{})
	if err != nil || len(moved.Clusters) != 1 || moved.Clusters[0].ID != clusters.Clusters[0].ID {
		t.Fatalf("address move re-founded the cluster: %v, %v", moved, err)
	}
	if _, err := client.GetService(ctx, &api.GetServiceRequest{ServiceID: created.Service.ID}); err != nil {
		t.Fatalf("address move lost Raft state: %v", err)
	}

	joinerState := t.TempDir()
	joiner, _ := start(joinerState, private, JoinerAdmission("joiner-1", "instance-joiner-1", private, moved.Clusters[0].RootCA.JoinTokens.Worker))
	members, err := ListMembers(ctx, client)
	if err != nil || len(members) != 2 || members[0].Hostname != "joiner-1" || members[0].Role != "worker" || members[0].State != "READY" ||
		members[1].Hostname != "single-host" || members[1].Address != private {
		t.Fatalf("members after join: %+v, %v", members, err)
	}

	// Both restart: the founder re-asserts its address (SwarmKit replays a
	// member's own address change as a no-op until a Raft snapshot holds it),
	// and the worker reconnects from its persisted identity and manager list.
	stop(joiner)
	stop(founder)
	founder, client = start(state, private, FounderAdmission())
	if got := managerAddr(client, id); got != private {
		t.Fatalf("Raft member address after restart %s, want %s", got, private)
	}
	stored, ok, err := StoredAdmission(joinerState)
	if err != nil || !ok || stored.HostID != "joiner-1" || stored.Role != "container" || stored.JoinToken != "" {
		t.Fatalf("stored joiner admission: %+v, %v, %v", stored, ok, err)
	}
	joiner, _ = start(joinerState, private, stored)
	defer func() { _ = joiner.Stop(ctx) }() // removed: the upstream node reports its revocation
	defer stop(founder)

	if err := LeaveMember(ctx, client, "single-host"); err == nil {
		t.Fatal("the manager left its own cluster")
	}
	if err := LeaveMember(ctx, client, "joiner-1"); err != nil {
		t.Fatal(err)
	}
	if members, err := ListMembers(ctx, client); err != nil || len(members) != 1 || members[0].Hostname != "single-host" {
		t.Fatalf("members after leave: %+v, %v", members, err)
	}
}

func freeAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().String()
}
