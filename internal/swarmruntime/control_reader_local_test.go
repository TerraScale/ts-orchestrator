//go:build linux

package swarmruntime

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/manager"
)

// The caller supplies the actual persistent Raft manager from the local
// observation integration; all fixture writes use its genuine control RPC.
func testLocalControlSocketIndependence(t *testing.T, ctx context.Context, node *Node, client api.ControlClient) *manager.ControlReader {
	t.Helper()
	reader, err := node.ReadOnlyControlClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	sourceCtx, stopSource := context.WithCancel(ctx)
	shortReader, err := node.ReadOnlyControlClient(sourceCtx)
	if err != nil {
		t.Fatal(err)
	}
	stopSource()
	if _, err := shortReader.GetNode(ctx, &api.GetNodeRequest{NodeID: node.ID()}); err == nil {
		t.Fatal("readonly source outlived its original context")
	}
	if _, ok := any(reader).(api.ControlClient); ok {
		t.Fatal("readonly source exposed mutation methods")
	}
	clusters, err := client.ListClusters(ctx, &api.ListClustersRequest{})
	if err != nil || len(clusters.Clusters) != 1 {
		t.Fatalf("actual cluster identity unavailable: %v %v", clusters, err)
	}
	config, err := client.CreateConfig(ctx, &api.CreateConfigRequest{Spec: &api.ConfigSpec{Annotations: api.Annotations{Name: "local-read-config"}, Data: []byte("public-fixture")}})
	if err != nil {
		t.Fatal(err)
	}
	service, err := client.CreateService(ctx, &api.CreateServiceRequest{Spec: &api.ServiceSpec{
		Annotations: api.Annotations{Name: "local-read-service"},
		Task: api.TaskSpec{
			Runtime:   &api.TaskSpec_Container{Container: &api.ContainerSpec{Image: "example.invalid/proof@sha256:" + strings.Repeat("0", 64)}},
			Placement: &api.Placement{Constraints: []string{"node.id==unavailable"}},
		},
		Mode: &api.ServiceSpec_Replicated{Replicated: &api.ReplicatedService{Replicas: 1}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	var taskID string
	taskFilter := &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{ServiceIDs: []string{service.Service.ID}}}
	serviceEventually(t, ctx, func() bool {
		tasks, err := client.ListTasks(ctx, taskFilter)
		if err != nil || len(tasks.Tasks) != 1 {
			return false
		}
		taskID = tasks.Tasks[0].ID
		return taskID != ""
	})
	// Closing the real cached connection proves independence even when the
	// original socket client would otherwise reuse an already-open transport.
	socketCtx, stopSocket := context.WithCancel(ctx)
	connections := node.upstream.ListenControlSocket(socketCtx)
	connection := <-connections
	stopSocket()
	select {
	case _, open := <-connections:
		if open {
			t.Fatal("canceled socket listener retained a connection")
		}
	case <-ctx.Done():
		t.Fatal("canceled socket listener did not close: ", ctx.Err())
	}
	if connection == nil {
		t.Fatal("actual manager control connection unavailable")
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: node.ID()}); err == nil {
		t.Fatal("closed actual control RPC still worked")
	}
	if response, err := reader.GetNode(ctx, &api.GetNodeRequest{NodeID: node.ID()}); err != nil || response.Node.ID != node.ID() {
		t.Fatalf("store-backed node read depended on socket: %v %v", response, err)
	}
	if response, err := reader.ListNodes(ctx, &api.ListNodesRequest{Filters: &api.ListNodesRequest_Filters{Roles: []api.NodeRole{api.NodeRoleManager}}}); err != nil || len(response.Nodes) != 1 || response.Nodes[0].ID != node.ID() {
		t.Fatalf("store-backed filtered node list: %v %v", response, err)
	}
	if response, err := reader.GetTask(ctx, &api.GetTaskRequest{TaskID: taskID}); err != nil || response.Task.ID != taskID || response.Task.ServiceID != service.Service.ID {
		t.Fatalf("store-backed task read: %v %v", response, err)
	}
	if response, err := reader.ListTasks(ctx, taskFilter); err != nil || len(response.Tasks) != 1 || response.Tasks[0].ID != taskID {
		t.Fatalf("store-backed filtered task list: %v %v", response, err)
	}
	if response, err := reader.GetService(ctx, &api.GetServiceRequest{ServiceID: service.Service.ID}); err != nil || response.Service.ID != service.Service.ID {
		t.Fatalf("store-backed service read: %v %v", response, err)
	}
	if response, err := reader.ListServices(ctx, &api.ListServicesRequest{Filters: &api.ListServicesRequest_Filters{Names: []string{"local-read-service"}}}); err != nil || len(response.Services) != 1 || response.Services[0].ID != service.Service.ID {
		t.Fatalf("store-backed filtered service list: %v %v", response, err)
	}
	if response, err := reader.GetConfig(ctx, &api.GetConfigRequest{ConfigID: config.Config.ID}); err != nil || response.Config.ID != config.Config.ID {
		t.Fatalf("store-backed config read: %v %v", response, err)
	}
	if response, err := reader.ListConfigs(ctx, &api.ListConfigsRequest{Filters: &api.ListConfigsRequest_Filters{Names: []string{"local-read-config"}}}); err != nil || len(response.Configs) != 1 || response.Configs[0].ID != config.Config.ID {
		t.Fatalf("store-backed filtered config list: %v %v", response, err)
	}
	identity, err := reader.ClusterIdentity(ctx)
	if err != nil || identity.ID != clusters.Clusters[0].ID || !bytes.Equal(identity.RootCACert, clusters.Clusters[0].RootCA.CACert) {
		t.Fatalf("store-backed public cluster identity: %v %v", identity, err)
	}
	identity.RootCACert[0] ^= 1
	current, err := reader.ClusterIdentity(ctx)
	if err != nil || !bytes.Equal(current.RootCACert, clusters.Clusters[0].RootCA.CACert) {
		t.Fatal("cluster identity leaked mutable store certificate bytes")
	}
	if _, err := reader.GetNode(ctx, nil); err == nil {
		t.Fatal("nil readonly request accepted")
	}
	return reader
}
