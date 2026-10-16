package app

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/functionmaterial"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/manager/controlapi"
	"github.com/moby/swarmkit/v2/manager/state/store"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestFunctionMaterialRetirementRequiresAuthoritativeUnusedTask(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	control, err := authority.Start(ctx, testRolloutJetStream(t), authority.Config{
		DeploymentID: entityid.New(), Scope: "gru", CandidateID: entityid.New(), Replicas: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Close() })
	tasks := store.NewMemoryStore(nil)
	t.Cleanup(func() { _ = tasks.Close() })
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	api.RegisterControlServer(server, controlapi.NewServer(tasks, nil, nil, nil, nil))
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	connection, err := grpc.NewClient("passthrough:///"+listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	controller := functionController{config: functionControllerConfig{Authority: control, Client: api.NewControlClient(connection)}}
	binding := functionmaterial.Binding{TaskID: strings.Repeat("a", 25), ServiceID: strings.Repeat("b", 25), NodeID: strings.Repeat("c", 25)}
	task := &api.Task{ID: binding.TaskID, ServiceID: binding.ServiceID, NodeID: binding.NodeID,
		DesiredState: api.TaskStateRunning, Status: api.TaskStatus{State: api.TaskStateRunning}}
	if err := tasks.Update(func(tx store.Tx) error { return store.CreateTask(tx, task) }); err != nil {
		t.Fatal(err)
	}
	if err := controller.requireUnusedMaterial(ctx, binding); err == nil {
		t.Fatal("running assigned task permitted material retirement")
	}
	if err := tasks.Update(func(tx store.Tx) error {
		current := store.GetTask(tx, binding.TaskID)
		current.DesiredState = api.TaskStateShutdown
		return store.UpdateTask(tx, current)
	}); err != nil {
		t.Fatal(err)
	}
	if err := controller.requireUnusedMaterial(ctx, binding); err == nil {
		t.Fatal("desired shutdown retired material before observed process shutdown")
	}
	if err := tasks.Update(func(tx store.Tx) error {
		current := store.GetTask(tx, binding.TaskID)
		current.Status.State = api.TaskStateShutdown
		return store.UpdateTask(tx, current)
	}); err != nil {
		t.Fatal(err)
	}
	if err := controller.requireUnusedMaterial(ctx, binding); err != nil {
		t.Fatalf("terminal exact task denied retirement: %v", err)
	}
	foreign := binding
	foreign.NodeID = strings.Repeat("d", 25)
	if err := controller.requireUnusedMaterial(ctx, foreign); err == nil {
		t.Fatal("terminal task for a different recipient permitted retirement")
	}
	if _, err := controller.config.Client.RemoveTask(ctx, &api.RemoveTaskRequest{TaskID: binding.TaskID}); err != nil {
		t.Fatal(err)
	}
	if err := controller.requireUnusedMaterial(ctx, binding); err != nil {
		t.Fatalf("authoritatively removed task denied retirement: %v", err)
	}
	server.Stop()
	failed, cancelFailed := context.WithTimeout(ctx, time.Second)
	defer cancelFailed()
	if err := controller.requireUnusedMaterial(failed, binding); err == nil {
		t.Fatal("failed manager observation permitted retirement")
	}
}
