package swarmruntime

import (
	"context"
	"crypto/tls"
	"errors"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/moby/swarmkit/v2/agent/exec"
	"github.com/moby/swarmkit/v2/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// This starts at the verified-identity boundary and exercises real CA joins,
// Vault SDK requests, dispatcher registration and upstream task scheduling.
func TestAcceptedManagersRegisterPausedBeforeExecutionAdmission(t *testing.T) {
	// Managers must outlive service cleanup, which runs after t.Context is canceled.
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	_, vaultClient, bundles := bootstrapVaultServer(t)
	target := vaultsecret.Target{CompartmentID: "ocid1.compartment.oc1..control", VaultID: "ocid1.vault.oc1.sa-saopaulo-1.control", KeyID: "ocid1.key.oc1.sa-saopaulo-1.control"}
	identity := bootstrapstart.RuntimeIdentity{DeploymentID: "0000000000F9PR1WNVDTEXS31Z", ClusterID: "0000000000RMSAJ9B0JFV7ESHN",
		Environment: "production", Cell: "GRU", OCIRegion: "sa-saopaulo-1", Slot: "controller-a", SeedSlot: "controller-a",
		InstanceID: "ocid1.instance.oc1.sa-saopaulo-1.founder", PrivateIP: "127.181.0.11", SeedPrivateIP: "127.181.0.11"}
	var executors []*acceptedPauseExecutor
	start := func(binding bootstrapstart.RuntimeIdentity) *Node {
		t.Helper()
		executor := &acceptedPauseExecutor{first: make(chan api.NodeSpec_Availability, 1)}
		executors = append(executors, executor)
		node, err := startAcceptedNodeAt(ctx, t.TempDir(), binding, target, vaultClient, bundles, executor, func(context.Context) error { return nil })
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { nodeFixtureStop(t, node) })
		select {
		case availability := <-executor.first:
			if availability != api.NodeAvailabilityPause {
				t.Fatalf("%s first dispatcher registration was %s", binding.Slot, availability)
			}
		case <-ctx.Done():
			t.Fatal("dispatcher did not configure the registered manager", ctx.Err())
		}
		client, err := node.ControlClient(ctx)
		if err != nil {
			t.Fatal(err)
		}
		registered, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: node.ID()})
		if err != nil || registered.Node == nil {
			t.Fatal("registered manager unavailable", err)
		}
		if registered.Node.Spec.Availability != api.NodeAvailabilityPause || registered.Node.Spec.Annotations.Name != binding.Slot {
			t.Fatal("accepted manager returned before its paused placement identity")
		}
		return node
	}
	founder := start(identity)
	peer := identity
	peer.Slot, peer.InstanceID, peer.PrivateIP = "controller-b", "ocid1.instance.oc1.sa-saopaulo-1.peer", "127.181.0.12"
	_ = start(peer)
	client, err := founder.ControlClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	service, err := applyService(ctx, client, ServiceIntent{
		ID: entityid.Derive("integration", "accepted-initial-pause"), Role: "smoke", Region: identity.OCIRegion, Environment: identity.Environment,
		Architecture: runtime.GOARCH, Replicas: 1,
		Container: &api.ContainerSpec{Image: integrationImage, User: "65532:65532", Command: []string{"/bin/sleep", "60"}},
		Resources: &api.ResourceRequirements{Limits: &api.Resources{NanoCPUs: 125_000_000, MemoryBytes: 32 << 20}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if _, err := client.RemoveService(cleanup, &api.RemoveServiceRequest{ServiceID: service.ID}); err != nil {
			t.Error(err)
		}
	})
	waitRuntime(t, ctx, func() (bool, error) {
		tasks, err := client.ListTasks(ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{ServiceIDs: []string{service.ID}}})
		if err != nil || len(tasks.Tasks) != 1 {
			return false, err
		}
		if tasks.Tasks[0].NodeID != "" || tasks.Tasks[0].Status.State > api.TaskState_PENDING {
			t.Fatal("scheduler assigned work before controller execution admission")
		}
		return tasks.Tasks[0].Status.State == api.TaskState_PENDING, nil
	})
	for _, executor := range executors {
		if executor.unpaused.Load() || executor.assignments.Load() != 0 {
			t.Fatal("accepted manager executed or registered unpaused before admission")
		}
	}
}

func TestAcceptedManagerRestartPausesBeforeAgentRegistration(t *testing.T) {
	// Retain manager lifetime through cleanup of both starts of its persisted state.
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	_, vaultClient, bundles := bootstrapVaultServer(t)
	target := vaultsecret.Target{CompartmentID: "ocid1.compartment.oc1..control", VaultID: "ocid1.vault.oc1.sa-saopaulo-1.control", KeyID: "ocid1.key.oc1.sa-saopaulo-1.control"}
	identity := bootstrapstart.RuntimeIdentity{DeploymentID: "0000000000F9PR1WNVDTEXS31Z", ClusterID: "0000000000RMSAJ9B0JFV7ESHN",
		Environment: "production", Cell: "GRU", OCIRegion: "sa-saopaulo-1", Slot: "controller-a", SeedSlot: "controller-a",
		InstanceID: "ocid1.instance.oc1.sa-saopaulo-1.founder", PrivateIP: "127.181.0.21", SeedPrivateIP: "127.181.0.21"}
	directory := t.TempDir()
	start := func(executor *acceptedPauseExecutor) *Node {
		t.Helper()
		node, err := startAcceptedNodeAt(ctx, directory, identity, target, vaultClient, bundles, executor, func(context.Context) error { return nil })
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { nodeFixtureStop(t, node) })
		return node
	}
	node := start(&acceptedPauseExecutor{first: make(chan api.NodeSpec_Availability, 1)})
	nodeID := node.ID()
	client, err := node.ControlClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	current, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: nodeID})
	if err != nil {
		t.Fatal(err)
	}
	spec := current.Node.Spec.Copy()
	spec.Availability = api.NodeAvailabilityActive
	// The fixture deliberately persists an admitted ACTIVE predecessor.
	if _, err := client.UpdateNode(ctx, &api.UpdateNodeRequest{NodeID: nodeID, NodeVersion: &current.Node.Meta.Version, Spec: spec}); err != nil {
		t.Fatal(err)
	}
	nodeFixtureStop(t, node)

	described := make(chan error, 1)
	executor := &acceptedPauseExecutor{first: make(chan api.NodeSpec_Availability, 1), describe: func(ctx context.Context) error {
		report := func(err error) {
			select {
			case described <- err:
			default:
			}
		}
		// Observe the real persisted row at the first delegated Describe, before registration.
		conn, err := grpc.NewClient("unix:"+filepath.Join(directory, "node", "control.sock"),
			grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})))
		if err != nil {
			report(err)
			return err
		}
		defer conn.Close()
		current, err := api.NewControlClient(conn).GetNode(ctx, &api.GetNodeRequest{NodeID: nodeID})
		if err == nil && (current.Node == nil || current.Node.Spec.Availability != api.NodeAvailabilityPause) {
			err = errors.New("persisted manager was not PAUSE before agent description")
		}
		report(err)
		return err
	}}
	node = start(executor)
	if node.ID() != nodeID {
		t.Fatal("restart changed the persisted manager identity")
	}
	select {
	case err := <-described:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("restarted executor was not described", ctx.Err())
	}
	select {
	case availability := <-executor.first:
		if availability != api.NodeAvailabilityPause || executor.unpaused.Load() || executor.assignments.Load() != 0 {
			t.Fatal("restarted manager reconnected before its PAUSE barrier")
		}
	case <-ctx.Done():
		t.Fatal("restarted manager was not configured", ctx.Err())
	}
}

type acceptedPauseExecutor struct {
	bootstrapHostExecutor
	first       chan api.NodeSpec_Availability
	describe    func(context.Context) error
	unpaused    atomic.Bool
	assignments atomic.Int32
}

func (e *acceptedPauseExecutor) Describe(ctx context.Context) (*api.NodeDescription, error) {
	if e.describe != nil {
		if err := e.describe(ctx); err != nil {
			return nil, err
		}
	}
	return e.bootstrapHostExecutor.Describe(ctx)
}

func (e *acceptedPauseExecutor) Configure(_ context.Context, node *api.Node) error {
	if node.Spec.Availability != api.NodeAvailabilityPause {
		e.unpaused.Store(true)
	}
	select {
	case e.first <- node.Spec.Availability:
	default:
	}
	return nil
}

func (e *acceptedPauseExecutor) Controller(task *api.Task) (exec.Controller, error) {
	e.assignments.Add(1)
	return e.bootstrapHostExecutor.Controller(task)
}
