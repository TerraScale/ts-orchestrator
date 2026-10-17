package swarmruntime

import (
	"context"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/moby/swarmkit/v2/api"
	"google.golang.org/grpc"
)

// Snapshot overlays exercise allocation-only lifecycle states using the real
// fixture's signed recipe, durable floor and enrolled worker certificate.
type functionAllocationSnapshotClient struct {
	api.ControlClient
	task       *api.Task
	service    *api.Service
	node       *api.Node
	taskReads  int
	changeTask bool
}

func (client *functionAllocationSnapshotClient) GetTask(context.Context, *api.GetTaskRequest, ...grpc.CallOption) (*api.GetTaskResponse, error) {
	client.taskReads++
	task := client.task.Copy()
	if client.changeTask && client.taskReads > 1 {
		task.Spec.ForceUpdate++
	}
	return &api.GetTaskResponse{Task: task}, nil
}

func (client *functionAllocationSnapshotClient) GetService(context.Context, *api.GetServiceRequest, ...grpc.CallOption) (*api.GetServiceResponse, error) {
	return &api.GetServiceResponse{Service: client.service.Copy()}, nil
}

func (client *functionAllocationSnapshotClient) GetNode(context.Context, *api.GetNodeRequest, ...grpc.CallOption) (*api.GetNodeResponse, error) {
	return &api.GetNodeResponse{Node: client.node.Copy()}, nil
}

func testFunctionAllocationObservation(t *testing.T, ctx context.Context, client api.ControlClient, intent FunctionServiceIntent,
	current *functionIntentFixture, worker release.VerifiedContainer, task *api.Task,
) {
	t.Helper()
	if err := VerifyFunctionTaskAllocation(ctx, client, task, intent, current, worker); err != nil {
		t.Fatalf("actual manager function allocation: %v", err)
	}
	service, err := client.GetService(ctx, &api.GetServiceRequest{ServiceID: task.ServiceID})
	if err != nil || service == nil || service.Service == nil {
		t.Fatalf("allocation service snapshot: %v", err)
	}
	node, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: task.NodeID})
	if err != nil || node == nil || node.Node == nil {
		t.Fatalf("allocation recipient snapshot: %v", err)
	}
	snapshot := func() *functionAllocationSnapshotClient {
		return &functionAllocationSnapshotClient{ControlClient: client, task: task.Copy(), service: service.Service.Copy(), node: node.Node.Copy()}
	}
	for _, state := range []api.TaskState{api.TaskStateNew, api.TaskStatePending, api.TaskStateAssigned, api.TaskStateAccepted,
		api.TaskStatePreparing, api.TaskStateReady, api.TaskStateStarting, api.TaskStateRunning} {
		t.Run("allocation_"+state.String(), func(t *testing.T) {
			observed := snapshot()
			observed.task.Status.State = state
			observed.task.DesiredState = api.TaskStateShutdown
			observed.node.Spec.Availability = api.NodeAvailabilityDrain
			if err := VerifyFunctionTaskAllocation(ctx, observed, observed.task, intent, current, worker); err != nil {
				t.Fatalf("nonterminal shutdown reservation lost: %v", err)
			}
			if err := VerifyFunctionRegistryTask(ctx, observed, observed.task, intent, current, worker); err == nil {
				t.Fatal("allocation observation widened registry credential admission")
			}
			if err := VerifyFunctionMaterialTask(ctx, observed, observed.task, intent, current, worker); err == nil {
				t.Fatal("allocation observation widened material admission")
			}
		})
	}
	t.Run("allocation_previous_recipe", func(t *testing.T) {
		observed := snapshot()
		observed.service.PreviousSpec = observed.service.Spec.Copy()
		observed.service.Spec.Task.ForceUpdate++
		observed.service.PendingDelete = true
		observed.task.DesiredState = api.TaskStateRemove
		observed.node.Spec.Availability = api.NodeAvailabilityPause
		if err := VerifyFunctionTaskAllocation(ctx, observed, observed.task, intent, current, worker); err != nil {
			t.Fatalf("signed previous reservation lost during deletion: %v", err)
		}
	})
	for _, test := range []struct {
		name   string
		change func(*functionAllocationSnapshotClient)
	}{
		{"unassigned", func(c *functionAllocationSnapshotClient) { c.task.NodeID = "" }},
		{"terminal", func(c *functionAllocationSnapshotClient) { c.task.Status.State = api.TaskStateCompleted }},
		{"unknown_state", func(c *functionAllocationSnapshotClient) { c.task.Status.State = api.TaskState(128) }},
		{"resources", func(c *functionAllocationSnapshotClient) { c.task.Spec.Resources.Limits.MemoryBytes++ }},
		{"function_proof", func(c *functionAllocationSnapshotClient) {
			c.task.ServiceAnnotations.Labels[LabelFunctionProof] = "unverified"
		}},
		{"worker_bundle", func(c *functionAllocationSnapshotClient) {
			c.task.ServiceAnnotations.Labels[LabelFunctionWorkerBundle] = "unverified"
		}},
		{"recipient_scope", func(c *functionAllocationSnapshotClient) {
			c.node.Spec.Annotations.Labels[LabelExecutionScope] = "platform"
		}},
		{"recipient_certificate", func(c *functionAllocationSnapshotClient) { c.node.Certificate.Certificate = nil }},
		{"manager_race", func(c *functionAllocationSnapshotClient) { c.changeTask = true }},
	} {
		t.Run("allocation_reject_"+test.name, func(t *testing.T) {
			observed := snapshot()
			test.change(observed)
			if err := VerifyFunctionTaskAllocation(ctx, observed, observed.task, intent, current, worker); err == nil {
				t.Fatal("unverified allocation was accepted")
			}
		})
	}
	t.Run("allocation_revoked_function", func(t *testing.T) {
		observed := snapshot()
		revoked := &functionIntentFixture{proof: current.proof, revoked: true}
		if err := VerifyFunctionTaskAllocation(ctx, observed, observed.task, intent, revoked, worker); err == nil {
			t.Fatal("revoked function allocation was accepted")
		}
	})
}
