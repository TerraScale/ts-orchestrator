package swarmruntime

import (
	"context"
	"crypto/ed25519"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/moby/swarmkit/v2/api"
	"google.golang.org/grpc"
)

type functionMaterialFloorReadClient struct {
	api.ControlClient
	afterRead func(context.Context, *api.ListConfigsResponse) (*api.ListConfigsResponse, error)
}

func (client functionMaterialFloorReadClient) ListConfigs(ctx context.Context, request *api.ListConfigsRequest, options ...grpc.CallOption) (*api.ListConfigsResponse, error) {
	response, err := client.ControlClient.ListConfigs(ctx, request, options...)
	if err != nil {
		return nil, err
	}
	return client.afterRead(ctx, response)
}

// Continue the genuine rejected-102 -> current-101 manager rollback scenario.
func testFunctionMaterialTaskManagerIntegration(t *testing.T, ctx context.Context, client api.ControlClient, intent FunctionServiceIntent, current *functionIntentFixture, task *api.Task, worker, renewedWorker, failedWorker release.VerifiedContainer, nextFunction release.VerifiedFunction, root ed25519.PrivateKey) {
	t.Helper()
	serviceEventually(t, ctx, func() bool {
		service, err := client.GetService(ctx, &api.GetServiceRequest{ServiceID: task.ServiceID})
		return err == nil && service.Service.UpdateStatus != nil && service.Service.UpdateStatus.State == api.UpdateStatus_ROLLBACK_COMPLETED
	})
	if err := VerifyFunctionMaterialTask(ctx, client, task, intent, current, worker); err != nil {
		t.Fatal("actual current rollback task could not obtain independently qualified material: ", err)
	}
	denied := func(name string, reader api.ControlClient, candidate *api.Task, authority CurrentFunctionIntent, qualified release.VerifiedContainer) {
		t.Helper()
		if err := VerifyFunctionMaterialTask(ctx, reader, candidate, intent, authority, qualified); err == nil {
			t.Fatal(name + " authorized function material")
		}
	}
	deniedAfterFloor := func(name string, authority CurrentFunctionIntent, after func(context.Context, *api.ListConfigsResponse) (*api.ListConfigsResponse, error)) {
		t.Helper()
		reached := false
		reader := functionMaterialFloorReadClient{ControlClient: client, afterRead: func(ctx context.Context, response *api.ListConfigsResponse) (*api.ListConfigsResponse, error) {
			reached = true
			return after(ctx, response)
		}}
		denied(name, reader, task, authority, worker)
		if !reached {
			t.Fatal(name + " did not reach the actual manager floor read")
		}
	}
	denied("different whole bundle", client, task, current, renewedWorker)
	denied("failed next worker", client, task, current, failedWorker)
	altered := task.Copy()
	altered.Spec.ForceUpdate++
	denied("altered ForceUpdate", client, altered, current, worker)
	altered = task.Copy()
	altered.Endpoint = &api.Endpoint{Ports: []*api.PortConfig{{Name: "altered-fingerprint", PublishedPort: 9999}}}
	denied("altered fingerprint", client, altered, current, worker)
	denied("stale function proof", client, task, &functionIntentFixture{proof: nextFunction}, worker)
	actualTasks, err := client.ListTasks(ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{ServiceIDs: []string{task.ServiceID}}})
	if err != nil {
		t.Fatal(err)
	}
	failedTask := false
	for _, candidate := range actualTasks.Tasks {
		if candidate.ServiceAnnotations.Labels[labelReleaseSequence] == "102" {
			failedTask = true
			denied("actual rejected worker task", client, candidate, current, failedWorker)
		}
	}
	if !failedTask {
		t.Fatal("automatic rollback had no actual rejected next worker task")
	}
	otherMigration := worker.Migration()
	otherMigration.Namespace += "-different"
	signedMigration, err := release.SignSequenceMigration(otherMigration, time.Now().UTC(), root)
	if err != nil {
		t.Fatal(err)
	}
	otherMigrationWire, _ := trust.EncodeEnvelope(signedMigration)
	for _, fault := range []struct {
		name   string
		change func(*api.ListConfigsResponse)
	}{
		{"absent floor", func(response *api.ListConfigsResponse) { response.Configs = nil }},
		{"ambiguous floor", func(response *api.ListConfigsResponse) {
			response.Configs = append(response.Configs, response.Configs[0].Copy())
		}},
		{"different migration", func(response *api.ListConfigsResponse) { response.Configs[0].Spec.Data = otherMigrationWire }},
		{"floor below worker", func(response *api.ListConfigsResponse) {
			response.Configs[0].Spec.Annotations.Labels[labelReleaseSequence] = strconv.FormatUint(worker.Claim().ReleaseSequence-1, 10)
		}},
		{"equal sequence identity conflict", func(response *api.ListConfigsResponse) {
			response.Configs[0].Spec.Annotations.Labels[labelReleaseSequence] = strconv.FormatUint(worker.Claim().ReleaseSequence, 10)
			response.Configs[0].Spec.Annotations.Labels[labelReleaseFingerprint] = strings.Repeat("0", 64)
		}},
	} {
		deniedAfterFloor(fault.name, current, func(_ context.Context, response *api.ListConfigsResponse) (*api.ListConfigsResponse, error) {
			if response == nil || len(response.Configs) != 1 {
				t.Fatal("actual manager floor was not unique before response fault injection")
			}
			changed := response.Copy()
			fault.change(changed)
			return changed, nil
		})
	}
	changingFunction := &functionIntentFixture{proof: current.proof}
	deniedAfterFloor("function changed during floor read", changingFunction, func(_ context.Context, response *api.ListConfigsResponse) (*api.ListConfigsResponse, error) {
		changingFunction.proof = nextFunction
		return response, nil
	})

	awaitReplacement := func(previousID string) *api.Task {
		t.Helper()
		var replacement *api.Task
		serviceEventually(t, ctx, func() bool {
			actual, err := client.GetService(ctx, &api.GetServiceRequest{ServiceID: task.ServiceID})
			if err != nil {
				return false
			}
			tasks, err := client.ListTasks(ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{ServiceIDs: []string{task.ServiceID}, DesiredStates: []api.TaskState{api.TaskStateRunning}}})
			if err != nil {
				return false
			}
			for _, candidate := range tasks.Tasks {
				if candidate.ID != previousID && candidate.Status.State == api.TaskStateRunning && intent.VerifyTask(candidate, actual.Service, current.proof, worker) == nil {
					replacement = candidate
					return true
				}
			}
			return false
		})
		return replacement
	}
	deniedAfterFloor("actual task removed during floor read", current, func(ctx context.Context, response *api.ListConfigsResponse) (*api.ListConfigsResponse, error) {
		_, err := client.RemoveTask(ctx, &api.RemoveTaskRequest{TaskID: task.ID})
		if err != nil {
			t.Fatal(err)
		}
		return response, nil
	})
	task = awaitReplacement(task.ID)
	deniedAfterFloor("actual assignment drained during floor read", current, func(ctx context.Context, response *api.ListConfigsResponse) (*api.ListConfigsResponse, error) {
		node, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: task.NodeID})
		if err != nil {
			t.Fatal(err)
			return nil, err
		}
		spec := node.Node.Spec.Copy()
		spec.Availability = api.NodeAvailabilityDrain
		if _, err := client.UpdateNode(ctx, &api.UpdateNodeRequest{NodeID: task.NodeID, NodeVersion: &node.Node.Meta.Version, Spec: spec}); err != nil {
			t.Fatal(err)
			return nil, err
		}
		serviceEventually(t, ctx, func() bool {
			actual, err := client.GetTask(ctx, &api.GetTaskRequest{TaskID: task.ID})
			return err == nil && actual.Task.DesiredState != api.TaskStateRunning
		})
		node, err = client.GetNode(ctx, &api.GetNodeRequest{NodeID: task.NodeID})
		if err != nil {
			t.Fatal(err)
			return nil, err
		}
		spec = node.Node.Spec.Copy()
		spec.Availability = api.NodeAvailabilityActive
		_, err = client.UpdateNode(ctx, &api.UpdateNodeRequest{NodeID: task.NodeID, NodeVersion: &node.Node.Meta.Version, Spec: spec})
		if err != nil {
			t.Fatal(err)
		}
		return response, nil
	})
	task = awaitReplacement(task.ID)
	if err := VerifyFunctionMaterialTask(ctx, client, task, intent, current, worker); err != nil {
		t.Fatal("replacement current rollback task was denied after actual manager recovery: ", err)
	}
	deniedAfterFloor("actual current service changed during floor read", current, func(ctx context.Context, response *api.ListConfigsResponse) (*api.ListConfigsResponse, error) {
		actual, err := client.GetService(ctx, &api.GetServiceRequest{ServiceID: task.ServiceID})
		if err != nil {
			t.Fatal(err)
			return nil, err
		}
		spec := actual.Service.Spec.Copy()
		spec.Update.Delay += time.Second
		_, err = client.UpdateService(ctx, &api.UpdateServiceRequest{ServiceID: task.ServiceID, ServiceVersion: &actual.Service.Meta.Version, Spec: spec})
		if err != nil {
			t.Fatal(err)
		}
		return response, nil
	})
}
