package swarmruntime

import (
	"context"
	"errors"
	"math"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/gogo/protobuf/proto"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/manager/orchestrator"
	"google.golang.org/grpc"
)

func TestSignedServiceFinalMutationGuard(t *testing.T) {
	revoked := errors.New("current authority revoked")
	client := guardedServiceClient{guard: func(context.Context) error { return revoked }}
	for _, test := range []struct {
		name   string
		mutate func(context.Context) error
	}{
		{"create-floor", func(ctx context.Context) error {
			_, err := client.CreateConfig(ctx, &api.CreateConfigRequest{})
			return err
		}},
		{"update-floor", func(ctx context.Context) error {
			_, err := client.UpdateConfig(ctx, &api.UpdateConfigRequest{})
			return err
		}},
		{"create-service", func(ctx context.Context) error {
			_, err := client.CreateService(ctx, &api.CreateServiceRequest{})
			return err
		}},
		{"update-service", func(ctx context.Context) error {
			_, err := client.UpdateService(ctx, &api.UpdateServiceRequest{})
			return err
		}},
		{"rollback", func(ctx context.Context) error {
			_, err := client.UpdateService(ctx, &api.UpdateServiceRequest{Rollback: api.UpdateServiceRequest_PREVIOUS})
			return err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			// A missing underlying client also proves the mutation was never reached.
			if err := test.mutate(t.Context()); !errors.Is(err, revoked) {
				t.Fatalf("mutation escaped current authority: %v", err)
			}
		})
	}
}

func TestServiceIntentGeneration(t *testing.T) {
	intent := serviceIntent()
	intent.Generation = 7
	spec, err := intent.serviceSpec()
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := serviceIntentFingerprint(spec)
	if err != nil {
		t.Fatal(err)
	}
	intent.intentFingerprint = fingerprint
	labels := map[string]string{LabelIntentGeneration: "7", labelIntentFingerprint: fingerprint}
	if err := checkIntentGeneration(labels, intent); err != nil {
		t.Fatal(err)
	}
	changed := spec.Copy()
	changed.GetReplicated().Replicas++
	changed.Task.ForceUpdate++
	changed.Annotations.Labels[LabelOperationID] = "another-operation"
	if actual, err := serviceIntentFingerprint(changed); err != nil || actual != fingerprint {
		t.Fatalf("manager scale or operation changed workload identity: %q %v", actual, err)
	}
	for name, mutate := range map[string]func(*api.ServiceSpec){
		"update delay":   func(spec *api.ServiceSpec) { spec.Update.Delay++ },
		"rollback delay": func(spec *api.ServiceSpec) { spec.Rollback.Delay++ },
	} {
		changed := spec.Copy()
		mutate(changed)
		if actual, err := serviceIntentFingerprint(changed); err != nil || actual == fingerprint {
			t.Fatalf("%s lost workload identity: %q %v", name, actual, err)
		}
	}
	for _, stored := range []string{"8", "07", "0", "bad"} {
		labels[LabelIntentGeneration] = stored
		if err := checkIntentGeneration(labels, intent); err == nil {
			t.Fatalf("accepted stale or malformed delivery generation %q", stored)
		}
	}
	labels[LabelIntentGeneration] = "7"
	intent.intentFingerprint = "changed-workload"
	if err := checkIntentGeneration(labels, intent); err == nil {
		t.Fatal("same generation admitted another workload")
	}
	intent.Generation++
	if err := checkIntentGeneration(labels, intent); err != nil {
		t.Fatal(err)
	}
}

type metadataServiceClient struct {
	api.ControlClient
	service *api.Service
	updates int
}

func (c *metadataServiceClient) ListServices(context.Context, *api.ListServicesRequest, ...grpc.CallOption) (*api.ListServicesResponse, error) {
	return &api.ListServicesResponse{Services: []*api.Service{c.service.Copy()}}, nil
}

func (c *metadataServiceClient) UpdateService(_ context.Context, request *api.UpdateServiceRequest, _ ...grpc.CallOption) (*api.UpdateServiceResponse, error) {
	c.updates++
	c.service.Spec = *request.Spec.Copy()
	return &api.UpdateServiceResponse{Service: c.service.Copy()}, nil
}

func TestServiceMetadataRolloutPreservesRenewal(t *testing.T) {
	intent := serviceIntent()
	intent.Generation = 7
	prepare := func() *api.ServiceSpec {
		t.Helper()
		spec, err := intent.serviceSpec()
		if err != nil {
			t.Fatal(err)
		}
		intent.intentFingerprint, err = serviceIntentFingerprint(spec)
		if err != nil {
			t.Fatal(err)
		}
		spec, err = intent.serviceSpec()
		if err != nil {
			t.Fatal(err)
		}
		return spec
	}
	spec := prepare()
	spec.Task.ForceUpdate = 4
	spec.GetReplicated().Replicas = 2
	client := &metadataServiceClient{service: &api.Service{ID: "metadata", Spec: *spec}}
	intent.OperationID = entityid.Derive("metadata-operation", "retry")
	if _, err := applyService(t.Context(), client, intent); err != nil {
		t.Fatal(err)
	}
	if client.updates != 0 {
		t.Fatal("equivalent retry replaced healthy tasks or their retained operation locator")
	}
	intent.Generation++
	prepare()
	previous := client.service.Copy()
	updated, err := applyService(t.Context(), client, intent)
	if err != nil {
		t.Fatal(err)
	}
	if client.updates != 1 || updated.Spec.Task.ForceUpdate != 5 || updated.Spec.GetReplicated().Replicas != 2 || updated.Spec.Annotations.Labels[LabelOperationID] != intent.OperationID {
		t.Fatalf("metadata amendment lost rollout or scale: %+v", updated.Spec)
	}
	task := &api.Task{Spec: previous.Spec.Task, ServiceAnnotations: previous.Spec.Annotations}
	if !orchestrator.IsTaskDirty(updated, task, nil) {
		t.Fatal("upstream retained old task authority after metadata-only amendment")
	}
	if _, err := applyService(t.Context(), client, intent); err != nil {
		t.Fatal(err)
	}
	if client.updates != 1 || !proto.Equal(&client.service.Spec, &updated.Spec) {
		t.Fatal("exact retry reset the manager-owned renewal counter")
	}
	client.service.Spec.Task.ForceUpdate = math.MaxUint64
	intent.Generation++
	prepare()
	if _, err := applyService(t.Context(), client, intent); err == nil || client.updates != 1 {
		t.Fatal("rollout counter wrapped or mutated at exhaustion")
	}
}
