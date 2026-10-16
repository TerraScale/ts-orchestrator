package app

import (
	"context"
	"errors"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/containermaterial"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/manager/controlapi"
	"github.com/moby/swarmkit/v2/manager/state/store"
	"google.golang.org/grpc"
)

// The real upstream control API rejects mutable Config.Data. Only the lost
// service-update response is injected; version checks and stores are real.
type materialControlClient struct {
	api.ControlClient
	server     *controlapi.Server
	failUpdate bool
	updates    int
}

func (client *materialControlClient) ListConfigs(ctx context.Context, request *api.ListConfigsRequest, _ ...grpc.CallOption) (*api.ListConfigsResponse, error) {
	return client.server.ListConfigs(ctx, request)
}
func (client *materialControlClient) CreateConfig(ctx context.Context, request *api.CreateConfigRequest, _ ...grpc.CallOption) (*api.CreateConfigResponse, error) {
	return client.server.CreateConfig(ctx, request)
}
func (client *materialControlClient) UpdateConfig(ctx context.Context, request *api.UpdateConfigRequest, _ ...grpc.CallOption) (*api.UpdateConfigResponse, error) {
	return client.server.UpdateConfig(ctx, request)
}
func (client *materialControlClient) UpdateService(ctx context.Context, request *api.UpdateServiceRequest, _ ...grpc.CallOption) (*api.UpdateServiceResponse, error) {
	client.updates++
	if client.failUpdate {
		client.failUpdate = false
		return nil, errors.New("manager unavailable after metadata reservation")
	}
	return client.server.UpdateService(ctx, request)
}

type materialFence struct{}

func (materialFence) Current() authority.Snapshot         { return authority.Snapshot{Epoch: 1} }
func (materialFence) Guard(context.Context, uint64) error { return nil }

func TestContainerSecretRotationUpstreamRecovery(t *testing.T) {
	memory := store.NewMemoryStore(nil)
	t.Cleanup(func() { _ = memory.Close() })
	client := &materialControlClient{server: controlapi.NewServer(memory, nil, nil, nil, nil)}
	runtime, err := swarmruntime.ContainerRuntime(&api.ContainerSpec{Image: "registry.example/auth@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", User: "65532:65532"})
	if err != nil {
		t.Fatal(err)
	}
	service := &api.Service{ID: "service-id", Spec: api.ServiceSpec{Annotations: api.Annotations{Name: "auth"}, Task: api.TaskSpec{Runtime: runtime, ForceUpdate: 4}, Mode: &api.ServiceSpec_Replicated{Replicated: &api.ReplicatedService{Replicas: 3}}}}
	if err := memory.Update(func(tx store.Tx) error { return store.CreateService(tx, service) }); err != nil {
		t.Fatal(err)
	}
	loaded, err := client.server.GetService(t.Context(), &api.GetServiceRequest{ServiceID: service.ID})
	if err != nil {
		t.Fatal(err)
	}
	service = loaded.Service
	fence := materialFence{}
	before := containerSecretSnapshot{OperationID: "operation", ServiceID: service.ID, ConfigDigest: "digest", Generation: 4, Versions: map[string]containerSecretVersion{"KEY_FILE": {ID: "vault-id", Version: 1}}}
	if err := syncContainerSnapshot(t.Context(), client, fence, service, before); err != nil {
		t.Fatal(err)
	}
	after := before
	after.Versions = map[string]containerSecretVersion{"KEY_FILE": {ID: "vault-id", Version: 2}}
	client.failUpdate = true
	if err := syncContainerSnapshot(t.Context(), client, fence, service, after); err == nil {
		t.Fatal("lost update was accepted")
	}
	after.Versions["KEY_FILE"] = containerSecretVersion{ID: "vault-id", Version: 3}
	if err := syncContainerSnapshot(t.Context(), client, fence, service, after); !errors.Is(err, containermaterial.ErrPending) {
		t.Fatal("reserved generation did not resume", err)
	}
	loaded, err = client.server.GetService(t.Context(), &api.GetServiceRequest{ServiceID: service.ID})
	if err != nil || loaded.Service.Spec.Task.ForceUpdate != 5 || loaded.Service.Spec.GetReplicated().Replicas != 3 {
		t.Fatal("rotation lost generation or replica count", err)
	}
	service = loaded.Service
	after.Generation = 5
	if err := syncContainerSnapshot(t.Context(), client, fence, service, after); !errors.Is(err, containermaterial.ErrPending) {
		t.Fatal("newer credential version did not get its own replacement generation", err)
	}
	loaded, err = client.server.GetService(t.Context(), &api.GetServiceRequest{ServiceID: service.ID})
	if err != nil || loaded.Service.Spec.Task.ForceUpdate != 6 || loaded.Service.Spec.GetReplicated().Replicas != 3 {
		t.Fatal("second rotation lost generation or replica count", err)
	}
	service = loaded.Service
	after.Generation = 6
	if err := syncContainerSnapshot(t.Context(), client, fence, service, after); err != nil {
		t.Fatal("replacement generation did not converge", err)
	}
	if client.updates != 3 {
		t.Fatal("unchanged credential version restarted the service")
	}
	if err := checkContainerSnapshot(t.Context(), client, after); err != nil {
		t.Fatal(err)
	}
	stored, err := lookupContainerSnapshot(t.Context(), client, service.ID)
	if err != nil || string(stored.Spec.Data) != containerSecretSnapshotSchema {
		t.Fatal("mutable metadata entered Config.Data", err)
	}
	var metadata containerSecretSnapshot
	if err := protocol.DecodeStrict([]byte(stored.Spec.Annotations.Labels[containerSecretSnapshotLabel]), &metadata, 32<<10); err != nil || metadata.Versions["KEY_FILE"].Version != 3 {
		t.Fatal("reserved credential metadata lost", err)
	}
	before.Generation = 6
	if err := syncContainerSnapshot(t.Context(), client, fence, service, before); !errors.Is(err, containermaterial.ErrPending) {
		t.Fatal("credential rollback was accepted", err)
	}
}
