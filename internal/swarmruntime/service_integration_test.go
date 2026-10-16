package swarmruntime

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/moby/swarmkit/v2/agent/exec"
	"github.com/moby/swarmkit/v2/api"
)

// The fixture executes only lifecycle transitions. The assertions cross the
// real manager, CA/dispatcher RPC, scheduler and durable Raft boundaries.
type serviceExecutor struct{}

func (serviceExecutor) Describe(context.Context) (*api.NodeDescription, error) {
	return &api.NodeDescription{Platform: &api.Platform{OS: "linux", Architecture: runtime.GOARCH}, Resources: &api.Resources{NanoCPUs: 8_000_000_000, MemoryBytes: 8 << 30}}, nil
}
func (serviceExecutor) Configure(context.Context, *api.Node) error         { return nil }
func (serviceExecutor) SetNetworkBootstrapKeys([]*api.EncryptionKey) error { return nil }
func (serviceExecutor) Controller(task *api.Task) (exec.Controller, error) {
	spec, err := DecodeContainer(task)
	if err != nil {
		return nil, err
	}
	return &serviceController{fail: len(spec.Args) > 0 && spec.Args[0] == "reject", done: make(chan struct{})}, nil
}

type serviceController struct {
	fail bool
	done chan struct{}
	once sync.Once
}

func (*serviceController) Update(context.Context, *api.Task) error { return nil }
func (c *serviceController) Prepare(context.Context) error {
	if c.fail {
		return errors.New("rejected integration revision")
	}
	return nil
}
func (*serviceController) Start(context.Context) error { return nil }
func (c *serviceController) Wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.done:
		return nil
	}
}
func (c *serviceController) Shutdown(context.Context) error {
	c.once.Do(func() { close(c.done) })
	return nil
}
func (c *serviceController) Terminate(ctx context.Context) error { return c.Shutdown(ctx) }
func (*serviceController) Remove(context.Context) error          { return nil }
func (*serviceController) Close() error                          { return nil }

func serviceConfig(t *testing.T, host, role string) NodeConfig {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return NodeConfig{StateDir: t.TempDir(), ListenAddress: addr, AdvertiseAddress: addr, Admission: Admission{Region: "sa-saopaulo-1", HostID: host, InstanceID: "ocid1.instance.integration." + host, FounderID: "ts-gru-1", Role: role}}
}
func serviceStart(t *testing.T, ctx context.Context, cfg NodeConfig) *Node {
	t.Helper()
	node, err := StartNode(ctx, cfg, serviceExecutor{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := node.Stop(ctx); err != nil {
			t.Errorf("stop service fixture: %v", err)
		}
	})
	return node
}
func serviceCluster(t *testing.T, ctx context.Context) (api.ControlClient, NodeConfig, *Node) {
	t.Helper()
	managerCfg := serviceConfig(t, "ts-gru-1", "manager")
	manager := serviceStart(t, ctx, managerCfg)
	client, err := manager.ControlClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	clusters, err := client.ListClusters(ctx, &api.ListClustersRequest{})
	if err != nil {
		t.Fatal(err)
	}
	address, err := manager.RemoteAddress()
	if err != nil {
		t.Fatal(err)
	}
	workerCfg := serviceConfig(t, "ts-gru-2", "container")
	workerCfg.Admission.ManagerAddress = address
	workerCfg.Admission.JoinToken = clusters.Clusters[0].RootCA.JoinTokens.Worker
	worker := serviceStart(t, ctx, workerCfg)
	if _, err := AdmitNode(ctx, client, worker.ID(), workerCfg.Admission); err != nil {
		t.Fatal(err)
	}
	return client, workerCfg, worker
}
func serviceIntent() ServiceIntent {
	return ServiceIntent{ID: entityid.Derive("service", "production", "sa-saopaulo-1", "ts-auth"), OperationID: entityid.Derive("operation", "service-integration"), Role: "ts-auth", Region: "sa-saopaulo-1", Environment: "production", Architecture: runtime.GOARCH, Replicas: 1, Container: &api.ContainerSpec{Image: "example.invalid/fixture@sha256:" + strings.Repeat("a", 64), User: "65532:65532"}, Resources: &api.ResourceRequirements{Limits: &api.Resources{NanoCPUs: 100_000_000, MemoryBytes: 64 << 20}}}
}
func serviceEventually(t *testing.T, ctx context.Context, check func() bool) {
	t.Helper()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if check() {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("upstream state did not converge: ", ctx.Err())
		case <-ticker.C:
		}
	}
}

func TestServiceManagerIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Second)
	defer cancel()
	client, _, _ := serviceCluster(t, ctx)
	intent := serviceIntent()
	created, err := applyService(ctx, client, intent)
	if err != nil {
		t.Fatal(err)
	}
	if created.Spec.Annotations.Labels[LabelOperationID] != intent.OperationID {
		t.Fatal("delivery operation locator missing")
	}
	if created.Spec.Update.FailureAction != api.UpdateConfig_ROLLBACK || created.Spec.Rollback.FailureAction != api.UpdateConfig_PAUSE || created.Spec.Update.Parallelism != 1 {
		t.Fatal("upstream rollback policy missing")
	}
	serviceEventually(t, ctx, func() bool {
		view, err := ObserveService(ctx, client, created.ID, nil)
		return err == nil && view.RunningReplicas == 1 && view.ReadyReplicas == 0
	})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/readyz" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	probe := func(ctx context.Context, task *api.Task) error {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/readyz", nil)
		if err != nil {
			return err
		}
		request.Header.Set("X-Task-ID", task.ID)
		response, err := server.Client().Do(request)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode != 200 {
			return fmt.Errorf("probe status %d", response.StatusCode)
		}
		return nil
	}
	view, err := ObserveService(ctx, client, created.ID, probe)
	if err != nil || view.ReadyReplicas != 1 || len(view.Tasks) != 1 || view.RequestedDigest != "sha256:"+strings.Repeat("a", 64) {
		t.Fatalf("actual task readiness: %+v, %v", view, err)
	}
	intent.Replicas = 7
	replayed, err := applyService(ctx, client, intent)
	if err != nil || replayed.ID != created.ID || replayed.Spec.GetReplicated().Replicas != 1 || replayed.Meta.Version.Index != created.Meta.Version.Index {
		t.Fatalf("idempotent release must preserve autoscale: %+v %v", replayed, err)
	}
	wrongOwner := intent
	wrongOwner.Role = "another-role"
	if _, err := applyService(ctx, client, wrongOwner); err == nil {
		t.Fatal("service ownership changed")
	}
	stale := replayed.Copy()
	scaled := replayed.Spec.Copy()
	scaled.GetReplicated().Replicas = 2
	if _, err := client.UpdateService(ctx, &api.UpdateServiceRequest{ServiceID: created.ID, ServiceVersion: &replayed.Meta.Version, Spec: scaled}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.UpdateService(ctx, &api.UpdateServiceRequest{ServiceID: created.ID, ServiceVersion: &stale.Meta.Version, Spec: &stale.Spec}); err == nil {
		t.Fatal("manager accepted stale CAS")
	}
	intent.Container = intent.Container.Copy()
	intent.Container.Args = []string{"reject"}
	updated, err := applyService(ctx, client, intent)
	if err != nil {
		t.Fatal(err)
	}
	if updated.ID != created.ID || updated.Spec.GetReplicated().Replicas != 2 {
		t.Fatal("update lost service identity or scaled replica count")
	}
	serviceEventually(t, ctx, func() bool {
		response, err := client.GetService(ctx, &api.GetServiceRequest{ServiceID: created.ID})
		return err == nil && response.Service.UpdateStatus != nil && response.Service.UpdateStatus.State == api.UpdateStatus_ROLLBACK_COMPLETED
	})
	view, err = ObserveService(ctx, client, created.ID, probe)
	if err != nil || view.RequestedDigest != "sha256:"+strings.Repeat("a", 64) {
		t.Fatalf("rollback observation %+v %v", view, err)
	}
}

func TestServicePlacementIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	client, workerCfg, worker := serviceCluster(t, ctx)
	intent := serviceIntent()
	intent.Architecture = "arm64"
	if runtime.GOARCH == "arm64" {
		intent.Architecture = "amd64"
	}
	service, err := applyService(ctx, client, intent)
	if err != nil {
		t.Fatal(err)
	}
	serviceEventually(t, ctx, func() bool {
		view, err := ObserveService(ctx, client, service.ID, nil)
		return err == nil && len(view.Tasks) > 0 && view.Tasks[0].State == "PENDING" && view.Tasks[0].NodeID == ""
	})
	intent.Architecture = runtime.GOARCH
	if _, err := applyService(ctx, client, intent); err != nil {
		t.Fatal(err)
	}
	serviceEventually(t, ctx, func() bool {
		view, err := ObserveService(ctx, client, service.ID, nil)
		if err != nil || view.RunningReplicas != 1 {
			return false
		}
		for _, task := range view.Tasks {
			if task.State == "RUNNING" && task.NodeID == worker.ID() {
				return true
			}
		}
		return false
	})
	wasmCfg := serviceConfig(t, "ts-gru-3", "wasm")
	wasmCfg.Admission.ManagerAddress = workerCfg.Admission.ManagerAddress
	wasmCfg.Admission.JoinToken = workerCfg.Admission.JoinToken
	wasm := serviceStart(t, ctx, wasmCfg)
	admitted, err := AdmitNode(ctx, client, wasm.ID(), wasmCfg.Admission)
	if err != nil || admitted.Spec.Annotations.Labels[LabelExecutionScope] != "tenant" {
		t.Fatalf("Wasm isolation admission: %+v %v", admitted, err)
	}
	current, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: worker.ID()})
	if err != nil {
		t.Fatal(err)
	}
	workerSpec := current.Node.Spec.Copy()
	workerSpec.Availability = api.NodeAvailabilityDrain
	if _, err := client.UpdateNode(ctx, &api.UpdateNodeRequest{NodeID: worker.ID(), NodeVersion: &current.Node.Meta.Version, Spec: workerSpec}); err != nil {
		t.Fatal(err)
	}
	serviceEventually(t, ctx, func() bool {
		tasks, err := client.ListTasks(ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{ServiceIDs: []string{service.ID}, DesiredStates: []api.TaskState{api.TaskStateRunning}}})
		return err == nil && len(tasks.Tasks) == 1 && tasks.Tasks[0].Status.State == api.TaskStatePending && tasks.Tasks[0].NodeID == ""
	})
}
