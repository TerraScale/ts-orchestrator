//go:build linux

package swarmruntime

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/moby/swarmkit/v2/api"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// The kernel supplies peer credentials and /proc supplies the actual service
// cgroup; requests cross a second Unix gRPC server into real persistent Raft.
func TestManagementIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	cfg := nodeFixtureConfig(t, "founder", "manager")
	cfg.Admission.Region = "sa-saopaulo-1"
	node := nodeFixtureStart(t, ctx, cfg)
	upstream, err := node.ControlClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	line := strings.Split(strings.TrimSpace(string(wire)), "\n")[0]
	parts := strings.SplitN(line, ":", 3)
	if len(parts) != 3 {
		t.Fatalf("unexpected process cgroup: %q", line)
	}
	cgroup := parts[2]
	path := filepath.Join(t.TempDir(), "management.sock")
	var revoked atomic.Bool
	refresh := func(context.Context) error {
		if revoked.Load() {
			return errors.New("current authority revoked")
		}
		return nil
	}
	server, err := startManagementAt(ctx, path, uint32(os.Getuid()), uint32(os.Getgid()), cgroup, "accepted-current", node, "sa-saopaulo-1", "test", upstream, refresh)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, id, conn, err := dialManagementAt(ctx, path, uint32(os.Getuid()), "accepted-current")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if id != node.ID() {
		t.Fatalf("manager ID = %q, want %q", id, node.ID())
	}

	for _, method := range []string{workerPrepareMethod, workerAdmitMethod} {
		t.Run(method, func(t *testing.T) {
			query := WorkerRegistrationQuery{}
			var payload any = query
			if method == workerAdmitMethod {
				payload = workerAdmitRequest{Query: query}
			}
			wire, err := protocol.EncodeJSON(payload)
			if err != nil {
				t.Fatal(err)
			}
			// The real fixture manager has no production worker authority and must redact its failure.
			err = conn.Invoke(ctx, method, &wrapperspb.BytesValue{Value: wire}, new(wrapperspb.BytesValue))
			if status.Code(err) != codes.Unknown || status.Convert(err).Message() != "management operation failed" {
				t.Fatalf("missing concrete worker authority: %v", err)
			}
			query.Swarm = new(hostenroll.SwarmWorker)
			payload = query
			if method == workerAdmitMethod {
				payload = workerAdmitRequest{Query: query}
			}
			wire, err = protocol.EncodeJSON(payload)
			if err != nil {
				t.Fatal(err)
			}
			for _, invalid := range [][]byte{wire, []byte(`{"unexpected":true}`), []byte(strings.Repeat(" ", (128<<10)+1))} {
				err := conn.Invoke(ctx, method, &wrapperspb.BytesValue{Value: invalid}, new(wrapperspb.BytesValue))
				if status.Code(err) != codes.PermissionDenied {
					t.Fatalf("caller-supplied projection or invalid worker request accepted: %v", err)
				}
			}
		})
	}
	nodeResult, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: id})
	if err != nil {
		t.Fatal(err)
	}
	nodeSpec := nodeResult.Node.Spec.Copy()
	nodeSpec.DesiredRole = api.NodeRoleWorker
	if _, err := client.UpdateNode(ctx, &api.UpdateNodeRequest{NodeID: id, NodeVersion: &nodeResult.Node.Meta.Version, Spec: nodeSpec}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("certificate role mutation accepted: %v", err)
	}
	labels := map[string]string{LabelIntentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", LabelRole: "api", LabelRegion: "sa-saopaulo-1", LabelEnvironment: "test"}
	runtimeSpec, err := ContainerRuntime(&api.ContainerSpec{Image: "example.invalid/proof@sha256:" + strings.Repeat("0", 64), User: "65532:65532"})
	if err != nil {
		t.Fatal(err)
	}
	request := &api.CreateServiceRequest{Spec: &api.ServiceSpec{
		Annotations: api.Annotations{Name: "management-proof", Labels: labels},
		Task:        api.TaskSpec{Runtime: runtimeSpec, Resources: &api.ResourceRequirements{Limits: &api.Resources{NanoCPUs: 100_000_000, MemoryBytes: 32 << 20}}, Placement: &api.Placement{Constraints: []string{"node.labels." + LabelRegion + "==sa-saopaulo-1", "node.labels." + LabelExecutionScope + "==platform"}, Platforms: []*api.Platform{{OS: "linux", Architecture: runtime.GOARCH}}}},
		Mode:        &api.ServiceSpec_Replicated{Replicated: &api.ReplicatedService{Replicas: 0}},
	}}
	unsafe := request.Spec.Copy()
	unsafe.Task.Placement.Constraints = nil
	if _, err := client.CreateService(ctx, &api.CreateServiceRequest{Spec: unsafe}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unscoped placement accepted: %v", err)
	}
	unsafe = request.Spec.Copy()
	unsafe.Annotations.Labels[LabelRole] = "terrabase"
	if _, err := client.CreateService(ctx, &api.CreateServiceRequest{Spec: unsafe}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("stateful workload accepted: %v", err)
	}
	created, err := client.CreateService(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := upstream.GetService(ctx, &api.GetServiceRequest{ServiceID: created.Service.ID})
	if err != nil || actual.Service.Spec.Annotations.Name != "management-proof" {
		t.Fatalf("upstream persisted service: %v %v", actual, err)
	}
	changed := actual.Service.Spec.Copy()
	changed.Task.ForceUpdate++
	changedService, err := client.UpdateService(ctx, &api.UpdateServiceRequest{ServiceID: actual.Service.ID, ServiceVersion: &actual.Service.Meta.Version, Spec: changed})
	if err != nil {
		t.Fatal(err)
	}
	rolledBack, err := client.UpdateService(ctx, &api.UpdateServiceRequest{ServiceID: actual.Service.ID, ServiceVersion: &changedService.Service.Meta.Version, Spec: &changedService.Service.Spec, Rollback: api.UpdateServiceRequest_PREVIOUS})
	if err != nil {
		t.Fatalf("valid admitted rollback denied: %v", err)
	}
	waitRuntime(t, ctx, func() (bool, error) {
		current, err := upstream.GetService(ctx, &api.GetServiceRequest{ServiceID: actual.Service.ID})
		if err != nil {
			return false, err
		}
		rolledBack.Service = current.Service
		return current.Service.UpdateStatus == nil || current.Service.UpdateStatus.State == api.UpdateStatus_ROLLBACK_COMPLETED, nil
	})
	unsafe = rolledBack.Service.Spec.Copy()
	unsafe.Task.Placement.Constraints = nil
	unscoped, err := upstream.UpdateService(ctx, &api.UpdateServiceRequest{ServiceID: actual.Service.ID, ServiceVersion: &rolledBack.Service.Meta.Version, Spec: unsafe})
	if err != nil {
		t.Fatal(err)
	}
	restored, err := upstream.UpdateService(ctx, &api.UpdateServiceRequest{ServiceID: actual.Service.ID, ServiceVersion: &unscoped.Service.Meta.Version, Spec: request.Spec})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.UpdateService(ctx, &api.UpdateServiceRequest{ServiceID: actual.Service.ID, ServiceVersion: &restored.Service.Meta.Version, Spec: request.Spec, Rollback: api.UpdateServiceRequest_PREVIOUS}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unscoped previous spec accepted through rollback: %v", err)
	}
	floorLabels := map[string]string{LabelIntentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", LabelRole: "api", LabelRegion: "sa-saopaulo-1", LabelEnvironment: "test", "terrascale.release-sequence": "2", "terrascale.release-fingerprint": "signed-release"}
	digest := sha256.Sum256([]byte("test/sa-saopaulo-1/api"))
	config, err := client.CreateConfig(ctx, &api.CreateConfigRequest{Spec: &api.ConfigSpec{Annotations: api.Annotations{Name: fmt.Sprintf("ts-release-%x", digest[:16]), Labels: floorLabels}, Data: []byte("immutable release evidence")}})
	if err != nil {
		t.Fatal(err)
	}
	templated := config.Config.Spec.Copy()
	templated.Templating = &api.Driver{Name: "golang"}
	if _, err := client.UpdateConfig(ctx, &api.UpdateConfigRequest{ConfigID: config.Config.ID, ConfigVersion: &config.Config.Meta.Version, Spec: templated}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unsupported config templating accepted: %v", err)
	}
	spec := config.Config.Spec.Copy()
	spec.Annotations.Labels["terrascale.release-sequence"] = "1"
	if _, err := client.UpdateConfig(ctx, &api.UpdateConfigRequest{ConfigID: config.Config.ID, ConfigVersion: &config.Config.Meta.Version, Spec: spec}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("release floor rollback accepted: %v", err)
	}
	spec.Annotations.Labels["terrascale.release-sequence"] = "3"
	updated, err := client.UpdateConfig(ctx, &api.UpdateConfigRequest{ConfigID: config.Config.ID, ConfigVersion: &config.Config.Meta.Version, Spec: spec})
	if err != nil {
		t.Fatalf("increasing release floor denied: %v", err)
	}
	config.Config = updated.Config
	spec = config.Config.Spec.Copy()
	spec.Data = []byte("replacement")
	if _, err := client.UpdateConfig(ctx, &api.UpdateConfigRequest{ConfigID: config.Config.ID, ConfigVersion: &config.Config.Meta.Version, Spec: spec}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("mutable evidence accepted: %v", err)
	}
	if _, err := client.CreateConfig(ctx, &api.CreateConfigRequest{Spec: &api.ConfigSpec{Annotations: api.Annotations{Name: "other-secret"}, Data: []byte("must not store")}}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("arbitrary config accepted: %v", err)
	}
	if _, err := client.ListClusters(ctx, &api.ListClustersRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("cluster/join-token access accepted: %v", err)
	}
	if _, err := client.ListSecrets(ctx, &api.ListSecretsRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("secret access accepted: %v", err)
	}
	if _, _, bad, err := dialManagementAt(ctx, path, uint32(os.Getuid()), "another-instance"); status.Code(err) != codes.PermissionDenied {
		if bad != nil {
			bad.Close()
		}
		t.Fatalf("other accepted identity admitted: %v", err)
	}
	revoked.Store(true)
	if _, err := client.ListNodes(ctx, &api.ListNodesRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("revoked authority admitted existing connection: %v", err)
	}

	for _, method := range []string{workerPrepareMethod, workerAdmitMethod} {
		if err := conn.Invoke(ctx, method, &wrapperspb.BytesValue{Value: []byte(`{}`)}, new(wrapperspb.BytesValue)); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("revoked authority admitted existing worker connection: %v", err)
		}
	}
	revoked.Store(false)
	if _, err := startManagementAt(ctx, path, uint32(os.Getuid()), uint32(os.Getgid()), cgroup, "accepted-current", node, "sa-saopaulo-1", "test", upstream, refresh); err == nil {
		t.Fatal("concurrent management server replaced active socket")
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		uid    uint32
		cgroup string
	}{
		{"wrong UID", uint32(os.Getuid() + 1), cgroup},
		{"wrong service", uint32(os.Getuid()), "/another.service"},
	} {
		t.Run(test.name, func(t *testing.T) {
			deniedServer, err := startManagementAt(ctx, path, test.uid, uint32(os.Getgid()), test.cgroup, "accepted-current", node, "sa-saopaulo-1", "test", upstream, refresh)
			if err != nil {
				t.Fatal(err)
			}
			defer deniedServer.Close()
			if _, _, bad, err := dialManagementAt(ctx, path, uint32(os.Getuid()), "accepted-current"); status.Code(err) != codes.PermissionDenied {
				if bad != nil {
					bad.Close()
				}
				t.Fatalf("unauthorized process admitted: %v", err)
			}
		})
	}
}
