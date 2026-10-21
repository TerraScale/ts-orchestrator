//go:build linux

package swarmruntime

import (
	"bytes"
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

	"github.com/TerraScale/ts-orchestrator/internal/autoscale"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/gogo/protobuf/proto"
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
	var revokeDuring atomic.Bool
	refresh := func(context.Context) error {
		if revoked.Load() {
			return errors.New("current authority revoked")
		}
		if revokeDuring.Swap(false) {
			revoked.Store(true)
		}
		return nil
	}
	server, err := startManagementAt(ctx, path, uint32(os.Getuid()), uint32(os.Getgid()), cgroup, "accepted-current", node, "sa-saopaulo-1", "test", upstream, refresh, nil)
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
	for _, method := range []string{workerAuditMethod, workerReadMembershipMethod} {
		payload := []byte(`{}`)
		if method == workerReadMembershipMethod {
			payload = []byte(`{"node_id":"aaaaaaaaaaaaaaaaaaaaaaaaa"}`)
		}
		err := conn.Invoke(ctx, method, &wrapperspb.BytesValue{Value: payload}, new(wrapperspb.BytesValue))
		if status.Code(err) != codes.Unknown || status.Convert(err).Message() != "management operation failed" {
			t.Fatalf("missing concrete worker membership authority: %v", err)
		}
		for _, invalid := range [][]byte{[]byte(`{"unexpected":true}`), []byte(strings.Repeat(" ", (128<<10)+1))} {
			if err := conn.Invoke(ctx, method, &wrapperspb.BytesValue{Value: invalid}, new(wrapperspb.BytesValue)); status.Code(err) != codes.PermissionDenied {
				t.Fatalf("invalid membership transport accepted: %v", err)
			}
		}
	}
	nodeResult, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: id})
	if err != nil {
		t.Fatal(err)
	}
	nodeSpec := nodeResult.Node.Spec.Copy()
	nodeSpec.DesiredRole = api.NodeRoleWorker
	nodeSpec.Availability = api.NodeAvailabilityPause
	if _, err := client.UpdateNode(ctx, &api.UpdateNodeRequest{NodeID: id, NodeVersion: &nodeResult.Node.Meta.Version, Spec: nodeSpec}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("certificate role mutation accepted: %v", err)
	}
	nodeSpec = nodeResult.Node.Spec.Copy()
	nodeSpec.Availability = api.NodeAvailabilityActive
	// Pause is scoped to an admitted node in this region; label the fixture manager as admission does.
	nodeSpec.Annotations.Labels = map[string]string{LabelRegion: "sa-saopaulo-1", LabelInstanceID: cfg.Admission.InstanceID, LabelHostRole: "manager"}
	active, err := upstream.UpdateNode(ctx, &api.UpdateNodeRequest{NodeID: id, NodeVersion: &nodeResult.Node.Meta.Version, Spec: nodeSpec})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.UpdateNode(ctx, &api.UpdateNodeRequest{NodeID: id, NodeVersion: &active.Node.Meta.Version, Spec: active.Node.Spec.Copy()}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("ordinary socket accepted no-op activation: %v", err)
	}
	nodeSpec = active.Node.Spec.Copy()
	nodeSpec.Availability = api.NodeAvailabilityPause
	paused, err := client.UpdateNode(ctx, &api.UpdateNodeRequest{NodeID: id, NodeVersion: &active.Node.Meta.Version, Spec: nodeSpec})
	if err != nil {
		t.Fatalf("ordinary socket rejected pause: %v", err)
	}
	for _, availability := range []api.NodeSpec_Availability{api.NodeAvailabilityActive, api.NodeAvailabilityDrain} {
		nodeSpec = paused.Node.Spec.Copy()
		nodeSpec.Availability = availability
		if _, err := client.UpdateNode(ctx, &api.UpdateNodeRequest{NodeID: id, NodeVersion: &paused.Node.Meta.Version, Spec: nodeSpec}); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("ordinary socket accepted availability %v: %v", availability, err)
		}
	}
	nodeResult, err = upstream.GetNode(ctx, &api.GetNodeRequest{NodeID: id})
	if err != nil || nodeResult.Node.Spec.Availability != api.NodeAvailabilityPause {
		t.Fatalf("denied node updates changed upstream node: %v %v", nodeResult, err)
	}
	labels := map[string]string{LabelIntentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", LabelRole: "api", LabelRegion: "sa-saopaulo-1", LabelEnvironment: "test"}
	runtimeSpec, err := ContainerRuntime(&api.ContainerSpec{Image: "example.invalid/proof@sha256:" + strings.Repeat("0", 64), User: "65532:65532"})
	if err != nil {
		t.Fatal(err)
	}
	request := &api.CreateServiceRequest{Spec: &api.ServiceSpec{
		Annotations: api.Annotations{Name: "management-proof", Labels: labels},
		Task:        api.TaskSpec{Runtime: runtimeSpec, Resources: containerTestResources(100_000_000, 32<<20), Placement: &api.Placement{Constraints: []string{"node.labels." + LabelRegion + "==sa-saopaulo-1", "node.labels." + LabelExecutionScope + "==platform"}, Platforms: []*api.Platform{{OS: "linux", Architecture: runtime.GOARCH}}}},
		Mode:        &api.ServiceSpec_Replicated{Replicated: &api.ReplicatedService{Replicas: 0}},
	}}
	authSpec := request.Spec.Copy()
	authSpec.Annotations.Name = "management-auth-proof"
	authSpec.Annotations.Labels[LabelRole] = "ts-auth"
	authSpec.Task.Placement.Constraints = append(authSpec.Task.Placement.Constraints, "node.role==manager")
	authSpec.Task.Placement.MaxReplicas = 1
	authDesired := authSpec.Copy()
	authDesired.GetReplicated().Replicas = 3
	if !(&managementServer{region: "sa-saopaulo-1", environment: "test"}).managedService(authDesired) {
		t.Fatal("auth per-node cap incorrectly restricted desired replicas")
	}
	authExcess := authDesired.Copy()
	authExcess.GetReplicated().Replicas = 4
	if _, err := client.CreateService(ctx, &api.CreateServiceRequest{Spec: authExcess}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("auth desired replicas exceeded the three manager domains: %v", err)
	}
	for _, placement := range []*api.Placement{
		{Constraints: authSpec.Task.Placement.Constraints[:2], MaxReplicas: 1},
		{Constraints: append(request.Spec.Task.Placement.Constraints[:2:2], "node.role==worker"), MaxReplicas: 1},
		{Constraints: authSpec.Task.Placement.Constraints},
		{Constraints: authSpec.Task.Placement.Constraints, MaxReplicas: 2},
	} {
		invalid := authSpec.Copy()
		invalid.Task.Placement.Constraints = placement.Constraints
		invalid.Task.Placement.MaxReplicas = placement.MaxReplicas
		if _, err := client.CreateService(ctx, &api.CreateServiceRequest{Spec: invalid}); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("unsafe auth placement accepted: %v", err)
		}
	}
	authService, err := client.CreateService(ctx, &api.CreateServiceRequest{Spec: authSpec})
	if err != nil {
		t.Fatalf("manager-only per-node-limited auth service rejected: %v", err)
	}
	if _, err := client.RemoveService(ctx, &api.RemoveServiceRequest{ServiceID: authService.Service.ID}); err != nil {
		t.Fatal(err)
	}
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
	unsafe.Annotations.Labels["terrascale.stateful"] = "true"
	if _, err := client.CreateService(ctx, &api.CreateServiceRequest{Spec: unsafe}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("stateful labels bypassed missing root signed-intent authorizer: %v", err)
	}
	unsafe = request.Spec.Copy()
	unsafe.GetReplicated().Replicas = autoscale.MaxReplicas + 1
	if _, err := client.CreateService(ctx, &api.CreateServiceRequest{Spec: unsafe}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("service creation exceeded replica limit: %v", err)
	}
	created, err := client.CreateService(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := upstream.GetService(ctx, &api.GetServiceRequest{ServiceID: created.Service.ID})
	if err != nil || actual.Service.Spec.Annotations.Name != "management-proof" {
		t.Fatalf("upstream persisted service: %v %v", actual, err)
	}
	unsafe = actual.Service.Spec.Copy()
	unsafe.GetReplicated().Replicas = autoscale.MaxReplicas + 1
	if _, err := client.UpdateService(ctx, &api.UpdateServiceRequest{ServiceID: actual.Service.ID, ServiceVersion: &actual.Service.Meta.Version, Spec: unsafe}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("service update exceeded replica limit: %v", err)
	}
	migrated := actual.Service.Spec.Copy()
	migrated.Annotations.Labels[LabelIntentGeneration] = "1"
	migrated.Annotations.Labels[labelIntentFingerprint] = strings.Repeat("a", 64)
	adopted, err := client.UpdateService(ctx, &api.UpdateServiceRequest{ServiceID: actual.Service.ID, ServiceVersion: &actual.Service.Meta.Version, Spec: migrated})
	if err != nil {
		t.Fatalf("legacy service intent generation adoption denied: %v", err)
	}
	actual.Service = adopted.Service
	changed := actual.Service.Spec.Copy()
	changed.Task.ForceUpdate++
	changed.Annotations.Labels[LabelIntentGeneration] = "2"
	changed.Annotations.Labels[labelIntentFingerprint] = strings.Repeat("b", 64)
	changedService, err := client.UpdateService(ctx, &api.UpdateServiceRequest{ServiceID: actual.Service.ID, ServiceVersion: &actual.Service.Meta.Version, Spec: changed})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.UpdateService(ctx, &api.UpdateServiceRequest{ServiceID: actual.Service.ID, ServiceVersion: &actual.Service.Meta.Version, Spec: changed}); err == nil {
		t.Fatal("management accepted stale service CAS")
	}
	for _, invalid := range []struct{ generation, fingerprint string }{
		{"1", strings.Repeat("a", 64)},
		{"2", strings.Repeat("c", 64)},
		{"02", strings.Repeat("b", 64)},
		{"3", strings.Repeat("A", 64)},
		{"", ""},
	} {
		unsafe := changed.Copy()
		unsafe.Annotations.Labels[LabelIntentGeneration] = invalid.generation
		unsafe.Annotations.Labels[labelIntentFingerprint] = invalid.fingerprint
		if invalid.generation == "" {
			delete(unsafe.Annotations.Labels, LabelIntentGeneration)
			delete(unsafe.Annotations.Labels, labelIntentFingerprint)
		}
		if _, err := client.UpdateService(ctx, &api.UpdateServiceRequest{ServiceID: actual.Service.ID, ServiceVersion: &changedService.Service.Meta.Version, Spec: unsafe}); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("invalid service intent generation %q accepted: %v", invalid.generation, err)
		}
	}
	rolledBack, err := client.UpdateService(ctx, &api.UpdateServiceRequest{ServiceID: actual.Service.ID, ServiceVersion: &changedService.Service.Meta.Version, Spec: &changedService.Service.Spec, Rollback: api.UpdateServiceRequest_PREVIOUS})
	if err != nil {
		t.Fatalf("valid admitted rollback denied: %v", err)
	}
	if rolledBack.Service.Spec.Annotations.Labels[LabelIntentGeneration] != "1" {
		t.Fatal("rollback did not restore the genuine previous intent generation")
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
	if _, err := client.RemoveService(ctx, &api.RemoveServiceRequest{ServiceID: actual.Service.ID}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("removal accepted unscoped placement: %v", err)
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
	intentFloor := config.Config.Spec.Copy()
	intentFloor.Annotations.Labels[LabelIntentGeneration] = "1"
	intentFloor.Annotations.Labels[labelIntentFingerprint] = strings.Repeat("a", 64)
	adoptedFloor, err := client.UpdateConfig(ctx, &api.UpdateConfigRequest{ConfigID: config.Config.ID, ConfigVersion: &config.Config.Meta.Version, Spec: intentFloor})
	if err != nil {
		t.Fatalf("legacy floor intent generation adoption denied: %v", err)
	}
	intentFloor.Annotations.Labels[LabelIntentGeneration] = "2"
	intentFloor.Annotations.Labels[labelIntentFingerprint] = strings.Repeat("b", 64)
	advancedFloor, err := client.UpdateConfig(ctx, &api.UpdateConfigRequest{ConfigID: config.Config.ID, ConfigVersion: &adoptedFloor.Config.Meta.Version, Spec: intentFloor})
	if err != nil {
		t.Fatalf("floor intent generation advance denied: %v", err)
	}
	for _, invalid := range []struct{ key, value string }{
		{LabelIntentGeneration, "1"},
		{labelIntentFingerprint, strings.Repeat("c", 64)},
		{"unexpected", "mutable"},
	} {
		unsafe := intentFloor.Copy()
		unsafe.Annotations.Labels[invalid.key] = invalid.value
		if _, err := client.UpdateConfig(ctx, &api.UpdateConfigRequest{ConfigID: config.Config.ID, ConfigVersion: &advancedFloor.Config.Meta.Version, Spec: unsafe}); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("invalid floor intent mutation %s accepted: %v", invalid.key, err)
		}
	}
	for _, architecture := range []string{"arm64", "amd64"} {
		workerFloor := config.Config.Spec.Copy()
		workerFloor.Annotations.Labels[LabelRole] = "function-worker"
		workerFloor.Annotations.Labels[labelReleaseArchitecture] = architecture
		digest := sha256.Sum256([]byte("test/sa-saopaulo-1/function-worker/" + architecture))
		workerFloor.Annotations.Name = fmt.Sprintf("ts-release-%x", digest[:16])
		created, err := client.CreateConfig(ctx, &api.CreateConfigRequest{Spec: workerFloor})
		if err != nil {
			t.Fatalf("architecture-partitioned worker floor denied: %v", err)
		}
		listed, err := client.ListConfigs(ctx, &api.ListConfigsRequest{Filters: &api.ListConfigsRequest_Filters{Names: []string{workerFloor.Annotations.Name}}})
		if err != nil || len(listed.Configs) != 1 || listed.Configs[0].ID != created.Config.ID {
			t.Fatalf("architecture-partitioned worker floor unavailable: %v", err)
		}
		workerFloor.Annotations.Labels[labelReleaseSequence] = "4"
		advanced, err := client.UpdateConfig(ctx, &api.UpdateConfigRequest{ConfigID: created.Config.ID, ConfigVersion: &created.Config.Meta.Version, Spec: workerFloor})
		if err != nil {
			t.Fatalf("architecture-partitioned worker floor advance denied: %v", err)
		}
		workerFloor.Annotations.Labels[labelReleaseArchitecture] = "unsupported"
		if _, err := client.UpdateConfig(ctx, &api.UpdateConfigRequest{ConfigID: created.Config.ID, ConfigVersion: &advanced.Config.Meta.Version, Spec: workerFloor}); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("unsupported worker floor architecture accepted: %v", err)
		}
	}
	family := config.Config.Spec.Copy()
	family.Annotations.Labels[LabelRole] = "function-worker"
	family.Annotations.Labels[labelReleaseMigration] = strings.Repeat("a", 64)
	familyIdentity := sha256.Sum256([]byte(strings.Repeat("a", 64) + "/function-worker/test/3"))
	family.Annotations.Name = fmt.Sprintf("ts-worker-family-%x", familyIdentity[:16])
	createdFamily, err := client.CreateConfig(ctx, &api.CreateConfigRequest{Spec: family})
	if err != nil {
		t.Fatalf("scoped immutable worker family denied: %v", err)
	}
	if _, err := client.GetConfig(ctx, &api.GetConfigRequest{ConfigID: createdFamily.Config.ID}); err != nil {
		t.Fatalf("scoped worker family unavailable: %v", err)
	}
	if _, err := client.UpdateConfig(ctx, &api.UpdateConfigRequest{ConfigID: createdFamily.Config.ID, ConfigVersion: &createdFamily.Config.Meta.Version, Spec: family}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("immutable worker family update accepted: %v", err)
	}
	for _, wrong := range []struct{ key, value string }{
		{LabelRegion, "eu-frankfurt-1"},
		{LabelRole, "api"},
		{labelReleaseSequence, "4"},
		{labelReleaseMigration, strings.Repeat("A", 64)},
	} {
		invalid := family.Copy()
		invalid.Annotations.Labels[wrong.key] = wrong.value
		if _, err := client.CreateConfig(ctx, &api.CreateConfigRequest{Spec: invalid}); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("worker family identity mutation accepted %s: %v", wrong.key, err)
		}
	}
	publicClusters, err := client.ListClusters(ctx, &api.ListClustersRequest{})
	if err != nil || len(publicClusters.Clusters) != 1 {
		t.Fatalf("public cluster CA unavailable: %v", err)
	}
	actualClusters, err := upstream.ListClusters(ctx, &api.ListClustersRequest{})
	if err != nil || len(actualClusters.Clusters) != 1 {
		t.Fatalf("actual cluster unavailable: %v", err)
	}
	expectedPublic := &api.Cluster{ID: actualClusters.Clusters[0].ID, RootCA: api.RootCA{CACert: actualClusters.Clusters[0].RootCA.CACert}}
	if !proto.Equal(publicClusters.Clusters[0], expectedPublic) || len(publicClusters.Clusters[0].RootCA.CACert) == 0 {
		t.Fatal("public projection exposed cluster credentials or lost exact CA")
	}
	if !bytes.Equal(publicClusters.Clusters[0].RootCA.CACert, actualClusters.Clusters[0].RootCA.CACert) {
		t.Fatal("public projection changed trusted CA")
	}
	if _, err := client.ListClusters(ctx, &api.ListClustersRequest{Filters: new(api.ListClustersRequest_Filters)}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("filtered fullcluster query accepted: %v", err)
	}
	if _, err := client.GetCluster(ctx, &api.GetClusterRequest{ClusterID: actualClusters.Clusters[0].ID}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("full cluster/join-token access accepted: %v", err)
	}
	if _, err := client.ListSecrets(ctx, &api.ListSecretsRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("secret access accepted: %v", err)
	}
	for _, changedScope := range []struct{ key, value string }{
		{LabelRegion, "eu-frankfurt-1"},
		{LabelEnvironment, "production"},
		{LabelRole, "terrabase"},
	} {
		outside := request.Spec.Copy()
		outside.Annotations.Name = "removal-" + changedScope.value
		outside.Annotations.Labels[changedScope.key] = changedScope.value
		retained, err := upstream.CreateService(ctx, &api.CreateServiceRequest{Spec: outside})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.RemoveService(ctx, &api.RemoveServiceRequest{ServiceID: retained.Service.ID}); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("removal outside admitted scope %s=%s: %v", changedScope.key, changedScope.value, err)
		}
		if _, err := upstream.GetService(ctx, &api.GetServiceRequest{ServiceID: retained.Service.ID}); err != nil {
			t.Fatalf("denied removal changed upstream service: %v", err)
		}
		if _, err := upstream.RemoveService(ctx, &api.RemoveServiceRequest{ServiceID: retained.Service.ID}); err != nil {
			t.Fatal(err)
		}
	}
	revoked.Store(true)
	if _, err := client.RemoveService(ctx, &api.RemoveServiceRequest{ServiceID: actual.Service.ID}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("revoked authority removed admitted service: %v", err)
	}
	if _, err := upstream.GetService(ctx, &api.GetServiceRequest{ServiceID: actual.Service.ID}); err != nil {
		t.Fatalf("revoked removal changed upstream service: %v", err)
	}
	revoked.Store(false)
	if _, err := client.RemoveService(ctx, &api.RemoveServiceRequest{ServiceID: actual.Service.ID}); err != nil {
		t.Fatalf("admitted service removal denied: %v", err)
	}
	if _, err := upstream.GetService(ctx, &api.GetServiceRequest{ServiceID: actual.Service.ID}); status.Code(err) != codes.NotFound {
		t.Fatalf("admitted removal did not delete upstream service: %v", err)
	}
	if _, _, bad, err := dialManagementAt(ctx, path, uint32(os.Getuid()), "another-instance"); status.Code(err) != codes.PermissionDenied {
		if bad != nil {
			bad.Close()
		}
		t.Fatalf("other accepted identity admitted: %v", err)
	}
	revokeDuring.Store(true)
	if _, err := client.ListNodes(ctx, &api.ListNodesRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("authority revoked during actual Raft read returned data: %v", err)
	}
	revoked.Store(false)
	revoked.Store(true)
	if _, err := client.ListNodes(ctx, &api.ListNodesRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("revoked authority admitted existing connection: %v", err)
	}

	for _, method := range []string{workerPrepareMethod, workerAdmitMethod, workerAuditMethod, workerReadMembershipMethod} {
		if err := conn.Invoke(ctx, method, &wrapperspb.BytesValue{Value: []byte(`{}`)}, new(wrapperspb.BytesValue)); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("revoked authority admitted existing worker connection: %v", err)
		}
	}
	revoked.Store(false)
	if _, err := startManagementAt(ctx, path, uint32(os.Getuid()), uint32(os.Getgid()), cgroup, "accepted-current", node, "sa-saopaulo-1", "test", upstream, refresh, nil); err == nil {
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
			deniedServer, err := startManagementAt(ctx, path, test.uid, uint32(os.Getgid()), test.cgroup, "accepted-current", node, "sa-saopaulo-1", "test", upstream, refresh, nil)
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
