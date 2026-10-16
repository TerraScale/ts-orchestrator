//go:build linux

package swarmruntime

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/moby/swarmkit/v2/api"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The kernel supplies peer credentials and /proc supplies the actual service
// cgroup; requests cross a second Unix gRPC server into real persistent Raft.
func TestManagementIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	cfg := nodeFixtureConfig(t, "founder", "manager")
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
	server, err := startManagementAt(ctx, path, uint32(os.Getuid()), uint32(os.Getgid()), cgroup, "accepted-current", node.ID(), "integration", "test", upstream, refresh)
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
	labels := map[string]string{LabelIntentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", LabelRole: "api", LabelRegion: "integration", LabelEnvironment: "test"}
	created, err := client.CreateService(ctx, &api.CreateServiceRequest{Spec: &api.ServiceSpec{
		Annotations: api.Annotations{Name: "management-proof", Labels: labels},
		Task:        api.TaskSpec{Runtime: &api.TaskSpec_Container{Container: &api.ContainerSpec{Image: "example.invalid/proof@sha256:" + strings.Repeat("0", 64)}}},
		Mode:        &api.ServiceSpec_Replicated{Replicated: &api.ReplicatedService{Replicas: 0}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	actual, err := upstream.GetService(ctx, &api.GetServiceRequest{ServiceID: created.Service.ID})
	if err != nil || actual.Service.Spec.Annotations.Name != "management-proof" {
		t.Fatalf("upstream persisted service: %v %v", actual, err)
	}
	digest := sha256.Sum256([]byte("test/integration/api"))
	config, err := client.CreateConfig(ctx, &api.CreateConfigRequest{Spec: &api.ConfigSpec{Annotations: api.Annotations{Name: fmt.Sprintf("ts-release-%x", digest[:16]), Labels: labels}, Data: []byte("immutable release evidence")}})
	if err != nil {
		t.Fatal(err)
	}
	spec := config.Config.Spec.Copy()
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
	revoked.Store(false)
	if _, err := startManagementAt(ctx, path, uint32(os.Getuid()), uint32(os.Getgid()), cgroup, "accepted-current", node.ID(), "integration", "test", upstream, refresh); err == nil {
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
			deniedServer, err := startManagementAt(ctx, path, test.uid, uint32(os.Getgid()), test.cgroup, "accepted-current", node.ID(), "integration", "test", upstream, refresh)
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
