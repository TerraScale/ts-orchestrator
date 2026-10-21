package app

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/gogo/protobuf/types"
	"github.com/moby/swarmkit/v2/api"
	"google.golang.org/grpc"
)

type opsControlClient struct {
	api.ControlClient
	services []*api.Service
	tasks    []*api.Task
}

func (c opsControlClient) ListServices(context.Context, *api.ListServicesRequest, ...grpc.CallOption) (*api.ListServicesResponse, error) {
	return &api.ListServicesResponse{Services: c.services}, nil
}
func (c opsControlClient) ListTasks(context.Context, *api.ListTasksRequest, ...grpc.CallOption) (*api.ListTasksResponse, error) {
	return &api.ListTasksResponse{Tasks: c.tasks}, nil
}
func (c opsControlClient) GetNode(_ context.Context, r *api.GetNodeRequest, _ ...grpc.CallOption) (*api.GetNodeResponse, error) {
	return &api.GetNodeResponse{Node: &api.Node{ID: r.NodeID, Description: &api.NodeDescription{Hostname: "single-host"}}}, nil
}

func opsFixture(t *testing.T) (opsControlClient, *api.Service) {
	spec, err := swarmruntime.ServiceSpec{Name: "whoami", Image: "docker.io/library/alpine@sha256:3e9b4b680bfc9fb5269227cffbd6d42be39fbf7c0b908123913864aa4447e764",
		Port: 8099, Replicas: 1, Secrets: map[string]vaultsecret.Ref{"API_KEY": {Vault: "ocid1.vault.oc1.sa-saopaulo-1.aa.bb", Name: "gru-1-whoami-api-key"}}, Env: map[string]string{"MODE": "demo"}, Hostnames: []string{"who.example.com"}}.SwarmSpec()
	if err != nil {
		t.Fatal(err)
	}
	at := func(minutes int) *types.Timestamp {
		ts, _ := types.TimestampProto(time.Date(2026, 10, 21, 20, minutes, 0, 0, time.UTC))
		return ts
	}
	service := &api.Service{ID: "svc1", Spec: *spec, Meta: api.Meta{Version: api.Version{Index: 7}, CreatedAt: at(0), UpdatedAt: at(1)}}
	tasks := []*api.Task{
		{ID: "old", NodeID: "n1", Slot: 1, ServiceAnnotations: spec.Annotations, DesiredState: api.TaskStateShutdown, Status: api.TaskStatus{State: api.TaskStateFailed, Timestamp: at(2), Err: "task: non-zero exit (1)"}},
		{ID: "new", NodeID: "n1", Slot: 1, ServiceAnnotations: spec.Annotations, DesiredState: api.TaskStateRunning, Status: api.TaskStatus{State: api.TaskStateRejected, Timestamp: at(3), Err: swarmruntime.ErrContainerMaterialPending.Error()}},
	}
	return opsControlClient{services: []*api.Service{service}, tasks: tasks}, service
}

func TestServicePsShowsNewestTaskAndFix(t *testing.T) {
	client, service := opsFixture(t)
	rows, err := swarmruntime.ServiceTasks(t.Context(), client, service)
	if err != nil || len(rows) != 2 || rows[0].ID != "new" || rows[0].Node != "single-host" {
		t.Fatalf("rows %+v, %v", rows, err)
	}
	var out bytes.Buffer
	if err := writeTaskRows(&out, rows, time.Date(2026, 10, 21, 20, 5, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if f := strings.Fields(lines[1]); len(lines) != 4 || strings.Join(f[:6], " ") != "new single-host rejected running 2m0s ago" ||
		!strings.HasPrefix(lines[3], "Fix: ") || !strings.Contains(lines[3], "OCI Vault") {
		t.Fatalf("ps output:\n%s", out.String())
	}
}

func TestServiceInspectShowsSecretNamesOnly(t *testing.T) {
	_, service := opsFixture(t)
	inspection, err := swarmruntime.InspectService(service)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(inspection)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	spec := got["spec"].(map[string]any)
	if got["imageDigest"] != "sha256:3e9b4b680bfc9fb5269227cffbd6d42be39fbf7c0b908123913864aa4447e764" || got["version"] != float64(7) ||
		spec["name"] != "whoami" || spec["port"] != float64(8099) || spec["readyPath"] != "/readyz" ||
		spec["secrets"].(map[string]any)["API_KEY"].(map[string]any)["name"] != "gru-1-whoami-api-key" || spec["env"].(map[string]any)["MODE"] != "demo" {
		t.Fatalf("inspect: %s", data)
	}
	// The round trip is the declaration `service apply` accepted.
	if _, err := inspection.Spec.SwarmSpec(); err != nil {
		t.Fatal(err)
	}
}

func TestRecentEventsOldestFirstWithFix(t *testing.T) {
	client, _ := opsFixture(t)
	var out bytes.Buffer
	if err := recentEvents(t.Context(), client, &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 || !strings.Contains(lines[0], "service whoami updated version 7") ||
		!strings.Contains(lines[1], "task whoami.1 old failed") || !strings.Contains(lines[1], `fix="the container exited`) ||
		!strings.Contains(lines[2], "task whoami.1 new rejected") {
		t.Fatalf("events:\n%s", out.String())
	}
}

func TestServiceLogsReadsBothStreamsAndFollowsTruncation(t *testing.T) {
	state := t.TempDir()
	write := func(stream, data string) {
		path := swarmruntime.RuntimeLogFile(state, "task1", stream)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	row := swarmruntime.TaskRow{ID: "task1", State: "RUNNING"}
	var out bytes.Buffer
	if err := writeTaskLogs(t.Context(), &out, state, row, false); err == nil || !strings.Contains(err.Error(), "no container logs yet") {
		t.Fatalf("missing logs: %v", err)
	}
	write("stdout", "out\n")
	write("stderr", "err\n")
	if err := writeTaskLogs(t.Context(), &out, state, row, false); err != nil || out.String() != "out\nerr\n" {
		t.Fatalf("logs %q, %v", out.String(), err)
	}
	out.Reset()
	ctx, cancel := context.WithTimeout(t.Context(), 1500*time.Millisecond)
	defer cancel()
	go func() {
		time.Sleep(700 * time.Millisecond)
		write("stdout", "x\n") // Shorter than before: the logger truncated a full segment.
	}()
	if err := writeTaskLogs(ctx, &out, state, row, true); err != nil || out.String() != "out\nerr\nx\n" {
		t.Fatalf("follow %q, %v", out.String(), err)
	}
}

func TestOperatorErrorsNameTheFix(t *testing.T) {
	for message, want := range map[string]string{
		"open /var/lib/ts-orch/swarm/certificates/swarm-root-ca.crt: permission denied":                             "sudo",
		"rpc error: code = Unavailable desc = dial unix /var/lib/ts-orch/control.sock: connect: connection refused": "systemctl status ts-orch",
		"resolve current signed container material: current signed container material is pending":                   "OCI Vault",
		"task disk capacity or retained storage is unavailable":                                                     "df -h",
		"no suitable node (insufficient resources on 1 node)":                                                       "service ls",
		"load admitted container image: failed to resolve reference":                                                "images pull",
	} {
		if err := explain(errors.New(message)); !strings.Contains(err.Error(), ". Fix: ") || !strings.Contains(err.Error(), want) {
			t.Errorf("%q -> %v", message, err)
		}
	}
	if err := explain(errors.New("unrelated")); err.Error() != "unrelated" {
		t.Fatal(err)
	}
}
