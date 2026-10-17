package swarmruntime

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/autoscale"
	"github.com/TerraScale/ts-orchestrator/internal/hostload"
	"github.com/gogo/protobuf/types"
	"github.com/moby/swarmkit/v2/api"
)

func TestAutoscaleHistoryManagerIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	cfg := serviceConfig(t, "ts-gru-1", "manager")
	manager := serviceStart(t, ctx, cfg)
	client, err := manager.ControlClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AdmitNode(ctx, client, manager.ID(), cfg.Admission); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	probe := func(ctx context.Context, _ *api.Task) error {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
		if err != nil {
			return err
		}
		response, err := server.Client().Do(request)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("application readiness returned %d", response.StatusCode)
		}
		return nil
	}
	intent := serviceIntent()
	intent.Role, intent.Replicas = "api", 2
	created, err := applyService(ctx, client, intent)
	if err != nil {
		t.Fatal(err)
	}
	get := func() *api.Service {
		t.Helper()
		response, err := client.GetService(ctx, &api.GetServiceRequest{ServiceID: created.ID})
		if err != nil {
			t.Fatal(err)
		}
		return response.Service
	}
	requests := created.Spec.Task.Resources.Reservations
	source := hostload.NewAggregator(hostload.AggregatorConfig{Requests: map[string]hostload.Request{intent.Role: {
		CPUCores: float64(requests.NanoCPUs) / 1e9, MemoryBytes: requests.MemoryBytes,
	}}, MinInterval: time.Nanosecond, StaleAfter: 5 * time.Second})
	target := autoscale.Target{Cell: "gru", Environment: intent.Environment, Role: intent.Role}
	policy := ScalePolicy{Target: target, Bounds: autoscale.Bounds{Min: 1, Max: 4}, Policy: &autoscale.Policy{
		Signals: []autoscale.Signal{{Name: autoscale.SignalCPUUtilization, Target: 0.5, WindowSeconds: 1}}, DownStabilizationSeconds: 1,
	}}
	scaler, err := NewAutoscaler(client, manager.ID(), source, probe, []ScalePolicy{policy})
	if err != nil {
		t.Fatal(err)
	}
	tick := func() {
		t.Helper()
		if err := scaler.Tick(ctx); err != nil {
			t.Fatal(err)
		}
	}
	record := func() {
		t.Helper()
		if err := source.Record(hostload.Origin{Cell: target.Cell, Environment: target.Environment, Node: cfg.Admission.HostID}, hostload.Report{
			SchemaVersion: hostload.SchemaVersion, Roles: []hostload.RoleUsage{{Role: intent.Role, CPUCores: new(0.01)}},
		}); err != nil {
			t.Fatal(err)
		}
	}
	ready := func() {
		t.Helper()
		serviceEventually(t, ctx, func() bool {
			record()
			current := get()
			ready, err := ReadyService(ctx, client, current, probe)
			return err == nil && ready && (current.UpdateStatus == nil || current.UpdateStatus.State == api.UpdateStatus_COMPLETED)
		})
	}
	warm := func() {
		t.Helper()
		start := time.Now()
		serviceEventually(t, ctx, func() bool { record(); return time.Since(start) > 1100*time.Millisecond })
	}
	ready()
	tick() // Acquiring leadership discards the preceding term's telemetry.
	warm()
	tick()
	if result := scaler.Last()[target]; result.Reason != autoscale.ReasonScaleDownStabilizing || len(result.Readings) != 1 || math.Abs(result.Readings[0].Value-0.1) > 1e-9 {
		t.Fatalf("committed-request normalization/stabilization=%+v", result)
	}
	warm()
	if err := scaler.SetPolicies([]ScalePolicy{policy}); err != nil {
		t.Fatal(err)
	}
	tick()
	if current := get(); current.Spec.GetReplicated().Replicas != 1 {
		t.Fatalf("unchanged signed policy restarted stabilization: %+v", scaler.Last()[target])
	}
	ready()
	current := get()
	spec := current.Spec.Copy()
	spec.GetReplicated().Replicas = 2
	spec.Task.Resources.Reservations.NanoCPUs *= 2
	spec.Task.Resources.Limits.NanoCPUs *= 2
	spec.Update.Monitor = types.DurationProto(time.Millisecond)
	if _, err := client.UpdateService(ctx, &api.UpdateServiceRequest{ServiceID: current.ID, ServiceVersion: &current.Meta.Version, Spec: spec}); err != nil {
		t.Fatal(err)
	}
	ready()
	tick()
	if result := scaler.Last()[target]; result.Reason != autoscale.ReasonScaleDownStabilizing || get().Spec.GetReplicated().Replicas != 2 {
		t.Fatalf("resource-changing release reused old decision window: %+v", result)
	}
	scaler.Reset()
	if len(scaler.Last()) != 0 || len(source.Nodes()) != 0 {
		t.Fatal("authority loss retained decisions or host telemetry")
	}
	tick()
	if result := scaler.Last()[target]; result.Reason != autoscale.ReasonNoSignalData || get().Spec.GetReplicated().Replicas != 2 {
		t.Fatalf("new authority scaled before fresh telemetry: %+v", result)
	}
}
