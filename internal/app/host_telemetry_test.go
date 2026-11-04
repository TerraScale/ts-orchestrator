package app

import (
	"context"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/hostload"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

func TestHostTelemetryCollectsWithoutAutoscaling(t *testing.T) {
	for _, config := range []*AutoscaleConfig{nil} {
		fencer := &switchingFencer{snapshot: authority.Snapshot{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Ready: true, Leader: true, Epoch: 1,
			Revision: 1, ExpiresAt: time.Now().Add(time.Hour)}}
		if err := validateAutoscaleConfig(config, nil); err != nil {
			t.Fatal(err)
		}
		telemetry := startHostTelemetry(nil, &host.Controller{}, fencer)
		if telemetry == nil || telemetry.load == nil {
			t.Fatalf("collection without scaling: collector=%v", telemetry)
		}
		cpu, cores := 0.4, 0.125
		if err := telemetry.record(hostload.Origin{Cell: "gru", Environment: "production", Node: "Host-A"},
			hostload.Report{SchemaVersion: hostload.SchemaVersion, Host: hostload.HostUsage{CPU: &cpu},
				Roles: []hostload.RoleUsage{{Role: "api", CPUCores: &cores}}}); err != nil {
			t.Fatal(err)
		}
		collect := withAutoscaleSamples(func(context.Context) []observability.Sample { return nil }, nil, telemetry)
		now := time.Now()
		history := observability.NewHistory(observability.HistoryConfig{})
		history.Append(now, collect(t.Context()))
		for metric, want := range map[string]float64{observability.HistHostCPUUtilization: cpu,
			observability.HistServiceCPUCores: cores} {
			result := history.Range(observability.HistoryQuery{Metric: metric,
				Labels: map[string]string{"member": "host-a"}, Start: now.Add(-time.Minute), End: now})
			if len(result.Series) != 1 || len(result.Series[0].Points) != 1 || result.Series[0].Points[0].Value != want {
				t.Fatalf("%s did not reach history without autoscaling: %+v", metric, result)
			}
		}
	}
}
