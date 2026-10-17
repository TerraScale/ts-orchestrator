package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/hostload"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
)

func TestHostTelemetryCollectsWithoutAutoscaling(t *testing.T) {
	for _, config := range []*AutoscaleConfig{nil, {}} {
		fencer := &switchingFencer{snapshot: authority.Snapshot{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Ready: true, Leader: true, Epoch: 1,
			Revision: 1, ExpiresAt: time.Now().Add(time.Hour)}}
		reconciler, telemetry, err := startWorkloadAutoscale("gru", config, nil, nil,
			&host.Controller{}, fencer, nil)
		if err != nil || reconciler.Signals() == nil || telemetry == nil {
			t.Fatalf("collection without scaling: reconciler=%v collector=%v err=%v", reconciler, telemetry, err)
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

func TestHostTelemetryDiscardsPreviousAuthorityTerms(t *testing.T) {
	leader := authority.Snapshot{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Ready: true, Leader: true, Epoch: 1, Revision: 1, ExpiresAt: time.Now().Add(time.Hour)}
	fencer := &switchingFencer{snapshot: leader}
	telemetry := &hostTelemetry{fencer: fencer, load: hostload.NewAggregator(hostload.AggregatorConfig{})}
	cpu := 0.4
	origin := hostload.Origin{Cell: "gru", Environment: "production", Node: "host-a"}
	report := hostload.Report{SchemaVersion: hostload.SchemaVersion, Host: hostload.HostUsage{CPU: &cpu}}
	if err := telemetry.record(origin, report); err != nil {
		t.Fatal(err)
	}
	if len(telemetry.samples()) != 3 {
		t.Fatal("current leader report missing")
	}
	// The leader can leave and reacquire authority between sampler ticks.
	leader.Epoch = 2
	fencer.set(leader)
	if len(telemetry.samples()) != 0 {
		t.Fatal("new authority term charted an earlier term's report")
	}
	if err := telemetry.record(origin, report); err != nil {
		t.Fatal(err)
	}
	fencer.set(authority.Snapshot{})
	if len(telemetry.samples()) != 0 {
		t.Fatal("demoted controller charted cached load")
	}
	if err := telemetry.record(origin, report); !errors.Is(err, authority.ErrFenced) {
		t.Fatalf("demoted controller accepted load: %v", err)
	}
	leader.Epoch = 3
	fencer.set(leader)
	if len(telemetry.samples()) != 0 {
		t.Fatal("reacquired authority reused old load")
	}
	if err := telemetry.record(origin, report); err != nil || len(telemetry.samples()) != 3 {
		t.Fatalf("fresh report did not resume collection: %v", err)
	}
	leader.ExpiresAt = time.Now().Add(-time.Second)
	fencer.set(leader)
	if len(telemetry.samples()) != 0 {
		t.Fatal("expired authority charted load")
	}
}

func TestHostTelemetryRestoresReleaseResourceNormalization(t *testing.T) {
	fencer := &switchingFencer{snapshot: authority.Snapshot{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Ready: true, Leader: true, Epoch: 1, Revision: 1, ExpiresAt: time.Now().Add(time.Minute)}}
	telemetry := &hostTelemetry{fencer: fencer, load: hostload.NewAggregator(hostload.AggregatorConfig{})}
	for _, resources := range []placement.Resources{{CPU: 2, MemoryBytes: 2048}, {CPU: 1, MemoryBytes: 1024}} {
		telemetry.setResources(map[string]placement.Resources{"ts-auth": resources})
		if len(telemetry.load.Nodes()) != 0 || telemetry.requests["ts-auth"].CPUCores != float64(resources.CPU) || telemetry.requests["ts-auth"].MemoryBytes != resources.MemoryBytes {
			t.Fatal("resource change retained incompatible normalized samples")
		}
		cpu := 0.5
		if err := telemetry.record(hostload.Origin{Cell: "gru", Environment: "production", Node: "host-a"}, hostload.Report{SchemaVersion: hostload.SchemaVersion, Roles: []hostload.RoleUsage{{Role: "ts-auth", CPUCores: &cpu}}}); err != nil {
			t.Fatal(err)
		}
		telemetry.setResources(map[string]placement.Resources{"ts-auth": resources})
		if len(telemetry.load.Nodes()) != 1 {
			t.Fatal("unchanged release discarded current utilization window")
		}
	}
}
