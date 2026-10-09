package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostload"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
)

func TestHostTelemetryCollectsWithoutAutoscaling(t *testing.T) {
	for _, config := range []*AutoscaleConfig{nil, {}, {HostTelemetry: true}, {Enabled: true}} {
		fencer := &switchingFencer{snapshot: authority.Snapshot{Ready: true, Leader: true, Epoch: 1,
			Revision: 1, ExpiresAt: time.Now().Add(time.Hour)}}
		reconciler, scaler, telemetry, err := startWorkloadAutoscale("gru", config, nil, nil, nil,
			time.Time{}, &host.Controller{}, fencer)
		if err != nil || scaler != nil || reconciler.Signals() != nil || telemetry == nil {
			t.Fatalf("collection without scaling: reconciler=%v scaler=%v collector=%v err=%v", reconciler, scaler, telemetry, err)
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
	leader := authority.Snapshot{Ready: true, Leader: true, Epoch: 1, Revision: 1, ExpiresAt: time.Now().Add(time.Hour)}
	fencer := &switchingFencer{snapshot: leader}
	telemetry := &hostTelemetry{fencer: fencer, load: hostload.NewAggregator(hostload.AggregatorConfig{})}
	cpu := 0.4
	origin := hostload.Origin{Cell: "gru", Environment: "production", Node: "host-a"}
	report := hostload.Report{SchemaVersion: hostload.SchemaVersion, Host: hostload.HostUsage{CPU: &cpu}}
	if err := telemetry.record(origin, report); err != nil {
		t.Fatal(err)
	}
	if len(telemetry.samples()) != 1 {
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
	if err := telemetry.record(origin, report); err != nil || len(telemetry.samples()) != 1 {
		t.Fatalf("fresh report did not resume collection: %v", err)
	}
	leader.ExpiresAt = time.Now().Add(-time.Second)
	fencer.set(leader)
	if len(telemetry.samples()) != 0 {
		t.Fatal("expired authority charted load")
	}
}
