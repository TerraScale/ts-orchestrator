package app

import (
	"context"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/autoscale"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/hostload"
	"github.com/TerraScale/ts-orchestrator/internal/memberstatus"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/workload"
)

// Host telemetry starts an aggregator independently of scheduling; its
// normalized readings and resource samples reach metric history.
func TestHostTelemetryFeedsAutoscaleHistory(t *testing.T) {
	resources := placement.Resources{CPU: 2, MemoryBytes: 1 << 30, DiskBytes: 1 << 30}
	config := &AutoscaleConfig{Services: []workload.ServiceSpec{{Role: "api",
		Environment: "prod", Kind: workload.KindStateless, Replicas: workload.ReplicaBounds{Min: 1, Max: 3},
		Scaling: &autoscale.Policy{Signals: []autoscale.Signal{{Name: autoscale.SignalCPUUtilization, Target: 0.6}}}}}}
	fencer := &switchingFencer{snapshot: authority.Snapshot{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Ready: true, Leader: true, Epoch: 1, Revision: 1,
		ExpiresAt: time.Now().Add(time.Hour)}}
	profiles := map[string]WorkloadProfile{"api": {Resources: resources}}
	if err := validateAutoscaleConfig(config, profiles); err != nil {
		t.Fatal(err)
	}
	telemetry := startHostTelemetry(profiles, &host.Controller{}, fencer)
	load := telemetry.load
	cores := 1.0
	if err := telemetry.record(hostload.Origin{Cell: "gru", Environment: "prod", Node: "pool-1"},
		hostload.Report{SchemaVersion: 1, Roles: []hostload.RoleUsage{{Role: "api", CPUCores: &cores}}}); err != nil {
		t.Fatal(err)
	}
	// The aggregator holds until reports cover the signal window; one
	// report covers a 10s window five seconds later.
	reading, err := load.Read(t.Context(), autoscale.Target{Cell: "gru", Environment: "prod", Role: "api"},
		autoscale.Signal{Name: autoscale.SignalCPUUtilization, Target: 0.6, WindowSeconds: 10}, time.Now().Add(5*time.Second))
	if err != nil || reading.Samples != 1 || reading.Value != 0.5 {
		t.Fatalf("cpu_util normalized by the signed 2-core request = %+v, %v", reading, err)
	}
	tbLoad := &memberstatus.Load{Connections: 4, ReplicationLagSeq: 2}
	if err := telemetry.record(hostload.Origin{Cell: "gru", Environment: "prod", Node: "tb-1"},
		hostload.Report{SchemaVersion: 1, Roles: []hostload.RoleUsage{{Role: "terrabase", TerraBase: tbLoad}}}); err != nil {
		t.Fatal(err)
	}
	// Resource history does not wait for an autoscaler tick; its own term
	// gate accepts the current leader's reports independently.
	samples := withAutoscaleSamples(func(context.Context) []observability.Sample { return nil }, nil, telemetry)(t.Context())
	found := map[string]float64{}
	for _, sample := range samples {
		found[sample.Metric] = sample.Value
	}
	if found[observability.HistTerraBaseConnections] != 4 || found[observability.HistTerraBaseLagSeq] != 2 {
		t.Fatalf("terrabase load samples = %+v", samples)
	}
	if _, present := found[observability.HistAutoscaleReplicas]; present {
		t.Fatal("a service without a reconciliation result was sampled")
	}
	// A member that is not (or no longer) the authority leader records
	// nothing extra: its cached reports and last results are not current.
	fencer.set(authority.Snapshot{})
	if samples := withAutoscaleSamples(func(context.Context) []observability.Sample { return nil }, nil, telemetry)(t.Context()); len(samples) != 0 {
		t.Fatalf("follower recorded autoscale samples: %+v", samples)
	}
}
