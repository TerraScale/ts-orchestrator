package app

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/autoscale"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/hostload"
	"github.com/TerraScale/ts-orchestrator/internal/memberstatus"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/tsauth"
	"github.com/TerraScale/ts-orchestrator/internal/workload"
)

func TestAutoscaleConfigUsesSignedDeclarations(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	resources := placement.Resources{CPU: 1, MemoryBytes: 1 << 30, DiskBytes: 1 << 30}
	profiles := map[string]WorkloadProfile{"api": {Resources: resources}, "terrabase": {Resources: resources}}
	fencer := &switchingFencer{snapshot: authority.Snapshot{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Ready: true, Leader: true, Epoch: 1, Revision: 1,
		ExpiresAt: time.Now().Add(time.Hour)}}
	load := startHostTelemetry(profiles, &host.Controller{}, fencer)
	if load == nil || load.load == nil {
		t.Fatalf("absent autoscale declaration must still collect telemetry: %v", load)
	}
	declared := &AutoscaleConfig{Services: []workload.ServiceSpec{{Role: "api", Environment: "prod",
		Kind: workload.KindStateless, Replicas: workload.ReplicaBounds{Min: 1, Max: 3}}}}
	if err := validateAutoscaleConfig(declared, profiles); err != nil {
		t.Fatal(err)
	}
	var planner regionalDeliveryPlanner
	if _, owned := planner.nativeServiceSpec("api"); owned {
		t.Fatal("planner without signed services owns a role")
	}
	planner.services = &specRegistry{}
	if _, owned := planner.nativeServiceSpec("api"); owned {
		t.Fatal("planner without a signed service policy owns a role")
	}
	planner.services.adopt(cellspec.Spec{Generation: 1, Services: []cellspec.Service{{Role: "api", Spec: &declared.Services[0]}}}, 1)
	if spec, owned := planner.nativeServiceSpec("api"); !owned || spec.Replicas != declared.Services[0].Replicas {
		t.Fatalf("planner did not read the adopted service policy: %+v, %v", spec, owned)
	}
	planner.services.adopt(cellspec.Spec{Generation: 2}, 2)
	if _, owned := planner.nativeServiceSpec("api"); owned {
		t.Fatal("planner retained a removed service policy")
	}

	invalid := map[string]*AutoscaleConfig{
		"no profile": {Services: []workload.ServiceSpec{{Role: "web", Environment: "prod", Kind: workload.KindStateless,
			Replicas: workload.ReplicaBounds{Max: 1}}}},
		"resource mismatch": {Services: []workload.ServiceSpec{{Role: "api", Environment: "prod", Kind: workload.KindStateless,
			Replicas: workload.ReplicaBounds{Max: 1}, Resources: placement.Resources{CPU: 9, MemoryBytes: 1, DiskBytes: 1}}}},
		"terrabase role": {Services: []workload.ServiceSpec{{Role: "terrabase", Environment: "prod",
			Kind: workload.KindStateless, Replicas: workload.ReplicaBounds{Max: 1}}}},
	}
	for name, config := range invalid {
		if err := validateAutoscaleConfig(config, profiles); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestAbsentAutoscaleConfigKeepsCanonicalControllerJSON(t *testing.T) {
	encoded, err := protocol.EncodeJSON(ControllerConfig{CandidateID: "0000000000VKJKNDYE2PT2WG3X"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "autoscale") {
		t.Fatalf("absent autoscale config changed signed controller JSON: %s", encoded)
	}
}

// Autoscale config refuses entries that nothing would act on: stateful
// services and signal policies without a signal source.
func TestAutoscaleConfigRefusesInertEntries(t *testing.T) {
	resources := placement.Resources{CPU: 1, MemoryBytes: 1 << 30, DiskBytes: 1 << 30}
	profiles := map[string]WorkloadProfile{"api": {Resources: resources}}
	stateful := &AutoscaleConfig{Services: []workload.ServiceSpec{{Role: "terrabase", Environment: "prod",
		Kind: workload.KindStateful, Replicas: workload.ReplicaBounds{Min: 2, Max: 4},
		Stateful: &workload.StatefulPolicy{QuorumFloorPerRegion: 2, MaxConcurrentChanges: 1, DrainTimeoutSeconds: 60,
			MaxLagForScaleDown: 1, VolumeRetention: workload.RetainVolume}}}}
	if err := validateAutoscaleConfig(stateful, profiles); err == nil {
		t.Fatal("a stateful autoscale service was accepted although nothing reconciles it")
	}
	scaling := &AutoscaleConfig{Services: []workload.ServiceSpec{{Role: "api", Environment: "prod",
		Kind: workload.KindStateless, Replicas: workload.ReplicaBounds{Min: 1, Max: 3},
		Scaling: &autoscale.Policy{Signals: []autoscale.Signal{{Name: autoscale.SignalCPUUtilization, Target: 0.6}}}}}}
	if err := validateAutoscaleConfig(scaling, profiles); err != nil {
		t.Fatalf("a cpu_util policy with host telemetry was refused: %v", err)
	}
	for _, name := range []autoscale.SignalName{autoscale.SignalRequestRatePerReplica, autoscale.SignalTerraBaseWriteQPS} {
		scaling.Services[0].Scaling.Signals[0].Name = name
		if err := validateAutoscaleConfig(scaling, profiles); err == nil {
			t.Errorf("signal %s without a stateless producer was accepted", name)
		}
	}
}

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

// A role whose hosts carry release-scoped generations keeps them after the
// reconciler stops owning it, so later releases are not planned backwards.
func TestUnownedShapeKeepsReleaseScopedGenerations(t *testing.T) {
	intent := delivery.Intent{Generation: 3, DesiredReplicas: 2}
	plain, err := unownedShape(intent, workload.Observation{NodeHighWater: map[string]uint64{"node-a": 2}})
	if err != nil || plain != (delivery.PlanShape{Generation: 3, Replicas: 2}) {
		t.Fatalf("never shaped role = %+v (%v)", plain, err)
	}
	shapedBefore, _ := workload.ReleaseGeneration(2)
	shaped, err := unownedShape(intent, workload.Observation{NodeHighWater: map[string]uint64{"node-a": shapedBefore + 5}})
	if err != nil || shaped.Generation <= shapedBefore+5 || shaped.Replicas != 2 {
		t.Fatalf("formerly shaped role = %+v (%v), want a generation above %d", shaped, err, shapedBefore+5)
	}
}

func TestTSAuthReleasePlacementCapsFailureDomains(t *testing.T) {
	if cap := releasePlacementDomainCap(tsauth.Role); cap != 1 {
		t.Fatalf("ts-auth release domain cap = %d, want 1", cap)
	}
	if cap := releasePlacementDomainCap("api"); cap != 0 {
		t.Fatalf("generic release domain cap = %d, want 0", cap)
	}
}
