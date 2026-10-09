package app

import (
	"context"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/autoscale"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostload"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostpool"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/memberstatus"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/tsauth"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/workload"
	"github.com/nats-io/nats.go/jetstream"
)

func TestAutoscaleConfigDefaultsOffAndValidates(t *testing.T) {
	resources := placement.Resources{CPU: 1, MemoryBytes: 1 << 30, DiskBytes: 1 << 30}
	profiles := map[string]WorkloadProfile{"api": {Resources: resources}, "terrabase": {Resources: resources}}
	fencer := &switchingFencer{snapshot: authority.Snapshot{Ready: true, Leader: true, Epoch: 1, Revision: 1,
		ExpiresAt: time.Now().Add(time.Hour)}}
	// The reconciler always runs, for the roles a cell spec adds later;
	// without a service it owns nothing.
	reconciler, scaler, load, err := startWorkloadAutoscale("gru", nil, profiles, nil, nil, time.Time{}, &host.Controller{}, fencer)
	if err != nil || scaler != nil || load == nil || reconciler.Signals() != nil {
		t.Fatalf("absent autoscale config must collect without scaling: %v %v %v", scaler, load, err)
	}
	if _, owned := reconciler.Owns("api"); owned {
		t.Fatal("a reconciler without services owns a role")
	}
	disabled := &AutoscaleConfig{Services: []workload.ServiceSpec{{Role: "api", Environment: "prod",
		Kind: workload.KindStateless, Replicas: workload.ReplicaBounds{Min: 1, Max: 3}}}}
	if err := validateAutoscaleConfig(disabled, profiles); err != nil {
		t.Fatal(err)
	}
	disabled.HostTelemetry = true
	if reconciler, scaler, load, err := startWorkloadAutoscale("gru", disabled, profiles, nil, nil, time.Time{}, &host.Controller{}, fencer); err != nil || scaler != nil || load == nil || reconciler.Signals() != nil {
		t.Fatal("disabled autoscale config must collect without scaling")
	}
	var planner regionalDeliveryPlanner
	if _, owned := planner.workloads.Owns("api"); owned {
		t.Fatal("planner without a reconciler owns a role")
	}

	invalid := map[string]*AutoscaleConfig{
		"interval": {IntervalSeconds: -1},
		"no profile": {Services: []workload.ServiceSpec{{Role: "web", Environment: "prod", Kind: workload.KindStateless,
			Replicas: workload.ReplicaBounds{Max: 1}}}},
		"resource mismatch": {Services: []workload.ServiceSpec{{Role: "api", Environment: "prod", Kind: workload.KindStateless,
			Replicas: workload.ReplicaBounds{Max: 1}, Resources: placement.Resources{CPU: 9, MemoryBytes: 1, DiskBytes: 1}}}},
		"invalid pool": {NodePools: []hostpool.NodePool{{Name: "general"}}},
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
	encoded, err := protocol.EncodeJSON(ControllerConfig{CandidateID: "slot-a"})
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
	if err := validateAutoscaleConfig(scaling, profiles); err == nil {
		t.Fatal("a scaling policy was accepted although no signal source feeds it")
	}
	// Host telemetry is the signal source: with it the policy is accepted,
	// but only for signals it produces for stateless roles.
	scaling.HostTelemetry = true
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

func TestLoadTelemetrySecondsIsCheckedBeforeConversion(t *testing.T) {
	for _, valid := range []int{0, 5, 15, 3600} {
		if err := validateLoadTelemetrySeconds(valid); err != nil {
			t.Errorf("%d refused: %v", valid, err)
		}
	}
	// 1<<55 seconds overflows a time.Duration to zero.
	for _, invalid := range []int{-1, 1, 4, 3601, 1 << 55} {
		if err := validateLoadTelemetrySeconds(invalid); err == nil {
			t.Errorf("%d accepted", invalid)
		}
	}
}

// Host telemetry starts an aggregator as the reconciler's signal source,
// installs it as the host controller's load sink, and its readings and the
// reconciler's results reach the metric history.
func TestHostTelemetryFeedsAutoscaleHistory(t *testing.T) {
	resources := placement.Resources{CPU: 2, MemoryBytes: 1 << 30, DiskBytes: 1 << 30}
	config := &AutoscaleConfig{Enabled: true, HostTelemetry: true, Services: []workload.ServiceSpec{{Role: "api",
		Environment: "prod", Kind: workload.KindStateless, Replicas: workload.ReplicaBounds{Min: 1, Max: 3},
		Scaling: &autoscale.Policy{Signals: []autoscale.Signal{{Name: autoscale.SignalCPUUtilization, Target: 0.6}}}}}}
	fencer := &switchingFencer{snapshot: authority.Snapshot{Ready: true, Leader: true, Epoch: 1, Revision: 1,
		ExpiresAt: time.Now().Add(time.Hour)}}
	reconciler, _, telemetry, err := startWorkloadAutoscale("gru", config, map[string]WorkloadProfile{"api": {Resources: resources}},
		config.Services, nil, time.Time{}, &host.Controller{}, fencer)
	if err != nil {
		t.Fatal(err)
	}
	load, ok := reconciler.Signals().(*hostload.Aggregator)
	if !ok {
		t.Fatalf("signal source = %T, want the host load aggregator", reconciler.Signals())
	}
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
	samples := withAutoscaleSamples(func(context.Context) []observability.Sample { return nil }, reconciler, telemetry)(t.Context())
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
	if samples := withAutoscaleSamples(func(context.Context) []observability.Sample { return nil }, reconciler, telemetry)(t.Context()); len(samples) != 0 {
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

// The pool scaler dates the cell by its replicated authority log; a cell
// whose log cannot be read has an unknown age.
func TestAuthorityLogCreatedDatesTheCell(t *testing.T) {
	js := testRolloutJetStream(t)
	if created := authorityLogCreated(t.Context(), js); !created.IsZero() {
		t.Fatalf("a cell without an authority log is dated %v", created)
	}
	stream, err := js.CreateStream(t.Context(), jetstream.StreamConfig{Name: authority.ControlStreamName,
		Subjects: []string{"test.authority"}})
	if err != nil {
		t.Fatal(err)
	}
	if created := authorityLogCreated(t.Context(), js); created.IsZero() || !created.Equal(stream.CachedInfo().Created) {
		t.Fatalf("authority log dated %v, created %v", created, stream.CachedInfo().Created)
	}
}
