package app

import (
	"strings"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/autoscale"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostpool"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/workload"
)

func TestAutoscaleConfigDefaultsOffAndValidates(t *testing.T) {
	resources := placement.Resources{CPU: 1, MemoryBytes: 1 << 30, DiskBytes: 1 << 30}
	profiles := map[string]WorkloadProfile{"api": {Resources: resources}, "terrabase": {Resources: resources}}
	reconciler, scaler, err := startWorkloadAutoscale("gru", nil, profiles, nil, nil)
	if err != nil || reconciler != nil || scaler != nil {
		t.Fatalf("absent autoscale config started workers: %v %v %v", reconciler, scaler, err)
	}
	disabled := &AutoscaleConfig{Services: []workload.ServiceSpec{{Role: "api", Environment: "prod",
		Kind: workload.KindStateless, Replicas: workload.ReplicaBounds{Min: 1, Max: 3}}}}
	if err := validateAutoscaleConfig(disabled, profiles); err != nil {
		t.Fatal(err)
	}
	if reconciler, scaler, err := startWorkloadAutoscale("gru", disabled, profiles, nil, nil); err != nil || reconciler != nil || scaler != nil {
		t.Fatal("disabled autoscale config started workers")
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
