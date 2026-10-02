package app

import (
	"strings"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/capacity"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/workload"
)

func TestAutoscaleConfigDefaultsOffAndValidates(t *testing.T) {
	profiles := map[string]WorkloadProfile{"api": {Resources: placement.Resources{CPU: 1, MemoryBytes: 1 << 30, DiskBytes: 1 << 30}}}
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
		"invalid pool": {NodePools: []capacity.NodePool{{Name: "general"}}},
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
