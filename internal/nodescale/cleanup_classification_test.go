package nodescale

import (
	"context"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/manager/state/store"
)

// Inert cleanup selectors exercise decision classification over a real control
// API. They do not establish ROOT provenance or authorize provider effects.
func TestCleanupMetadataOnlySelectsRetirement(t *testing.T) {
	hosts := newSwarmHosts(t)
	hosts.live["ts-gru-4"] = true
	hosts.sync(t)
	if err := hosts.store.Update(func(tx store.Tx) error {
		node := store.GetNode(tx, "ts-gru-4")
		node.Certificate.Role = api.NodeRoleWorker
		return store.UpdateNode(tx, node)
	}); err != nil {
		t.Fatal(err)
	}
	listed, err := hosts.control.ListNodes(t.Context(), &api.ListNodesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	instance := PoolInstance{ID: "ocid-ts-gru-4", Name: "ts-gru-4", State: "RUNNING", PrivateIP: "10.0.0.4",
		Capacity: Capacity{Role: RoleWasm, Architecture: "arm64", Shape: PreferredShape},
		Cleanup:  &rootoci.PoolRetirementPreparation{Node: "ts-gru-4", Retirement: rootoci.PoolRetirementExpectation{InstanceID: "ocid-ts-gru-4"}}}
	scaler := &Scaler{Cell: "gru", Control: hosts.control, Loads: func() []NodeLoad { return []NodeLoad{{Node: instance.Name, CPU: .1}} },
		CanRetire: func(_ context.Context, name, id string) error {
			if name != instance.Name || id != instance.ID {
				t.Fatal("cleanup selected a different original worker")
			}
			return nil
		}}
	pool := PoolState{Size: 1, Instances: []PoolInstance{instance}, AdmissionPending: "worker admission unavailable"}
	obs := scaler.observe(pool, listed.Nodes)
	if obs.pool != 1 || obs.live[instance.Name] || obs.counted[instance.Name] || len(obs.addresses) != 0 || len(countedLoads(scaler.Loads(), obs)) != 0 {
		t.Fatalf("cleanup metadata gained serving credit or lost resource liability: %+v", obs)
	}
	pass := &tick{now: time.Now(), pool: pool, obs: obs, hosts: listed.Nodes}
	state := State{Nodes: MinNodes + 1, Allowance: MaxNodes}
	pass.pool.Pending = "unknown provider observation"
	decision, err := scaler.decide(t.Context(), pass, state)
	if err != nil || decision.Action != Hold || pass.record.Action != nil {
		t.Fatalf("general unknown observation permitted cleanup: %+v %v", decision, err)
	}
	pass.pool.Pending = ""
	scaler.FunctionDemand = func(context.Context) ([]CapacityDemand, error) {
		t.Fatal("admission-pending cleanup reached growth demand")
		return nil, nil
	}
	decision, err = scaler.decide(t.Context(), pass, state)
	if err != nil || decision.Action != Down || pass.record.Action == nil || pass.record.Action.Kind != Down || pass.record.Action.InstanceID != instance.ID {
		t.Fatalf("known cleanup could not select only original retirement: %+v %v", decision, err)
	}
	pass.record.Action = nil
	scaler.FunctionDemand = func(context.Context) ([]CapacityDemand, error) {
		return []CapacityDemand{{Architecture: "arm64", Slots: 1}}, nil
	}
	demand, err := scaler.functionDemand(t.Context(), pass)
	if err != nil || demand == nil || demand.Slots != 1 {
		t.Fatalf("cleanup metadata earned function-serving capacity credit: %+v %v", demand, err)
	}
}
