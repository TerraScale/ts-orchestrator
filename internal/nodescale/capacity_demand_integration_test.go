package nodescale

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/api/genericresource"
	"github.com/moby/swarmkit/v2/manager/state/store"
	"github.com/oracle/oci-go-sdk/v65/core"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

func TestFunctionCapacityTracksManagerAndActualPoolSlots(t *testing.T) {
	ctx := t.Context()
	hosts := newSwarmHosts(t)
	hosts.live = map[string]bool{"ts-gru-1": true, "ts-gru-2": true, "ts-gru-3": true}
	hosts.sync(t)
	cloud := newCapacityCloud()
	base := capacityRecipe()
	observed := protocolPool(t, cloud, base.Capacity)
	records, err := OpenStore(ctx, capacityJetStream(t), 1)
	if err != nil {
		t.Fatal(err)
	}
	pool := chosenProtocolPool(t, observed, records, capacitySelectors)
	now := time.Now().UTC()
	var demandErr error
	scaler := &Scaler{Cell: "gru", Pool: pool, Store: records, Control: hosts.control,
		Leader: &capacityLeader{snapshot: authority.Snapshot{DeploymentID: entityid.New(), Leader: true, Ready: true, Epoch: 7, Revision: 3, ExpiresAt: now.Add(time.Hour)}},
		Now:    func() time.Time { return now }, Recipe: func(context.Context) (Recipe, error) { return base, nil },
		// Signed demand-producer qualification is separate from these actual SDK/manager observations.
		FunctionDemand: func(context.Context) ([]CapacityDemand, error) {
			return []CapacityDemand{{Architecture: "amd64", Slots: 1}}, demandErr
		},
		FunctionRecipe: func(_ context.Context, architecture string) (Recipe, error) {
			chosen := base
			chosen.Capacity = Capacity{Role: RoleWasm, Architecture: architecture, Shape: "VM.Standard.E4.Flex"}
			return chosen, nil
		},
		Allowance: func(time.Time) (int, bool) { return MaxNodes, true }, Loads: func() []NodeLoad { return nil },
		Journal: func(context.Context, decisionlog.Decision) {},
	}
	if err := scaler.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	chosen, revision, err := records.Load(ctx)
	if err != nil || chosen.Action == nil || chosen.Action.Kind != Up || chosen.Action.Step != stepGrow || chosen.Recipe == nil ||
		chosen.Recipe.Capacity.Role != RoleWasm || chosen.Recipe.Capacity.Architecture != "amd64" || chosen.Child != nil || chosen.Reservation != nil || len(cloud.pools) != 0 {
		t.Fatalf("demand did not durably plan isolated preparation: %+v err=%v", chosen, err)
	}
	if _, err := records.Save(ctx, Record{}, revision); err != nil {
		t.Fatal(err)
	}
	// Provider observations below are seeded independently; they are not successful scaler births.
	seeded := seedCapacityPool(cloud, *chosen.Recipe, 1)
	readDemand := func(t *testing.T) (*CapacityDemand, error) {
		t.Helper()
		state, err := observed.Observe(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, in := range state.Instances {
			if in.Birth != nil {
				t.Fatal("fixture observation invented an admitted birth")
			}
		}
		nodes, err := hosts.control.ListNodes(ctx, &api.ListNodesRequest{})
		if err != nil {
			t.Fatal(err)
		}
		return scaler.functionDemand(ctx, &tick{pool: state, hosts: nodes.Nodes})
	}
	if demand, err := readDemand(t); err != nil || demand != nil {
		t.Fatalf("actual pool target caused duplicate provisioning: demand=%+v err=%v", demand, err)
	}
	instance := cloud.launch("ts-gru-4", seeded.PoolID, "10.0.0.4", core.InstanceLifecycleStateRunning, launchTags(*chosen.Recipe, roleNode, ""))
	if demand, err := readDemand(t); err != nil || demand != nil {
		t.Fatalf("actual unadmitted member caused duplicate provisioning: demand=%+v err=%v", demand, err)
	}
	hosts.live["ts-gru-4"], hosts.instanceIDs["ts-gru-4"] = true, instance
	hosts.sync(t)
	if err := hosts.store.Update(func(tx store.Tx) error {
		node := store.GetNode(tx, "ts-gru-4")
		node.Certificate.Role = api.NodeRoleWorker
		node.Spec.Annotations.Labels["terrascale.host-role"] = RoleWasm
		node.Spec.Annotations.Labels["terrascale.execution-scope"] = "tenant"
		node.Description = &api.NodeDescription{Platform: &api.Platform{OS: "linux", Architecture: "amd64"},
			Resources: &api.Resources{Generic: []*api.GenericResource{genericresource.NewDiscrete("terrascale.function-worker-slot", 1)}}}
		return store.UpdateNode(tx, node)
	}); err != nil {
		t.Fatal(err)
	}
	if demand, err := readDemand(t); err != nil || demand != nil {
		t.Fatalf("free exact manager slot caused duplicate capacity: demand=%+v err=%v", demand, err)
	}
	for _, change := range []struct {
		name  string
		apply func(*api.Node)
	}{
		{"wrong role", func(n *api.Node) { n.Spec.Annotations.Labels["terrascale.host-role"] = RoleContainer }},
		{"wrong scope", func(n *api.Node) { n.Spec.Annotations.Labels["terrascale.execution-scope"] = "platform" }},
		{"wrong architecture", func(n *api.Node) { n.Description.Platform.Architecture = "arm64" }},
		{"missing slot", func(n *api.Node) { n.Description.Resources.Generic = nil }},
		{"two slots", func(n *api.Node) {
			n.Description.Resources.Generic = []*api.GenericResource{genericresource.NewDiscrete("terrascale.function-worker-slot", 2)}
		}},
	} {
		t.Run(change.name, func(t *testing.T) {
			original, err := hosts.control.GetNode(ctx, &api.GetNodeRequest{NodeID: "ts-gru-4"})
			if err != nil {
				t.Fatal(err)
			}
			if err := hosts.store.Update(func(tx store.Tx) error {
				node := store.GetNode(tx, "ts-gru-4")
				change.apply(node)
				return store.UpdateNode(tx, node)
			}); err != nil {
				t.Fatal(err)
			}
			if demand, err := readDemand(t); err == nil || demand != nil {
				t.Fatalf("malformed actual worker supplied capacity: demand=%+v err=%v", demand, err)
			}
			if err := hosts.store.Update(func(tx store.Tx) error {
				node := store.GetNode(tx, "ts-gru-4")
				node.Spec = original.Node.Spec
				node.Description = original.Node.Description
				return store.UpdateNode(tx, node)
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
	if err := hosts.store.Update(func(tx store.Tx) error {
		return store.CreateTask(tx, &api.Task{ID: "occupied-worker", NodeID: "ts-gru-4", DesiredState: api.TaskStateRunning, Status: api.TaskStatus{State: api.TaskStateRunning}})
	}); err != nil {
		t.Fatal(err)
	}
	if demand, err := readDemand(t); err != nil || demand == nil || demand.Architecture != "amd64" || demand.Slots != 1 {
		t.Fatalf("occupied actual worker hid remaining demand: demand=%+v err=%v", demand, err)
	}
	demandErr = errors.New("current signed function intent is unavailable")
	if demand, err := readDemand(t); !errors.Is(err, demandErr) || demand != nil {
		t.Fatalf("unavailable demand was accepted: demand=%+v err=%v", demand, err)
	}
	if len(cloud.pools) != 1 || deref(cloud.pools[seeded.PoolID].Size) != 1 || deref(cloud.instances[instance].DisplayName) != "ts-gru-4" {
		t.Fatal("slot observations changed actual capacity")
	}
}
