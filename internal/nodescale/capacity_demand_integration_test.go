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
	js := capacityJetStream(t)
	records, err := OpenStore(ctx, js, 1)
	if err != nil {
		t.Fatal(err)
	}
	configureProtocolJournal(t, observed, records)
	pool, err := NewChosenPool(observed, records)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	pending := true
	demandErr := error(nil)
	scaler := &Scaler{Cell: "gru", Pool: pool, Store: records, Control: hosts.control,
		Leader: &capacityLeader{snapshot: authority.Snapshot{DeploymentID: entityid.New(), Leader: true, Ready: true, Epoch: 7, Revision: 3, ExpiresAt: now.Add(time.Hour)}},
		Now:    func() time.Time { return now }, Recipe: func(context.Context) (Recipe, error) { return base, nil },
		// Demand is supplied here; signed producer qualification is separate from the real manager/OCI slot observations.
		FunctionDemand: func(context.Context) ([]CapacityDemand, error) {
			if !pending {
				return nil, demandErr
			}
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
	tick := func() Record {
		t.Helper()
		if err := scaler.Tick(ctx); err != nil {
			t.Fatal(err)
		}
		current, _, err := records.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return current
	}
	chosen := tick()
	if chosen.Action == nil || chosen.Action.Kind != Up || chosen.Recipe == nil || chosen.Recipe.Capacity.Role != RoleWasm || chosen.Recipe.Capacity.Architecture != "amd64" || len(cloud.pools) != 0 {
		t.Fatalf("exact unassigned function demand did not plan isolated capacity without telemetry: %+v", chosen)
	}
	launched := tick()
	if launched.Action == nil || launched.Action.Step != stepEnroll || len(cloud.pools) != 1 {
		t.Fatalf("function capacity did not grow through durable selected pool: %+v", launched)
	}
	var poolID string
	for id := range cloud.pools {
		poolID = id
	}
	// The actual pool target already represents the slot before OCI returns an instance ID.
	if _, err := records.Save(ctx, Record{Recipe: launched.Recipe}, revisionOf(t, records)); err != nil {
		t.Fatal(err)
	}
	if current := tick(); current.Action != nil {
		t.Fatal("one still-provisioning pool slot caused duplicate host growth")
	}
	instance := cloud.launch("ts-gru-4", poolID, "10.0.0.4", core.InstanceLifecycleStateRunning, launchTags(*launched.Recipe, roleNode, chosen.Action.ID))
	cloud.instances[instance].CompartmentId = new(testCompartment)
	for _, err := range []error{pool.Name(ctx, instance, "ts-gru-5"), pool.Remove(ctx, instance)} {
		if !errors.Is(err, ErrCapacityPending) {
			t.Fatalf("slot observation minted child mutation authority: %v", err)
		}
	}
	if deref(cloud.instances[instance].DisplayName) != "ts-gru-4" || len(cloud.detaches) != 0 {
		t.Fatal("unproven function child was renamed or removed")
	}
	hosts.live["ts-gru-4"], hosts.instanceIDs["ts-gru-4"] = true, instance
	hosts.sync(t)
	if err := hosts.store.Update(func(tx store.Tx) error {
		node := store.GetNode(tx, "ts-gru-4")
		node.Spec.Annotations.Labels["terrascale.host-role"] = RoleWasm
		node.Spec.Annotations.Labels["terrascale.execution-scope"] = "tenant"
		node.Description = &api.NodeDescription{Platform: &api.Platform{OS: "linux", Architecture: "amd64"},
			Resources: &api.Resources{Generic: []*api.GenericResource{genericresource.NewDiscrete("terrascale.function-worker-slot", 1)}}}
		return store.UpdateNode(tx, node)
	}); err != nil {
		t.Fatal(err)
	}
	if current := tick(); current.Action != nil {
		t.Fatal("observed free manager slot caused duplicate host growth")
	}
	if err := hosts.store.Update(func(tx store.Tx) error {
		return store.CreateTask(tx, &api.Task{ID: "occupied-worker", NodeID: "ts-gru-4", DesiredState: api.TaskStateRunning, Status: api.TaskStatus{State: api.TaskStateRunning}})
	}); err != nil {
		t.Fatal(err)
	}
	if current := tick(); current.Action == nil || current.Recipe.Capacity.Role != RoleWasm || *current.TargetFrom != 1 || current.From != 1 {
		t.Fatalf("occupied slot hid remaining unassigned function demand: %+v", current)
	}
	if _, err := records.Save(ctx, Record{Recipe: launched.Recipe}, revisionOf(t, records)); err != nil {
		t.Fatal(err)
	}
	pending, demandErr = false, errors.New("current signed function intent is unavailable")
	if current := tick(); current.Action != nil || scaler.Status().Action != Hold {
		t.Fatal("missing current function authority created capacity")
	}
}

func revisionOf(t *testing.T, records RecordStore) uint64 {
	t.Helper()
	_, revision, err := records.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return revision
}
