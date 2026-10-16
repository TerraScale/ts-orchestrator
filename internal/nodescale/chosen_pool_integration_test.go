package nodescale

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/budget"
	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/oracle/oci-go-sdk/v65/core"
)

func TestCapacityReservationPersistsBeforeOCIWrite(t *testing.T) {
	ctx := t.Context()
	js := capacityJetStream(t)
	store, err := OpenStore(ctx, js, 1)
	if err != nil {
		t.Fatal(err)
	}
	recipe := capacityRecipe()
	now := time.Now().UTC()
	action := &InFlight{ID: entityid.New(), Kind: Up, Step: stepGrow, Started: now}
	if _, err := store.Save(ctx, Record{Recipe: new(recipe), Action: action, TargetFrom: new(0)}, 0); err != nil {
		t.Fatal(err)
	}
	cloud := newCapacityCloud()
	observed := protocolPool(t, cloud, recipe.Capacity)
	admissions := 0
	observed.Admit = func(ctx context.Context, chosen Recipe) (func(), error) {
		stored, _, err := store.Load(ctx)
		if err != nil || stored.Reservation == nil || stored.Reservation.OperationID != action.ID || stored.Reservation.RecipeSHA256 != chosen.SHA256() {
			return nil, ErrCapacityPending
		}
		admissions++
		return func() {}, nil
	}
	configureProtocolJournal(t, observed, store)
	pool, err := NewChosenPool(observed, store)
	if err != nil {
		t.Fatal(err)
	}
	hosts := newSwarmHosts(t)
	reservations := 0
	scaler := &Scaler{Cell: "gru", Pool: pool, Store: store, Control: hosts.control,
		Leader: &capacityLeader{snapshot: authority.Snapshot{DeploymentID: entityid.New(), Leader: true, Ready: true, Epoch: 7, Revision: 3, ExpiresAt: now.Add(time.Hour)}},
		Now:    func() time.Time { return now }, Recipe: func(context.Context) (Recipe, error) { return recipe, nil },
		Reserve: func(context.Context, string, Recipe) (budget.Reservation, error) {
			reservations++
			return budget.Reservation{OperationID: action.ID, RecipeSHA256: recipe.SHA256()}, nil
		},
		Allowance: func(time.Time) (int, bool) { return MaxNodes, true }, Loads: func() []NodeLoad { return nil },
		Journal: func(context.Context, decisionlog.Decision) {},
	}
	if err := scaler.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	stored, _, err := store.Load(ctx)
	if err != nil || stored.Reservation == nil || stored.Reservation.OperationID != action.ID || reservations != 1 || admissions != 0 || len(cloud.configs) != 0 || len(cloud.pools) != 0 {
		t.Fatalf("reservation was not durable before OCI writes: record=%+v reservations=%d admissions=%d err=%v", stored, reservations, admissions, err)
	}
	reopened, err := OpenStore(ctx, js, 1)
	if err != nil {
		t.Fatal(err)
	}
	scaler.Store = reopened
	scaler.Pool, err = NewChosenPool(observed, reopened)
	if err != nil {
		t.Fatal(err)
	}
	if err := scaler.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if reservations != 1 || admissions == 0 || len(cloud.configs) != 1 || len(cloud.pools) != 1 {
		t.Fatalf("restart lost reservation or skipped per-write admission: reservations=%d admissions=%d configs=%d pools=%d", reservations, admissions, len(cloud.configs), len(cloud.pools))
	}
}

func TestChosenFallbackKeepsExistingCapacityPools(t *testing.T) {
	ctx := t.Context()
	cloud := newCapacityCloud()
	cloud.shapeRows = []core.Shape{capacityShape("VM.Standard.A1.Flex", "Ampere"), capacityShape("VM.Standard.A2.Flex", "Ampere")}
	base := capacityRecipe()
	observed := protocolPool(t, cloud, base.Capacity)
	initial, err := observed.Ensure(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	if err := observed.Grow(ctx, 0); err != nil {
		t.Fatal(err)
	}
	old := cloud.launch("ts-gru-4", initial.PoolID, "10.0.0.4", core.InstanceLifecycleStateRunning, launchTags(base, roleNode, entityid.New()))
	cloud.instances[old].CompartmentId = new(testCompartment)
	chosen := base
	chosen.Capacity.Shape = "VM.Standard.A2.Flex"
	action := &InFlight{ID: entityid.New(), Kind: Up, Started: time.Now().UTC()}
	store, err := OpenStore(ctx, capacityJetStream(t), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Save(ctx, Record{Recipe: new(chosen), Action: action, From: 1, TargetFrom: new(0)}, 0); err != nil {
		t.Fatal(err)
	}
	configureProtocolJournal(t, observed, store)
	pool, err := NewChosenPool(observed, store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Ensure(ctx, chosen); !errors.Is(err, ErrCapacityPending) {
		t.Fatalf("fallback adopted an older pool without protected original lineage: %v", err)
	}
	updates := cloud.updates
	for range 2 {
		if err := pool.Grow(ctx, 1); !errors.Is(err, ErrCapacityPending) && !errors.Is(err, ErrPoolChanged) || cloud.updates != updates {
			t.Fatalf("fallback retry changed unproven regional capacity: %v", err)
		}
	}
	state, err := pool.Observe(ctx)
	if err != nil || state.Pending == "" || state.Size != 1 || len(state.Instances) != 1 || state.Instances[0].ID != old || deref(cloud.pools[initial.PoolID].Size) != 1 || len(cloud.pools) != 2 {
		t.Fatalf("pending fallback hid or changed existing capacity: %+v err=%v", state, err)
	}
	if err := pool.Name(ctx, old, "ts-gru-5"); !errors.Is(err, ErrCapacityPending) || deref(cloud.instances[old].DisplayName) != "ts-gru-4" {
		t.Fatalf("current membership authorized naming an old child: %v", err)
	}
	cloud.instances[old].FreeformTags[tagCapacityRole] = RoleWasm
	if err := pool.Remove(ctx, old); !errors.Is(err, ErrNotPoolInstance) || len(cloud.detaches) != 0 {
		t.Fatalf("different isolation role was detached: %v", err)
	}
	cloud.instances[old].FreeformTags[tagCapacityRole] = RoleContainer
	if err := pool.Remove(ctx, old); !errors.Is(err, ErrCapacityPending) || len(cloud.detaches) != 0 || deref(cloud.pools[initial.PoolID].Size) != 1 {
		t.Fatalf("tags minted old child retirement authority: %v", err)
	}
}

func TestChosenCapacitySurvivesRestartAndFencesOCIChanges(t *testing.T) {
	ctx := t.Context()
	js := capacityJetStream(t)
	store, err := OpenStore(ctx, js, 1)
	if err != nil {
		t.Fatal(err)
	}
	cloud := newCapacityCloud()
	cloud.shapeRows = []core.Shape{capacityShape("VM.Standard.A2.Flex", "Ampere")}
	observed := protocolPool(t, cloud, capacityRecipe().Capacity)
	configureProtocolJournal(t, observed, store)
	pool, err := NewChosenPool(observed, store)
	if err != nil {
		t.Fatal(err)
	}
	chosen := capacityRecipe()
	chosen.Capacity.Shape = "VM.Standard.A2.Flex"
	chosen.ImageID = "ocid1.image.qualified-a2"
	chosen.AvailabilityDomains = []string{"AD-2"}
	if _, err := pool.Ensure(ctx, chosen); !errors.Is(err, ErrCapacityPending) || len(cloud.configs) != 0 || len(cloud.pools) != 0 {
		t.Fatalf("uncommitted choice changed OCI: %v", err)
	}
	action := &InFlight{ID: entityid.New(), Kind: Up, Started: time.Now().UTC()}
	revision, err := store.Save(ctx, Record{Recipe: new(chosen), Action: action, TargetFrom: new(0)}, 0)
	if err != nil {
		t.Fatal(err)
	}
	state, err := pool.Ensure(ctx, chosen)
	if err != nil {
		t.Fatal(err)
	}
	launch := cloud.configs[state.ConfigurationID].InstanceDetails.(core.ComputeInstanceDetails).LaunchDetails
	if deref(launch.Shape) != chosen.Capacity.Shape || launch.SourceDetails.(core.InstanceConfigurationInstanceSourceViaImageDetails).ImageId == nil ||
		*launch.SourceDetails.(core.InstanceConfigurationInstanceSourceViaImageDetails).ImageId != chosen.ImageID {
		t.Fatalf("fallback identity was replaced with observed controller shape: %+v", launch)
	}
	if launch.FreeformTags[tagOperationID] != action.ID || launch.FreeformTags[tagRecipeSHA256] != chosen.SHA256() {
		t.Fatalf("launched resources cannot be bound to their exact spending commitment: %+v", launch.FreeformTags)
	}
	if err := pool.Grow(ctx, 0); err != nil {
		t.Fatal(err)
	}
	updates := cloud.updates
	reopened, err := OpenStore(ctx, js, 1)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := NewChosenPool(observed, reopened)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := restarted.Observe(ctx)
	if err != nil || pending.Pending == "" || pending.Size != 1 || pending.PoolID != state.PoolID || pending.ConfigurationID != state.ConfigurationID {
		t.Fatalf("restart observation adopted stored create receipts: %+v err=%v", pending, err)
	}
	if err := restarted.Grow(ctx, 0); !errors.Is(err, ErrPoolChanged) || cloud.updates != updates || len(cloud.pools) != 1 || len(cloud.configs) != 1 ||
		deref(cloud.pools[state.PoolID].Size) != 1 || deref(cloud.pools[state.PoolID].InstanceConfigurationId) != state.ConfigurationID {
		t.Fatalf("restart failed to refuse growth on pending original lineage without changing OCI: %v", err)
	}
	if _, err := restarted.Ensure(ctx, chosen); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Grow(ctx, 0); err != nil || cloud.updates != updates {
		t.Fatalf("restart did not recognize observed growth: %v", err)
	}
	nextAction := &InFlight{ID: entityid.New(), Kind: Up, Started: time.Now().UTC()}
	revision, err = store.Save(ctx, Record{Recipe: new(chosen), Action: nextAction, From: 1, TargetFrom: new(1)}, revision)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Grow(ctx, 1); !errors.Is(err, ErrCapacityPending) || cloud.updates != updates {
		t.Fatalf("new operation reused a previous launch admission: %v", err)
	}
	if _, err := restarted.Ensure(ctx, chosen); !errors.Is(err, ErrCapacityPending) {
		t.Fatalf("new configuration was accepted before OCI applied it: %v", err)
	}
	cloud.settle()
	if _, err := restarted.Ensure(ctx, chosen); !errors.Is(err, ErrCapacityPending) || len(cloud.configs) != 1 || cloud.configs[state.ConfigurationID] == nil || cloud.updates != updates {
		t.Fatalf("settled observations minted new-operation authority: %v", err)
	}
	updates = cloud.updates
	changed := chosen
	changed.ImageID = "ocid1.image.replacement"
	if _, err := store.Save(ctx, Record{Recipe: new(changed), Action: nextAction, From: 1, TargetFrom: new(1)}, revision); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Grow(ctx, 1); !errors.Is(err, ErrCapacityPending) || cloud.updates != updates {
		t.Fatalf("stale admitted choice changed OCI: %v", err)
	}
	if _, err := restarted.Ensure(ctx, chosen); !errors.Is(err, ErrCapacityPending) || cloud.updates != updates {
		t.Fatalf("caller replaced durable choice: %v", err)
	}
	current, _, err := reopened.Load(ctx)
	if err != nil || current.Recipe == nil || current.Recipe.Digest() != changed.Digest() {
		t.Fatalf("durable fallback recipe lost: %+v, %v", current.Recipe, err)
	}
}
