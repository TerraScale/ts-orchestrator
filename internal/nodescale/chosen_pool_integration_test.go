package nodescale

import (
	"errors"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/oracle/oci-go-sdk/v65/core"
)

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
	action := &InFlight{ID: entityid.New(), Kind: Up}
	revision, err := store.Save(ctx, Record{Recipe: new(chosen), Action: action}, 0)
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
	if err := restarted.Grow(ctx, 1); !errors.Is(err, ErrCapacityPending) || cloud.updates != updates {
		t.Fatalf("restart grew without readmission: %v", err)
	}
	if _, err := restarted.Ensure(ctx, chosen); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Grow(ctx, 0); err != nil || cloud.updates != updates {
		t.Fatalf("restart did not recognize observed growth: %v", err)
	}
	nextAction := &InFlight{ID: entityid.New(), Kind: Up}
	revision, err = store.Save(ctx, Record{Recipe: new(chosen), Action: nextAction}, revision)
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
	nextState, err := restarted.Ensure(ctx, chosen)
	if err != nil {
		t.Fatal(err)
	}
	nextLaunch := cloud.configs[nextState.ConfigurationID].InstanceDetails.(core.ComputeInstanceDetails).LaunchDetails
	if nextState.ConfigurationID == state.ConfigurationID || nextLaunch.FreeformTags[tagOperationID] != nextAction.ID ||
		nextLaunch.FreeformTags[tagRecipeSHA256] != chosen.SHA256() {
		t.Fatalf("new operation retained the previous spending identity: %+v", nextLaunch)
	}
	updates = cloud.updates
	changed := chosen
	changed.ImageID = "ocid1.image.replacement"
	if _, err := store.Save(ctx, Record{Recipe: new(changed), Action: nextAction}, revision); err != nil {
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
