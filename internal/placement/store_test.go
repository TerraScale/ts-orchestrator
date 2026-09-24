package placement

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
)

func TestMemberStateKeyIncludesPartitionIdentity(t *testing.T) {
	first := memberStateKey("db-main", "partition-a", "permanent-a")
	second := memberStateKey("db-main", "partition-b", "permanent-a")
	if first == second {
		t.Fatalf("partition member keys collide: %q", first)
	}
	if memberStatePrefix("db-main", "partition-a") != "member.db-main.partition-a." ||
		memberStatePrefix("db-main", "partition-b") != "member.db-main.partition-b." {
		t.Fatal("member state prefixes do not preserve the composite identity")
	}
}

func TestIntentListAllowsDifferentPartitionsButRejectsDuplicateCompositeIdentity(t *testing.T) {
	reader := intentReaderFunc(func(context.Context, string) ([]Intent, error) {
		return []Intent{
			{SchemaVersion: placementSchemaVersion, DatabaseID: "db-main", PartitionID: "partition-b", ActiveRegions: []oci.Region{oci.RegionGRU}, Generation: 1},
			{SchemaVersion: placementSchemaVersion, DatabaseID: "db-main", PartitionID: "partition-a", ActiveRegions: []oci.Region{oci.RegionGRU}, Generation: 1},
		}, nil
	})
	store := &jetStreamStore{cell: "gru", intents: reader}
	intents, err := store.ListIntents(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []Intent{
		{SchemaVersion: placementSchemaVersion, DatabaseID: "db-main", PartitionID: "partition-a", ActiveRegions: []oci.Region{oci.RegionGRU}, Generation: 1},
		{SchemaVersion: placementSchemaVersion, DatabaseID: "db-main", PartitionID: "partition-b", ActiveRegions: []oci.Region{oci.RegionGRU}, Generation: 1},
	}
	if !reflect.DeepEqual(intents, want) {
		t.Fatalf("partition intents = %#v, want %#v", intents, want)
	}

	store.intents = intentReaderFunc(func(context.Context, string) ([]Intent, error) {
		return []Intent{want[0], want[0]}, nil
	})
	if _, err := store.ListIntents(context.Background()); !errors.Is(err, ErrInvalidIntent) {
		t.Fatalf("duplicate composite identity error = %v, want ErrInvalidIntent", err)
	}
}

type intentReaderFunc func(context.Context, string) ([]Intent, error)

func (reader intentReaderFunc) ListPlacementIntents(ctx context.Context, cell string) ([]Intent, error) {
	return reader(ctx, cell)
}
